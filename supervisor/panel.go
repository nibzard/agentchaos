// Package supervisor: heterogeneous reviewer panels (T051, spec
// 11.4, the consortium profile).
//
// A panel is independent first-pass reviewers with different models,
// training families, prompts, and evidence views, followed by a
// deterministic adjudicator. Independence is structural, not
// behavioral: each member receives only its own evidence view of the
// task and never another member's findings, and the first-pass
// ballots are fixed — hashed — before adjudication reads them.
//
// The panel grants no authority. Its output is one review decision
// under the same contract as every other reviewer: the strictest
// escalated verdict wins, a member that fails records an abstain, and
// a member's consent never releases a held effect on its own.
package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"gauntlet/broker"
	"gauntlet/evidence"
)

// Evidence views a panel member may be assigned (spec 11.4:
// "different ... evidence views"). A view is a filter over the
// window, applied by the panel before the member runs, so a member
// cannot widen its own view.
const (
	ViewAll         = "all"
	ViewIndependent = "independent"
	ViewWorker      = "worker_claims"
	ViewProposal    = "proposal_only"
)

// PanelMember is one independent first-pass reviewer with its
// declared heterogeneity and its per-review cost for matched-cost
// accounting (spec 11.4, spec 16).
type PanelMember struct {
	// Reviewer is the first-pass decision implementation.
	Reviewer ContextualReviewer
	// MemberID names the member on its ballot.
	MemberID string
	// ModelID, Family, and PromptVersion declare the member's
	// heterogeneity dimensions (spec 11.4).
	ModelID       string
	Family        string
	PromptVersion string
	// EvidenceView selects the view the panel applies for this
	// member. The member cannot see outside it.
	EvidenceView string
	// CostMicros is the member's declared cost per review.
	CostMicros int64
}

// PanelBallot is one member's fixed first-pass finding.
type PanelBallot struct {
	MemberID     string `json:"member_id"`
	ModelID      string `json:"model_id"`
	Family       string `json:"family"`
	PromptVersion string `json:"prompt_version"`
	EvidenceView string `json:"evidence_view"`
	Verdict      string `json:"verdict"`
	Rationale    string `json:"rationale"`
	LatencyMS    int64  `json:"latency_ms"`
	CostMicros   int64  `json:"cost_micros"`
	// Error records a member that failed or missed its deadline. A
	// failed member ballots abstain; it never ballots allow.
	Error string `json:"error,omitempty"`
}

// PanelReport is the fixed first pass plus the adjudicated decision.
type PanelReport struct {
	PanelID string        `json:"panel_id"`
	Ballots []PanelBallot `json:"ballots"`
	// FindingsDigest hashes the fixed ballots. Adjudication runs only
	// after this digest exists; the digest is on every decision, so a
	// changed ballot after adjudication is detectable.
	FindingsDigest string       `json:"findings_digest"`
	Adjudicated    broker.Review `json:"adjudicated"`
}

// Panel is the consortium profile: independent first pass, then
// deterministic adjudication (spec 11.4).
type Panel struct {
	ID      string
	Members []PanelMember
}

// verdict strictness for adjudication. The strictest escalated
// verdict wins: one member's deny holds the effect even if every
// other member would allow.
var verdictRank = map[string]int{
	broker.ReviewDeny:    3,
	broker.ReviewWatch:   2,
	broker.ReviewAbstain: 1,
	broker.ReviewAllow:   0,
}

// NewPanel builds a panel and refuses anything that is not a
// heterogeneous first pass: at least two members, no shared member or
// reviewer identity, no duplicated heterogeneity profile, and a known
// evidence view on every member.
func NewPanel(id string, members ...PanelMember) (*Panel, error) {
	if id == "" {
		return nil, fmt.Errorf("a panel needs an id")
	}
	if len(members) < 2 {
		return nil, fmt.Errorf(
			"a panel needs at least two first-pass reviewers; %d is not a panel",
			len(members))
	}
	seenMember := map[string]bool{}
	seenReviewer := map[string]bool{}
	seenProfile := map[string]bool{}
	for i, member := range members {
		if member.MemberID == "" || member.Reviewer == nil {
			return nil, fmt.Errorf("member %d needs an id and a reviewer", i)
		}
		if seenMember[member.MemberID] {
			return nil, fmt.Errorf(
				"member %q appears twice on the panel", member.MemberID)
		}
		seenMember[member.MemberID] = true
		switch member.EvidenceView {
		case ViewAll, ViewIndependent, ViewWorker, ViewProposal:
		default:
			return nil, fmt.Errorf(
				"member %q carries unknown evidence view %q",
				member.MemberID, member.EvidenceView)
		}
		// The heterogeneity profile is model plus family plus prompt
		// plus view. Two members with the same profile are one
		// reviewer run twice; that is brand diversity, not a panel
		// (spec 11.4).
		profile := strings.Join([]string{
			member.ModelID, member.Family, member.PromptVersion,
			member.EvidenceView,
		}, "\x00")
		if seenProfile[profile] {
			return nil, fmt.Errorf(
				"members share the model, family, prompt, and view profile " +
					"of " + member.MemberID + "; a panel must be heterogeneous")
		}
		seenProfile[profile] = true
		if other, ok := reviewerIdentity(member); ok {
			if seenReviewer[other] {
				return nil, fmt.Errorf(
					"reviewer %q backs two members; a reviewer ballots once",
					other)
			}
			seenReviewer[other] = true
		}
	}
	return &Panel{ID: id, Members: append([]PanelMember{}, members...)}, nil
}

// reviewerIdentity reads a deterministic reviewer's identity when it
// has one, so one implementation cannot ballot twice.
func reviewerIdentity(member PanelMember) (string, bool) {
	if ref, ok := member.Reviewer.(*ReferenceReviewer); ok && ref != nil {
		return ref.ReviewerID, true
	}
	return "", false
}

// Review runs the first pass and adjudicates. It satisfies the same
// ContextualReviewer contract as every other reviewer.
func (p *Panel) Review(ctx context.Context, task ReviewTask) (broker.Review, error) {
	report, err := p.ReviewWithReport(ctx, task)
	if err != nil {
		return broker.Review{}, err
	}
	return report.Adjudicated, nil
}

// ReviewWithReport runs the panel and returns the full report:
// the fixed ballots, their digest, and the adjudicated decision.
func (p *Panel) ReviewWithReport(ctx context.Context, task ReviewTask) (*PanelReport, error) {
	ballots := make([]PanelBallot, 0, len(p.Members))
	for _, member := range p.Members {
		ballots = append(ballots, p.firstPass(ctx, member, task))
	}
	// The first pass is fixed here, before adjudication reads a
	// single verdict: the digest covers every ballot.
	digest := findingsDigest(ballots)
	decision, err := p.adjudicate(ballots, digest, task)
	if err != nil {
		return nil, err
	}
	return &PanelReport{
		PanelID:        p.ID,
		Ballots:        ballots,
		FindingsDigest: digest,
		Adjudicated:    decision,
	}, nil
}

// firstPass runs one member over its evidence view. The member sees
// only the filtered task: no other member's findings exist in its
// input, and a member that fails ballots abstain, never allow.
func (p *Panel) firstPass(ctx context.Context, member PanelMember,
	task ReviewTask) PanelBallot {
	ballot := PanelBallot{
		MemberID:      member.MemberID,
		ModelID:       member.ModelID,
		Family:        member.Family,
		PromptVersion: member.PromptVersion,
		EvidenceView:  member.EvidenceView,
		CostMicros:    member.CostMicros,
	}
	start := time.Now()
	view := p.applyView(task, member.EvidenceView)
	review, err := member.Reviewer.Review(ctx, view)
	ballot.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		ballot.Verdict = broker.ReviewAbstain
		ballot.Error = err.Error()
		ballot.Rationale = "the member failed; an abstain keeps the hold"
		return ballot
	}
	if review.Verdict == "" {
		ballot.Verdict = broker.ReviewAbstain
		ballot.Error = "the member returned no verdict"
		ballot.Rationale = "a member without a verdict abstains; it never allows"
		return ballot
	}
	ballot.Verdict = review.Verdict
	ballot.Rationale = review.Rationale
	return ballot
}

// applyView filters the window for one member. The proposal and the
// detector findings always travel; only the evidence window narrows.
func (p *Panel) applyView(task ReviewTask, view string) ReviewTask {
	filtered := ReviewTask{
		Proposal:  task.Proposal,
		Purpose:   task.Purpose,
		Detection: task.Detection,
	}
	switch view {
	case ViewAll:
		filtered.RecentEvents = task.RecentEvents
	case ViewIndependent:
		for i := range task.RecentEvents {
			label := task.RecentEvents[i].TrustLabel
			if label == evidence.TrustCollectorFact ||
				label == evidence.TrustMonitorReading {
				filtered.RecentEvents = append(
					filtered.RecentEvents, task.RecentEvents[i])
			}
		}
	case ViewWorker:
		for i := range task.RecentEvents {
			if task.RecentEvents[i].TrustLabel == evidence.TrustWorkerClaim {
				filtered.RecentEvents = append(
					filtered.RecentEvents, task.RecentEvents[i])
			}
		}
	case ViewProposal:
		// The proposal-only view sees no window at all: deterministic
		// specialization on the request itself.
	}
	return filtered
}

// adjudicate merges fixed ballots. The strictest verdict wins; every
// dissent is recorded on the decision. Agreement is a diagnostic, so
// the limitations say it is not an independence certificate.
//
// The decision cites the panel's input the same way a single
// contextual reviewer does (AC-014): the contextual-review policy
// plus every suspicion's policy, and the whole input window's event
// ids plus every suspicion's events. A panel that judged nothing
// citable cannot produce a record; it holds.
func (p *Panel) adjudicate(ballots []PanelBallot, digest string,
	task ReviewTask) (broker.Review, error) {
	counts := map[string]int{}
	for _, ballot := range ballots {
		counts[ballot.Verdict]++
	}
	strictest := broker.ReviewAllow
	for _, ballot := range ballots {
		if verdictRank[ballot.Verdict] > verdictRank[strictest] {
			strictest = ballot.Verdict
		}
	}
	verdicts := make([]string, 0, len(counts))
	for verdict := range counts {
		verdicts = append(verdicts, verdict)
	}
	sort.Strings(verdicts)
	parts := make([]string, 0, len(verdicts))
	for _, verdict := range verdicts {
		parts = append(parts, fmt.Sprintf("%d %s", counts[verdict], verdict))
	}
	review := broker.Review{
		ReviewerID:    p.ID,
		Verdict:       strictest,
		PromptVersion: "panel-adjudication-v1",
		PolicyRefs:    []string{panelAdjudicationPolicy, detectionReviewPolicy},
		Rationale: fmt.Sprintf(
			"first pass fixed over %d members (%s); adjudicated to the "+
				"strictest escalated verdict",
			len(ballots), strings.Join(parts, ", ")),
		Limitations: fmt.Sprintf(
			"adjudicated after first-pass findings were fixed (digest %s); "+
				"panel agreement is a diagnostic, not a statistical "+
				"independence certificate", digest),
		LatencyMS: 0,
	}
	for _, ballot := range ballots {
		if ballot.Verdict == strictest {
			if review.ModelID == "" {
				review.ModelID = ballot.ModelID
			} else if !strings.Contains(review.ModelID, ballot.ModelID) {
				review.ModelID += "," + ballot.ModelID
			}
		}
	}
	// Sequential first pass: the panel's wall time is the sum of its
	// members' latencies, and its cost the sum of their costs.
	var latency int64
	var cost int64
	for _, ballot := range ballots {
		latency += ballot.LatencyMS
		cost += ballot.CostMicros
	}
	review.LatencyMS = latency
	review.Rationale += fmt.Sprintf(
		"; sequential first pass cost %d micros", cost)

	// The references cover the panel's whole input: every member saw a
	// subset of this window, and the decision speaks for the panel.
	var eventRefs []string
	for i := range task.RecentEvents {
		eventRefs = append(eventRefs, task.RecentEvents[i].ID)
	}
	for i := range task.Detection.Suspicions {
		review.PolicyRefs = append(
			review.PolicyRefs, task.Detection.Suspicions[i].PolicyRef)
		eventRefs = append(eventRefs, task.Detection.Suspicions[i].EventRefs...)
	}
	review.PolicyRefs, review.EventRefs = refUnion(review.PolicyRefs, eventRefs)
	if errs := review.ValidateReview(); len(errs) > 0 {
		// A decision without citable events must not reach a record;
		// it becomes a hold, exactly like a single reviewer's fallback.
		return broker.Review{}, fmt.Errorf(
			"%w: the panel could not cite source events: %d contract errors",
			ErrReviewHeld, len(errs))
	}
	return review, nil
}

// panelAdjudicationPolicy is the policy rule the adjudication step
// itself enforces: strictest escalated verdict over fixed findings.
const panelAdjudicationPolicy = "pol_1.1.0/supervision.review.panel"

// findingsDigest hashes the fixed ballots, ordered by member id, so
// the same first pass always yields the same digest and any later
// edit breaks it.
func findingsDigest(ballots []PanelBallot) string {
	ordered := append([]PanelBallot{}, ballots...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].MemberID < ordered[j].MemberID
	})
	parts := make([]string, 0, len(ordered))
	for _, ballot := range ordered {
		parts = append(parts, strings.Join([]string{
			ballot.MemberID, ballot.ModelID, ballot.Family,
			ballot.PromptVersion, ballot.EvidenceView, ballot.Verdict,
		}, "\x1f"))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
