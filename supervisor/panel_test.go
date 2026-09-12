package supervisor

// Heterogeneous reviewer panels (T051, spec 11.4, the consortium
// profile).
//
// These tests prove the structural promises: members see only their
// own evidence view, the first pass is fixed and hashed before
// adjudication reads it, a failed member abstains instead of allowing,
// and the panel output stays under the ordinary review contract.

import (
	"context"
	"strings"
	"testing"

	"gauntlet/broker"
	"gauntlet/evidence"
)

// ballotSpy ballots one canned verdict and captures every task it
// received, so tests can inspect exactly what one member saw.
type ballotSpy struct {
	verdict string
	err     error
	tasks   []ReviewTask
}

func (s *ballotSpy) Review(ctx context.Context,
	task ReviewTask) (broker.Review, error) {
	s.tasks = append(s.tasks, task)
	if s.err != nil {
		return broker.Review{}, s.err
	}
	return broker.Review{
		ReviewerID: "stub",
		Verdict:    s.verdict,
		Rationale:  "canned verdict",
	}, nil
}

func member(id, model, family, prompt, view string,
	reviewer ContextualReviewer, cost int64) PanelMember {
	return PanelMember{
		Reviewer:      reviewer,
		MemberID:      id,
		ModelID:       model,
		Family:        family,
		PromptVersion: prompt,
		EvidenceView:  view,
		CostMicros:    cost,
	}
}

// panelWindow carries one event per trust label plus one monitor
// reading, so view filtering is observable.
func panelWindow() []evidence.Event {
	return []evidence.Event{
		event("evt_"+"p000000000000001", evidence.KindProposedAction,
			evidence.TrustWorkerClaim, evidence.ComponentWorker, 1),
		event("evt_"+"p000000000000002", evidence.KindExternalReceipt,
			evidence.TrustCollectorFact, evidence.ComponentCollector, 2),
		event("evt_"+"p000000000000003", evidence.KindResourceAccess,
			evidence.TrustMonitorReading, evidence.ComponentMonitor, 3),
	}
}

func panelTask() ReviewTask {
	return ReviewTask{
		Purpose:      "close issue #7",
		RecentEvents: panelWindow(),
	}
}

func threeMemberPanel(t *testing.T, first, second,
	third *ballotSpy) (*Panel, error) {
	t.Helper()
	return NewPanel("act_panel-fixture01",
		member("mem-alpha", "mdl_alpha-v1", "familyA", "p1", ViewAll, first, 100),
		member("mem-beta", "mdl_beta-v1", "familyB", "p2",
			ViewIndependent, second, 200),
		member("mem-gamma", "mdl_gamma-v1", "familyC", "p3",
			ViewWorker, third, 300),
	)
}

// TestAPanelNeedsHeterogeneousMembership refuses the panels that are
// not independent first passes: too few members, a repeated member id,
// a duplicated heterogeneity profile, one reviewer balloting twice,
// and an unknown evidence view.
func TestAPanelNeedsHeterogeneousMembership(t *testing.T) {
	ok := &ballotSpy{verdict: broker.ReviewAllow}
	if _, err := NewPanel("act_panel-fixture01"); err == nil {
		t.Fatal("an empty panel was accepted")
	}
	if _, err := NewPanel("act_panel-fixture01",
		member("mem-solo", "mdl_alpha-v1", "familyA", "p1", ViewAll, ok, 1)); err == nil {
		t.Fatal("a single-member panel was accepted")
	}
	if _, err := NewPanel("",
		member("mem-a", "mdl_a", "familyA", "p1", ViewAll, ok, 1),
		member("mem-b", "mdl_b", "familyB", "p2", ViewAll, ok, 1)); err == nil {
		t.Fatal("a panel without an id was accepted")
	}
	dup := &ballotSpy{verdict: broker.ReviewAllow}
	if _, err := NewPanel("act_panel-fixture01",
		member("mem-a", "mdl_a", "familyA", "p1", ViewAll, dup, 1),
		member("mem-a", "mdl_b", "familyB", "p2", ViewAll, dup, 1)); err == nil {
		t.Fatal("a repeated member id was accepted")
	} else if !strings.Contains(err.Error(), "appears twice") {
		t.Fatalf("error: %v", err)
	}
	if _, err := NewPanel("act_panel-fixture01",
		member("mem-a", "mdl_same-v1", "familyA", "p1", ViewAll, dup, 1),
		member("mem-b", "mdl_same-v1", "familyA", "p1", ViewAll, ok, 1)); err == nil {
		t.Fatal("a duplicated heterogeneity profile was accepted")
	} else if !strings.Contains(err.Error(), "heterogeneous") {
		t.Fatalf("error: %v", err)
	}
	if _, err := NewPanel("act_panel-fixture01",
		member("mem-a", "mdl_a", "familyA", "p1", ViewAll, dup, 1),
		member("mem-b", "mdl_b", "familyB", "p2", "sideways", ok, 1)); err == nil {
		t.Fatal("an unknown evidence view was accepted")
	} else if !strings.Contains(err.Error(), "unknown evidence view") {
		t.Fatalf("error: %v", err)
	}
	// One deterministic reviewer implementation ballots once: the
	// same *ReferenceReviewer cannot back two members even under
	// different labels.
	ref := NewReferenceReviewer()
	if _, err := NewPanel("act_panel-fixture01",
		member("mem-a", "mdl_a", "familyA", "p1", ViewAll, ref, 1),
		member("mem-b", "mdl_b", "familyB", "p2", ViewWorker, ref, 1)); err == nil {
		t.Fatal("one reviewer balloting twice was accepted")
	} else if !strings.Contains(err.Error(), "ballots once") {
		t.Fatalf("error: %v", err)
	}
}

// TestMembersSeeOnlyTheirOwnEvidenceView is the independence promise.
// Each member receives the same proposal and purpose but a different
// window: the view is applied by the panel, never widened by the
// member, and no member's input carries another member's findings.
func TestMembersSeeOnlyTheirOwnEvidenceView(t *testing.T) {
	all := &ballotSpy{verdict: broker.ReviewAllow}
	independent := &ballotSpy{verdict: broker.ReviewAllow}
	worker := &ballotSpy{verdict: broker.ReviewAllow}
	proposalOnly := &ballotSpy{verdict: broker.ReviewAllow}
	panel, err := NewPanel("act_panel-fixture01",
		member("mem-alpha", "mdl_alpha-v1", "familyA", "p1", ViewAll, all, 1),
		member("mem-beta", "mdl_beta-v1", "familyB", "p2",
			ViewIndependent, independent, 1),
		member("mem-gamma", "mdl_gamma-v1", "familyC", "p3",
			ViewWorker, worker, 1),
		member("mem-delta", "mdl_delta-v1", "familyD", "p4",
			ViewProposal, proposalOnly, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	task := panelTask()
	report, err := panel.ReviewWithReport(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if len(all.tasks) != 1 || len(independent.tasks) != 1 ||
		len(worker.tasks) != 1 || len(proposalOnly.tasks) != 1 {
		t.Fatalf("a member saw the task more than once: %d %d %d %d",
			len(all.tasks), len(independent.tasks),
			len(worker.tasks), len(proposalOnly.tasks))
	}
	if got := len(all.tasks[0].RecentEvents); got != 3 {
		t.Fatalf("the all view saw %d events, want 3", got)
	}
	for _, event := range independent.tasks[0].RecentEvents {
		if event.TrustLabel != evidence.TrustCollectorFact &&
			event.TrustLabel != evidence.TrustMonitorReading {
			t.Fatalf("the independent view saw %q", event.TrustLabel)
		}
	}
	if got := len(independent.tasks[0].RecentEvents); got != 2 {
		t.Fatalf("the independent view saw %d events, want 2", got)
	}
	for _, event := range worker.tasks[0].RecentEvents {
		if event.TrustLabel != evidence.TrustWorkerClaim {
			t.Fatalf("the worker view saw %q", event.TrustLabel)
		}
	}
	if got := len(worker.tasks[0].RecentEvents); got != 1 {
		t.Fatalf("the worker view saw %d events, want 1", got)
	}
	if got := len(proposalOnly.tasks[0].RecentEvents); got != 0 {
		t.Fatalf("the proposal view saw %d events, want 0", got)
	}
	// The request itself always travels, whatever the view.
	for _, spy := range []*ballotSpy{all, independent, worker, proposalOnly} {
		if spy.tasks[0].Purpose != "close issue #7" {
			t.Fatalf("a member lost the purpose")
		}
	}
	// Structural independence: every member ran before any ballot was
	// recorded, so no member's task can contain another's findings —
	// the ReviewTask type has no field that could carry them.
	if len(report.Ballots) != 4 {
		t.Fatalf("ballots: %d, want 4", len(report.Ballots))
	}
}

// TestAdjudicationTakesTheStrictestVerdict checks the fail-safe merge:
// one deny holds the effect even against two allows, and the dissent
// is recorded on the decision.
func TestAdjudicationTakesTheStrictestVerdict(t *testing.T) {
	denier := &ballotSpy{verdict: broker.ReviewDeny}
	allower := &ballotSpy{verdict: broker.ReviewAllow}
	watcher := &ballotSpy{verdict: broker.ReviewWatch}
	panel, err := threeMemberPanel(t, allower, watcher, denier)
	if err != nil {
		t.Fatal(err)
	}
	review, err := panel.Review(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != broker.ReviewDeny {
		t.Fatalf("verdict: %s, want DENY", review.Verdict)
	}
	if !strings.Contains(review.Rationale, "1 DENY") ||
		!strings.Contains(review.Rationale, "1 WATCH") ||
		!strings.Contains(review.Rationale, "1 ALLOW") {
		t.Fatalf("dissent missing from rationale: %q", review.Rationale)
	}
	// WATCH beats ALLOW when nobody denies.
	abstainer := &ballotSpy{err: context.Canceled}
	panel, err = threeMemberPanel(t, allower, watcher, abstainer)
	if err != nil {
		t.Fatal(err)
	}
	review, err = panel.Review(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != broker.ReviewWatch {
		t.Fatalf("verdict: %s, want WATCH", review.Verdict)
	}
	// All allow is the only path to allow.
	panel, err = threeMemberPanel(t, allower, allower, allower)
	if err != nil {
		t.Fatal(err)
	}
	review, err = panel.Review(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != broker.ReviewAllow {
		t.Fatalf("verdict: %s, want ALLOW", review.Verdict)
	}
}

// TestFindingsAreFixedBeforeAdjudication checks the ordering rule of
// spec 11.4: the adjudicator may compare findings only after they are
// fixed. The digest covers every ballot, is deterministic, appears on
// the decision, and changes when any ballot changes.
func TestFindingsAreFixedBeforeAdjudication(t *testing.T) {
	allower := &ballotSpy{verdict: broker.ReviewAllow}
	watcher := &ballotSpy{verdict: broker.ReviewWatch}
	panel, err := threeMemberPanel(t, allower, watcher, watcher)
	if err != nil {
		t.Fatal(err)
	}
	first, err := panel.ReviewWithReport(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	second, err := panel.ReviewWithReport(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if first.FindingsDigest == "" || first.FindingsDigest != second.FindingsDigest {
		t.Fatalf("digest not deterministic: %q vs %q",
			first.FindingsDigest, second.FindingsDigest)
	}
	if !strings.Contains(first.Adjudicated.Limitations,
		first.FindingsDigest) {
		t.Fatalf("the decision does not carry the findings digest: %q",
			first.Adjudicated.Limitations)
	}
	if !strings.Contains(first.Adjudicated.Limitations,
		"not a statistical independence certificate") {
		t.Fatalf("the agreement diagnostic note is missing: %q",
			first.Adjudicated.Limitations)
	}
	// A changed first pass must break the digest: flip one member.
	changed, err := threeMemberPanel(t, watcher, watcher, watcher)
	if err != nil {
		t.Fatal(err)
	}
	third, err := changed.ReviewWithReport(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if third.FindingsDigest == first.FindingsDigest {
		t.Fatal("a changed ballot kept the digest")
	}
}

// TestAFailedMemberBallotsAbstainNeverAllow proves the fail-safe for
// member failures: an error, a cancelled context, and an empty verdict
// all record an abstain ballot, and the failure text survives.
func TestAFailedMemberBallotsAbstainNeverAllow(t *testing.T) {
	broken := &ballotSpy{err: context.DeadlineExceeded}
	allower := &ballotSpy{verdict: broker.ReviewAllow}
	panel, err := threeMemberPanel(t, allower, broken, broken)
	if err != nil {
		t.Fatal(err)
	}
	report, err := panel.ReviewWithReport(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	abstains := 0
	for _, ballot := range report.Ballots {
		if ballot.Error == "" {
			continue
		}
		if ballot.Verdict != broker.ReviewAbstain {
			t.Fatalf("a failed member balloted %s", ballot.Verdict)
		}
		if !strings.Contains(ballot.Rationale, "abstain") {
			t.Fatalf("ballot rationale: %q", ballot.Rationale)
		}
		abstains++
	}
	if abstains != 2 {
		t.Fatalf("failed ballots: %d, want 2", abstains)
	}
	// Two abstains and one allow adjudicate to ABSTAIN: under the
	// decision contract an abstain keeps the hold, so it is stricter
	// than an allow. The panel never converts a member's failure into
	// consent.
	if report.Adjudicated.Verdict != broker.ReviewAbstain {
		t.Fatalf("verdict: %s, want ABSTAIN", report.Adjudicated.Verdict)
	}
}

// TestAnEmptyVerdictBallotsAbstain refuses a review without a verdict.
func TestAnEmptyVerdictBallotsAbstain(t *testing.T) {
	silent := &ballotSpy{verdict: broker.ReviewDeny}
	silent.verdict = ""
	allower := &ballotSpy{verdict: broker.ReviewAllow}
	panel, err := threeMemberPanel(t, silent, allower, allower)
	if err != nil {
		t.Fatal(err)
	}
	report, err := panel.ReviewWithReport(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if report.Ballots[0].Verdict != broker.ReviewAbstain {
		t.Fatalf("an empty verdict balloted %s", report.Ballots[0].Verdict)
	}
	if report.Ballots[0].Error == "" {
		t.Fatal("the empty verdict left no error text")
	}
}

// TestThePanelSatisfiesTheReviewerContract keeps the panel inside the
// ordinary decision contract: it is a ContextualReviewer, its verdict
// is contract-valid, and its review decision names the panel, not a
// member, as the reviewer.
func TestThePanelSatisfiesTheReviewerContract(t *testing.T) {
	var _ ContextualReviewer = (*Panel)(nil)
	allower := &ballotSpy{verdict: broker.ReviewAllow}
	panel, err := threeMemberPanel(t, allower, allower, allower)
	if err != nil {
		t.Fatal(err)
	}
	review, err := panel.Review(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	if errs := review.ValidateReview(); len(errs) > 0 {
		t.Fatalf("the panel decision violates the review contract: %+v", errs)
	}
	if review.ReviewerID != "act_panel-fixture01" {
		t.Fatalf("reviewer id: %q", review.ReviewerID)
	}
	if review.ModelID == "" {
		t.Fatal("the decision names no models")
	}
}

// TestPanelCostAndLatencyAreAccounted keeps spec 16's separate panel
// reporting honest: cost is the declared sum of the members that ran,
// and latency is the measured sum of the first pass.
func TestPanelCostAndLatencyAreAccounted(t *testing.T) {
	allower := &ballotSpy{verdict: broker.ReviewAllow}
	panel, err := threeMemberPanel(t, allower, allower, allower)
	if err != nil {
		t.Fatal(err)
	}
	report, err := panel.ReviewWithReport(context.Background(), panelTask())
	if err != nil {
		t.Fatal(err)
	}
	var ballotCost, ballotLatency int64
	for _, ballot := range report.Ballots {
		ballotCost += ballot.CostMicros
		ballotLatency += ballot.LatencyMS
	}
	if ballotCost != 600 {
		t.Fatalf("ballot cost: %d, want 600", ballotCost)
	}
	if report.Adjudicated.LatencyMS != ballotLatency {
		t.Fatalf("decision latency %d, want the ballot sum %d",
			report.Adjudicated.LatencyMS, ballotLatency)
	}
	if !strings.Contains(report.Adjudicated.Rationale, "600 micros") {
		t.Fatalf("cost missing from the rationale: %q",
			report.Adjudicated.Rationale)
	}
}
