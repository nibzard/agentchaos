package supervisor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gauntlet/broker"
	"gauntlet/evidence"
)

// DefaultDeadline is the contextual reviewer's default budget
// (spec 11.2): three seconds from task to decision.
const DefaultDeadline = 3 * time.Second

// FailureMode is what happens when the reviewer produces no usable
// decision — it timed out, errored, panicked, or returned a review
// that violates the decision contract (F19). The mode is set by the
// autonomy profile, never by the reviewer itself, and none of the
// modes is a silent allow.
type FailureMode int

const (
	// FailHold returns an error and leaves the effect PROPOSED. The
	// broker keeps the hold; local work may continue (spec 11.4).
	FailHold FailureMode = iota
	// FailDeny attaches a contract-valid DENY: the safest terminal
	// answer when holding is not acceptable.
	FailDeny
	// FailAbstain attaches a contract-valid ABSTAIN. ABSTAIN is not
	// benign — the broker keeps the hold — so it reads as "no usable
	// decision", never as consent.
	FailAbstain
)

// String keeps failure modes readable in logs and tests.
func (m FailureMode) String() string {
	switch m {
	case FailDeny:
		return "deny"
	case FailAbstain:
		return "abstain"
	default:
		return "hold"
	}
}

// ReviewTask is everything the contextual reviewer sees: the proposal
// under review, the declared task purpose, the detector's suspicions,
// and the bounded window of recent evidence (spec 11.1 layer 3).
type ReviewTask struct {
	Proposal     broker.ProposedAction
	Purpose      string
	Detection    Detection
	RecentEvents []evidence.Event
}

// ContextualReviewer decides one held proposal (spec 11.1 layer 3).
// Implementations may call a model; they must respect the context
// deadline, and their output must satisfy the broker's review
// decision contract or it never reaches a record.
type ContextualReviewer interface {
	Review(ctx context.Context, task ReviewTask) (broker.Review, error)
}

// ReferenceReviewer is the deterministic contextual reviewer. It
// needs no model and makes no claim of judgment quality — it is the
// reference implementation of the decision contract and the floor a
// model-backed reviewer must beat (spec 11.3 evaluation).
//
// Decision mapping:
//
//   - any high-severity suspicion → DENY
//   - low-severity suspicions only → WATCH (the broker keeps the hold)
//   - no suspicions, independent evidence present → ALLOW
//   - no suspicions, worker claims only → ABSTAIN (not consent)
type ReferenceReviewer struct {
	// ReviewerID identifies the reviewer on every decision.
	ReviewerID string
	// ModelID and PromptVersion satisfy spec 11.2's provenance fields
	// for a deterministic reviewer.
	ModelID       string
	PromptVersion string
}

// NewReferenceReviewer builds the reference reviewer with a valid
// default identity.
func NewReferenceReviewer() *ReferenceReviewer {
	return &ReferenceReviewer{
		ReviewerID:    "act_sentinel-reference-01",
		ModelID:       "rule-based-reference-v1",
		PromptVersion: "builtin",
	}
}

// Review maps a task to a decision. It never returns an error: a task
// it cannot judge gets ABSTAIN, which the broker reads as "keep the
// hold".
func (r *ReferenceReviewer) Review(_ context.Context, task ReviewTask) (broker.Review, error) {
	review := broker.Review{
		ReviewerID:    r.ReviewerID,
		ModelID:       r.ModelID,
		PromptVersion: r.PromptVersion,
	}
	policyRefs := []string{detectionReviewPolicy}
	var eventRefs []string
	for i := range task.Detection.Suspicions {
		suspicion := &task.Detection.Suspicions[i]
		policyRefs = append(policyRefs, suspicion.PolicyRef)
		eventRefs = append(eventRefs, suspicion.EventRefs...)
	}
	for i := range task.RecentEvents {
		eventRefs = append(eventRefs, task.RecentEvents[i].ID)
	}
	review.PolicyRefs, review.EventRefs = refUnion(policyRefs, eventRefs)

	high := 0
	low := 0
	for i := range task.Detection.Suspicions {
		switch task.Detection.Suspicions[i].Severity {
		case SeverityHigh:
			high++
		default:
			low++
		}
	}
	independent := false
	for i := range task.RecentEvents {
		if task.RecentEvents[i].TrustLabel == evidence.TrustCollectorFact ||
			task.RecentEvents[i].TrustLabel == evidence.TrustMonitorReading {
			independent = true
			break
		}
	}

	switch {
	case high > 0:
		review.Verdict = broker.ReviewDeny
		review.Rationale = fmt.Sprintf(
			"%d high-severity detector findings in the window; the reference reviewer denies",
			high)
		review.Limitations = "deterministic mapping; a contextual reviewer may clear it with evidence"
	case low > 0:
		review.Verdict = broker.ReviewWatch
		review.Rationale = fmt.Sprintf(
			"%d low-severity detector findings; the effect stays held under watch", low)
		review.Limitations = "watch keeps the hold; it releases nothing"
	case independent:
		review.Verdict = broker.ReviewAllow
		review.Rationale = fmt.Sprintf(
			"no detector findings and %d events of independent evidence in the window",
			len(task.RecentEvents))
		review.Limitations = "judged a bounded window; later events are not covered"
	default:
		review.Verdict = broker.ReviewAbstain
		review.Rationale = "no detector findings but the window carries worker claims only; " +
			"there is no independent evidence to check the proposal against"
		review.Limitations = "abstain keeps the hold; it is not consent"
	}
	return review, nil
}

// ReviewPolicy is the profile-defined behavior around the reviewer:
// how long to wait and what to do when no usable decision arrives.
// The defaults are the spec's: a three-second deadline and a hold.
type ReviewPolicy struct {
	ReviewerID string
	Deadline   time.Duration
	OnFailure  FailureMode
	// FallbackPolicy is the policy rule cited by fallback decisions.
	FallbackPolicy string
}

// DefaultReviewPolicy returns the spec defaults.
func DefaultReviewPolicy() ReviewPolicy {
	return ReviewPolicy{
		ReviewerID:     "act_sentinel-reference-01",
		Deadline:       DefaultDeadline,
		OnFailure:      FailHold,
		FallbackPolicy: "pol_1.1.0/supervision.review.fallback",
	}
}

// DeadlineReviewer wraps any ContextualReviewer with the profile's
// deadline and failure mode. On success it validates the inner
// decision against the broker's review contract and stamps the
// measured latency. On timeout, error, panic, contract violation, or
// an already-cancelled context it produces the profile's fallback —
// and a fallback that cannot satisfy the contract becomes an error,
// so no path ever returns a decision that would silently release an
// effect (F19).
type DeadlineReviewer struct {
	Inner   ContextualReviewer
	Policy  ReviewPolicy
	NowFunc func() time.Time // tests inject a clock; production uses time.Now
}

// NewDeadlineReviewer wraps inner with the policy; a zero policy
// becomes the defaults.
func NewDeadlineReviewer(inner ContextualReviewer, policy ReviewPolicy) *DeadlineReviewer {
	if policy.ReviewerID == "" {
		policy.ReviewerID = DefaultReviewPolicy().ReviewerID
	}
	if policy.Deadline <= 0 {
		policy.Deadline = DefaultDeadline
	}
	if policy.FallbackPolicy == "" {
		policy.FallbackPolicy = DefaultReviewPolicy().FallbackPolicy
	}
	return &DeadlineReviewer{Inner: inner, Policy: policy, NowFunc: time.Now}
}

// ErrReviewHeld reports that no usable decision existed and the
// profile says hold. The effect stays PROPOSED.
var ErrReviewHeld = errors.New("reviewer produced no usable decision; the effect stays held")

type reviewResult struct {
	review broker.Review
	err    error
}

// Review runs the inner reviewer under the deadline.
func (d *DeadlineReviewer) Review(ctx context.Context, task ReviewTask) (broker.Review, error) {
	deadline := d.deadline()
	start := d.now()
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	results := make(chan reviewResult, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				results <- reviewResult{err: fmt.Errorf("reviewer panicked: %v", recovered)}
			}
		}()
		review, err := d.Inner.Review(ctx, task)
		results <- reviewResult{review: review, err: err}
	}()

	var result reviewResult
	select {
	case result = <-results:
		if result.err == nil && len(result.review.ValidateReview()) == 0 {
			result.review.LatencyMS = d.now().Sub(start).Milliseconds()
			return result.review, nil
		}
		if result.err == nil {
			result.err = errors.New("reviewer returned a decision that violates the review contract")
		}
	case <-ctx.Done():
		result.err = fmt.Errorf("reviewer did not decide within %s: %w", deadline, ctx.Err())
	}
	return d.fallback(task, result.err, d.now().Sub(start).Milliseconds())
}

func (d *DeadlineReviewer) fallback(task ReviewTask, cause error, latencyMS int64) (broker.Review, error) {
	if d.Policy.OnFailure == FailHold {
		return broker.Review{}, fmt.Errorf("%w: %v", ErrReviewHeld, cause)
	}

	verdict := broker.ReviewAbstain
	if d.Policy.OnFailure == FailDeny {
		verdict = broker.ReviewDeny
	}
	review := broker.Review{
		Verdict:    verdict,
		ReviewerID: d.Policy.ReviewerID,
		PolicyRefs: []string{d.Policy.FallbackPolicy},
		Rationale: fmt.Sprintf(
			"the contextual reviewer produced no usable decision (%v); profile fallback %s applies",
			cause, d.Policy.OnFailure),
		Limitations: "fallback decision; no contextual judgment was made",
		LatencyMS:   latencyMS,
	}
	var eventRefs []string
	for i := range task.RecentEvents {
		eventRefs = append(eventRefs, task.RecentEvents[i].ID)
	}
	for i := range task.Detection.Suspicions {
		eventRefs = append(eventRefs, task.Detection.Suspicions[i].EventRefs...)
	}
	_, review.EventRefs = refUnion(nil, eventRefs)

	// A fallback that violates the contract (no events to cite) must
	// not reach a record either: it becomes a hold.
	if len(review.ValidateReview()) > 0 {
		return broker.Review{}, fmt.Errorf(
			"%w: the fallback could not cite source events: %v", ErrReviewHeld, cause)
	}
	return review, nil
}

func (d *DeadlineReviewer) deadline() time.Duration {
	if d.Policy.Deadline > 0 {
		return d.Policy.Deadline
	}
	return DefaultDeadline
}

func (d *DeadlineReviewer) now() time.Time {
	if d.NowFunc != nil {
		return d.NowFunc()
	}
	return time.Now()
}
