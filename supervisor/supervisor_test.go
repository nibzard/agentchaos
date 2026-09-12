package supervisor

// Spec 11.1 / 11.2 / T018: the fast detector routes review, the
// contextual reviewer decides under a deadline, failures fall back
// per the profile and never silently allow, and every decision
// satisfies the broker's review contract (AC-014).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gauntlet/broker"
	"gauntlet/evidence"
)

func event(id, kind, trust, component string, sequence int64) evidence.Event {
	return evidence.Event{
		Kind:       "gauntlet.evidence.event.v1",
		APIVersion: "v1",
		ID:         id,
		TenantID:   "tnt_9d4c1e2a3b4f5c67",
		RunID:      "run_0a0b0c0d0e0f0102",
		EventKind:  kind,
		TrustLabel: trust,
		Source:     evidence.EventSource{ID: "src_w-000000000001", Component: component},
		Sequence:   sequence,
		EffectID:   "eff_0a0b0c0d0e0f0102",
		ObservedAt: "2026-09-12T10:00:00Z",
	}
}

func denyEvent(id string, sequence int64) evidence.Event {
	e := event(id, evidence.KindBrokerDecision, evidence.TrustCollectorFact,
		evidence.ComponentBroker, sequence)
	e.Payload.Content = "deny:operation_hard_denied"
	return e
}

func cleanWindow() []evidence.Event {
	// A benign window: one worker proposal, tool traffic, a broker
	// allow, and independent coverage.
	return []evidence.Event{
		event("evt_"+"a000000000000001", evidence.KindProposedAction, evidence.TrustWorkerClaim,
			evidence.ComponentWorker, 1),
		event("evt_"+"a000000000000002", evidence.KindToolRequest, evidence.TrustWorkerClaim,
			evidence.ComponentWorker, 2),
		event("evt_"+"a000000000000003", evidence.KindExternalReceipt, evidence.TrustCollectorFact,
			evidence.ComponentCollector, 3),
		event("evt_"+"a000000000000004", evidence.KindCollectorHeartbeat, evidence.TrustCollectorFact,
			evidence.ComponentCollector, 4),
	}
}

func TestCleanWindowDoesNotRouteReview(t *testing.T) {
	detection := NewFastDetector(DetectorConfig{}).Detect(cleanWindow())
	if detection.RouteReview || len(detection.Suspicions) != 0 {
		t.Fatalf("clean window routed review: %+v", detection)
	}
	if detection.WindowEvents != 4 {
		t.Fatalf("window events: %d", detection.WindowEvents)
	}
}

func TestDetectorFlagsARetryAfterADeny(t *testing.T) {
	window := append(cleanWindow(),
		denyEvent("evt_"+"a000000000000005", 5),
		event("evt_"+"a000000000000006", evidence.KindProposedAction, evidence.TrustWorkerClaim,
			evidence.ComponentWorker, 6),
	)
	detection := NewFastDetector(DetectorConfig{}).Detect(window)
	if !detection.RouteReview {
		t.Fatal("a proposal after a deny did not route review")
	}
	if len(detection.Suspicions) != 1 {
		t.Fatalf("suspicions: %+v", detection.Suspicions)
	}
	suspicion := detection.Suspicions[0]
	if suspicion.Rule != "denied_retry" || suspicion.Severity != SeverityHigh {
		t.Fatalf("suspicion: %+v", suspicion)
	}
	want := []string{"evt_" + "a000000000000005", "evt_" + "a000000000000006"}
	if strings.Join(suspicion.EventRefs, ",") != strings.Join(want, ",") {
		t.Fatalf("event refs: %v", suspicion.EventRefs)
	}
}

func TestADenyAloneRoutesNothing(t *testing.T) {
	window := append(cleanWindow(), denyEvent("evt_"+"a000000000000005", 5))
	detection := NewFastDetector(DetectorConfig{}).Detect(window)
	if detection.RouteReview {
		t.Fatalf("a deny with no retry routed review: %+v", detection.Suspicions)
	}
}

func TestDetectorFlagsCorrectedClaims(t *testing.T) {
	window := cleanWindow()
	corrected := event("evt_"+"a000000000000005", evidence.KindToolResponse,
		evidence.TrustWorkerClaim, evidence.ComponentWorker, 5)
	corrected.CorrectsEventID = "evt_" + "a000000000000002"
	window = append(window, corrected)
	detection := NewFastDetector(DetectorConfig{}).Detect(window)
	if !detection.RouteReview {
		t.Fatal("a corrected claim did not route review")
	}
	if detection.Suspicions[0].Rule != "corrected_claim" ||
		detection.Suspicions[0].Severity != SeverityHigh {
		t.Fatalf("suspicion: %+v", detection.Suspicions[0])
	}
}

func TestDetectorFlagsProposalBursts(t *testing.T) {
	detector := NewFastDetector(DetectorConfig{MaxProposals: 2})
	window := cleanWindow()
	for i := int64(5); i <= 7; i++ {
		id := "evt_" + "a00000000000000" + string(rune('0'+i))
		window = append(window, event(id, evidence.KindProposedAction,
			evidence.TrustWorkerClaim, evidence.ComponentWorker, i))
	}
	detection := detector.Detect(window)
	routed := false
	for _, suspicion := range detection.Suspicions {
		if suspicion.Rule == "proposal_burst" {
			routed = true
			if suspicion.Severity != SeverityLow {
				t.Fatalf("burst severity: %+v", suspicion)
			}
		}
	}
	if !routed {
		t.Fatalf("a burst of proposals routed nothing: %+v", detection.Suspicions)
	}
}

func TestDetectorFlagsASilentCollector(t *testing.T) {
	window := []evidence.Event{
		event("evt_"+"b000000000000001", evidence.KindProposedAction, evidence.TrustWorkerClaim,
			evidence.ComponentWorker, 1),
		event("evt_"+"b000000000000002", evidence.KindToolRequest, evidence.TrustWorkerClaim,
			evidence.ComponentWorker, 2),
	}
	detection := NewFastDetector(DefaultDetectorConfig()).Detect(window)
	if !detection.RouteReview {
		t.Fatal("worker tool traffic without a collector heartbeat routed nothing")
	}
	if detection.Suspicions[0].Rule != "collector_silent" {
		t.Fatalf("suspicion: %+v", detection.Suspicions[0])
	}
}

func TestDetectorBoundsItsWindow(t *testing.T) {
	detector := NewFastDetector(DetectorConfig{WindowSize: 4, MaxProposals: 1})
	var window []evidence.Event
	// Four benign proposals inside the window; five older noisy ones
	// fall outside it.
	for i := int64(0); i < 5; i++ {
		id := "evt_" + "c00000000000000" + string(rune('0'+i))
		window = append(window, denyEvent(id, i))
	}
	for i := int64(5); i < 9; i++ {
		id := "evt_" + "c00000000000000" + string(rune('0'+i))
		window = append(window, event(id, evidence.KindProposedAction,
			evidence.TrustWorkerClaim, evidence.ComponentWorker, i))
	}
	detection := detector.Detect(window)
	if detection.WindowEvents != 4 {
		t.Fatalf("window: %d", detection.WindowEvents)
	}
	// The denies fell outside the window, so the proposals are not
	// retries — but four proposals from one source exceed the limit
	// of one, so the burst rule fires.
	for _, suspicion := range detection.Suspicions {
		if suspicion.Rule == "denied_retry" {
			t.Fatal("a deny outside the window was treated as evidence")
		}
	}
	if !detection.RouteReview {
		t.Fatal("the burst inside the window routed nothing")
	}
}

func proposal() broker.ProposedAction {
	return broker.ProposedAction{
		Operation:       "repo.push",
		Resource:        "repos/acme/demo",
		Destination:     "https://api.github.com/repos/acme/demo/git/refs/heads/fix-1",
		ResourceVersion: "commit-7f3a",
		ArgumentsDigest: "sha256:" + strings.Repeat("0", 64),
	}
}

func TestReferenceReviewerProducesContractValidDecisions(t *testing.T) {
	reviewer := NewReferenceReviewer()
	tasks := map[string]struct {
		task    ReviewTask
		verdict string
	}{
		"deny": {
			task: ReviewTask{
				Proposal: proposal(),
				Purpose:  "close issue #7",
				Detection: Detection{Suspicions: []Suspicion{{
					Rule: "denied_retry", Severity: SeverityHigh,
					PolicyRef: "pol_1.1.0/supervision.detector.denied_retry",
					EventRefs: []string{"evt_" + strings.Repeat("1", 16)},
				}}},
				RecentEvents: cleanWindow(),
			},
			verdict: broker.ReviewDeny,
		},
		"watch": {
			task: ReviewTask{
				Proposal: proposal(),
				Purpose:  "close issue #7",
				Detection: Detection{Suspicions: []Suspicion{{
					Rule: "proposal_burst", Severity: SeverityLow,
					PolicyRef: "pol_1.1.0/supervision.detector.proposal_burst",
					EventRefs: []string{"evt_" + strings.Repeat("1", 16)},
				}}},
				RecentEvents: cleanWindow(),
			},
			verdict: broker.ReviewWatch,
		},
		"allow": {
			task: ReviewTask{
				Proposal:     proposal(),
				Purpose:      "close issue #7",
				Detection:    Detection{},
				RecentEvents: cleanWindow(), // carries collector facts
			},
			verdict: broker.ReviewAllow,
		},
		"abstain": {
			task: ReviewTask{
				Proposal:  proposal(),
				Purpose:   "close issue #7",
				Detection: Detection{},
				// Worker claims only: no independent evidence.
				RecentEvents: []evidence.Event{
					event("evt_"+"d000000000000001", evidence.KindToolRequest,
						evidence.TrustWorkerClaim, evidence.ComponentWorker, 1),
				},
			},
			verdict: broker.ReviewAbstain,
		},
	}
	for name, test := range tasks {
		review, err := reviewer.Review(context.Background(), test.task)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if review.Verdict != test.verdict {
			t.Fatalf("%s: verdict %s, want %s", name, review.Verdict, test.verdict)
		}
		if problems := review.ValidateReview(); len(problems) != 0 {
			t.Fatalf("%s: contract violations: %+v", name, problems)
		}
		if len(review.PolicyRefs) < 1 || len(review.EventRefs) < 1 {
			t.Fatalf("%s: thin references: %+v", name, review)
		}
		// Suspicion-driven decisions inherit the detector's policy
		// reference (AC-014), not only the generic review rule.
		if name == "deny" || name == "watch" {
			cited := false
			for _, ref := range review.PolicyRefs {
				if ref == "pol_1.1.0/supervision.detector."+test.task.Detection.Suspicions[0].Rule {
					cited = true
				}
			}
			if !cited {
				t.Fatalf("%s: the detector rule was not cited: %+v", name, review.PolicyRefs)
			}
		}
	}
}

// stubReviewer returns a fixed decision or failure.
type stubReviewer struct {
	review broker.Review
	err    error
	panics bool
	delay  time.Duration
}

func (s *stubReviewer) Review(ctx context.Context, _ ReviewTask) (broker.Review, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return broker.Review{}, ctx.Err()
		}
	}
	if s.panics {
		panic("reviewer exploded")
	}
	return s.review, s.err
}

func validAllow() broker.Review {
	return broker.Review{
		Verdict:       broker.ReviewAllow,
		ReviewerID:    "act_sentinel-reference-01",
		PolicyRefs:    []string{"pol_1.1.0/operations.repo.push"},
		EventRefs:     []string{"evt_" + strings.Repeat("1", 16)},
		Rationale:     "matches the approved plan",
		ModelID:       "stub-v1",
		PromptVersion: "2026-09",
	}
}

func TestDefaultDeadlineIsThreeSeconds(t *testing.T) {
	if DefaultDeadline != 3*time.Second {
		t.Fatalf("default deadline: %s", DefaultDeadline)
	}
	if mode := DefaultReviewPolicy(); mode.OnFailure != FailHold {
		t.Fatalf("default failure mode: %s", mode.OnFailure)
	}
}

func TestValidDecisionsPassThroughWithMeasuredLatency(t *testing.T) {
	wrapped := NewDeadlineReviewer(&stubReviewer{review: validAllow()}, DefaultReviewPolicy())
	review, err := wrapped.Review(context.Background(), ReviewTask{RecentEvents: cleanWindow()})
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != broker.ReviewAllow {
		t.Fatalf("verdict: %s", review.Verdict)
	}
	if problems := review.ValidateReview(); len(problems) != 0 {
		t.Fatalf("contract violations: %+v", problems)
	}
}

func TestFallbackNeverSilentlyAllows(t *testing.T) {
	broken := &stubReviewer{panics: true}
	brokenTask := ReviewTask{RecentEvents: cleanWindow()}
	invalid := &stubReviewer{review: broker.Review{
		Verdict: "MAYBE", ReviewerID: "act_sentinel-reference-01",
		Rationale: "x",
	}}
	failing := &stubReviewer{err: errors.New("model plane down")}
	cases := []struct {
		name   string
		inner  ContextualReviewer
		onFail FailureMode
	}{
		{"panic_deny", broken, FailDeny},
		{"panic_abstain", broken, FailAbstain},
		{"panic_hold", broken, FailHold},
		{"malformed_deny", invalid, FailDeny},
		{"error_abstain", failing, FailAbstain},
	}
	for _, test := range cases {
		policy := DefaultReviewPolicy()
		policy.Deadline = 500 * time.Millisecond
		policy.OnFailure = test.onFail
		review, err := NewDeadlineReviewer(test.inner, policy).Review(
			context.Background(), brokenTask)
		switch test.onFail {
		case FailHold:
			if err == nil || !errors.Is(err, ErrReviewHeld) {
				t.Fatalf("%s: expected a hold error, got review %+v err %v",
					test.name, review, err)
			}
			if review.Verdict != "" {
				t.Fatalf("%s: a held review carried a verdict", test.name)
			}
		case FailDeny:
			if err != nil {
				t.Fatalf("%s: %v", test.name, err)
			}
			if review.Verdict != broker.ReviewDeny {
				t.Fatalf("%s: fallback verdict %s", test.name, review.Verdict)
			}
			if review.Verdict == broker.ReviewAllow {
				t.Fatalf("%s: an ALLOW leaked out of a failure path", test.name)
			}
		case FailAbstain:
			if err != nil {
				t.Fatalf("%s: %v", test.name, err)
			}
			if review.Verdict != broker.ReviewAbstain {
				t.Fatalf("%s: fallback verdict %s", test.name, review.Verdict)
			}
		}
		if err == nil {
			if problems := review.ValidateReview(); len(problems) != 0 {
				t.Fatalf("%s: fallback violates the contract: %+v", test.name, problems)
			}
		}
	}
}

func TestASlowReviewerHitsTheDeadlineAndFallsBack(t *testing.T) {
	slow := &stubReviewer{review: validAllow(), delay: 10 * time.Second}
	policy := DefaultReviewPolicy()
	policy.Deadline = 25 * time.Millisecond
	policy.OnFailure = FailDeny
	start := time.Now()
	review, err := NewDeadlineReviewer(slow, policy).Review(
		context.Background(), ReviewTask{RecentEvents: cleanWindow()})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the wrapper waited %s past its deadline", elapsed)
	}
	if review.Verdict != broker.ReviewDeny {
		t.Fatalf("verdict: %s", review.Verdict)
	}
	if !strings.Contains(review.Rationale, "did not decide within") {
		t.Fatalf("rationale hides the cause: %q", review.Rationale)
	}
	if review.LatencyMS < 20 {
		t.Fatalf("latency not measured: %d", review.LatencyMS)
	}
}

func TestACancelledContextFallsBackInsteadOfHanging(t *testing.T) {
	inner := &stubReviewer{review: validAllow()}
	policy := DefaultReviewPolicy()
	policy.OnFailure = FailAbstain
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	review, err := NewDeadlineReviewer(inner, policy).Review(ctx, ReviewTask{
		RecentEvents: cleanWindow(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != broker.ReviewAbstain {
		t.Fatalf("verdict: %s", review.Verdict)
	}
}

func TestAFallbackWithoutEventsToCiteBecomesAHold(t *testing.T) {
	empty := &stubReviewer{err: errors.New("nothing")}
	policy := DefaultReviewPolicy()
	policy.OnFailure = FailDeny // even a deny profile cannot cite events
	review, err := NewDeadlineReviewer(empty, policy).Review(
		context.Background(), ReviewTask{}) // no events, no suspicions
	if err == nil || !errors.Is(err, ErrReviewHeld) {
		t.Fatalf("expected a hold, got review %+v err %v", review, err)
	}
	if !strings.Contains(err.Error(), "could not cite source events") {
		t.Fatalf("error hides the real cause: %v", err)
	}
}

func TestSupervisorRoutesAndDecides(t *testing.T) {
	window := append(cleanWindow(),
		denyEvent("evt_"+"a000000000000005", 5),
		event("evt_"+"a000000000000006", evidence.KindProposedAction, evidence.TrustWorkerClaim,
			evidence.ComponentWorker, 6),
	)
	wrapped := NewDeadlineReviewer(NewReferenceReviewer(), DefaultReviewPolicy())
	supervisor := New(wrapped)
	review, detection, err := supervisor.Consider(context.Background(), proposal(),
		"close issue #7", window)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.RouteReview {
		t.Fatal("the detector did not route the retry")
	}
	if review.Verdict != broker.ReviewDeny {
		t.Fatalf("verdict: %s", review.Verdict)
	}
	if problems := review.ValidateReview(); len(problems) != 0 {
		t.Fatalf("contract violations: %+v", problems)
	}

	// A clean window needs no review at all.
	review, detection, err = supervisor.Consider(context.Background(), proposal(),
		"close issue #7", cleanWindow())
	if err != nil {
		t.Fatal(err)
	}
	if detection.RouteReview || review.Verdict != "" {
		t.Fatalf("clean window produced a review: %+v", review)
	}
}
