package supervisor

// Spec 10.2 / AC-021 / T020: reviewer failure preserves permitted
// local work and holds required effects; evidence-capture and
// governor-lease failure fence new external effects.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gauntlet/evidence"
)

func TestReviewerFailureDegradesButNeverStopsLocalWork(t *testing.T) {
	tracker := NewDegradationTracker()

	// A reviewer that errors within its deadline: the wrapper holds.
	policy := DefaultReviewPolicy()
	policy.OnFailure = FailHold
	broken := NewDeadlineReviewer(&stubReviewer{err: errors.New("model plane down")}, policy)
	_, err := broken.Review(context.Background(), ReviewTask{RecentEvents: cleanWindow()})
	if !errors.Is(err, ErrReviewHeld) {
		t.Fatalf("expected a hold, got %v", err)
	}

	// The failure degrades the reviewer dependency; local work and
	// review-held effects follow the spec 10.2 rules.
	tracker.MarkDegraded(DependencyReviewer, "reviewer error: model plane down")
	if !tracker.LocalWorkAllowed() {
		t.Fatal("local work stopped on a reviewer failure (AC-021)")
	}
	if !tracker.HoldEffectsRequiringReview() {
		t.Fatal("a degraded reviewer does not hold review-routed effects")
	}
	if tracker.FenceNewExternalEffects() {
		t.Fatal("a reviewer failure fenced effects that need no review")
	}

	// Recovery restores the normal state.
	tracker.MarkHealthy(DependencyReviewer, "reviewer recovered")
	if tracker.HoldEffectsRequiringReview() {
		t.Fatal("recovery did not clear the hold state")
	}
}

func TestEvidenceCaptureFailureFencesNewExternalEffects(t *testing.T) {
	tracker := NewDegradationTracker()
	tracker.MarkDegraded(DependencyEvidenceCapture, "recorder unreachable 12s")
	if !tracker.FenceNewExternalEffects() {
		t.Fatal("an evidence outage does not fence new external effects")
	}
	if !tracker.LocalWorkAllowed() {
		t.Fatal("local work stopped on an evidence outage")
	}
	if tracker.HoldEffectsRequiringReview() {
		t.Fatal("an evidence outage was misread as a reviewer outage")
	}
}

func TestGovernorLeaseLossFencesNewExternalEffects(t *testing.T) {
	tracker := NewDegradationTracker()
	tracker.MarkDegraded(DependencyGovernorLease, "lease expired; sweep pending")
	if !tracker.FenceNewExternalEffects() {
		t.Fatal("a lost governor lease does not fence new external effects")
	}
	if !tracker.LocalWorkAllowed() {
		t.Fatal("local work stopped on a lease loss")
	}
}

func TestDegradationTransitionsAreRecordedOncePerChange(t *testing.T) {
	tracker := NewDegradationTracker()
	clock := time.Unix(0, 0).UTC()
	tracker.now = func() time.Time { return clock }

	tracker.MarkDegraded(DependencyReviewer, "first failure")
	clock = clock.Add(time.Second)
	tracker.MarkDegraded(DependencyReviewer, "still failing") // no new transition
	clock = clock.Add(time.Second)
	tracker.MarkHealthy(DependencyReviewer, "recovered")

	transitions := tracker.Transitions()
	if len(transitions) != 2 {
		t.Fatalf("transitions: %+v", transitions)
	}
	if transitions[0].From != Healthy || transitions[0].To != Degraded {
		t.Fatalf("first transition: %+v", transitions[0])
	}
	if transitions[0].Detail != "first failure" {
		t.Fatalf("detail not recorded: %+v", transitions[0])
	}
	if transitions[1].To != Healthy || transitions[1].At.Equal(transitions[0].At) {
		t.Fatalf("second transition: %+v", transitions[1])
	}
	if !strings.HasPrefix(transitions[0].At.Format(time.RFC3339), "1970") {
		t.Fatalf("injected clock ignored: %+v", transitions[0])
	}
}

func TestUnknownDependenciesAreIgnored(t *testing.T) {
	tracker := NewDegradationTracker()
	tracker.MarkDegraded("coffee_machine", "empty")
	if len(tracker.Transitions()) != 0 {
		t.Fatalf("an unknown dependency was recorded: %+v", tracker.Transitions())
	}
}

func TestTheSupervisorComposesWithDegradationTracking(t *testing.T) {
	// The full AC-021 loop: the reviewer fails, the wrapper holds the
	// effect, the tracker records the degradation, and local work
	// keeps its green light. The broker-side half — the effect stays
	// PROPOSED — is covered in the broker's gate tests.
	tracker := NewDegradationTracker()
	policy := DefaultReviewPolicy()
	policy.Deadline = 10 * time.Millisecond
	policy.OnFailure = FailHold
	sup := New(NewDeadlineReviewer(&stubReviewer{review: validAllow(), delay: time.Second}, policy))

	_, detection, err := sup.Consider(context.Background(), proposal(),
		"close issue #7", append(cleanWindow(), denyEvent("evt_"+"a000000000000005", 5),
			event("evt_"+"a000000000000006", evidence.KindProposedAction,
				evidence.TrustWorkerClaim, evidence.ComponentWorker, 6)))
	if !errors.Is(err, ErrReviewHeld) {
		t.Fatalf("expected a hold from the slow reviewer, got %v", err)
	}
	if !detection.RouteReview {
		t.Fatal("the detector did not route the retry")
	}
	tracker.MarkDegraded(DependencyReviewer, "reviewer missed its deadline")

	if !tracker.LocalWorkAllowed() || !tracker.HoldEffectsRequiringReview() {
		t.Fatalf("degradation state: %+v", tracker.Transitions())
	}
}
