package supervisor

import (
	"sync"
	"time"
)

// Dependencies whose failure changes what the system may do (spec
// 10.2 outage behavior, T020).
const (
	// DependencyReviewer covers the contextual reviewer plane: the
	// model, its runner, and its queue.
	DependencyReviewer = "reviewer"
	// DependencyEvidenceCapture covers mandatory evidence collection:
	// the recorder, its collectors, and the ingest path.
	DependencyEvidenceCapture = "evidence_capture"
	// DependencyGovernorLease covers the safety governor's grant
	// lease; losing it stops new injection and fences experiment
	// effects.
	DependencyGovernorLease = "governor_lease"
)

// Health states for a dependency.
const (
	Healthy  = "healthy"
	Degraded = "degraded"
)

// DegradationTransition is one recorded health change. Transitions
// are evidence: an operator can read why the system degraded and
// when it recovered.
type DegradationTransition struct {
	Dependency string    `json:"dependency"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	At         time.Time `json:"at"`
	Detail     string    `json:"detail,omitempty"`
}

// DegradationTracker records the health of the supervision
// dependencies and answers the spec 10.2 questions: what may still
// run, what holds, and what fences. The tracker decides nothing on
// its own — the broker holds effects, the governor fences runs, and
// this type is the shared, observable state behind those behaviors.
//
// The safe-degradation rules it encodes (AC-021, F18):
//
//   - Permitted local work continues in every degraded state. Local
//     work needs no external effect and no reviewer, so nothing here
//     stops it.
//   - Effects whose profile requires review hold while the reviewer
//     is degraded. The broker already holds them PROPOSED; the
//     tracker's state explains why an attach never comes.
//   - New external effects fence while evidence capture or the
//     governor lease is degraded: an effect without an evidence
//     trail, or under a lost safety lease, never executes silently.
type DegradationTracker struct {
	mu          sync.Mutex
	states      map[string]string
	transitions []DegradationTransition
	now         func() time.Time
}

// NewDegradationTracker starts every dependency healthy.
func NewDegradationTracker() *DegradationTracker {
	return &DegradationTracker{
		states: map[string]string{
			DependencyReviewer:        Healthy,
			DependencyEvidenceCapture: Healthy,
			DependencyGovernorLease:   Healthy,
		},
		now: time.Now,
	}
}

// MarkDegraded records a dependency failure. Repeated marks on an
// already-degraded dependency change nothing and add no transition;
// each carries its detail for the record.
func (t *DegradationTracker) MarkDegraded(dependency, detail string) {
	t.mark(dependency, Degraded, detail)
}

// MarkHealthy records recovery.
func (t *DegradationTracker) MarkHealthy(dependency, detail string) {
	t.mark(dependency, Healthy, detail)
}

// mark applies a state and journals the transition when the state
// actually changed.
func (t *DegradationTracker) mark(dependency, state, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	from, known := t.states[dependency]
	if !known {
		return // an unknown dependency is a programming error; ignore
	}
	if from == state {
		return
	}
	t.states[dependency] = state
	t.transitions = append(t.transitions, DegradationTransition{
		Dependency: dependency,
		From:       from,
		To:         state,
		At:         t.now(),
		Detail:     detail,
	})
}

// State returns a dependency's current health.
func (t *DegradationTracker) State(dependency string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.states[dependency]
}

// LocalWorkAllowed reports whether permitted local work may continue.
// It is always true: no degraded dependency is a reason to stop
// local computation, and none of them can make local work unsafe
// (AC-021). The method exists so callers state the rule instead of
// implying it.
func (t *DegradationTracker) LocalWorkAllowed() bool {
	return true
}

// HoldEffectsRequiringReview reports whether review-routed effects
// hold: true while the reviewer is degraded. Permitted local work
// continues; only the effects needing the missing review wait.
func (t *DegradationTracker) HoldEffectsRequiringReview() bool {
	return t.State(DependencyReviewer) == Degraded
}

// FenceNewExternalEffects reports whether new external effects fence:
// true while evidence capture or the governor lease is degraded. An
// external effect that cannot leave an evidence trail, or that runs
// under a lost safety lease, never executes silently (spec 10.2).
func (t *DegradationTracker) FenceNewExternalEffects() bool {
	return t.State(DependencyEvidenceCapture) == Degraded ||
		t.State(DependencyGovernorLease) == Degraded
}

// Transitions returns the recorded health changes in order.
func (t *DegradationTracker) Transitions() []DegradationTransition {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]DegradationTransition, len(t.transitions))
	copy(out, t.transitions)
	return out
}
