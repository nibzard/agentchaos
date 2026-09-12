package broker

import (
	"errors"
)

// The evidence fence (spec 10.2 outage behavior, T020): when
// mandatory evidence capture fails, the broker fences new external
// effects rather than executing them silently. Engaging the fence is
// an explicit authority action — the collector that cannot reach the
// evidence plane reports the outage, and an operator or service
// engages the fence on the broker.
//
// While engaged, the fence is absolute: new proposals deny with
// evidence_capture_fenced, permits do not dispatch, and the stop
// protocol's compensations wait like everything else. Cleanup that
// the fence blocks resumes when capture is restored and the fence is
// released; executing an external effect with no evidence trail is
// never the fallback. Already-committed effects are facts about the
// world; the fence does not pretend to undo them.

// EvidenceFenceState is the fence's last-known state.
type EvidenceFenceState struct {
	Engaged   bool   `json:"engaged"`
	Reason    string `json:"reason,omitempty"`
	EngagedAt string `json:"engaged_at,omitempty"`
	// ReleasedAt is set once the fence has been engaged and released.
	ReleasedAt string `json:"released_at,omitempty"`
}

var (
	// errFenceState reports a fence call that would repeat the
	// current state — engaging while engaged, releasing while open.
	errFenceState = errors.New("the evidence fence is already in that state")
	// ErrEvidenceFenced reports a dispatch the fence refused.
	ErrEvidenceFenced = errors.New(
		"the evidence fence is engaged; this effect does not dispatch")
)

// EngageEvidenceFence fences new external effects (spec 10.2). Only
// service and operator principals may engage it; workers and
// collectors never can (spec 18.3). The engagement is journaled as a
// recovery_action evidence event.
func (b *Broker) EngageEvidenceFence(principal *Principal, reason string) error {
	return b.setEvidenceFence(principal, true, reason)
}

// ReleaseEvidenceFence lifts the fence. The same authority that
// engaged it releases it, and the release names its reason.
func (b *Broker) ReleaseEvidenceFence(principal *Principal, reason string) error {
	return b.setEvidenceFence(principal, false, reason)
}

func (b *Broker) setEvidenceFence(principal *Principal, engage bool, reason string) error {
	if err := b.CheckAuthority(principal); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.evidenceFence.Engaged == engage {
		return errFenceState
	}
	now := b.ClockUTC()
	if engage {
		b.evidenceFence = EvidenceFenceState{
			Engaged:   true,
			Reason:    reason,
			EngagedAt: now,
		}
	} else {
		b.evidenceFence.Engaged = false
		b.evidenceFence.Reason = reason
		b.evidenceFence.ReleasedAt = now
	}
	action := "evidence_fence_released"
	if engage {
		action = "evidence_fence_engaged"
	}
	b.events = append(b.events, EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         mintEventIDSoon(),
		TenantID:   principal.TenantID,
		RunID:      "run_" + fenceRunSuffix,
		EventKind:  "recovery_action",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		Sequence:   b.nextSequence(brokerSourceID),
		ObservedAt: now,
		Payload: inlinePayload(map[string]any{
			"action": action,
			"reason": reason,
		}),
	})
	return nil
}

// EvidenceFence returns the fence's current state.
func (b *Broker) EvidenceFence() EvidenceFenceState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.evidenceFence
}

// fenced reports whether new external effects are fenced. Callers
// hold b.mu.
func (b *Broker) fenced() bool { return b.evidenceFence.Engaged }

// fenceRunSuffix gives the fence journal events a syntactically valid
// run id; the fence is a broker-scope action, not part of any run.
const fenceRunSuffix = "00000000fence"
