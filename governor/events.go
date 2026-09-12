package governor

import (
	"encoding/json"
	"fmt"
)

// EvidenceEvent mirrors the EvidenceEvent contract
// (shared/schemas/evidence-event.schema.json). The governor is part of
// the trusted computing base (spec 8), so its enforcement facts are
// authoritative facts.
//
// The evidence contract's event kinds come from spec 9.4 and carry no
// governor-specific kind, so the governor journals within the closed
// set: enforcement actions (trips, fences, emergency stops, handoffs,
// cleanup states) are recovery_action events, and accepted spend
// accounting is budget_change events. Grant issuance and renewal stay
// in the governor's decision log only — capture is minimized by
// default (spec 19), and the grant is fully described by the run
// record the API returns.
type EvidenceEvent struct {
	Kind               string       `json:"kind"`
	APIVersion         string       `json:"api_version"`
	ID                 string       `json:"id"`
	TenantID           string       `json:"tenant_id"`
	RunID              string       `json:"run_id"`
	EventKind          string       `json:"event_kind"`
	TrustLabel         string       `json:"trust_label"`
	Source             EventSource  `json:"source"`
	Sequence           int64        `json:"sequence"`
	ObservedAt         string       `json:"observed_at"`
	ClockUncertaintyMS int64        `json:"clock_uncertainty_ms"`
	Payload            EventPayload `json:"payload"`
}

// EventSource identifies the authoritative origin.
type EventSource struct {
	ID        string `json:"id"`
	Component string `json:"component"` // governor
}

// EventPayload is the closed payload reference. Governor events carry
// only small inline content: conditions, actions, totals (spec 19).
type EventPayload struct {
	Kind        string `json:"kind"` // metadata_only | object_ref | inline
	StorageRef  string `json:"storage_ref,omitempty"`
	Digest      string `json:"digest,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Redacted    bool   `json:"redacted"`
	Truncated   bool   `json:"truncated"`
	Tombstone   string `json:"tombstone,omitempty"`
	Content     string `json:"content,omitempty"`
}

// governorSourceID identifies this governor in the evidence journal.
var governorSourceID = "src_governor-safety"

// appendEvent journals an event with its per-source sequence. The
// caller holds g.mu.
func (g *Governor) appendEvent(event EvidenceEvent) {
	event.Kind = "EvidenceEvent"
	event.APIVersion = "v1"
	event.ID = g.mintEventID()
	event.TrustLabel = "collector_fact"
	event.Source = EventSource{ID: governorSourceID, Component: "governor"}
	event.Sequence = g.nextSequence()
	event.ObservedAt = g.ClockUTC()
	g.events = append(g.events, event)
}

// nextSequence advances the per-source counter. The caller holds g.mu.
func (g *Governor) nextSequence() int64 {
	g.sequences[governorSourceID]++
	return g.sequences[governorSourceID]
}

// recoveryEvent journals an enforcement action (spec 9.4 recovery
// actions: trips, fences, handoffs, cleanup states).
func recoveryEvent(run *GovernedRun, action, condition string, extra map[string]any) EvidenceEvent {
	payload := map[string]any{
		"component": "governor",
		"action":    action,
	}
	if condition != "" {
		payload["condition"] = condition
	}
	for key, value := range extra {
		payload[key] = value
	}
	return EvidenceEvent{
		TenantID:  run.TenantID,
		RunID:     run.RunID,
		EventKind: "recovery_action",
		Payload:   inlinePayload(payload),
	}
}

// budgetEvent journals accepted spend accounting (spec 9.4 budget
// changes).
func budgetEvent(run *GovernedRun, aggregateMicros int64) EvidenceEvent {
	return EvidenceEvent{
		TenantID:  run.TenantID,
		RunID:     run.RunID,
		EventKind: "budget_change",
		Payload: inlinePayload(map[string]any{
			"currency":         run.SpendCurrency,
			"aggregate_micros": aggregateMicros,
			"session_count":    len(run.SessionSpend),
		}),
	}
}

// inlinePayload builds a small, safe payload. The fields must be safe
// to retain: no credentials, no reviewer internals (spec 18.3).
func inlinePayload(fields map[string]any) EventPayload {
	encoded, err := json.Marshal(fields)
	if err != nil {
		return EventPayload{Kind: "metadata_only", Redacted: true}
	}
	return EventPayload{
		Kind:        "inline",
		Redacted:    false,
		Truncated:   false,
		Content:     string(encoded),
		ContentType: "application/json",
	}
}

// mintEventID mints an evidence event id. Event ids are opaque to the
// governor's logic, so a counter keeps tests deterministic and the
// ids stay inside the contract pattern evt_[a-z0-9]{8,64}.
func (g *Governor) mintEventID() string {
	g.eventCounter++
	return fmt.Sprintf("evt_governor%08d", g.eventCounter)
}
