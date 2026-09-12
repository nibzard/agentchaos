package broker

import "encoding/json"

// EvidenceEvent mirrors the EvidenceEvent contract
// (shared/schemas/evidence-event.schema.json). The broker is part of
// the trusted computing base (spec 8), so its decisions and receipts
// are authoritative facts, never worker claims.
type EvidenceEvent struct {
	Kind               string       `json:"kind"`
	APIVersion         string       `json:"api_version"`
	ID                 string       `json:"id"`
	TenantID           string       `json:"tenant_id"`
	RunID              string       `json:"run_id"`
	DelegationID       string       `json:"delegation_id,omitempty"`
	EventKind          string       `json:"event_kind"`
	TrustLabel         string       `json:"trust_label"`
	Source             EventSource  `json:"source"`
	Sequence           int64        `json:"sequence"`
	EffectID           string       `json:"effect_id,omitempty"`
	ObservedAt         string       `json:"observed_at"`
	ClockUncertaintyMS int64        `json:"clock_uncertainty_ms"`
	Payload            EventPayload `json:"payload"`
}

// EventSource identifies the authoritative origin.
type EventSource struct {
	ID        string `json:"id"`
	Component string `json:"component"` // collector | broker | governor | ...
	Coverage  string `json:"coverage,omitempty"`
}

// EventPayload is the closed payload reference. Broker events carry
// only small inline content: verdicts, reasons, receipt digests
// (spec 19: capture is minimized by default).
type EventPayload struct {
	Kind        string `json:"kind"` // metadata_only | object_ref | inline
	StorageRef  string `json:"storage_ref,omitempty"`
	Digest      string `json:"digest,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Redacted    bool   `json:"redacted"`
	Truncated   bool   `json:"truncated"`
	Tombstone   bool   `json:"tombstone,omitempty"`
	Content     string `json:"content,omitempty"`
}

// inlinePayload builds a small, safe payload. The fields must be safe
// to retain: no credentials, no reviewer internals (spec 18.3).
func inlinePayload(fields map[string]any) EventPayload {
	encoded, err := json.Marshal(fields)
	if err != nil {
		return EventPayload{Kind: "metadata_only", Redacted: true, Truncated: false}
	}
	return EventPayload{
		Kind:        "inline",
		Redacted:    false,
		Truncated:   false,
		Content:     string(encoded),
		ContentType: "application/json",
	}
}
