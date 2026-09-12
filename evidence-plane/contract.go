// Package evidence implements the authoritative evidence recorder
// (spec 9.4). Worker claims, collector facts, and monitor
// interpretations are recorded as separate trust-labeled events
// (AC-012); collectors run under identities independent of the worker
// and the store is append-only with a per-tenant hash chain.
package evidence

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Trust labels (spec 9.4, AC-012). Worker-generated transcripts are
// lower-trust evidence; authoritative collectors and the broker are
// part of the trusted computing base.
const (
	TrustWorkerClaim    = "worker_claim"
	TrustCollectorFact  = "collector_fact"
	TrustMonitorReading = "monitor_interpretation"
)

// Evidence event kinds (spec 9.4). Each collected surface keeps its
// own kind, so a worker's account of a tool call never merges with the
// broker's record of it.
const (
	KindProposedAction     = "proposed_action"
	KindBrokerDecision     = "broker_decision"
	KindResourceAccess     = "resource_access"
	KindToolRequest        = "tool_request"
	KindToolResponse       = "tool_response"
	KindExternalReceipt    = "external_receipt"
	KindDelegation         = "delegation"
	KindBudgetChange       = "budget_change"
	KindInjectionReceipt   = "injection_receipt"
	KindCollectorHeartbeat = "collector_heartbeat"
	KindRecoveryAction     = "recovery_action"
)

// Source components (the EvidenceEvent contract's enum).
const (
	ComponentCollector = "collector"
	ComponentBroker    = "broker"
	ComponentGovernor  = "governor"
	ComponentAdapter   = "adapter"
	ComponentMonitor   = "monitor"
	ComponentWorker    = "worker"
	ComponentVerifier  = "verifier"
)

// Payload reference kinds (the contract's payload.kind enum).
const (
	PayloadMetadataOnly = "metadata_only"
	PayloadObjectRef    = "object_ref"
	PayloadInline       = "inline"
)

// Coverage declarations for collector events (spec 13.2 feeds on
// these; a collector must state whether it observed directly).
const (
	CoverageObserved  = "observed"
	CoverageContained = "contained"
)

// Event mirrors the EvidenceEvent contract
// (shared/schemas/evidence-event.schema.json). Every field the schema
// knows is representable; nothing else is.
type Event struct {
	Kind               string       `json:"kind"`
	APIVersion         string       `json:"api_version"`
	ID                 string       `json:"id"`
	TenantID           string       `json:"tenant_id"`
	RunID              string       `json:"run_id"`
	ExperimentID       string       `json:"experiment_id,omitempty"`
	EventKind          string       `json:"event_kind"`
	TrustLabel         string       `json:"trust_label"`
	Source             EventSource  `json:"source"`
	Sequence           int64        `json:"sequence"`
	CorrelationIDs     []string     `json:"correlation_ids,omitempty"`
	ParentEventIDs     []string     `json:"parent_event_ids,omitempty"`
	EffectID           string       `json:"effect_id,omitempty"`
	DelegationID       string       `json:"delegation_id,omitempty"`
	FindingID          string       `json:"finding_id,omitempty"`
	ObservedAt         string       `json:"observed_at"`
	ClockUncertaintyMS int64        `json:"clock_uncertainty_ms"`
	Payload            EventPayload `json:"payload"`
	CorrectsEventID    string       `json:"corrects_event_id,omitempty"`
	Checkpoint         *Checkpoint  `json:"checkpoint,omitempty"`
	IngestedAt         string       `json:"ingested_at,omitempty"`
}

// EventSource identifies the authoritative origin. Collector events
// declare coverage; the contract enforces it, and so does this mirror.
type EventSource struct {
	ID        string `json:"id"`
	Component string `json:"component"` // collector | broker | governor | adapter | monitor | worker | verifier
	Coverage  string `json:"coverage,omitempty"`
}

// EventPayload is the closed payload reference. Raw prompts and tool
// results stay in object storage; only small safe content is inline
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

// Checkpoint is a signed per-source checkpoint covering a contiguous
// sequence range (spec 9.4).
type Checkpoint struct {
	SequenceFrom             int64     `json:"sequence_from"`
	SequenceTo               int64     `json:"sequence_to"`
	PreviousCheckpointDigest string    `json:"previous_checkpoint_digest,omitempty"`
	Digest                   string    `json:"digest"`
	Signature                Signature `json:"signature"`
}

// Signature is the detached signature over the canonical bytes of the
// signed object (the contract fixes the fields; verification is a
// service responsibility).
type Signature struct {
	Algorithm string `json:"algorithm"` // ed25519
	KeyID     string `json:"key_id"`
	Value     string `json:"value"` // base64 signature bytes
}

// Contract patterns, mirrored from shared/schemas/common.schema.json.
var (
	reTenantID    = regexp.MustCompile(`^tnt_[a-z0-9]{8,64}$`)
	reRunID       = regexp.MustCompile(`^run_[a-z0-9]{8,64}$`)
	reExperiment  = regexp.MustCompile(`^exp_[a-z0-9]{8,64}$`)
	reEffectID    = regexp.MustCompile(`^eff_[a-z0-9]{8,64}$`)
	reDelegation  = regexp.MustCompile(`^dlg_[a-z0-9]{8,64}$`)
	reEventID     = regexp.MustCompile(`^evt_[a-z0-9]{8,64}$`)
	reFindingID   = regexp.MustCompile(`^fnd_[a-z0-9]{8,64}$`)
	reSourceID    = regexp.MustCompile(`^src_[a-z0-9][a-z0-9-]{3,63}$`)
	reKeyID       = regexp.MustCompile(`^key_[a-z0-9][a-z0-9-]{3,63}$`)
	reDigest      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reTimestamp   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
	reCorrelation = regexp.MustCompile(`^cid_[A-Za-z0-9_-]{4,128}$`)
	reStorageRef  = regexp.MustCompile(`^obj://[a-z0-9][a-z0-9._/-]{3,508}$`)
	reContentType = regexp.MustCompile(`^[A-Za-z0-9./+-]{3,127}$`)
)

var knownEventKinds = map[string]bool{
	KindProposedAction: true, KindBrokerDecision: true, KindResourceAccess: true,
	KindToolRequest: true, KindToolResponse: true, KindExternalReceipt: true,
	KindDelegation: true, KindBudgetChange: true, KindInjectionReceipt: true,
	KindCollectorHeartbeat: true, KindRecoveryAction: true,
}

var knownComponents = map[string]bool{
	ComponentCollector: true, ComponentBroker: true, ComponentGovernor: true,
	ComponentAdapter: true, ComponentMonitor: true, ComponentWorker: true,
	ComponentVerifier: true,
}

// labelComponents lists which source components may carry each trust
// label. A worker never originates a collector fact; a broker decision
// or receipt never arrives as a monitor interpretation.
var labelComponents = map[string]map[string]bool{
	TrustCollectorFact: {
		ComponentCollector: true, ComponentBroker: true, ComponentGovernor: true,
		ComponentAdapter: true, ComponentVerifier: true,
	},
	TrustWorkerClaim: {
		ComponentWorker: true, ComponentCollector: true,
	},
	TrustMonitorReading: {
		ComponentMonitor: true, ComponentCollector: true,
	},
}

// kindLabels pins the event kinds whose trust label is not a choice:
// broker decisions and collector heartbeats are authoritative facts by
// definition — a worker claiming either is exactly the confusion the
// labels exist to prevent.
var kindLabels = map[string]string{
	KindBrokerDecision:     TrustCollectorFact,
	KindCollectorHeartbeat: TrustCollectorFact,
}

// ContractError is one contract violation with a JSON-pointer-style
// path, matching the problem envelope convention (spec 18.3).
type ContractError struct {
	Check  string `json:"check"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

func (e ContractError) Error() string {
	return fmt.Sprintf("%s: %s", e.Check, e.Detail)
}

// ValidateEvent checks one event against the EvidenceEvent contract
// fail-closed: unknown fields are impossible by construction (the
// decoder rejects them), and every present field must conform.
func (e *Event) ValidateEvent() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if e.Kind != "EvidenceEvent" {
		add("kind", "$.kind", "must be EvidenceEvent")
	}
	if e.APIVersion != "v1" {
		add("api_version", "$.api_version", "must be v1")
	}
	if !reEventID.MatchString(e.ID) {
		add("id", "$.id", "must match evt_[a-z0-9]{8,64}")
	}
	if !reTenantID.MatchString(e.TenantID) {
		add("tenant_id", "$.tenant_id", "must match tnt_[a-z0-9]{8,64}")
	}
	if !reRunID.MatchString(e.RunID) {
		add("run_id", "$.run_id", "must match run_[a-z0-9]{8,64}")
	}
	if e.ExperimentID != "" && !reExperiment.MatchString(e.ExperimentID) {
		add("experiment_id", "$.experiment_id", "must match exp_[a-z0-9]{8,64}")
	}
	if !knownEventKinds[e.EventKind] {
		add("event_kind", "$.event_kind", "must be one of the evidence event kinds")
	}
	switch e.TrustLabel {
	case TrustWorkerClaim, TrustCollectorFact, TrustMonitorReading:
	default:
		add("trust_label", "$.trust_label",
			"must be worker_claim, collector_fact, or monitor_interpretation")
	}
	if !reSourceID.MatchString(e.Source.ID) {
		add("source.id", "$.source.id", "must match src_[a-z0-9][a-z0-9-]{3,63}")
	}
	if !knownComponents[e.Source.Component] {
		add("source.component", "$.source.component", "must be a known component")
	}
	switch e.Source.Coverage {
	case "":
		if e.Source.Component == ComponentCollector {
			add("source.coverage", "$.source.coverage",
				"a collector event must declare observed or contained coverage")
		}
	case CoverageObserved, CoverageContained:
	default:
		add("source.coverage", "$.source.coverage", "must be observed or contained")
	}
	if e.Sequence < 0 {
		add("sequence", "$.sequence", "must not be negative")
	}
	if problem := validateIDList(e.CorrelationIDs, reCorrelation, "correlation_ids",
		"$.correlation_ids", "must match cid_[A-Za-z0-9_-]{4,128}"); problem.Detail != "" {
		errs = append(errs, problem)
	}
	if problem := validateIDList(e.ParentEventIDs, reEventID, "parent_event_ids",
		"$.parent_event_ids", "must match evt_[a-z0-9]{8,64}"); problem.Detail != "" {
		errs = append(errs, problem)
	}
	if e.EffectID != "" && !reEffectID.MatchString(e.EffectID) {
		add("effect_id", "$.effect_id", "must match eff_[a-z0-9]{8,64}")
	}
	if e.DelegationID != "" && !reDelegation.MatchString(e.DelegationID) {
		add("delegation_id", "$.delegation_id", "must match dlg_[a-z0-9]{8,64}")
	}
	if e.FindingID != "" && !reFindingID.MatchString(e.FindingID) {
		add("finding_id", "$.finding_id", "must match fnd_[a-z0-9]{8,64}")
	}
	if e.CorrectsEventID != "" && !reEventID.MatchString(e.CorrectsEventID) {
		add("corrects_event_id", "$.corrects_event_id", "must match evt_[a-z0-9]{8,64}")
	}
	if !reTimestamp.MatchString(e.ObservedAt) {
		add("observed_at", "$.observed_at", "must be an RFC 3339 UTC timestamp with a Z")
	}
	if e.ClockUncertaintyMS < 0 || e.ClockUncertaintyMS > 3600000 {
		add("clock_uncertainty_ms", "$.clock_uncertainty_ms", "must be between 0 and 3600000")
	}
	errs = append(errs, e.validatePayload()...)
	if pinned, ok := kindLabels[e.EventKind]; ok && e.TrustLabel != "" && e.TrustLabel != pinned {
		add("trust_label", "$.trust_label",
			fmt.Sprintf("a %s event is a %s, never a %s", e.EventKind, pinned, e.TrustLabel))
	}
	if e.TrustLabel != "" && e.Source.Component != "" {
		if allowed := labelComponents[e.TrustLabel]; allowed != nil && !allowed[e.Source.Component] {
			add("source.component", "$.source.component",
				fmt.Sprintf("a %s cannot originate a %s", e.Source.Component, e.TrustLabel))
		}
	}
	if e.Checkpoint != nil {
		errs = append(errs, e.validateCheckpoint()...)
	}
	return errs
}

func (e *Event) validatePayload() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	payload := e.Payload
	switch payload.Kind {
	case PayloadMetadataOnly:
		// A metadata-only event carries no captured content; a storage
		// reference or inline body would misstate what was captured.
		for field, value := range map[string]string{
			"storage_ref": payload.StorageRef, "digest": payload.Digest,
			"content_type": payload.ContentType, "content": payload.Content,
		} {
			if value != "" {
				add("payload."+field, "$.payload."+field,
					"a metadata_only payload carries no captured content")
			}
		}
		if payload.SizeBytes != 0 {
			add("payload.size_bytes", "$.payload.size_bytes",
				"a metadata_only payload has no content to size")
		}
	case PayloadObjectRef:
		if !reStorageRef.MatchString(payload.StorageRef) {
			add("payload.storage_ref", "$.payload.storage_ref", "must match obj://…")
		}
		if !reDigest.MatchString(payload.Digest) {
			add("payload.digest", "$.payload.digest",
				"must be sha256: plus 64 lowercase hex characters")
		}
		if payload.SizeBytes <= 0 {
			add("payload.size_bytes", "$.payload.size_bytes", "must be positive")
		}
		if !reContentType.MatchString(payload.ContentType) {
			add("payload.content_type", "$.payload.content_type",
				"must be a MIME type such as application/json")
		}
		if payload.Content != "" {
			add("payload.content", "$.payload.content",
				"an object_ref payload keeps content in object storage")
		}
	case PayloadInline:
		if payload.Content == "" {
			add("payload.content", "$.payload.content", "an inline payload carries its content")
		}
		if len(payload.Content) > 4096 {
			add("payload.content", "$.payload.content", "exceeds 4096 characters")
		}
		if payload.StorageRef != "" {
			add("payload.storage_ref", "$.payload.storage_ref",
				"a parallel storage reference creates two competing authorities")
		}
	default:
		add("payload.kind", "$.payload.kind", "must be metadata_only, object_ref, or inline")
	}
	if payload.Tombstone && payload.Kind != PayloadObjectRef {
		add("payload.tombstone", "$.payload.tombstone",
			"only a stored object can be tombstoned")
	}
	return errs
}

func (e *Event) validateCheckpoint() []ContractError {
	c := e.Checkpoint
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if c.SequenceFrom < 0 || c.SequenceTo < c.SequenceFrom {
		add("checkpoint", "$.checkpoint", "sequence range must be contiguous and non-negative")
	}
	if !reDigest.MatchString(c.Digest) {
		add("checkpoint.digest", "$.checkpoint.digest",
			"must be sha256: plus 64 lowercase hex characters")
	}
	if c.PreviousCheckpointDigest != "" && !reDigest.MatchString(c.PreviousCheckpointDigest) {
		add("checkpoint.previous_checkpoint_digest",
			"$.checkpoint.previous_checkpoint_digest", "must be a sha256: digest")
	}
	if c.Signature.Algorithm != "ed25519" {
		add("checkpoint.signature.algorithm",
			"$.checkpoint.signature.algorithm", "must be ed25519")
	}
	if !reKeyID.MatchString(c.Signature.KeyID) {
		add("checkpoint.signature.key_id",
			"$.checkpoint.signature.key_id", "must match key_[a-z0-9][a-z0-9-]{3,63}")
	}
	if len(c.Signature.Value) < 64 {
		add("checkpoint.signature.value",
			"$.checkpoint.signature.value", "must be base64 signature bytes")
	}
	return errs
}

// validateIDList checks the shared shape of correlation and parent-id
// lists: bounded, unique, and each item matching its pattern.
func validateIDList(values []string, pattern *regexp.Regexp, check, path, detail string) ContractError {
	if len(values) > 64 {
		return ContractError{Check: check, Path: path, Detail: "exceeds 64 entries"}
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return ContractError{Check: check, Path: path, Detail: "entries must be unique"}
		}
		seen[value] = true
		if !pattern.MatchString(value) {
			return ContractError{Check: check, Path: path, Detail: detail}
		}
	}
	return ContractError{}
}

// batchKeys and eventKeys are the exact accepted spellings at each
// object level (AC-001: contract keys are exact; anything else fails
// closed).
var (
	batchKeys = map[string]bool{"events": true}
	eventKeys = map[string]bool{
		"kind": true, "api_version": true, "id": true, "tenant_id": true,
		"run_id": true, "experiment_id": true, "event_kind": true,
		"trust_label": true, "source": true, "sequence": true,
		"correlation_ids": true, "parent_event_ids": true, "effect_id": true,
		"delegation_id": true, "finding_id": true, "observed_at": true,
		"clock_uncertainty_ms": true, "payload": true, "corrects_event_id": true,
		"checkpoint": true,
	}
	sourceKeys  = map[string]bool{"id": true, "component": true, "coverage": true}
	payloadKeys = map[string]bool{
		"kind": true, "storage_ref": true, "digest": true, "size_bytes": true,
		"content_type": true, "redacted": true, "truncated": true,
		"tombstone": true, "content": true,
	}
	checkpointKeys = map[string]bool{
		"sequence_from": true, "sequence_to": true,
		"previous_checkpoint_digest": true, "digest": true, "signature": true,
	}
	signatureKeys = map[string]bool{"algorithm": true, "key_id": true, "value": true}
)

// Batch is the ingestion request body: a list of events from one
// authenticated collector. At-least-once delivery is the norm, so the
// recorder deduplicates by event id (spec 18.3).
type Batch struct {
	Events []*Event `json:"events"`
}

// DecodeBatch parses an ingestion body with exact-key validation at
// every nesting level. Each event is checked against the wire bytes,
// never against a re-marshaled struct: re-encoding would silently drop
// unknown fields, and the contract must fail closed on them (AC-001).
// The ingested_at field never comes from the wire: the recorder stamps
// it, so it is not an accepted key.
func DecodeBatch(data []byte) (*Batch, error) {
	raw, err := decodeExact(data, batchKeys)
	if err != nil {
		return nil, err
	}
	batch := &Batch{}
	if len(raw) == 0 {
		return batch, nil
	}
	if list, ok := raw["events"]; ok {
		var elements []json.RawMessage
		if err := json.Unmarshal(list, &elements); err != nil {
			return nil, fmt.Errorf("malformed events list: %w", err)
		}
		for i, element := range elements {
			nested, err := decodeExact(element, eventKeys)
			if err != nil {
				return nil, fmt.Errorf("events[%d]: %w", i, err)
			}
			if object, ok := nested["source"]; ok {
				if _, err := decodeExact(object, sourceKeys); err != nil {
					return nil, fmt.Errorf("events[%d].source: %w", i, err)
				}
			}
			if object, ok := nested["payload"]; ok {
				if _, err := decodeExact(object, payloadKeys); err != nil {
					return nil, fmt.Errorf("events[%d].payload: %w", i, err)
				}
			}
			if object, ok := nested["checkpoint"]; ok {
				checkpoint, err := decodeExact(object, checkpointKeys)
				if err != nil {
					return nil, fmt.Errorf("events[%d].checkpoint: %w", i, err)
				}
				if signature, ok := checkpoint["signature"]; ok {
					if _, err := decodeExact(signature, signatureKeys); err != nil {
						return nil, fmt.Errorf("events[%d].checkpoint.signature: %w", i, err)
					}
				}
			}
		}
	}
	if err := json.Unmarshal(data, batch); err != nil {
		return nil, fmt.Errorf("malformed batch: %w", err)
	}
	return batch, nil
}

// decodeExact decodes one object level and rejects any key outside
// the allowed set.
func decodeExact(data []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("malformed object: %w", err)
	}
	for key := range raw {
		if !allowed[key] {
			return nil, fmt.Errorf(
				"unknown or misspelled field %q: contract keys are exact snake_case", key)
		}
	}
	return raw, nil
}

// CloneEvent copies an event so callers never share stored state.
func CloneEvent(event *Event) *Event {
	duplicate := *event
	duplicate.CorrelationIDs = append([]string(nil), event.CorrelationIDs...)
	duplicate.ParentEventIDs = append([]string(nil), event.ParentEventIDs...)
	if event.Checkpoint != nil {
		checkpoint := *event.Checkpoint
		duplicate.Checkpoint = &checkpoint
	}
	return &duplicate
}

// canonicalBytes marshals an event deterministically: a JSON object
// with sorted keys (Go sorts map keys), over every field the contract
// knows. The chain covers the whole record; a change to any field,
// payload content included, must break verification.
func (e *Event) canonicalBytes() []byte {
	source := map[string]any{"id": e.Source.ID, "component": e.Source.Component}
	if e.Source.Coverage != "" {
		source["coverage"] = e.Source.Coverage
	}
	payload := map[string]any{
		"kind": e.Payload.Kind, "redacted": e.Payload.Redacted,
		"truncated": e.Payload.Truncated,
	}
	if e.Payload.StorageRef != "" {
		payload["storage_ref"] = e.Payload.StorageRef
	}
	if e.Payload.Digest != "" {
		payload["digest"] = e.Payload.Digest
	}
	if e.Payload.SizeBytes != 0 {
		payload["size_bytes"] = e.Payload.SizeBytes
	}
	if e.Payload.ContentType != "" {
		payload["content_type"] = e.Payload.ContentType
	}
	if e.Payload.Tombstone {
		payload["tombstone"] = true
	}
	if e.Payload.Content != "" {
		payload["content"] = e.Payload.Content
	}
	object := map[string]any{
		"kind":                 e.Kind,
		"api_version":          e.APIVersion,
		"id":                   e.ID,
		"tenant_id":            e.TenantID,
		"run_id":               e.RunID,
		"event_kind":           e.EventKind,
		"trust_label":          e.TrustLabel,
		"source":               source,
		"sequence":             e.Sequence,
		"observed_at":          e.ObservedAt,
		"clock_uncertainty_ms": e.ClockUncertaintyMS,
		"payload":              payload,
		"ingested_at":          e.IngestedAt,
	}
	if e.ExperimentID != "" {
		object["experiment_id"] = e.ExperimentID
	}
	if e.EffectID != "" {
		object["effect_id"] = e.EffectID
	}
	if e.DelegationID != "" {
		object["delegation_id"] = e.DelegationID
	}
	if e.FindingID != "" {
		object["finding_id"] = e.FindingID
	}
	if e.CorrectsEventID != "" {
		object["corrects_event_id"] = e.CorrectsEventID
	}
	if len(e.CorrelationIDs) > 0 {
		object["correlation_ids"] = e.CorrelationIDs
	}
	if len(e.ParentEventIDs) > 0 {
		object["parent_event_ids"] = e.ParentEventIDs
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		// A struct of strings, ints, bools, and maps of the same cannot
		// fail to marshal; an empty answer fails verification loudly.
		return []byte("{}")
	}
	return encoded
}
