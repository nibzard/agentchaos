// Package broker implements the mandatory effect broker's HTTP tool
// interface (spec 6.1, 10, 18.2): workers propose effects, the broker
// decides them against a deterministic policy, and dispatch happens
// only through bound permits with recorded receipts.
package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// Effect states (spec 10.1, common.schema.json effectState).
const (
	StateProposed     = "PROPOSED"
	StateAuthorized   = "AUTHORIZED"
	StatePrepared     = "PREPARED"
	StateCommitting   = "COMMITTING"
	StateCommitted    = "COMMITTED"
	StateDenied       = "DENIED"
	StateExpired      = "EXPIRED"
	StateCancelled    = "CANCELLED"
	StateUnknown      = "UNKNOWN_EFFECT"
	StateCompensating = "COMPENSATING"
)

// Action classes (spec 6.1). A3 is not representable on a brokered
// effect, so it has no constant here.
const (
	ClassA0 = "A0"
	ClassA1 = "A1"
	ClassA2 = "A2"
)

// Dispatch outcomes (Effect contract).
const (
	OutcomeAcknowledged = "acknowledged"
	OutcomeTimeout      = "timeout_unknown"
	OutcomeFailed       = "failed"
)

// Pattern anchors from shared/schemas/common.schema.json. The schemas
// stay authoritative; these mirror them so the broker can reject
// malformed requests without a schema engine.
var (
	reEffectID  = regexp.MustCompile(`^eff_[a-z0-9]{8,64}$`)
	reRunID     = regexp.MustCompile(`^run_[a-z0-9]{8,64}$`)
	reTenantID  = regexp.MustCompile(`^tnt_[a-z0-9]{8,64}$`)
	reActorID   = regexp.MustCompile(`^act_[a-z0-9][a-z0-9-]{3,63}$`)
	reSourceID  = regexp.MustCompile(`^src_[a-z0-9][a-z0-9-]{3,63}$`)
	reEventID   = regexp.MustCompile(`^evt_[a-z0-9]{8,64}$`)
	reDigest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reNonce     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	reIdemKey   = regexp.MustCompile(`^idk_[A-Za-z0-9_-]{8,128}$`)
	reOperation = regexp.MustCompile(`^[a-z][a-z0-9_.]{1,127}$`)
	reResource  = regexp.MustCompile(`^[a-z][a-z0-9._:/-]{2,252}$`)
	reSemVer    = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	reTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
)

// Effect mirrors the Effect contract (shared/schemas/effect.schema.json).
// Field names match the JSON exactly; decoding rejects unknown fields.
type Effect struct {
	Kind           string         `json:"kind"`
	APIVersion     string         `json:"api_version"`
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	RunID          string         `json:"run_id"`
	DelegationID   string         `json:"delegation_id,omitempty"`
	Actor          string         `json:"actor"`
	ActionClass    string         `json:"action_class"`
	ProposedAction ProposedAction `json:"proposed_action"`
	Authorization  *Authorization `json:"authorization,omitempty"`
	Review         *Review        `json:"review,omitempty"`
	Dispatch       *Dispatch      `json:"dispatch,omitempty"`
	Receipt        *Receipt       `json:"receipt,omitempty"`
	CompensationOf string         `json:"compensation_of,omitempty"`
	State          string         `json:"state"`
	Transitions    []Transition   `json:"transitions"`
	CreatedAt      string         `json:"created_at"`
}

// ProposedAction is the worker's proposal: what to call, where, with
// what content. The broker never accepts downstream credentials.
type ProposedAction struct {
	Operation       string `json:"operation"`
	Resource        string `json:"resource"`
	Destination     string `json:"destination"`
	ArgumentsDigest string `json:"arguments_digest"`
	SizeBytes       int64  `json:"size_bytes,omitempty"`
}

// Authorization is the broker's bound permit (spec 10). A permit
// always carries a bounded quantity: money or bytes. SizeLimit is a
// pointer so a zero-byte ceiling serializes explicitly (a bound of
// zero is meaningful) while costed permits omit it.
type Authorization struct {
	TaskID          string       `json:"task_id"`
	PolicyVersion   string       `json:"policy_version"`
	PolicyDigest    string       `json:"policy_digest"`
	ResourceVersion string       `json:"resource_version,omitempty"`
	AmountLimit     *AmountLimit `json:"amount_limit,omitempty"`
	SizeLimit       *int64       `json:"size_limit,omitempty"`
	ExpiresAt       string       `json:"expires_at"`
	Nonce           string       `json:"nonce"`
	AuthorizedAt    string       `json:"authorized_at,omitempty"`
}

// AmountLimit bounds a costed effect in integer micros.
type AmountLimit struct {
	Money Money  `json:"money"`
	Unit  string `json:"unit,omitempty"`
}

// Money in integer micro-units with an ISO-4317-style code.
type Money struct {
	Currency string `json:"currency"`
	Micros   int64  `json:"micros"`
}

// Review is a machine-review decision attached to the effect
// (spec 11.2). The deterministic gate alone decides T006 effects;
// risk-routed review attaches these later.
type Review struct {
	Verdict       string   `json:"verdict"`
	ReviewerID    string   `json:"reviewer_id"`
	PolicyRefs    []string `json:"policy_refs"`
	EventRefs     []string `json:"event_refs"`
	Rationale     string   `json:"rationale"`
	Limitations   string   `json:"limitations"`
	ModelID       string   `json:"model_id,omitempty"`
	PromptVersion string   `json:"prompt_version,omitempty"`
	LatencyMS     int64    `json:"latency_ms"`
}

// Dispatch records the external send (spec 10.1). It exists only
// after the intent and decision were durably recorded.
type Dispatch struct {
	DispatchedAt   string `json:"dispatched_at"`
	Outcome        string `json:"outcome"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// Receipt reconciles the true outcome from outside the worker
// (spec 10.1, AC-010).
type Receipt struct {
	Source          string `json:"source"`
	ReceivedAt      string `json:"received_at"`
	Reconciled      bool   `json:"reconciled"`
	EvidenceEventID string `json:"evidence_event_id,omitempty"`
	Digest          string `json:"digest,omitempty"`
}

// Transition is one append-only lifecycle step.
type Transition struct {
	State string `json:"state"`
	At    string `json:"at"`
	Actor string `json:"actor,omitempty"`
}

// Exact key sets for proposal decoding. Go's encoding/json matches
// keys case-insensitively when no exact tag match exists, so
// "Action_Class" would silently bind to action_class. Security-
// sensitive manifests fail closed on any non-contract spelling
// (AC-001, spec 18.3).
var (
	proposalTopKeys = map[string]bool{
		"kind": true, "api_version": true, "id": true, "tenant_id": true,
		"run_id": true, "delegation_id": true, "actor": true,
		"action_class": true, "proposed_action": true, "state": true,
		"transitions": true, "created_at": true, "authorization": true,
		"review": true, "dispatch": true, "receipt": true,
		"compensation_of": true,
	}
	proposedActionKeys = map[string]bool{
		"operation": true, "resource": true, "destination": true,
		"arguments_digest": true, "size_bytes": true,
	}
	transitionKeys = map[string]bool{"state": true, "at": true, "actor": true}
)

// DecodeProposal parses a request body into an Effect. It rejects
// trailing content and any key that is not the exact contract
// spelling at the top level, inside proposed_action, and inside
// transitions entries (AC-001).
func DecodeProposal(data []byte) (*Effect, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("malformed proposal body: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing content after JSON document")
	}
	for key := range raw {
		if !proposalTopKeys[key] {
			return nil, fmt.Errorf("unknown or misspelled field %q: contract keys are exact snake_case", key)
		}
	}
	if actionRaw, ok := raw["proposed_action"]; ok {
		var actionFields map[string]json.RawMessage
		if err := json.Unmarshal(actionRaw, &actionFields); err != nil {
			return nil, fmt.Errorf("malformed proposed_action: %w", err)
		}
		for key := range actionFields {
			if !proposedActionKeys[key] {
				return nil, fmt.Errorf("unknown or misspelled field %q in proposed_action", key)
			}
		}
	}
	if transitionsRaw, ok := raw["transitions"]; ok {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(transitionsRaw, &entries); err != nil {
			return nil, fmt.Errorf("malformed transitions: %w", err)
		}
		for _, entry := range entries {
			for key := range entry {
				if !transitionKeys[key] {
					return nil, fmt.Errorf("unknown or misspelled field %q in transitions", key)
				}
			}
		}
	}
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	var effect Effect
	if err := strict.Decode(&effect); err != nil {
		return nil, fmt.Errorf("unknown or malformed field: %w", err)
	}
	return &effect, nil
}

// ValidateProposal checks a freshly decoded proposal against the
// Effect contract's shape for the PROPOSED state. Every violation
// returns a stable check name plus detail for the problem body.
func (e *Effect) ValidateProposal() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if e.Kind != "Effect" {
		add("kind", "$.kind", "must be \"Effect\"")
	}
	if e.APIVersion != "v1" {
		add("api_version", "$.api_version", "must be \"v1\"")
	}
	if !reEffectID.MatchString(e.ID) {
		add("id", "$.id", "must match eff_[a-z0-9]{8,64}")
	}
	if !reTenantID.MatchString(e.TenantID) {
		add("tenant_id", "$.tenant_id", "must match tnt_[a-z0-9]{8,64}")
	}
	if !reRunID.MatchString(e.RunID) {
		add("run_id", "$.run_id", "must match run_[a-z0-9]{8,64}")
	}
	if e.DelegationID != "" && !matches(`^dlg_[a-z0-9]{8,64}$`, e.DelegationID) {
		add("delegation_id", "$.delegation_id", "must match dlg_[a-z0-9]{8,64}")
	}
	if !reActorID.MatchString(e.Actor) {
		add("actor", "$.actor", "must match act_[a-z0-9][a-z0-9-]{3,63}")
	}
	switch e.ActionClass {
	case ClassA1, ClassA2:
	default:
		add("action_class", "$.action_class",
			"must be A1 or A2; A0 stays local and A3 is not brokerable (spec 6.1)")
	}
	if e.State != StateProposed {
		add("state", "$.state", "a new proposal must arrive in state PROPOSED")
	}
	if e.Authorization != nil {
		add("authorization", "$.authorization",
			"a proposal cannot carry a permit; a pre-authorized denial would make replay look legitimate (AC-009)")
	}
	if e.Dispatch != nil {
		add("dispatch", "$.dispatch", "a proposal cannot already be dispatched")
	}
	if e.Receipt != nil {
		add("receipt", "$.receipt", "a proposal cannot already carry a receipt")
	}
	if e.CompensationOf != "" {
		add("compensation_of", "$.compensation_of", "only a compensating effect references another effect")
	}
	if e.Review != nil {
		add("review", "$.review",
			"a proposal cannot attach a machine-review verdict; the broker attaches reviews (spec 11.2)")
	}
	errs = append(errs, e.ProposedAction.validate()...)
	if !reTimestamp.MatchString(e.CreatedAt) {
		add("created_at", "$.created_at", "must be an RFC 3339 UTC timestamp with Z")
	}
	if len(e.Transitions) != 1 || e.Transitions[0].State != StateProposed {
		add("transitions", "$.transitions",
			"a proposal arrives with exactly one PROPOSED transition; history is append-only broker-side")
	}
	for i, t := range e.Transitions {
		if t.State == "" || !reTimestamp.MatchString(t.At) {
			add("transitions", fmt.Sprintf("$.transitions[%d]", i),
				"every transition needs a state and a UTC timestamp")
		}
	}
	return errs
}

func (p *ProposedAction) validate() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if !reOperation.MatchString(p.Operation) {
		add("operation", "$.proposed_action.operation",
			"must match ^[a-z][a-z0-9_.]{1,127}")
	}
	if !reResource.MatchString(p.Resource) {
		add("resource", "$.proposed_action.resource",
			"must match ^[a-z][a-z0-9._:/-]{2,252}")
	}
	if !matches(`^(https?://|sink:)[A-Za-z0-9._:/-]{3,252}$`, p.Destination) {
		add("destination", "$.proposed_action.destination",
			"must be an http(s) URL or a sink: destination")
	}
	if !reDigest.MatchString(p.ArgumentsDigest) {
		add("arguments_digest", "$.proposed_action.arguments_digest",
			"must be sha256: plus 64 lowercase hex characters")
	}
	if p.SizeBytes < 0 || p.SizeBytes > 5368709120 {
		add("size_bytes", "$.proposed_action.size_bytes", "must be 0..5368709120")
	}
	return errs
}

// ContractError is one contract violation in a problem body.
type ContractError struct {
	Check  string `json:"check"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

func matches(pattern, value string) bool {
	return regexp.MustCompile(pattern).MatchString(value)
}
