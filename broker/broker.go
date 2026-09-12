package broker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// PermitTTL bounds how long a minted authorization stays valid. It is
// deliberately shorter than any grant window; short-lived means
// short-lived (spec 10).
const PermitTTL = 5 * time.Minute

// Principal is the authenticated caller. The transport resolves it;
// the broker trusts only these fields, never a tenant in a body
// (spec 18.3).
type Principal struct {
	ID       string
	TenantID string
	Role     string // worker | service | collector | operator
}

// Roles recognized by the broker.
const (
	RoleWorker   = "worker"
	RoleService  = "service"
	RoleOperator = "operator"
)

// BrokerDecision is the evaluation result returned by Authorize. A
// deny is a successful evaluation, so it travels as data, not as a
// transport error.
type BrokerDecision struct {
	Verdict         string   `json:"verdict"` // allow | deny
	Reason          string   `json:"reason,omitempty"`
	PolicyRefs      []string `json:"policy_refs"`
	DeterminedAt    string   `json:"determined_at"`
	EvidenceEventID string   `json:"evidence_event_id"`
}

// Sink dispatches a permitted effect to its destination. Sinks sit
// outside the worker environment and are the only holders of
// downstream credentials (spec 10).
type Sink interface {
	// Name identifies the receipt source.
	Name() string
	// Supports reports whether the sink owns a destination.
	Supports(destination string) bool
	// Dispatch performs the external send and reports the outcome.
	// A timeout is reported as OutcomeTimeout and reconciled later;
	// dispatch must never blindly reissue (spec 10.1).
	Dispatch(effect *Effect, now string) SinkResult
}

// SinkResult is what a sink reports back.
type SinkResult struct {
	Outcome       string // acknowledged | timeout_unknown | failed
	ReceiptDigest string
	Detail        string
}

// Broker is the effect broker service (spec 10). All state is
// append-only: effects record their transitions, and the event
// journal records decisions and receipts. Effect records are scoped
// by tenant: an id held by one tenant never collides with another.
type Broker struct {
	policy *Policy
	runs   map[string]*RunContext
	sinks  []Sink
	now    func() time.Time

	mu          sync.Mutex
	effects     map[string]*Effect // by tenant-scoped key
	events      []EvidenceEvent
	idempotency map[string]idempotentCall // by tenant-scoped key
	sequences   map[string]int64          // per source
}

type idempotentCall struct {
	bodyDigest string
	reply      any // first reply, captured at completion
	ready      chan struct{}
}

// idempotencyWait bounds how long a request waits for a concurrent
// request that reserved the same idempotency key.
const idempotencyWait = 10 * time.Second

// effectKey scopes an effect id to a tenant.
func effectKey(tenantID, effectID string) string {
	return tenantID + "\x00" + effectID
}

// ledgerKey scopes an idempotency key to a tenant (spec 18.3: keys
// from one tenant never surface another tenant's stored reply).
func ledgerKey(tenantID, key string) string {
	return tenantID + "\x00" + key
}

// New builds a broker from a policy, the run contexts it serves, and
// the sinks it may dispatch through.
func New(policy *Policy, runs []*RunContext, sinks []Sink) *Broker {
	index := make(map[string]*RunContext, len(runs))
	for _, run := range runs {
		index[run.RunID] = run
	}
	return &Broker{
		policy:      policy,
		runs:        index,
		sinks:       sinks,
		now:         time.Now,
		effects:     make(map[string]*Effect),
		idempotency: make(map[string]idempotentCall),
		sequences:   make(map[string]int64),
	}
}

// ClockUTC formats the broker clock as contract timestamps.
func (b *Broker) ClockUTC() string {
	return b.now().UTC().Format("2006-01-02T15:04:05Z")
}

// Effects returns a copy of every recorded effect (test and collector
// aid). Callers get clones; the internal records stay append-only.
func (b *Broker) Effects() []*Effect {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Effect, 0, len(b.effects))
	for _, effect := range b.effects {
		out = append(out, cloneEffect(effect))
	}
	return out
}

// Events returns the broker's evidence journal (spec 9.4: the broker
// is part of the trusted computing base and records authoritative
// facts, not worker claims).
func (b *Broker) Events() []EvidenceEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]EvidenceEvent, len(b.events))
	copy(out, b.events)
	return out
}

// Reserve enforces the mutation contract (spec 18.3) atomically: the
// first caller of a (tenant, key) reserves it, identical reuse replays
// the first reply, and reuse with a different body conflicts. A
// concurrent identical request waits for the first one to finish.
func (b *Broker) Reserve(tenantID, key, bodyDigest string) (reply any, replay bool, err error) {
	scoped := ledgerKey(tenantID, key)
	b.mu.Lock()
	previous, seen := b.idempotency[scoped]
	if !seen {
		b.idempotency[scoped] = idempotentCall{
			bodyDigest: bodyDigest, ready: make(chan struct{}),
		}
		b.mu.Unlock()
		return nil, false, nil
	}
	b.mu.Unlock()
	if previous.bodyDigest != bodyDigest {
		return nil, true, errIdempotencyConflict
	}
	select {
	case <-previous.ready:
	case <-time.After(idempotencyWait):
		return nil, true, errIdempotencyPending
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	settled := b.idempotency[scoped]
	if settled.bodyDigest == bodyDigest && settled.reply != nil {
		return settled.reply, true, nil
	}
	// The first attempt failed and released the key; execute afresh.
	return nil, false, nil
}

// Complete stores the reply for a reserved key and wakes waiters.
func (b *Broker) Complete(tenantID, key, bodyDigest string, reply any) {
	scoped := ledgerKey(tenantID, key)
	b.mu.Lock()
	defer b.mu.Unlock()
	if call, seen := b.idempotency[scoped]; seen && call.bodyDigest == bodyDigest {
		call.reply = reply
		b.idempotency[scoped] = call
		close(call.ready)
	}
}

// Release drops a pending reservation after a failed execution so a
// corrected retry can proceed.
func (b *Broker) Release(tenantID, key, bodyDigest string) {
	scoped := ledgerKey(tenantID, key)
	b.mu.Lock()
	defer b.mu.Unlock()
	if call, seen := b.idempotency[scoped]; seen && call.bodyDigest == bodyDigest && call.reply == nil {
		delete(b.idempotency, scoped)
		close(call.ready) // waiters re-execute instead of blocking
	}
}

// CheckAuthority reports whether the principal may drive broker
// mutations at all. Workers and collectors never can (spec 18.3).
func (b *Broker) CheckAuthority(principal *Principal) error {
	if principal == nil {
		return fmt.Errorf("unauthenticated caller")
	}
	switch principal.Role {
	case RoleService, RoleOperator:
		return nil
	default:
		return fmt.Errorf("role %s cannot drive broker authority", principal.Role)
	}
}

// Authorize evaluates a proposal through the deterministic gate and
// records the decision as a broker_decision evidence event. The
// proposal's tenant must match the principal's tenant; the principal
// must not be a worker (workers cannot issue permits, spec 18.3).
func (b *Broker) Authorize(principal *Principal, proposal *Effect) (*Effect, *BrokerDecision, error) {
	if err := b.checkPrincipal(principal, proposal.TenantID, "authorize"); err != nil {
		return nil, nil, err
	}
	scoped := effectKey(principal.TenantID, proposal.ID)
	b.mu.Lock()
	if _, exists := b.effects[scoped]; exists {
		b.mu.Unlock()
		// The lifecycle is append-only under one id: a re-proposal
		// must use a fresh effect id (spec 18.1).
		return nil, nil, errEffectExists
	}
	b.mu.Unlock()

	now := b.ClockUTC()
	run := b.runs[proposal.RunID]
	verdict := b.policy.Evaluate(proposal, run, now)

	decision := &BrokerDecision{
		Verdict:         "deny",
		PolicyRefs:      verdict.PolicyRefs,
		DeterminedAt:    now,
		EvidenceEventID: b.mintEventID(),
	}
	effect := cloneEffect(proposal)

	if !verdict.Allowed {
		decision.Reason = verdict.Reason
		effect.State = StateDenied
		effect.Transitions = append(effect.Transitions,
			Transition{State: StateDenied, At: now, Actor: brokerSourceID})
		b.record(decision, effect, "deny: "+verdict.Reason)
		if !b.storeIfAbsent(scoped, effect) {
			return nil, nil, errEffectExists
		}
		return cloneEffect(effect), decision, nil
	}

	authorization := &Authorization{
		TaskID:        run.TaskID,
		PolicyVersion: b.policy.Version,
		PolicyDigest:  b.policy.digest,
		ExpiresAt:     b.permitExpiry(run),
		Nonce:         mintNonce(),
		AuthorizedAt:  now,
	}
	if verdict.Rule.AmountLimit != nil {
		authorization.AmountLimit = &AmountLimit{Money: *verdict.Rule.AmountLimit}
	} else {
		ceiling := verdict.Rule.MaxSizeBytes
		authorization.SizeLimit = &ceiling
	}
	effect.Authorization = authorization
	effect.State = StateAuthorized
	effect.Transitions = append(effect.Transitions,
		Transition{State: StateAuthorized, At: now, Actor: brokerSourceID})
	decision.Verdict = "allow"
	b.record(decision, effect, "allow: deterministic gate passed")
	if !b.storeIfAbsent(scoped, effect) {
		return nil, nil, errEffectExists
	}
	return cloneEffect(effect), decision, nil
}

// storeIfAbsent commits the effect record under its scoped key and
// reports whether this call won the race for the id.
func (b *Broker) storeIfAbsent(scoped string, effect *Effect) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.effects[scoped]; exists {
		return false
	}
	b.effects[scoped] = effect
	return true
}

// permitExpiry mints the permit window: the five-minute TTL clamped
// to the run's grant window. An unparseable grant fails closed to
// "no remaining window" (though the gate already denied it).
func (b *Broker) permitExpiry(run *RunContext) string {
	now := b.now().UTC()
	grant, err := time.Parse(time.RFC3339Nano, run.GrantExpiresAt)
	if err != nil {
		grant = now
	}
	expiresAt := now.Add(PermitTTL)
	if grant.Before(expiresAt) {
		expiresAt = grant
	}
	return expiresAt.UTC().Format("2006-01-02T15:04:05Z")
}

// Commit dispatches an authorized effect through the sink that owns
// its destination (spec 10.1). The intent and decision are already
// durably recorded; dispatch happens only through the bound permit.
func (b *Broker) Commit(principal *Principal, effectID string) (*Effect, error) {
	if principal == nil {
		return nil, fmt.Errorf("unauthenticated caller cannot commit")
	}
	b.mu.Lock()
	effect, ok := b.effects[effectKey(principal.TenantID, effectID)]
	b.mu.Unlock()
	if !ok {
		// A cross-tenant lookup is indistinguishable from a miss, so
		// it never confirms another tenant's effect exists.
		return nil, errNotFound
	}
	if err := b.checkPrincipal(principal, effect.TenantID, "commit"); err != nil {
		return nil, err
	}
	now := b.ClockUTC()

	b.mu.Lock()
	defer b.mu.Unlock()
	switch effect.State {
	case StateAuthorized:
	default:
		return nil, &TransitionError{EffectID: effectID, From: effect.State,
			Why: "only an AUTHORIZED effect can commit"}
	}
	if momentAtOrBefore(effect.Authorization.ExpiresAt, now) {
		effect.State = StateExpired
		effect.Transitions = append(effect.Transitions,
			Transition{State: StateExpired, At: now, Actor: brokerSourceID})
		return nil, &TransitionError{EffectID: effectID, From: StateExpired,
			Why: "authorization expired; propose again"}
	}

	sink := b.sinkFor(effect.ProposedAction.Destination)
	if sink == nil {
		return nil, &TransitionError{EffectID: effectID, From: effect.State,
			Why: "no sink owns destination " + effect.ProposedAction.Destination}
	}

	effect.State = StateCommitting
	effect.Dispatch = &Dispatch{DispatchedAt: now, Outcome: OutcomeTimeout}
	result := sink.Dispatch(cloneEffect(effect), now)
	switch result.Outcome {
	case OutcomeAcknowledged, OutcomeFailed:
		effect.Dispatch.Outcome = result.Outcome
	default:
		// The Effect contract's dispatch outcome enum has no slot for
		// an unrecognized sink report; it is an unknown outcome, which
		// the contract represents as timeout_unknown. The raw string
		// survives in the evidence event payload.
		effect.Dispatch.Outcome = OutcomeTimeout
	}

	switch result.Outcome {
	case OutcomeAcknowledged:
		effect.State = StateCommitted
		effect.Receipt = &Receipt{
			Source:     sink.Name(),
			ReceivedAt: b.ClockUTC(),
			Reconciled: true,
			Digest:     result.ReceiptDigest,
		}
		event := b.appendEvent(receiptEvent(effect, sink.Name(), result))
		effect.Receipt.EvidenceEventID = event.ID
	case OutcomeFailed:
		// The sink reports the send never took effect; the exceptional
		// state that says "no effect happened" is CANCELLED. The
		// attempt still lands in the evidence journal.
		effect.State = StateCancelled
		b.appendEvent(receiptEvent(effect, sink.Name(), result))
	default:
		// A timeout — or any outcome the broker does not recognize —
		// is an unknown outcome: record it, fence retries behind
		// reconciliation (spec 10.1, AC-010). An unrecognized outcome
		// never claims the send did not happen.
		effect.State = StateUnknown
		effect.Receipt = &Receipt{
			Source:     sink.Name(),
			ReceivedAt: b.ClockUTC(),
			Reconciled: false,
		}
		b.appendEvent(receiptEvent(effect, sink.Name(), result))
	}
	effect.Transitions = append(effect.Transitions,
		Transition{State: effect.State, At: b.ClockUTC(), Actor: brokerSourceID})
	return cloneEffect(effect), nil
}

func (b *Broker) checkPrincipal(principal *Principal, tenantID, action string) error {
	if principal == nil {
		return fmt.Errorf("unauthenticated caller cannot %s", action)
	}
	if principal.TenantID != tenantID {
		return fmt.Errorf("tenant %s cannot act on tenant %s records",
			principal.TenantID, tenantID)
	}
	switch principal.Role {
	case RoleService, RoleOperator:
		return nil
	default:
		// Worker and collector identities never drive the broker's
		// authority path (spec 18.3).
		return fmt.Errorf("role %s cannot %s", principal.Role, action)
	}
}

func (b *Broker) sinkFor(destination string) Sink {
	for _, sink := range b.sinks {
		if sink.Supports(destination) {
			return sink
		}
	}
	return nil
}

func (b *Broker) record(decision *BrokerDecision, effect *Effect, rationale string) {
	event := EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         decision.EvidenceEventID,
		TenantID:   effect.TenantID,
		RunID:      effect.RunID,
		EventKind:  "broker_decision",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		ObservedAt: decision.DeterminedAt,
		EffectID:   effect.ID,
		Payload: inlinePayload(map[string]any{
			"verdict": decision.Verdict,
			"reason":  decision.Reason,
			"detail":  rationale,
		}),
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	event.Sequence = b.nextSequence(brokerSourceID)
	b.events = append(b.events, event)
}

func receiptEvent(effect *Effect, source string, result SinkResult) EvidenceEvent {
	return EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         mintEventIDSoon(),
		TenantID:   effect.TenantID,
		RunID:      effect.RunID,
		EventKind:  "external_receipt",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		ObservedAt: effect.Dispatch.DispatchedAt,
		EffectID:   effect.ID,
		Payload: inlinePayload(map[string]any{
			"outcome":        result.Outcome,
			"detail":         result.Detail,
			"receipt_digest": result.ReceiptDigest,
		}),
	}
}

// appendEvent stamps the sequence and appends. The caller holds b.mu.
func (b *Broker) appendEvent(event EvidenceEvent) EvidenceEvent {
	event.Sequence = b.nextSequence(brokerSourceID)
	b.events = append(b.events, event)
	return event
}

// nextSequence advances the per-source counter. The caller holds b.mu.
func (b *Broker) nextSequence(source string) int64 {
	b.sequences[source]++
	return b.sequences[source]
}

func (b *Broker) mintEventID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return mintEventIDSoon()
}

var brokerSourceID = "src_broker-effect-broker"

// mintNonce mints a single-use permit nonce (spec 10).
func mintNonce() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(raw)
}

func mintEventIDSoon() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "evt_" + hex.EncodeToString(raw)
}

func cloneEffect(effect *Effect) *Effect {
	duplicate := *effect
	duplicate.Transitions = append([]Transition(nil), effect.Transitions...)
	if effect.Authorization != nil {
		permit := *effect.Authorization
		if effect.Authorization.AmountLimit != nil {
			amount := *effect.Authorization.AmountLimit
			permit.AmountLimit = &amount
		}
		if effect.Authorization.SizeLimit != nil {
			ceiling := *effect.Authorization.SizeLimit
			permit.SizeLimit = &ceiling
		}
		duplicate.Authorization = &permit
	}
	if effect.Review != nil {
		review := *effect.Review
		review.PolicyRefs = append([]string(nil), effect.Review.PolicyRefs...)
		review.EventRefs = append([]string(nil), effect.Review.EventRefs...)
		duplicate.Review = &review
	}
	if effect.Dispatch != nil {
		dispatch := *effect.Dispatch
		duplicate.Dispatch = &dispatch
	}
	if effect.Receipt != nil {
		receipt := *effect.Receipt
		duplicate.Receipt = &receipt
	}
	return &duplicate
}

// TransitionError reports a lifecycle refusal.
type TransitionError struct {
	EffectID string
	From     string
	Why      string
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("effect %s: %s", e.EffectID, e.Why)
}

// errNotFound is the tenant-safe miss.
var errNotFound = fmt.Errorf("effect not found")

// errEffectExists refuses a re-proposal under an id that already has
// a lifecycle (append-only, spec 18.1).
var errEffectExists = fmt.Errorf("effect id already has a record")

// errIdempotencyConflict and errIdempotencyPending distinguish the
// two reservation failures (spec 18.3).
var (
	errIdempotencyConflict = fmt.Errorf("idempotency key reused with a different body")
	errIdempotencyPending  = fmt.Errorf("idempotency key still executing; retry")
)
