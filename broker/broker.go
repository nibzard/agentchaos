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

// PreparingSink is a sink whose service supports transactional
// preparation or conditional writes (spec 10.1). Sinks without it
// dispatch directly from AUTHORIZED; that limitation is declared in
// the dispatch evidence instead of silently skipping the stage.
type PreparingSink interface {
	// Prepare stages the write without sending it.
	Prepare(effect *Effect, now string) SinkResult
}

// Reconcile outcomes for a state read on an unknown dispatch.
const (
	ReconciledCommitted = "committed" // the send took effect
	ReconciledNoEffect  = "no_effect" // the send never happened
	ReconciledUnknown   = "unknown"   // still unresolved
)

// ReconcilingSink supports a state read that resolves an unknown
// dispatch outcome (spec 10.1: reconcile before any retry).
type ReconcilingSink interface {
	// Reconcile reads the service's own state for the effect.
	Reconcile(effect *Effect, now string) ReconcileResult
}

// ReconcileResult is what a reconciling sink reports back.
type ReconcileResult struct {
	Outcome       string // committed | no_effect | unknown
	ReceiptDigest string
	Detail        string
}

// allowedTransitions is the spec 10.1 lifecycle: the happy path
// PROPOSED -> AUTHORIZED -> PREPARED -> COMMITTING -> COMMITTED, with
// exceptional EXPIRED, CANCELLED, UNKNOWN_EFFECT, and COMPENSATING.
// The AUTHORIZED edges to CANCELLED and UNKNOWN_EFFECT cover a failed
// or unresolved preparation, which is part of the dispatch attempt;
// UNKNOWN_EFFECT resolves only through reconciliation; COMPENSATING is
// the dispatch phase of an effect that carries compensation_of.
var allowedTransitions = map[string][]string{
	StateProposed:     {StateDenied, StateAuthorized},
	StateAuthorized:   {StatePrepared, StateCommitting, StateCompensating, StateExpired, StateCancelled, StateUnknown},
	StatePrepared:     {StateCommitting, StateCompensating, StateCancelled, StateExpired, StateUnknown},
	StateCommitting:   {StateCommitted, StateCancelled, StateUnknown},
	StateCompensating: {StateCommitted, StateCancelled, StateUnknown},
	StateUnknown:      {StateCommitted, StateCancelled},
}

// canTransition reports whether the lifecycle allows the edge.
func canTransition(from, to string) bool {
	for _, next := range allowedTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
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
	effects     map[string]*Effect        // by tenant-scoped key
	events      []EvidenceEvent           // append-only journal
	idempotency map[string]idempotentCall // by tenant-scoped key
	sequences   map[string]int64          // per source
	dispatchers map[string]*sync.Mutex    // per-effect dispatch serialization
}

type idempotentCall struct {
	bodyDigest string
	reply      any  // first reply, captured at completion
	settled    bool // exactly one Complete wins; the first reply is authoritative
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
		dispatchers: make(map[string]*sync.Mutex),
	}
}

// dispatchGate serializes dispatch and reconciliation attempts on one
// effect. It is acquired with b.mu NOT held: external sink calls run
// outside the broker lock, so a slow or hung sink fences only its own
// effect, never the journal, the ledger, or other tenants (spec 10.2).
func (b *Broker) dispatchGate(scoped string) *sync.Mutex {
	b.mu.Lock()
	defer b.mu.Unlock()
	gate := b.dispatchers[scoped]
	if gate == nil {
		gate = &sync.Mutex{}
		b.dispatchers[scoped] = gate
	}
	return gate
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
	if settled.bodyDigest == bodyDigest && settled.settled {
		return settled.reply, true, nil
	}
	// The first attempt failed and released the key; execute afresh.
	return nil, false, nil
}

// Complete stores the reply for a reserved key and wakes waiters. The
// settled flag closes the ready channel exactly once: a waiter woken
// by Release re-executes without a reservation, so two executors can
// both reach this call, and only the first reply is kept.
func (b *Broker) Complete(tenantID, key, bodyDigest string, reply any) {
	scoped := ledgerKey(tenantID, key)
	b.mu.Lock()
	defer b.mu.Unlock()
	if call, seen := b.idempotency[scoped]; seen && call.bodyDigest == bodyDigest && !call.settled {
		call.reply = reply
		call.settled = true
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
	if call, seen := b.idempotency[scoped]; seen && call.bodyDigest == bodyDigest && !call.settled {
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
// The existence check, the decision journal entry, and the store form
// one critical section: racing proposals under the same effect id
// produce exactly one decision event and one record.
func (b *Broker) Authorize(principal *Principal, proposal *Effect) (*Effect, *BrokerDecision, error) {
	if err := b.checkPrincipal(principal, proposal.TenantID, "authorize"); err != nil {
		return nil, nil, err
	}
	scoped := effectKey(principal.TenantID, proposal.ID)

	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.effects[scoped]; exists {
		// The lifecycle is append-only under one id: a re-proposal
		// must use a fresh effect id (spec 18.1).
		return nil, nil, errEffectExists
	}

	now := b.ClockUTC()
	run := b.runs[proposal.RunID]
	verdict := b.policy.Evaluate(proposal, run, now)

	// A compensating effect is a new authorized effect that references
	// a COMMITTED original (spec 10.1). The reference must resolve
	// within the caller's tenant; anything else fails closed.
	if verdict.Allowed && proposal.CompensationOf != "" {
		targetState := ""
		if target, ok := b.effects[effectKey(principal.TenantID, proposal.CompensationOf)]; ok {
			targetState = target.State
		}
		if targetState != StateCommitted {
			verdict = GateVerdict{
				Reason:     "compensation_target_invalid",
				PolicyRefs: []string{b.policy.ref("effects." + proposal.CompensationOf)},
			}
		}
	}

	decision := &BrokerDecision{
		Verdict:         "deny",
		PolicyRefs:      verdict.PolicyRefs,
		DeterminedAt:    now,
		EvidenceEventID: mintEventIDSoon(),
	}
	effect := cloneEffect(proposal)

	if !verdict.Allowed {
		decision.Reason = verdict.Reason
		effect.State = StateDenied
		effect.Transitions = append(effect.Transitions,
			Transition{State: StateDenied, At: now, Actor: brokerSourceID})
		b.recordLocked(decision, effect, "deny: "+verdict.Reason)
		b.effects[scoped] = effect
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
	b.recordLocked(decision, effect, "allow: deterministic gate passed")
	b.effects[scoped] = effect
	return cloneEffect(effect), decision, nil
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
// Committing an UNKNOWN_EFFECT effect performs a reconciliation state
// read instead of a dispatch: a timeout is never retried blindly
// (AC-010).
func (b *Broker) Commit(principal *Principal, effectID, idemKey string) (*Effect, error) {
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

	// Dispatch attempts on one effect serialize here, not under b.mu:
	// the sink calls below run with the broker lock released.
	gate := b.dispatchGate(effectKey(principal.TenantID, effectID))
	gate.Lock()
	defer gate.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.ClockUTC()
	switch effect.State {
	case StateAuthorized, StatePrepared:
		return b.dispatchLocked(effect, now, idemKey)
	case StateUnknown:
		return b.reconcileLocked(effect, now)
	default:
		return nil, &TransitionError{EffectID: effectID, From: effect.State,
			Why: "only an AUTHORIZED, PREPARED, or UNKNOWN_EFFECT effect can commit"}
	}
}

// dispatchLocked runs the two-phase dispatch. The caller holds b.mu.
func (b *Broker) dispatchLocked(effect *Effect, now, idemKey string) (*Effect, error) {
	permit := effect.Authorization
	if permit == nil {
		return nil, &TransitionError{EffectID: effect.ID, From: effect.State,
			Why: "record carries no permit; it cannot dispatch"}
	}
	if momentAtOrBefore(permit.ExpiresAt, now) {
		b.transitionTo(effect, StateExpired, now)
		return nil, &TransitionError{EffectID: effect.ID, From: StateExpired,
			Why: "authorization expired; propose again"}
	}
	if run := b.runs[effect.RunID]; run != nil && permit.TaskID != run.TaskID {
		// The permit no longer matches the task it was issued under;
		// an inconsistent record never dispatches (spec 10 binding).
		return nil, &TransitionError{EffectID: effect.ID, From: effect.State,
			Why: "permit task binding does not match the run"}
	}

	sink := b.sinkFor(effect.ProposedAction.Destination)
	if sink == nil {
		return nil, &TransitionError{EffectID: effect.ID, From: effect.State,
			Why: "no sink owns destination " + effect.ProposedAction.Destination}
	}

	// Preparation phase (spec 10.1): where the service supports
	// transactional preparation, stage the write before sending. The
	// sink call runs with b.mu released; the per-effect gate already
	// serializes dispatch attempts, so no other writer can touch this
	// record while the lock is down.
	if effect.State == StateAuthorized {
		if preparer, ok := sink.(PreparingSink); ok {
			staged := cloneEffect(effect)
			staged.Dispatch = &Dispatch{IdempotencyKey: idemKey}
			b.mu.Unlock()
			staging := preparer.Prepare(staged, now)
			b.mu.Lock()
			b.appendEvent(stageEvent(effect, sink.Name(), staging, now))
			switch staging.Outcome {
			case OutcomeAcknowledged:
				b.transitionTo(effect, StatePrepared, now)
			case OutcomeFailed:
				// The stage was refused; nothing was sent. The dispatch
				// record still completes: the attempt is history, and the
				// outcome that says "no send took effect" is failed.
				effect.Dispatch = &Dispatch{DispatchedAt: now, Outcome: OutcomeFailed, IdempotencyKey: idemKey}
				b.transitionTo(effect, StateCancelled, now)
				return cloneEffect(effect), nil
			default:
				// The stage request's outcome is unknown: a staged write
				// may exist, so the effect stays unknown, not cancelled.
				effect.Dispatch = &Dispatch{DispatchedAt: now, Outcome: OutcomeTimeout, IdempotencyKey: idemKey}
				effect.Receipt = &Receipt{Source: sink.Name(), ReceivedAt: b.ClockUTC(), Reconciled: false}
				b.transitionTo(effect, StateUnknown, now)
				b.appendEvent(receiptEvent(effect, sink.Name(), staging))
				return cloneEffect(effect), nil
			}
		}
	}

	// Dispatch phase: a compensating effect dispatches as COMPENSATING.
	dispersal := StateCommitting
	if effect.CompensationOf != "" {
		dispersal = StateCompensating
	}
	b.transitionTo(effect, dispersal, now)
	effect.Dispatch = &Dispatch{DispatchedAt: now, Outcome: OutcomeTimeout, IdempotencyKey: idemKey}
	dispatched := cloneEffect(effect)
	b.mu.Unlock()
	result := sink.Dispatch(dispatched, now)
	b.mu.Lock()
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
		b.transitionTo(effect, StateCommitted, b.ClockUTC())
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
		b.transitionTo(effect, StateCancelled, b.ClockUTC())
		b.appendEvent(receiptEvent(effect, sink.Name(), result))
	default:
		// A timeout — or any outcome the broker does not recognize —
		// is an unknown outcome: record it, fence retries behind
		// reconciliation (spec 10.1, AC-010). An unrecognized outcome
		// never claims the send did not happen.
		b.transitionTo(effect, StateUnknown, b.ClockUTC())
		effect.Receipt = &Receipt{
			Source:     sink.Name(),
			ReceivedAt: b.ClockUTC(),
			Reconciled: false,
		}
		b.appendEvent(receiptEvent(effect, sink.Name(), result))
	}
	return cloneEffect(effect), nil
}

// reconcileLocked resolves an UNKNOWN_EFFECT dispatch by reading the
// sink's state (spec 10.1). It never dispatches. The caller holds
// b.mu.
func (b *Broker) reconcileLocked(effect *Effect, now string) (*Effect, error) {
	sink := b.sinkFor(effect.ProposedAction.Destination)
	if sink == nil {
		return nil, &TransitionError{EffectID: effect.ID, From: effect.State,
			Why: "no sink owns destination " + effect.ProposedAction.Destination}
	}
	reconciler, ok := sink.(ReconcilingSink)
	if !ok {
		return nil, &TransitionError{EffectID: effect.ID, From: effect.State,
			Why: "destination supports no state read; reconciliation is manual"}
	}
	// The state read runs with b.mu released; the per-effect gate
	// serializes reconciliation attempts on this record.
	reading := cloneEffect(effect)
	b.mu.Unlock()
	result := reconciler.Reconcile(reading, now)
	b.mu.Lock()
	switch result.Outcome {
	case ReconciledCommitted:
		b.transitionTo(effect, StateCommitted, b.ClockUTC())
		effect.Receipt = &Receipt{
			Source:     sink.Name(),
			ReceivedAt: b.ClockUTC(),
			Reconciled: true,
			Digest:     result.ReceiptDigest,
		}
		event := b.appendEvent(receiptEvent(effect, sink.Name(), SinkResult{
			Outcome:       OutcomeAcknowledged,
			ReceiptDigest: result.ReceiptDigest,
			Detail:        "reconciled: " + result.Detail,
		}))
		effect.Receipt.EvidenceEventID = event.ID
	case ReconciledNoEffect:
		// The state read proves the send never took effect.
		b.transitionTo(effect, StateCancelled, b.ClockUTC())
	default:
		// Still unknown: the state stands, and the attempt is recorded.
	}
	b.appendEvent(reconcileEvent(effect, sink.Name(), result, b.ClockUTC()))
	return cloneEffect(effect), nil
}

// transitionTo appends one append-only lifecycle step (spec 18.1).
// The caller holds b.mu.
func (b *Broker) transitionTo(effect *Effect, state, at string) {
	if effect.State == state || !canTransition(effect.State, state) {
		return // no-op edges never append fabricated history
	}
	effect.State = state
	effect.Transitions = append(effect.Transitions,
		Transition{State: state, At: at, Actor: brokerSourceID})
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

// recordLocked journals the decision event. The caller holds b.mu.
func (b *Broker) recordLocked(decision *BrokerDecision, effect *Effect, rationale string) {
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

// stageEvent records the preparation attempt (spec 10.1 two-phase
// dispatch where the service supports it).
func stageEvent(effect *Effect, source string, staging SinkResult, now string) EvidenceEvent {
	return EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         mintEventIDSoon(),
		TenantID:   effect.TenantID,
		RunID:      effect.RunID,
		EventKind:  "tool_request",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		ObservedAt: now,
		EffectID:   effect.ID,
		Payload: inlinePayload(map[string]any{
			"stage":          "prepare",
			"outcome":        staging.Outcome,
			"detail":         staging.Detail,
			"receipt_digest": staging.ReceiptDigest,
			"source":         source,
		}),
	}
}

// reconcileEvent records a reconciliation state read on an unknown
// dispatch outcome (spec 10.1, AC-010).
func reconcileEvent(effect *Effect, source string, result ReconcileResult, now string) EvidenceEvent {
	return EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         mintEventIDSoon(),
		TenantID:   effect.TenantID,
		RunID:      effect.RunID,
		EventKind:  "recovery_action",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		ObservedAt: now,
		EffectID:   effect.ID,
		Payload: inlinePayload(map[string]any{
			"action":         "reconcile_unknown_effect",
			"reconciled":     result.Outcome,
			"detail":         result.Detail,
			"receipt_digest": result.ReceiptDigest,
			"source":         source,
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
