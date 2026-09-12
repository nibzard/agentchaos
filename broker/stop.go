package broker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
)

// Terminal states of the stop protocol (spec 13.3). Never inferred from
// worker exit: the state arrives only from cleanup verification.
const (
	TerminalClean   = "CLEAN"
	TerminalDirty   = "DIRTY_QUARANTINED"
	TerminalUnknown = "UNKNOWN"
)

// Sandbox dispositions (spec 13.3): terminate or preserve according to
// evidence policy. The order must state one; there is no default.
const (
	SandboxTerminate = "terminate"
	SandboxPreserve  = "preserve"
)

// Protocol step names, in spec 13.3's order. They mirror the governor's
// stop handoff so a report answers a handoff step by step.
const (
	StepRevokePermits    = "revoke_new_effect_permits"
	StepDisableInjectors = "disable_injectors"
	StepFenceDelegations = "fence_delegation_group"
	StepCancelPending    = "cancel_pending_effects"
	StepIdentifyUnknown  = "identify_inflight_and_unknown_effects"
	StepReconcile        = "reconcile_service_receipts"
	StepCompensate       = "execute_preapproved_compensation"
	StepSandbox          = "terminate_or_preserve_sandbox"
	StepCleanupVerifier  = "run_independent_cleanup_verifier"
	StepTerminalState    = "record_terminal_state"
)

// Step statuses in a stop report: done, or partial when the step could
// not complete for every effect it touched.
const (
	StepDone    = "done"
	StepPartial = "partial"
)

// StopOrder is the stop controller's input (spec 13.3). The governor
// ends experiment authority and emits a stop handoff; the controller —
// here, the broker, which already holds the permits, effects, and
// delegations — executes the protocol. The handoff id is an advisory
// cross-reference: the broker never depends on the governor to stop.
type StopOrder struct {
	RunID         string
	HandoffID     string
	Reason        string
	Sandbox       string // terminate | preserve
	Compensations []CompensationPlan
}

// CompensationPlan is one preapproved compensation (spec 13.3): a
// mutating effect that references a committed original. Plans come from
// the control plane; a worker never writes them.
type CompensationPlan struct {
	EffectID        string `json:"effect_id"`
	Operation       string `json:"operation"`
	Resource        string `json:"resource"`
	Destination     string `json:"destination"`
	ArgumentsDigest string `json:"arguments_digest"`
	ActionClass     string `json:"action_class"`
	SizeBytes       int64  `json:"size_bytes,omitempty"`
}

// CompensationOutcome records what one plan did.
type CompensationOutcome struct {
	Plan     CompensationPlan `json:"plan"`
	EffectID string           `json:"effect_id,omitempty"` // the minted compensating effect
	Outcome  string           `json:"outcome"`             // COMMITTED | CANCELLED | UNKNOWN_EFFECT | DENIED | ERROR
	Detail   string           `json:"detail,omitempty"`
}

// ReportStep is one executed protocol step.
type ReportStep struct {
	Name   string `json:"name"`
	Status string `json:"status"` // done | partial
	Detail string `json:"detail,omitempty"`
}

// EffectSummary carries what cleanup verification needs about one
// effect: where it pointed, so a dirty artifact can be named.
type EffectSummary struct {
	ID          string `json:"id"`
	ActionClass string `json:"action_class"`
	Operation   string `json:"operation"`
	Resource    string `json:"resource"`
	Destination string `json:"destination"`
}

// EffectInventory categorizes the run's effects at the end of the
// protocol. Compensating effects (which carry compensation_of) sit in
// their own bucket; every other bucket holds resting lifecycle states.
type EffectInventory struct {
	Denied        []string        `json:"denied"`
	Authorized    []string        `json:"authorized"`
	Prepared      []string        `json:"prepared"`
	Committing    []string        `json:"committing"`
	Committed     []string        `json:"committed"`
	Cancelled     []string        `json:"cancelled"`
	Unknown       []string        `json:"unknown"`
	Compensations []string        `json:"compensations"`
	CommittedMeta []EffectSummary `json:"committed_meta"`
}

// StopReport is the stop protocol's execution record (spec 13.3). The
// report is append-only per run: a second stop replays it. Reopened
// marks that a late event changed an effect after the terminal state
// was recorded — prior assurance is stale.
type StopReport struct {
	Kind              string                `json:"kind"` // StopReport
	APIVersion        string                `json:"api_version"`
	ID                string                `json:"id"`
	TenantID          string                `json:"tenant_id"`
	RunID             string                `json:"run_id"`
	HandoffID         string                `json:"handoff_id,omitempty"`
	Reason            string                `json:"reason,omitempty"`
	InjectionDisabled bool                  `json:"injection_disabled"`
	Sandbox           string                `json:"sandbox"`
	Steps             []ReportStep          `json:"steps"`
	Inventory         EffectInventory       `json:"inventory"`
	Compensations     []CompensationOutcome `json:"compensations,omitempty"`
	Quarantined       []string              `json:"quarantined,omitempty"`
	Verifier          string                `json:"verifier"`
	TerminalState     string                `json:"terminal_state"`
	Reopened          bool                  `json:"reopened"`
	StoppedAt         string                `json:"stopped_at"`
}

// CleanupVerdict is the verifier's answer.
type CleanupVerdict struct {
	State  string   // CLEAN | DIRTY_QUARANTINED | UNKNOWN
	Dirty  []string // dirty artifacts, as resource@destination
	Detail string
}

// CleanupVerifier independently verifies cleanup (spec 13.3). It runs
// outside the worker environment. The default derives its verdict from
// broker records; a deployment can inject one that checks the actual
// environment. A verifier can only make the verdict worse than the
// records floor — never cleaner.
type CleanupVerifier interface {
	Name() string
	Verify(report *StopReport) CleanupVerdict
}

// RecordsVerifier is the default verifier: it reads the report's
// inventory. Unresolved effects mean the outcome cannot be verified;
// a committed, uncompensated mutating effect means dirt.
type RecordsVerifier struct{}

// Name identifies the verifier in the report.
func (RecordsVerifier) Name() string { return "broker-records" }

// Verify derives the verdict from the recorded lifecycle states.
func (RecordsVerifier) Verify(report *StopReport) CleanupVerdict {
	unresolved := append(append(append(append([]string{},
		report.Inventory.Unknown...),
		report.Inventory.Committing...),
		report.Inventory.Authorized...),
		report.Inventory.Prepared...)
	if len(unresolved) > 0 {
		return CleanupVerdict{State: TerminalUnknown, Detail: fmt.Sprintf(
			"%d effect(s) rest unresolved: an unknown outcome cannot be verified", len(unresolved))}
	}
	compensated := make(map[string]bool, len(report.Compensations))
	for _, outcome := range report.Compensations {
		compensated[outcome.Plan.EffectID] = outcome.Outcome == StateCommitted
	}
	var dirty []string
	for _, meta := range report.Inventory.CommittedMeta {
		if meta.ActionClass == ClassA2 && !compensated[meta.ID] {
			dirty = append(dirty, meta.Resource+"@"+meta.Destination)
		}
	}
	if len(dirty) > 0 {
		return CleanupVerdict{State: TerminalDirty, Dirty: dirty, Detail: fmt.Sprintf(
			"%d committed mutating effect(s) have no completed compensation", len(dirty))}
	}
	return CleanupVerdict{State: TerminalClean, Detail: "nothing dispatched or everything resolved"}
}

// terminalSeverity orders the merge lattice: a worse verdict wins, and
// UNKNOWN (cannot verify) outranks DIRTY (verified dirty).
func terminalSeverity(state string) int {
	switch state {
	case TerminalClean:
		return 0
	case TerminalDirty:
		return 1
	default:
		return 2
	}
}

// StopRefusal reports stop-order contract violations.
type StopRefusal struct {
	Errors []ContractError
}

func (r *StopRefusal) Error() string {
	if len(r.Errors) == 0 {
		return "stop order refused"
	}
	return fmt.Sprintf("stop order refused: %s: %s", r.Errors[0].Check, r.Errors[0].Detail)
}

// ValidateStopOrder checks the order's shapes. The sandbox disposition
// is an evidence-policy decision, so it must be stated, never defaulted.
func (o *StopOrder) ValidateStopOrder() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if !reRunID.MatchString(o.RunID) {
		add("run_id", "$.run_id", "must match run_[a-z0-9]{8,64}")
	}
	if o.Sandbox != SandboxTerminate && o.Sandbox != SandboxPreserve {
		add("sandbox", "$.sandbox", "must be terminate or preserve; there is no default")
	}
	if o.HandoffID != "" && !matches(`^sgh_[a-z0-9]{8,64}$`, o.HandoffID) {
		add("handoff_id", "$.handoff_id", "must match sgh_[a-z0-9]{8,64}")
	}
	if len(o.Reason) > MaxRevocationReason {
		add("reason", "$.reason", "reason exceeds 512 characters")
	}
	seen := make(map[string]bool, len(o.Compensations))
	for i, plan := range o.Compensations {
		path := fmt.Sprintf("$.compensations[%d]", i)
		if !reEffectID.MatchString(plan.EffectID) {
			add("effect_id", path+".effect_id", "must match eff_[a-z0-9]{8,64}")
		}
		if seen[plan.EffectID] {
			add("effect_id", path+".effect_id", "one compensation per effect")
		}
		seen[plan.EffectID] = true
		if !reOperation.MatchString(plan.Operation) {
			add("operation", path+".operation", "must match the operation pattern")
		}
		if !reResource.MatchString(plan.Resource) {
			add("resource", path+".resource", "must match the resource pattern")
		}
		if !matches(`^(https?://|sink:)[A-Za-z0-9._:/-]{3,252}$`, plan.Destination) {
			add("destination", path+".destination", "must be an http(s) URL or a sink: destination")
		}
		if !reDigest.MatchString(plan.ArgumentsDigest) {
			add("arguments_digest", path+".arguments_digest",
				"must be sha256: plus 64 lowercase hex characters")
		}
		switch plan.ActionClass {
		case ClassA1, ClassA2:
		default:
			add("action_class", path+".action_class", "must be A1 or A2")
		}
		if plan.SizeBytes < 0 {
			add("size_bytes", path+".size_bytes", "must not be negative")
		}
	}
	return errs
}

// Stop executes the stop protocol (spec 13.3). Steps run in the spec's
// order; every state change lands in the append-only lifecycle and the
// evidence journal. The protocol is idempotent per run: a second stop
// replays the recorded report. Workers cannot order a stop.
func (b *Broker) Stop(principal *Principal, order *StopOrder) (*StopReport, error) {
	if err := b.CheckAuthority(principal); err != nil {
		return nil, err
	}
	if principal.TenantID == "" {
		return nil, fmt.Errorf("unauthenticated caller cannot stop")
	}
	if problems := order.ValidateStopOrder(); len(problems) > 0 {
		return nil, &StopRefusal{Errors: problems}
	}
	scopedRun := effectKey(principal.TenantID, order.RunID)

	b.mu.Lock()
	if existing := b.stops[scopedRun]; existing != nil {
		b.mu.Unlock()
		return cloneStopReport(existing), nil
	}
	run := b.runs[order.RunID]
	if run == nil || run.TenantID != principal.TenantID {
		b.mu.Unlock()
		return nil, errStopRunUnknown
	}

	// Step 1: revoke new effect permits. The stop record's presence is
	// the fence — authorize denies every non-compensation proposal and
	// dispatch cancels pre-stop permits. Recording it first means the
	// protocol's own sink calls are the only traffic left.
	report := &StopReport{
		Kind:              "StopReport",
		APIVersion:        "v1",
		ID:                mintStopID(),
		TenantID:          principal.TenantID,
		RunID:             order.RunID,
		HandoffID:         order.HandoffID,
		Reason:            truncateStopReason(order.Reason),
		InjectionDisabled: true,
		Sandbox:           order.Sandbox,
		StoppedAt:         b.ClockUTC(),
	}
	b.stops[scopedRun] = report
	b.stopEventLocked(report, "stop_ordered", map[string]any{
		"handoff_id": order.HandoffID,
	})

	// Step 2: disable injectors. The broker records the order and mints
	// no further permits for this run; injector teardown itself happens
	// in the execution plane, which reads this report.
	b.stopEventLocked(report, "disable_injectors", map[string]any{
		"ordered": true,
	})

	// Step 3: fence the affected delegation groups. Every active
	// delegation of the run revokes; a revoked group fences permits
	// already minted under it (AC-008).
	fenced := []string{}
	for _, delegation := range b.delegations {
		if delegation.TenantID == principal.TenantID && delegation.RunID == order.RunID &&
			delegation.State == DelegationActive {
			b.revokeLocked(delegation, "stop protocol fenced the delegation group")
			fenced = append(fenced, delegation.ID)
		}
	}
	sort.Strings(fenced)

	// Snapshot the run's effect records; they mutate below.
	effects := make([]*Effect, 0, 8)
	for _, effect := range b.effects {
		if effect.TenantID == principal.TenantID && effect.RunID == order.RunID {
			effects = append(effects, effect)
		}
	}
	b.mu.Unlock()

	// Step 4 (first pass): cancel pending effects that support
	// cancellation. AUTHORIZED never staged and never sent, so it
	// cancels outright. PREPARED holds a staged write, so it needs the
	// sink to drop the stage; that runs below with the lock released.
	// Step 5: identify in-flight and unknown effects — a dispatch that
	// was initiated but never recorded cannot be called off; its
	// outcome is unknown and reconciliation owns it.
	var prepared []*Effect
	cancelled := []string{}
	inflight := []string{}
	b.mu.Lock()
	for _, effect := range effects {
		switch effect.State {
		case StateAuthorized:
			b.transitionTo(effect, StateCancelled, b.ClockUTC())
			cancelled = append(cancelled, effect.ID)
		case StatePrepared:
			prepared = append(prepared, effect)
		case StateCommitting, StateCompensating:
			b.transitionTo(effect, StateUnknown, b.ClockUTC())
			inflight = append(inflight, effect.ID)
		}
	}
	sort.Strings(cancelled)
	sort.Strings(inflight)
	b.stopEventLocked(report, "cancel_pending_effects", map[string]any{
		"cancelled": cancelled,
	})
	b.stopEventLocked(report, "identify_inflight_and_unknown_effects", map[string]any{
		"moved_to_unknown": inflight,
		"prepared_pending": len(prepared),
	})
	b.mu.Unlock()

	// PREPARED cancellation through sinks that support it. A sink
	// without cancellation leaves the effect unknown: a staged write
	// may exist, and the fail-closed answer is never "clean".
	for _, effect := range prepared {
		b.cancelPrepared(principal.TenantID, effect)
	}

	// Step 6: reconcile service receipts. Every resting unknown gets a
	// state read through the sink that owns its destination; a read
	// that resolves appends the receipt, one that does not leaves the
	// state standing.
	unknown := b.unknownEffects(principal.TenantID, order.RunID)
	resolved, unresolved := b.reconcileAll(principal.TenantID, unknown)
	b.mu.Lock()
	b.stopEventLocked(report, "reconcile_service_receipts", map[string]any{
		"read":       len(unknown),
		"resolved":   resolved,
		"unresolved": unresolved,
	})
	b.mu.Unlock()

	// Step 7: execute preapproved compensation where safe. Compensations
	// authorize and dispatch under the stop protocol's own bounded
	// window — the run's experiment grant has usually ended — and only
	// against committed originals.
	outcomes := make([]CompensationOutcome, 0, len(order.Compensations))
	for _, plan := range order.Compensations {
		outcomes = append(outcomes, b.compensate(principal, order, plan))
	}

	// Step 8: the sandbox disposition is ordered, not executed here:
	// the runner terminates or preserves the sandbox according to
	// evidence policy and this order.
	// Step 9: run the independent cleanup verifier. The verdict merges
	// with a records-derived floor; the worse verdict wins, so an
	// injected verifier can never certify cleaner than the records.
	verifier := b.verifier
	if verifier == nil {
		verifier = RecordsVerifier{}
	}
	b.mu.Lock()
	report.Inventory = b.inventoryLocked(principal.TenantID, order.RunID)
	report.Compensations = outcomes
	b.stopEventLocked(report, "terminate_or_preserve_sandbox", map[string]any{
		"disposition": order.Sandbox,
	})
	b.mu.Unlock()

	verdict := verifier.Verify(cloneStopReport(report))
	floor := RecordsVerifier{}.Verify(cloneStopReport(report))
	final := floor.State
	if terminalSeverity(verdict.State) > terminalSeverity(final) {
		final = verdict.State
	}
	dirty := verdict.Dirty
	for _, meta := range floor.Dirty {
		dirty = append(dirty, meta)
	}

	// Step 10: record the terminal state. Quarantined artifacts enter
	// the tenant registry: a dirty resource cannot be reassigned to a
	// new experiment (spec 13.3).
	b.mu.Lock()
	dirtySet := make(map[string]bool, len(dirty))
	unique := make([]string, 0, len(dirty))
	for _, artifact := range dirty {
		if !dirtySet[artifact] {
			dirtySet[artifact] = true
			unique = append(unique, artifact)
		}
	}
	sort.Strings(unique)
	if len(unique) > 0 {
		if b.quarantine == nil {
			b.quarantine = make(map[string]map[string]bool)
		}
		registry := b.quarantine[principal.TenantID]
		if registry == nil {
			registry = make(map[string]bool)
			b.quarantine[principal.TenantID] = registry
		}
		for _, artifact := range unique {
			registry[artifact] = true
		}
	}
	report.Quarantined = unique
	report.Verifier = verifier.Name()
	report.TerminalState = final
	preparedIDs := make([]string, 0, len(prepared))
	for _, effect := range prepared {
		preparedIDs = append(preparedIDs, effect.ID)
	}
	report.Steps = protocolSteps(report, order, cancelled, inflight, preparedIDs, outcomes, verdict)
	b.stopEventLocked(report, "record_terminal_state", map[string]any{
		"terminal_state": final,
		"quarantined":    len(unique),
		"reopened":       false,
	})
	b.mu.Unlock()
	return cloneStopReport(report), nil
}

// protocolSteps assembles the ten report steps in spec 13.3 order.
func protocolSteps(report *StopReport, order *StopOrder, cancelled, inflight, prepared []string,
	outcomes []CompensationOutcome, verdict CleanupVerdict) []ReportStep {
	cancelStatus, cancelDetail := StepDone,
		fmt.Sprintf("%d authorized effect(s) cancelled; %d prepared await sink cancellation",
			len(cancelled), len(prepared))
	if len(prepared) > 0 {
		cancelStatus = StepPartial
	}
	reconcileStatus, reconcileDetail := StepDone,
		fmt.Sprintf("%d unknown effect(s) remain after reconciliation", countUnresolved(report))
	if countUnresolved(report) > 0 {
		reconcileStatus = StepPartial
	}
	compensateStatus, compensateDetail := StepDone, fmt.Sprintf("%d plan(s)", len(outcomes))
	for _, outcome := range outcomes {
		if outcome.Outcome != StateCommitted {
			compensateStatus = StepPartial
			compensateDetail = fmt.Sprintf("plan for %s ended %s",
				outcome.Plan.EffectID, outcome.Outcome)
		}
	}
	return []ReportStep{
		{Name: StepRevokePermits, Status: StepDone,
			Detail: "the stop record fences the run: new proposals deny and pre-stop permits cancel at dispatch"},
		{Name: StepDisableInjectors, Status: StepDone,
			Detail: "disablement ordered; the execution plane tears injectors down and the broker mints no further permits"},
		{Name: StepFenceDelegations, Status: StepDone,
			Detail: "every active delegation group of the run is revoked"},
		{Name: StepCancelPending, Status: cancelStatus, Detail: cancelDetail},
		{Name: StepIdentifyUnknown, Status: StepDone,
			Detail: fmt.Sprintf("%d in-flight dispatch(es) moved to unknown", len(inflight))},
		{Name: StepReconcile, Status: reconcileStatus, Detail: reconcileDetail},
		{Name: StepCompensate, Status: compensateStatus, Detail: compensateDetail},
		{Name: StepSandbox, Status: StepDone, Detail: "disposition ordered: " + order.Sandbox},
		{Name: StepCleanupVerifier, Status: StepDone,
			Detail: verdict.State + " from the cleanup verifier"},
		{Name: StepTerminalState, Status: StepDone, Detail: report.TerminalState},
	}
}

func countUnresolved(report *StopReport) int {
	return len(report.Inventory.Unknown)
}

// cancelPrepared cancels one PREPARED effect through its sink (spec
// 13.3: cancel pending effects that support cancellation). A sink
// without cancellation, or a cancel that cannot be confirmed, leaves
// the effect unknown — a staged write may exist. A busy dispatch gate
// means an operation is running on this record right now; the stop
// leaves it alone rather than wait on a hung sink, and the late
// completion reopens the report.
func (b *Broker) cancelPrepared(tenantID string, effect *Effect) {
	gate := b.dispatchGate(effectKey(tenantID, effect.ID))
	if !gate.TryLock() {
		return
	}
	defer gate.Unlock()

	b.mu.Lock()
	if effect.State != StatePrepared {
		b.mu.Unlock()
		return // a racing commit settled this record first
	}
	sink := b.sinkFor(effect.ProposedAction.Destination)
	canceller, ok := sink.(CancellingSink)
	if !ok {
		b.transitionTo(effect, StateUnknown, b.ClockUTC())
		b.stopEventLocked(&StopReport{TenantID: tenantID, RunID: effect.RunID},
			"cancel_pending_effects", map[string]any{
				"effect_id": effect.ID, "outcome": "unsupported",
				"detail": "destination supports no cancellation; the stage may exist",
			})
		b.mu.Unlock()
		return
	}
	reading := cloneEffect(effect)
	b.mu.Unlock()

	// The sink call runs with b.mu released, exactly like dispatch:
	// a slow destination fences only its own effect (spec 10.2).
	result := canceller.Cancel(reading, b.ClockUTC())

	b.mu.Lock()
	defer b.mu.Unlock()
	if effect.State != StatePrepared {
		return
	}
	switch result.Outcome {
	case OutcomeAcknowledged:
		b.transitionTo(effect, StateCancelled, b.ClockUTC())
	default:
		// A refused or unresolved cancel cannot claim the stage is gone.
		b.transitionTo(effect, StateUnknown, b.ClockUTC())
	}
	b.stopEventLocked(&StopReport{TenantID: tenantID, RunID: effect.RunID},
		"cancel_pending_effects", map[string]any{
			"effect_id": effect.ID, "outcome": result.Outcome,
		})
}

// unknownEffects collects the run's resting unknown effect ids.
func (b *Broker) unknownEffects(tenantID, runID string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	unknown := []string{}
	for _, effect := range b.effects {
		if effect.TenantID == tenantID && effect.RunID == runID && effect.State == StateUnknown {
			unknown = append(unknown, effect.ID)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// reconcileAll performs one reconciliation state read per unknown
// effect, serialized per effect exactly like a commit-driven read.
// An effect whose gate is busy is mid-dispatch or mid-read right now;
// the stop counts it unresolved instead of blocking on a hung sink —
// a slow sink fences only its own effect, never the stop protocol
// (spec 10.2).
func (b *Broker) reconcileAll(tenantID string, unknown []string) (resolved, unresolved int) {
	for _, effectID := range unknown {
		gate := b.dispatchGate(effectKey(tenantID, effectID))
		if !gate.TryLock() {
			unresolved++
			continue
		}
		b.mu.Lock()
		effect, ok := b.effects[effectKey(tenantID, effectID)]
		if !ok || effect.State != StateUnknown {
			b.mu.Unlock()
			gate.Unlock()
			continue
		}
		updated, err := b.reconcileLocked(effect, b.ClockUTC())
		b.mu.Unlock()
		gate.Unlock()
		if err != nil || updated == nil || updated.State == StateUnknown {
			unresolved++
			continue
		}
		resolved++
	}
	return resolved, unresolved
}

// compensate executes one preapproved compensation plan. The plan must
// reference a committed effect of this run; the proposal passes the
// deterministic gate like any other, and dispatch is a normal two-phase
// send. Anything less than a committed compensation counts as dirt.
func (b *Broker) compensate(principal *Principal, order *StopOrder,
	plan CompensationPlan) CompensationOutcome {
	outcome := CompensationOutcome{Plan: plan}
	b.mu.Lock()
	target, ok := b.effects[effectKey(principal.TenantID, plan.EffectID)]
	b.mu.Unlock()
	if !ok || target.RunID != order.RunID || target.State != StateCommitted {
		outcome.Outcome = "DENIED"
		outcome.Detail = "compensation target is not a committed effect of this run"
		return outcome
	}
	now := b.ClockUTC()
	proposal := &Effect{
		Kind:        "Effect",
		APIVersion:  "v1",
		ID:          mintCompensationID(),
		TenantID:    principal.TenantID,
		RunID:       order.RunID,
		Actor:       principal.ID,
		ActionClass: plan.ActionClass,
		ProposedAction: ProposedAction{
			Operation:       plan.Operation,
			Resource:        plan.Resource,
			Destination:     plan.Destination,
			ArgumentsDigest: plan.ArgumentsDigest,
			SizeBytes:       plan.SizeBytes,
		},
		CompensationOf: plan.EffectID,
		State:          StateProposed,
		Transitions:    []Transition{{State: StateProposed, At: now}},
		CreatedAt:      now,
	}
	effect, decision, err := b.Authorize(principal, proposal)
	if err != nil {
		outcome.Outcome = "ERROR"
		outcome.Detail = err.Error()
		return outcome
	}
	if decision.Verdict != "allow" {
		outcome.Outcome = "DENIED"
		outcome.Detail = "gate denied the plan: " + decision.Reason
		return outcome
	}
	outcome.EffectID = effect.ID
	committed, err := b.Commit(principal, effect.ID, "idk_stop-"+hex.EncodeToString(mintBytes(6)))
	if err != nil {
		outcome.Outcome = "ERROR"
		outcome.Detail = err.Error()
		return outcome
	}
	outcome.Outcome = committed.State
	return outcome
}

// inventoryLocked categorizes the run's effects after the protocol ran.
// The caller holds b.mu.
func (b *Broker) inventoryLocked(tenantID, runID string) EffectInventory {
	empty := func() []string { return []string{} }
	inventory := EffectInventory{
		Denied:        empty(),
		Authorized:    empty(),
		Prepared:      empty(),
		Committing:    empty(),
		Committed:     empty(),
		Cancelled:     empty(),
		Unknown:       empty(),
		Compensations: empty(),
		CommittedMeta: []EffectSummary{}, // empty array, never null
	}
	for _, effect := range b.effects {
		if effect.TenantID != tenantID || effect.RunID != runID {
			continue
		}
		if effect.CompensationOf != "" {
			inventory.Compensations = append(inventory.Compensations, effect.ID)
			continue
		}
		switch effect.State {
		case StateDenied:
			inventory.Denied = append(inventory.Denied, effect.ID)
		case StateAuthorized:
			inventory.Authorized = append(inventory.Authorized, effect.ID)
		case StatePrepared:
			inventory.Prepared = append(inventory.Prepared, effect.ID)
		case StateCommitting, StateCompensating:
			inventory.Committing = append(inventory.Committing, effect.ID)
		case StateCommitted:
			inventory.Committed = append(inventory.Committed, effect.ID)
			inventory.CommittedMeta = append(inventory.CommittedMeta, EffectSummary{
				ID:          effect.ID,
				ActionClass: effect.ActionClass,
				Operation:   effect.ProposedAction.Operation,
				Resource:    effect.ProposedAction.Resource,
				Destination: effect.ProposedAction.Destination,
			})
		case StateCancelled, StateExpired:
			inventory.Cancelled = append(inventory.Cancelled, effect.ID)
		case StateUnknown:
			inventory.Unknown = append(inventory.Unknown, effect.ID)
		}
	}
	for _, bucket := range []*[]string{&inventory.Denied, &inventory.Authorized,
		&inventory.Prepared, &inventory.Committing, &inventory.Committed,
		&inventory.Cancelled, &inventory.Unknown, &inventory.Compensations} {
		sort.Strings(*bucket)
	}
	return inventory
}

// stopEventLocked journals one stop-protocol action as a recovery
// event (spec 9.4's closed kind set). The caller holds b.mu.
func (b *Broker) stopEventLocked(report *StopReport, action string, fields map[string]any) {
	payload := map[string]any{"action": action}
	for key, value := range fields {
		payload[key] = value
	}
	b.appendEvent(EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         mintEventIDSoon(),
		TenantID:   report.TenantID,
		RunID:      report.RunID,
		EventKind:  "recovery_action",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		ObservedAt: b.ClockUTC(),
		Payload:    inlinePayload(payload),
	})
}

// reopenIfStoppedLocked marks a stopped run's report reopened when an
// effect changes after its terminal state was recorded (spec 13.3:
// late events reopen the result and mark prior assurance stale). The
// original terminal state stands; the reopened flag is the staleness
// marker. The caller holds b.mu.
func (b *Broker) reopenIfStoppedLocked(effect *Effect) {
	report := b.stops[effectKey(effect.TenantID, effect.RunID)]
	if report == nil || report.TerminalState == "" || report.Reopened {
		return
	}
	report.Reopened = true
	b.stopEventLocked(report, "stop_reopened", map[string]any{
		"effect_id":      effect.ID,
		"terminal_state": report.TerminalState,
		"detail":         "a late event changed an effect after the terminal state; prior assurance is stale",
	})
}

// StopRecord returns a run's stop report. Any authenticated principal
// of the tenant may read it; a worker that asks must see it is stopped.
func (b *Broker) StopRecord(principal *Principal, runID string) (*StopReport, error) {
	if principal == nil {
		return nil, fmt.Errorf("unauthenticated caller cannot read a stop report")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	report := b.stops[effectKey(principal.TenantID, runID)]
	if report == nil {
		return nil, errStopRunUnknown
	}
	return cloneStopReport(report), nil
}

// Quarantined lists the tenant's dirty artifacts (resource@destination).
// A quarantined artifact cannot be reassigned to a new experiment.
func (b *Broker) Quarantined(principal *Principal) []string {
	if principal == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.quarantine[principal.TenantID]))
	for artifact := range b.quarantine[principal.TenantID] {
		out = append(out, artifact)
	}
	sort.Strings(out)
	return out
}

// quarantinedArtifact reports whether a proposal's resource@destination
// is quarantined for the tenant. The caller holds b.mu.
func (b *Broker) quarantinedArtifact(tenantID string, action ProposedAction) bool {
	registry := b.quarantine[tenantID]
	if registry == nil {
		return false
	}
	return registry[action.Resource+"@"+action.Destination]
}

// CancellingSink can cancel a prepared (staged) or pending effect at
// the destination service (spec 13.3: cancel pending effects that
// support cancellation). Sinks without it leave prepared effects
// unknown, never clean.
type CancellingSink interface {
	// Cancel asks the destination service to drop the staged write.
	Cancel(effect *Effect, now string) SinkResult
}

var (
	errStopRunUnknown = fmt.Errorf("no such run in the caller's tenant")
)

func mintStopID() string {
	return "sgr_" + hex.EncodeToString(mintBytes(8))
}

func mintCompensationID() string {
	return "eff_stop" + hex.EncodeToString(mintBytes(5))
}

func mintBytes(n int) []byte {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return raw
}

func truncateStopReason(reason string) string {
	if len(reason) > MaxRevocationReason {
		return reason[:MaxRevocationReason]
	}
	return reason
}

// cloneStopReport copies a report so callers never share stored state.
func cloneStopReport(report *StopReport) *StopReport {
	duplicate := *report
	duplicate.Steps = append([]ReportStep{}, report.Steps...)
	duplicate.Quarantined = append([]string{}, report.Quarantined...)
	duplicate.Compensations = append([]CompensationOutcome{}, report.Compensations...)
	inventory := report.Inventory
	inventory.Denied = append([]string{}, report.Inventory.Denied...)
	inventory.Authorized = append([]string{}, report.Inventory.Authorized...)
	inventory.Prepared = append([]string{}, report.Inventory.Prepared...)
	inventory.Committing = append([]string{}, report.Inventory.Committing...)
	inventory.Committed = append([]string{}, report.Inventory.Committed...)
	inventory.Cancelled = append([]string{}, report.Inventory.Cancelled...)
	inventory.Unknown = append([]string{}, report.Inventory.Unknown...)
	inventory.Compensations = append([]string{}, report.Inventory.Compensations...)
	inventory.CommittedMeta = append([]EffectSummary{}, report.Inventory.CommittedMeta...)
	duplicate.Inventory = inventory
	return &duplicate
}
