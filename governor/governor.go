package governor

import (
	"fmt"
	"sync"
	"time"
)

// GrantLeaseTTL is the proposed default grant lease (spec 13.2): ten
// seconds with renewal. A runner that stops heartbeating loses its
// authority within this window, whatever the runner or its model
// provider claims about the time (AC-006).
const GrantLeaseTTL = 10 * time.Second

// Governor is the independent safety governor (spec 13.2). All state
// is append-only where it is evidence, and every time bound is
// measured on the governor's own clock: a runner or model outage can
// delay a heartbeat but never extend a grant (spec 10.2).
type Governor struct {
	now func() time.Time

	mu             sync.Mutex
	envelopes      map[string]*Envelope    // by tenant-scoped experiment key
	runs           map[string]*GovernedRun // by tenant-scoped run key
	tenantFenced   map[string]bool
	tripped        map[string]map[string]bool // run key -> tripped conditions
	handoffs       map[string]*StopHandoff    // by handoff id
	events         []EvidenceEvent
	decisions      []Decision
	sequences      map[string]int64
	eventCounter   int64
	handoffCounter int64
}

// scopedKey scopes an id to a tenant: an id held by one tenant never
// collides with another tenant's (spec 18.3).
func scopedKey(tenantID, id string) string {
	return tenantID + "\x00" + id
}

// New builds a governor. A nil clock falls back to the system clock;
// tests inject a fixed clock so expiry and renewal bounds are
// deterministic.
func New(now func() time.Time) *Governor {
	if now == nil {
		now = time.Now
	}
	return &Governor{
		now:          now,
		envelopes:    make(map[string]*Envelope),
		runs:         make(map[string]*GovernedRun),
		tenantFenced: make(map[string]bool),
		tripped:      make(map[string]map[string]bool),
		handoffs:     make(map[string]*StopHandoff),
		sequences:    make(map[string]int64),
	}
}

// ClockUTC formats the governor clock as contract timestamps. This is
// the only clock a grant ever trusts.
func (g *Governor) ClockUTC() string {
	return g.now().UTC().Format("2006-01-02T15:04:05Z")
}

func (g *Governor) nowUTC() time.Time {
	return g.now().UTC()
}

// refusal is a refused operation with a stable code.
type refusal struct {
	Code   string
	Detail string
}

func (r *refusal) Error() string {
	return fmt.Sprintf("%s: %s", r.Code, r.Detail)
}

func refuse(code, detail string) error {
	return &refusal{Code: code, Detail: detail}
}

// checkRole guards the authority path. Workers never drive the
// governor: a worker cannot register envelopes, start runs, or renew
// grants (spec 18.3).
func checkRole(principal *Principal, action string) error {
	if principal == nil {
		return refuse("unauthenticated", "caller identity headers are required")
	}
	switch principal.Role {
	case RoleService, RoleOperator:
		return nil
	default:
		return refuse("role_forbidden", fmt.Sprintf("role %s cannot %s", principal.Role, action))
	}
}

// RegisterEnvelope records an experiment's safety envelope (spec
// 13.1). Only the control plane does this: service or operator role.
// Registration is append-only — an existing envelope is never replaced,
// and a run can never start without one, so a template cannot widen
// its own envelope.
func (g *Governor) RegisterEnvelope(principal *Principal, envelope *Envelope) (*Envelope, error) {
	if err := checkRole(principal, "register an envelope"); err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	scoped := scopedKey(principal.TenantID, envelope.ExperimentID)
	if _, exists := g.envelopes[scoped]; exists {
		return nil, refuse("envelope_exists", "an envelope for this experiment already exists")
	}
	stored := cloneEnvelope(envelope)
	stored.Kind = "SafetyEnvelope"
	stored.APIVersion = "v1"
	stored.TenantID = principal.TenantID
	stored.RegisteredAt = g.ClockUTC()
	stored.eligible = eligibleSet(stored)
	g.envelopes[scoped] = stored
	g.logLocked(principal.TenantID, envelope.ExperimentID, "envelope_registered",
		"the safety envelope is recorded before any run starts")
	return cloneEnvelope(stored), nil
}

// StartRun issues a run's first grant. The run must name a registered,
// unfenced envelope in the caller's tenant; the tenant must not be
// emergency-fenced; and the experiment's concurrency budget must have
// room. A run holds a concurrency slot while its lease is live: the
// budget caps concurrently granted runs, so a run whose lease lapsed
// without a sweep frees its slot immediately (spec 13.1).
func (g *Governor) StartRun(principal *Principal, runID, experimentID string) (*GovernedRun, error) {
	if err := checkRole(principal, "start a run"); err != nil {
		return nil, err
	}
	if !reRunID.MatchString(runID) {
		return nil, refuse("run_id_invalid", "run id must match run_[a-z0-9]{8,64}")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.runs[scopedKey(principal.TenantID, runID)]; exists {
		return nil, refuse("run_exists", "run id already has a governor record")
	}
	if g.tenantFenced[principal.TenantID] {
		return nil, refuse("tenant_fenced",
			"an emergency stop fenced this tenant; experiment authority is revoked")
	}
	envelope := g.envelopes[scopedKey(principal.TenantID, experimentID)]
	if envelope == nil {
		return nil, refuse("envelope_unknown",
			"no safety envelope is registered for this experiment")
	}
	if envelope.Fenced {
		return nil, refuse("experiment_fenced",
			"the experiment's authority is revoked by an earlier stop")
	}
	now := g.nowUTC()
	granted := int64(0)
	for _, run := range g.runs {
		if run.TenantID == principal.TenantID && run.ExperimentID == experimentID &&
			run.State == RunStateActive && now.Before(parseTime(run.Grant.ExpiresAt)) {
			granted++
		}
	}
	if granted >= envelope.Budgets.MaxConcurrentSessions {
		return nil, refuse("concurrency_exhausted",
			"the experiment's concurrent-session budget is full")
	}

	deadline := now.Add(time.Duration(envelope.Budgets.MaxDurationS) * time.Second)
	run := &GovernedRun{
		RunID:         runID,
		ExperimentID:  experimentID,
		TenantID:      principal.TenantID,
		State:         RunStateActive,
		StartedAt:     g.ClockUTC(),
		SessionSpend:  map[string]int64{},
		SpendCurrency: envelope.Budgets.AggregateCostMax.Currency,
		Grant: Grant{
			RunID:        runID,
			ExperimentID: experimentID,
			Generation:   1,
			IssuedAt:     g.ClockUTC(),
			ExpiresAt:    formatTime(leaseEnd(now, deadline)),
			Deadline:     formatTime(deadline),
		},
	}
	g.runs[scopedKey(principal.TenantID, runID)] = run
	g.logLocked(principal.TenantID, runID, "grant_issued",
		fmt.Sprintf("generation 1 expires at %s", run.Grant.ExpiresAt))
	return cloneRun(run), nil
}

// leaseEnd clamps a new lease to the envelope's duration deadline: a
// renewal never buys time past the budget.
func leaseEnd(now, deadline time.Time) time.Time {
	end := now.Add(GrantLeaseTTL)
	if !deadline.After(end) {
		return deadline
	}
	return end
}

// Heartbeat renews a run's grant lease (spec 13.2). Every check runs
// on the governor's clock, and every claim is treated fail-closed:
// spend claims only ever raise recorded totals, observed targets must
// fall inside the envelope's eligible set, and a beat that arrives
// after expiry trips grant_expiry instead of renewing.
func (g *Governor) Heartbeat(principal *Principal, beat *Heartbeat) (*GovernedRun, error) {
	if err := checkRole(principal, "renew a grant"); err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	run, envelope, err := g.activeRunLocked(principal, beat.RunID, "heartbeat")
	if err != nil {
		return nil, err
	}
	now := g.nowUTC()

	// Expiry equal to now authorizes nothing: a late beat trips, even
	// one that only retries an earlier generation.
	grantExpiry := parseTime(run.Grant.ExpiresAt)
	if !now.Before(grantExpiry) {
		g.tripLocked(run, TripGrantExpiry, "heartbeat",
			fmt.Sprintf("the beat arrived at %s after the grant expired at %s",
				g.ClockUTC(), run.Grant.ExpiresAt), "")
		return nil, refuse("grant_expired",
			"the grant lease expired; new experiment work is rejected")
	}

	// A beat naming the previous generation is a retried beat that
	// already applied: return the current grant without renewing
	// again. Anything older is stale delivery; the runner must re-read
	// the grant instead of replaying beats.
	if beat.Generation != 0 {
		switch beat.Generation {
		case run.Grant.Generation:
		case run.Grant.Generation - 1:
			return cloneRun(run), nil
		default:
			return nil, refuse("stale_generation", fmt.Sprintf(
				"beat names generation %d; the grant is at generation %d",
				beat.Generation, run.Grant.Generation))
		}
	}

	// Selector enforcement (spec 13.1, AC-002): every observed target
	// must fall inside the eligible set the envelope recorded.
	for _, target := range beat.ObservedTargets {
		if !eligibleTarget(envelope, target) {
			g.tripLocked(run, TripTargetExpansion, "heartbeat",
				fmt.Sprintf("target %s is outside the envelope's eligible set", target), "")
			return nil, refuse("target_expansion",
				fmt.Sprintf("target %s expanded past the envelope", target))
		}
	}

	// Spend accounting. Claims are lower bounds: the recorded total for
	// a session only rises. A claim in a currency the budget cannot
	// denominate is incomparable, so it trips rather than passing.
	for _, spend := range beat.SessionSpends {
		if spend.Cost.Currency != envelope.Budgets.AggregateCostMax.Currency {
			g.tripLocked(run, TripBudgetExhaustion, "heartbeat",
				fmt.Sprintf("session %s claimed %s; the budget is denominated in %s",
					spend.SessionID, spend.Cost.Currency,
					envelope.Budgets.AggregateCostMax.Currency), "")
			return nil, refuse("budget_exhausted",
				"a spend claim is incomparable with the budget's currency")
		}
		if spend.Cost.Micros > run.SessionSpend[spend.SessionID] {
			run.SessionSpend[spend.SessionID] = spend.Cost.Micros
		}
	}
	for session, micros := range run.SessionSpend {
		if micros > envelope.Budgets.PerSessionCostMax.Micros {
			g.tripLocked(run, TripBudgetExhaustion, "heartbeat",
				fmt.Sprintf("session %s spent %d micros over the %d micro ceiling",
					session, micros, envelope.Budgets.PerSessionCostMax.Micros), "")
			return nil, refuse("budget_exhausted",
				"a session crossed its per-session cost ceiling")
		}
	}
	// Aggregate ceiling in subtraction form: a wrapped or saturated
	// sum must never read as under the ceiling. The recorded total is
	// clamped for reporting; the over-budget decision compares before
	// it clamps.
	ceiling := envelope.Budgets.AggregateCostMax.Micros
	aggregate, over := spendTotalLocked(run.SessionSpend, ceiling)
	if over {
		g.tripLocked(run, TripBudgetExhaustion, "heartbeat",
			fmt.Sprintf("aggregate spend crossed the %d micro ceiling", ceiling), "")
		return nil, refuse("budget_exhausted", "the aggregate cost budget is exhausted")
	}
	if aggregate != run.AggregateSpend {
		run.AggregateSpend = aggregate
		g.appendEvent(budgetEvent(run, aggregate))
	}

	// Duration budget: the lease renews only inside the envelope's
	// window, clamped to its end.
	deadline := parseTime(run.Grant.Deadline)
	if !now.Before(deadline) {
		g.tripLocked(run, TripBudgetExhaustion, "heartbeat",
			fmt.Sprintf("the duration budget ended at %s", run.Grant.Deadline), "")
		return nil, refuse("budget_exhausted", "the duration budget is exhausted")
	}

	// Every check passed: renew. A stop_injection trip does not retract
	// the grant — fault injection and task termination are separate
	// operations (spec 13.2) — but the reply carries the flag so the
	// runner knows injection is over.
	run.Grant.Generation++
	run.Grant.IssuedAt = g.ClockUTC()
	run.Grant.ExpiresAt = formatTime(leaseEnd(now, deadline))
	run.ObservedTargets = append([]string{}, beat.ObservedTargets...)
	g.logLocked(run.TenantID, run.RunID, "grant_renewed",
		fmt.Sprintf("generation %d expires at %s", run.Grant.Generation, run.Grant.ExpiresAt))
	return cloneRun(run), nil
}

// ReportIncident records an externally observed trip condition
// (spec 13.2): the broker names unauthorized effects, the collector
// names evidence-persistence failures, monitors name containment loss
// and service health. Every report trips fail-closed; a threshold
// condition with no declared threshold cannot be evaluated and trips.
func (g *Governor) ReportIncident(principal *Principal, incident *Incident) error {
	if err := checkRole(principal, "report an incident"); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	run, envelope, err := g.activeRunLocked(principal, incident.RunID, "incident")
	if err != nil {
		return err
	}
	switch incident.Condition {
	case TripServiceHealth:
		for _, rule := range envelope.StopRules {
			if rule.Condition == TripServiceHealth {
				if incident.Observed < rule.Threshold {
					return nil // below the declared threshold: no trip
				}
				break
			}
		}
		// No rule declared a threshold for this condition: the check is
		// not evaluable, and unevaluable fails closed.
	}
	g.tripLocked(run, incident.Condition, "incident", truncateReason(incident.Reason), "")
	return nil
}

// EmergencyStop revokes experiment authority (spec 13.2). It is the
// customer-accessible control: operator or customer role, never the
// worker or the runner's service identity. The stop terminates every
// active run in scope — an envelope's stop rules cannot weaken the
// emergency control — and emits a stop handoff for each. The tenant or
// experiment stays fenced so no new run starts. Idempotent: a repeated
// stop returns the current state without new trips.
func (g *Governor) EmergencyStop(principal *Principal, scope *EmergencyStopScope) (int, error) {
	if principal == nil {
		return 0, refuse("unauthenticated", "caller identity headers are required")
	}
	switch principal.Role {
	case RoleOperator, RoleCustomer:
	default:
		return 0, refuse("role_forbidden", fmt.Sprintf(
			"role %s cannot stop experiments; the emergency control belongs to operators and customers",
			principal.Role))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fenced := 0
	for _, run := range g.runs {
		if run.TenantID != principal.TenantID || run.State != RunStateActive {
			continue
		}
		if scope.Kind == "experiment" && run.ExperimentID != scope.ExperimentID {
			continue
		}
		g.tripLocked(run, TripOperatorRequest, "emergency", truncateReason(scope.Reason),
			ActionTerminate)
		fenced++
	}
	if scope.Kind == "tenant" {
		g.tenantFenced[principal.TenantID] = true
	} else if envelope := g.envelopes[scopedKey(principal.TenantID, scope.ExperimentID)]; envelope != nil {
		envelope.Fenced = true
	} else {
		return fenced, refuse("envelope_unknown", "no envelope is registered for this experiment")
	}
	g.logLocked(principal.TenantID, scope.ExperimentID, "emergency_stop",
		fmt.Sprintf("scope %s fenced %d active run(s)", scope.Kind, fenced))
	return fenced, nil
}

// Sweep trips grant_expiry for every active run whose lease lapsed
// without renewal (spec 13.2: enforcement immediately rejects new
// experiment work after expiration), and budget_exhaustion for every
// active run past its duration deadline. The daemon ticks this; tests
// call it on a fixed clock. A runner outage cannot prevent expiry —
// the governor's clock is the only clock involved (AC-006).
func (g *Governor) Sweep() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.nowUTC()
	trippedCount := 0
	for _, run := range g.runs {
		if run.State != RunStateActive {
			continue
		}
		switch {
		case now.Before(parseTime(run.Grant.ExpiresAt)):
			// The lease is live; a stop_injection trip still ends the
			// duration budget on time.
			if !now.Before(parseTime(run.Grant.Deadline)) {
				g.tripLocked(run, TripBudgetExhaustion, "sweep",
					fmt.Sprintf("the duration budget ended at %s", run.Grant.Deadline), "")
				trippedCount++
			}
		default:
			g.tripLocked(run, TripGrantExpiry, "sweep",
				fmt.Sprintf("the grant expired at %s without renewal", run.Grant.ExpiresAt), "")
			trippedCount++
		}
	}
	return trippedCount
}

// ReportCleanupState records the independent cleanup verifier's
// terminal state for a stopped or fenced run (spec 13.3): CLEAN,
// DIRTY_QUARANTINED, or UNKNOWN. Never inferred from worker exit, so
// the state arrives only through this report.
func (g *Governor) ReportCleanupState(principal *Principal, runID, terminalState string) (*GovernedRun, error) {
	if err := checkRole(principal, "report a cleanup state"); err != nil {
		return nil, err
	}
	if terminalState != TerminalClean && terminalState != TerminalDirtyQuarantined &&
		terminalState != TerminalUnknown {
		return nil, refuse("terminal_state_invalid",
			"terminal state must be CLEAN, DIRTY_QUARANTINED, or UNKNOWN")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	run := g.runs[scopedKey(principal.TenantID, runID)]
	if run == nil {
		return nil, refuse("run_unknown", "no such run for this tenant")
	}
	if run.State == RunStateActive {
		return nil, refuse("run_active",
			"an active run has no cleanup terminal state yet")
	}
	if run.TerminalState == "" {
		run.TerminalState = terminalState
		g.appendEvent(recoveryEvent(run, "cleanup_state", "", map[string]any{
			"terminal_state": terminalState,
		}))
		g.logLocked(run.TenantID, run.RunID, "cleanup_state_recorded", terminalState)
	}
	return cloneRun(run), nil
}

// Run returns one run's governor record; a cross-tenant lookup is
// indistinguishable from absence.
func (g *Governor) Run(principal *Principal, runID string) (*GovernedRun, error) {
	if principal == nil {
		return nil, refuse("unauthenticated", "caller identity headers are required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	run := g.runs[scopedKey(principal.TenantID, runID)]
	if run == nil {
		return nil, refuse("run_unknown", "no such run for this tenant")
	}
	return cloneRun(run), nil
}

// Envelope returns one experiment's registered envelope.
func (g *Governor) Envelope(principal *Principal, experimentID string) (*Envelope, error) {
	if principal == nil {
		return nil, refuse("unauthenticated", "caller identity headers are required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	envelope := g.envelopes[scopedKey(principal.TenantID, experimentID)]
	if envelope == nil {
		return nil, refuse("envelope_unknown", "no such envelope for this tenant")
	}
	return cloneEnvelope(envelope), nil
}

// Events returns the evidence journal.
func (g *Governor) Events() []EvidenceEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]EvidenceEvent{}, g.events...)
}

// Decisions returns the governor's decision log.
func (g *Governor) Decisions() []Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Decision{}, g.decisions...)
}

// activeRunLocked resolves an active run plus its envelope, or
// refuses. The caller holds g.mu.
func (g *Governor) activeRunLocked(principal *Principal, runID, action string) (*GovernedRun, *Envelope, error) {
	if principal == nil {
		return nil, nil, refuse("unauthenticated", "caller identity headers are required")
	}
	run := g.runs[scopedKey(principal.TenantID, runID)]
	if run == nil {
		return nil, nil, refuse("run_unknown", "no such run for this tenant")
	}
	if run.State == RunStateFenced {
		return nil, nil, refuse("run_fenced", "the run's effects are fenced")
	}
	if run.State == RunStateStopped {
		return nil, nil, refuse("run_stopped", "the run is terminated")
	}
	envelope := g.envelopes[scopedKey(run.TenantID, run.ExperimentID)]
	if envelope == nil {
		return nil, nil, refuse("envelope_unknown", "the run's envelope vanished; failing closed")
	}
	return run, envelope, nil
}

// tripLocked raises a trip condition and applies its action
// (spec 13.2). The experiment's stop rules choose the action; a
// condition with no matching rule fences — the fail-closed reading. A
// forced action (the emergency stop's terminate) overrides the rules:
// an envelope cannot weaken the customer emergency control. One
// condition trips a run once; later raises are recorded in the
// decision log only. The caller holds g.mu.
func (g *Governor) tripLocked(run *GovernedRun, condition, source, detail, forcedAction string) string {
	key := scopedKey(run.TenantID, run.RunID)
	if g.tripped[key] == nil {
		g.tripped[key] = map[string]bool{}
	}
	action := ActionFenceEffects
	for _, rule := range g.stopRulesLocked(run) {
		if rule.Condition == condition {
			action = rule.Action
			break
		}
	}
	if forcedAction != "" {
		action = forcedAction
	}
	if g.tripped[key][condition] {
		g.logLocked(run.TenantID, run.RunID, "trip_repeat",
			fmt.Sprintf("%s already tripped (%s)", condition, source))
		return action
	}
	g.tripped[key][condition] = true

	switch action {
	case ActionStopInjection:
		run.InjectionStopped = true
	case ActionFenceEffects:
		// A fenced run injects nothing either.
		run.InjectionStopped = true
		run.State = RunStateFenced
	case ActionTerminate:
		run.InjectionStopped = true
		run.State = RunStateStopped
	}
	trip := Trip{
		Condition: condition,
		Action:    action,
		Source:    source,
		Detail:    truncateReason(detail),
		At:        g.ClockUTC(),
	}
	run.Trips = append(run.Trips, trip)
	g.appendEvent(recoveryEvent(run, "trip", condition, map[string]any{
		"trip_source": source,
		"trip_action": action,
		"detail":      trip.Detail,
	}))
	if action != ActionStopInjection {
		handoff := g.handoffLocked(run, trip)
		run.HandoffID = handoff.ID
	}
	g.logLocked(run.TenantID, run.RunID, "trip",
		fmt.Sprintf("%s -> %s (%s)", condition, action, source))
	return action
}

// stopRulesLocked reads the envelope's stop rules. The caller holds
// g.mu.
func (g *Governor) stopRulesLocked(run *GovernedRun) []StopRule {
	envelope := g.envelopes[scopedKey(run.TenantID, run.ExperimentID)]
	if envelope == nil {
		return nil
	}
	return envelope.StopRules
}

// logLocked appends to the governor's own decision log. The caller
// holds g.mu.
func (g *Governor) logLocked(tenantID, subject, action, detail string) {
	g.decisions = append(g.decisions, Decision{
		At:      g.ClockUTC(),
		Subject: tenantID + "/" + subject,
		Action:  action,
		Detail:  truncateReason(detail),
	})
}

// eligibleSet precomputes the envelope's eligible target set: the
// union of every selector's explicit targets minus every exclusion
// (spec 13.1). Envelopes are immutable after registration, so the set
// is computed once — a heartbeat then costs one map lookup per
// observed target, never a walk over every selector list.
func eligibleSet(envelope *Envelope) map[string]bool {
	set := make(map[string]bool)
	for _, selector := range envelope.Selectors {
		for _, target := range selector.TargetIDs {
			set[target] = true
		}
	}
	for _, selector := range envelope.Selectors {
		for _, excluded := range selector.Exclusions {
			delete(set, excluded)
		}
	}
	return set
}

// eligibleTarget reports whether a target falls inside the envelope's
// precomputed eligible set.
func eligibleTarget(envelope *Envelope, target string) bool {
	return envelope.eligible[target]
}

// spendTotalLocked sums recorded session spend against a ceiling in
// subtraction form: any addend above the ceiling, or any partial sum
// that would cross it, reports the ceiling as exceeded instead of
// wrapping or saturating under it (the broker's budget arithmetic
// convention, spec 10). The returned total is clamped for reporting.
func spendTotalLocked(spend map[string]int64, ceiling int64) (int64, bool) {
	total := int64(0)
	for _, micros := range spend {
		if micros > ceiling || total > ceiling || total > ceiling-micros {
			return ceiling, true
		}
		total += micros
	}
	return total, false
}

// truncateReason bounds advisory text entering journals (spec 19).
func truncateReason(reason string) string {
	if len(reason) > MaxReason {
		return reason[:MaxReason]
	}
	return reason
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func parseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		// An unparseable bound fails closed to the earliest possible
		// time: nothing authorizes past it.
		return time.Time{}.UTC()
	}
	return parsed
}

// cloneRun copies a run record so callers never share stored state.
func cloneRun(run *GovernedRun) *GovernedRun {
	duplicate := *run
	duplicate.SessionSpend = make(map[string]int64, len(run.SessionSpend))
	for session, micros := range run.SessionSpend {
		duplicate.SessionSpend[session] = micros
	}
	duplicate.ObservedTargets = append([]string{}, run.ObservedTargets...)
	duplicate.Trips = append([]Trip{}, run.Trips...)
	return &duplicate
}

// cloneEnvelope copies an envelope, deep-copying every list.
func cloneEnvelope(envelope *Envelope) *Envelope {
	duplicate := *envelope
	selectors := make([]Selector, len(envelope.Selectors))
	for i, selector := range envelope.Selectors {
		selectors[i] = Selector{
			Kind:         selector.Kind,
			RecordedSeed: selector.RecordedSeed,
			TargetIDs:    append([]string{}, selector.TargetIDs...),
			Exclusions:   append([]string{}, selector.Exclusions...),
		}
	}
	duplicate.Selectors = selectors
	duplicate.AllowedPrimitives = append([]string{}, envelope.AllowedPrimitives...)
	duplicate.StopRules = append([]StopRule{}, envelope.StopRules...)
	return &duplicate
}
