package governor

import (
	"testing"
	"time"
)

// fixedClock gives tests deterministic time: the governor's own clock
// is the only clock a grant trusts (AC-006).
type fixedClock struct {
	at time.Time
}

func (c *fixedClock) Now() time.Time { return c.at }

func (c *fixedClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newFixedClock() *fixedClock {
	return &fixedClock{at: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)}
}

func servicePrincipal() *Principal {
	return &Principal{ID: "act_runner-svc-01", TenantID: "tnt_alpha00000001", Role: RoleService}
}

func customerPrincipal() *Principal {
	return &Principal{ID: "act_customer-admin1", TenantID: "tnt_alpha00000001", Role: RoleCustomer}
}

func workerPrincipal() *Principal {
	return &Principal{ID: "act_worker-under-tst", TenantID: "tnt_alpha00000001", Role: RoleWorker}
}

// testEnvelope is a well-formed safety envelope: two eligible targets,
// one excluded, generous budgets, and stop rules that leave one
// condition mapped to stop_injection so tests can pin the separation
// between stopping injection and fencing effects.
func testEnvelope() *Envelope {
	return &Envelope{
		ExperimentID: "exp_gate000000001",
		Selectors: []Selector{{
			Kind:         "enrolled_targets",
			TargetIDs:    []string{"tgt_alpha00000001", "tgt_beta000000002"},
			RecordedSeed: 7,
			Exclusions:   []string{"tgt_quar000000001"},
		}},
		Budgets: Budgets{
			MaxDurationS:          3600,
			MaxConcurrentSessions: 2,
			PerSessionCostMax:     Money{Currency: "USD", Micros: 1_000_000},
			AggregateCostMax:      Money{Currency: "USD", Micros: 2_000_000},
		},
		AllowedPrimitives: []string{"http.request", "repo.comment"},
		StopRules: []StopRule{
			{Condition: TripOperatorRequest, Action: ActionStopInjection},
			{Condition: TripUnauthorizedEffect, Action: ActionFenceEffects},
		},
		MaxSessions: 4,
	}
}

func registerEnvelope(t *testing.T, g *Governor) *Envelope {
	t.Helper()
	stored, err := g.RegisterEnvelope(servicePrincipal(), testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func startRun(t *testing.T, g *Governor, n int) *GovernedRun {
	t.Helper()
	run, err := g.StartRun(servicePrincipal(), "run_govtest00000"+string(rune('0'+n)), "exp_gate000000001")
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func beat(runID string, opts ...func(*Heartbeat)) *Heartbeat {
	beat := &Heartbeat{RunID: runID}
	for _, opt := range opts {
		opt(beat)
	}
	return beat
}

func withSpend(session string, micros int64) func(*Heartbeat) {
	return func(b *Heartbeat) {
		b.SessionSpends = append(b.SessionSpends, SessionSpend{
			SessionID: session, Cost: Money{Currency: "USD", Micros: micros},
		})
	}
}

func withTargets(targets ...string) func(*Heartbeat) {
	return func(b *Heartbeat) { b.ObservedTargets = targets }
}

// refusalCode returns a refusal's stable code, failing the test on
// any other error shape.
func refusalCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal")
	}
	denied, ok := err.(*refusal)
	if !ok {
		t.Fatalf("not a refusal: %v", err)
	}
	return denied.Code
}

func TestGrantLeaseRenewsAndClampsToDuration(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// The first lease is the ten-second default.
	if run.Grant.Generation != 1 {
		t.Fatalf("first generation: %d", run.Grant.Generation)
	}
	wantExpiry := clock.at.Add(GrantLeaseTTL).Format("2006-01-02T15:04:05Z")
	if run.Grant.ExpiresAt != wantExpiry {
		t.Fatalf("first expiry %s, want %s", run.Grant.ExpiresAt, wantExpiry)
	}

	// A beat inside the window renews to a new generation.
	clock.advance(9 * time.Second)
	renewed, err := g.Heartbeat(servicePrincipal(), beat(run.RunID))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Grant.Generation != 2 {
		t.Fatalf("renewed generation: %d", renewed.Grant.Generation)
	}
	wantRenewed := clock.at.Add(GrantLeaseTTL).Format("2006-01-02T15:04:05Z")
	if renewed.Grant.ExpiresAt != wantRenewed {
		t.Fatalf("renewed expiry %s, want %s", renewed.Grant.ExpiresAt, wantRenewed)
	}
}

func TestGrantNeverExtendsPastDurationBudget(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	envelope := testEnvelope()
	envelope.Budgets.MaxDurationS = 1 // shorter than one lease
	if _, err := g.RegisterEnvelope(servicePrincipal(), envelope); err != nil {
		t.Fatal(err)
	}
	run := startRun(t, g, 1)
	// The very first lease is clamped to the duration budget.
	if want := clock.at.Add(time.Second).Format("2006-01-02T15:04:05Z"); run.Grant.ExpiresAt != want {
		t.Fatalf("clamped expiry %s, want %s", run.Grant.ExpiresAt, want)
	}
}

func TestExpiredGrantRejectsNewWorkAndTrips(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	clock.advance(GrantLeaseTTL + time.Second)
	code := refusalCode(t, func() error {
		_, err := g.Heartbeat(servicePrincipal(), beat(run.RunID))
		return err
	}())
	if code != "grant_expired" {
		t.Fatalf("late beat refusal: %s", code)
	}
	// No stop rule matches grant_expiry, so the fail-closed default
	// fences, and a fence emits the stop handoff.
	stored, err := g.Run(servicePrincipal(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != RunStateFenced {
		t.Fatalf("state after expiry: %s", stored.State)
	}
	if len(stored.Trips) != 1 || stored.Trips[0].Condition != TripGrantExpiry {
		t.Fatalf("trips: %+v", stored.Trips)
	}
	if stored.HandoffID == "" {
		t.Fatal("expiry fence emitted no stop handoff")
	}
	// Every later beat is refused: enforcement immediately rejects new
	// experiment work after expiration (spec 13.2).
	if code := refusalCode(t, heartbeatErr(g, run.RunID)); code != "run_fenced" {
		t.Fatalf("post-fence beat: %s", code)
	}
}

func heartbeatErr(g *Governor, runID string) error {
	_, err := g.Heartbeat(servicePrincipal(), beat(runID))
	return err
}

func TestSweepTripsLapsedRunsWithoutRunnerHelp(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	startRun(t, g, 1)

	clock.advance(GrantLeaseTTL + 5*time.Second)
	if tripped := g.Sweep(); tripped != 1 {
		t.Fatalf("sweep tripped %d runs", tripped)
	}
	// Sweeping again finds nothing new: one condition trips once.
	if tripped := g.Sweep(); tripped != 0 {
		t.Fatalf("second sweep tripped %d runs", tripped)
	}
	// The trip and the stop handoff are the two journaled events.
	events := g.Events()
	if len(events) != 2 {
		t.Fatalf("events after sweep: %d", len(events))
	}
	if events[0].EventKind != "recovery_action" || events[1].EventKind != "recovery_action" {
		t.Fatalf("event kinds: %s, %s", events[0].EventKind, events[1].EventKind)
	}
}

func TestSelectorEnforcementTripsOnExpansion(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// An eligible target passes.
	if _, err := g.Heartbeat(servicePrincipal(), beat(run.RunID,
		withTargets("tgt_alpha00000001"))); err != nil {
		t.Fatal(err)
	}
	// A target outside the eligible set trips.
	code := refusalCode(t, heartbeatErrWith(g, run.RunID, withTargets("tgt_gamma00000009")))
	if code != "target_expansion" {
		t.Fatalf("expansion refusal: %s", code)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateFenced {
		t.Fatalf("state after expansion: %s", stored.State)
	}
}

func heartbeatErrWith(g *Governor, runID string, opts ...func(*Heartbeat)) error {
	_, err := g.Heartbeat(servicePrincipal(), beat(runID, opts...))
	return err
}

func TestExcludedTargetIsNotEligible(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)
	// The excluded target appears in no selector's target set, and the
	// exclusion list is enforced even if a selector later adds it.
	code := refusalCode(t, heartbeatErrWith(g, run.RunID, withTargets("tgt_quar000000001")))
	if code != "target_expansion" {
		t.Fatalf("excluded target refusal: %s", code)
	}
}

func TestSpendClaimsAreLowerBoundsAndBoundByBudgets(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// Record a high claim, then a lower one: recorded spend only rises.
	if _, err := g.Heartbeat(servicePrincipal(), beat(run.RunID,
		withSpend("ses_spender000001", 500_000))); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Heartbeat(servicePrincipal(), beat(run.RunID,
		withSpend("ses_spender000001", 100_000))); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if got := stored.SessionSpend["ses_spender000001"]; got != 500_000 {
		t.Fatalf("recorded spend dropped to %d", got)
	}

	// Crossing the per-session ceiling trips.
	code := refusalCode(t, heartbeatErrWith(g, run.RunID,
		withSpend("ses_spender000001", 1_000_001)))
	if code != "budget_exhausted" {
		t.Fatalf("per-session refusal: %s", code)
	}
}

func TestAggregateBudgetSaturatesInsteadOfPassing(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	envelope := testEnvelope()
	envelope.Budgets.PerSessionCostMax = Money{Currency: "USD", Micros: 9_000_000_000_000_000_000}
	envelope.Budgets.AggregateCostMax = Money{Currency: "USD", Micros: 9_000_000_000_000_000_000}
	if _, err := g.RegisterEnvelope(servicePrincipal(), envelope); err != nil {
		t.Fatal(err)
	}
	run := startRun(t, g, 1)
	// Two sessions whose recorded spend sums past the int64 range must
	// saturate at the ceiling and trip, never wrap under it.
	if _, err := g.Heartbeat(servicePrincipal(), beat(run.RunID,
		withSpend("ses_big0000000001", 9_000_000_000_000_000_000),
		withSpend("ses_big0000000002", 9_000_000_000_000_000_000))); err == nil {
		t.Fatal("saturating aggregate passed the budget")
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateFenced {
		t.Fatalf("state after saturation trip: %s", stored.State)
	}
}

func TestForeignCurrencyClaimFailsClosed(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)
	_, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID,
		SessionSpends: []SessionSpend{{
			SessionID: "ses_eur0000000001",
			Cost:      Money{Currency: "EUR", Micros: 1},
		}},
	})
	if code := refusalCode(t, err); code != "budget_exhausted" {
		t.Fatalf("currency refusal: %s", code)
	}
}

func TestConcurrencyBudgetCapsGrantedRuns(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	startRun(t, g, 1)
	startRun(t, g, 2)
	if _, err := g.StartRun(servicePrincipal(), "run_govtest000003", "exp_gate000000001"); err == nil {
		t.Fatal("third run started inside a two-session budget")
	} else if code := refusalCode(t, err); code != "concurrency_exhausted" {
		t.Fatalf("concurrency refusal: %s", code)
	}

	// A lapsed lease frees its slot even before the sweep trips it:
	// the budget caps concurrently GRANTED runs.
	clock.advance(GrantLeaseTTL + time.Second)
	third, err := g.StartRun(servicePrincipal(), "run_govtest000003", "exp_gate000000001")
	if err != nil {
		t.Fatalf("third run after lapse: %v", err)
	}
	if third.Grant.Generation != 1 {
		t.Fatalf("third run generation: %d", third.Grant.Generation)
	}
}

func TestIncidentTripsWithRuleAction(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: run.RunID, Condition: TripUnauthorizedEffect, Reason: "A2 write outside primitives",
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateFenced {
		t.Fatalf("state after incident: %s", stored.State)
	}
	if len(stored.Trips) != 1 || stored.Trips[0].Action != ActionFenceEffects {
		t.Fatalf("trips: %+v", stored.Trips)
	}
}

func TestServiceHealthThresholdGovernsIncidents(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	envelope := testEnvelope()
	envelope.StopRules = append(envelope.StopRules,
		StopRule{Condition: TripServiceHealth, Action: ActionTerminate, Threshold: 0.95})
	if _, err := g.RegisterEnvelope(servicePrincipal(), envelope); err != nil {
		t.Fatal(err)
	}
	low := startRun(t, g, 1)
	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: low.RunID, Condition: TripServiceHealth, Observed: 0.90,
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), low.RunID)
	if stored.State != RunStateActive {
		t.Fatalf("a healthy ratio tripped: %+v", stored.Trips)
	}

	high := startRun(t, g, 2)
	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: high.RunID, Condition: TripServiceHealth, Observed: 0.99,
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ = g.Run(servicePrincipal(), high.RunID)
	if stored.State != RunStateStopped {
		t.Fatalf("state after health trip: %s", stored.State)
	}
}

func TestUnevaluableThresholdFailsClosed(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g) // no service_health rule at all
	run := startRun(t, g, 1)
	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: run.RunID, Condition: TripServiceHealth, Observed: 0.99,
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateFenced {
		t.Fatalf("an unevaluable threshold passed: %s", stored.State)
	}
}

func TestStopInjectionIsSeparateFromFencing(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// The envelope maps operator_request to stop_injection.
	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: run.RunID, Condition: TripOperatorRequest, Reason: "operator asked",
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateActive || !stored.InjectionStopped {
		t.Fatalf("after stop_injection: state %s injection_stopped %v",
			stored.State, stored.InjectionStopped)
	}
	// Stopping injection does not fence effects (spec 13.2): the grant
	// still renews so the run can observe and record evidence.
	clock.advance(time.Second)
	renewed, err := g.Heartbeat(servicePrincipal(), beat(run.RunID))
	if err != nil {
		t.Fatalf("renewal after stop_injection: %v", err)
	}
	if !renewed.InjectionStopped {
		t.Fatal("the renewal reply lost the injection_stopped flag")
	}
}

func TestEmergencyStopTerminatesWithoutUI(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	first := startRun(t, g, 1)
	second := startRun(t, g, 2)

	// The customer role can stop; the envelope's stop rule maps
	// operator_request to stop_injection, but the emergency control
	// terminates regardless — an envelope cannot weaken it.
	fenced, err := g.EmergencyStop(customerPrincipal(), &EmergencyStopScope{
		Kind: "tenant", Reason: "customer incident",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fenced != 2 {
		t.Fatalf("fenced runs: %d", fenced)
	}
	for _, runID := range []string{first.RunID, second.RunID} {
		stored, _ := g.Run(servicePrincipal(), runID)
		if stored.State != RunStateStopped {
			t.Fatalf("run %s state: %s", runID, stored.State)
		}
		if stored.HandoffID == "" {
			t.Fatalf("run %s has no handoff", runID)
		}
	}
	// No new run starts under a fenced tenant.
	if code := refusalCode(t, startErr(g, "run_govtest000003")); code != "tenant_fenced" {
		t.Fatalf("post-emergency start: %s", code)
	}
	// Idempotent: a repeated stop changes nothing.
	if fenced, err := g.EmergencyStop(customerPrincipal(), &EmergencyStopScope{
		Kind: "tenant"}); err != nil || fenced != 0 {
		t.Fatalf("repeated stop: %d %v", fenced, err)
	}
}

func startErr(g *Governor, runID string) error {
	_, err := g.StartRun(servicePrincipal(), runID, "exp_gate000000001")
	return err
}

func TestEmergencyStopRoles(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	startRun(t, g, 1)

	for name, principal := range map[string]*Principal{
		"worker":  workerPrincipal(),
		"service": servicePrincipal(),
		"nil":     nil,
	} {
		if _, err := g.EmergencyStop(principal, &EmergencyStopScope{Kind: "tenant"}); err == nil {
			t.Fatalf("%s stopped experiments", name)
		}
	}
	operator := &Principal{ID: "act_operator-oncal", TenantID: "tnt_alpha00000001", Role: RoleOperator}
	if _, err := g.EmergencyStop(operator, &EmergencyStopScope{
		Kind: "experiment", ExperimentID: "exp_gate000000001"}); err != nil {
		t.Fatalf("operator stop: %v", err)
	}
	envelope, err := g.Envelope(servicePrincipal(), "exp_gate000000001")
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.Fenced {
		t.Fatal("the experiment envelope is not fenced")
	}
}

func TestCleanupTerminalStateArrivesOnlyThroughReport(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// An active run has no terminal state.
	if code := refusalCode(t, cleanupErr(g, run.RunID, TerminalClean)); code != "run_active" {
		t.Fatalf("active cleanup report: %s", code)
	}
	clock.advance(GrantLeaseTTL + time.Second)
	g.Sweep()

	// Invalid states are refused; the first valid report wins.
	if code := refusalCode(t, cleanupErr(g, run.RunID, "mostly_clean")); code != "terminal_state_invalid" {
		t.Fatalf("invalid terminal state: %s", code)
	}
	stored, err := g.ReportCleanupState(servicePrincipal(), run.RunID, TerminalDirtyQuarantined)
	if err != nil {
		t.Fatal(err)
	}
	if stored.TerminalState != TerminalDirtyQuarantined {
		t.Fatalf("terminal state: %s", stored.TerminalState)
	}
	again, err := g.ReportCleanupState(servicePrincipal(), run.RunID, TerminalClean)
	if err != nil {
		t.Fatal(err)
	}
	if again.TerminalState != TerminalDirtyQuarantined {
		t.Fatal("a later report overwrote the verifier's terminal state")
	}
}

func cleanupErr(g *Governor, runID, state string) error {
	_, err := g.ReportCleanupState(servicePrincipal(), runID, state)
	return err
}

func TestStopHandoffListsProtocolSteps(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	envelope := testEnvelope()
	envelope.StopRules = []StopRule{{Condition: TripOperatorRequest, Action: ActionTerminate}}
	if _, err := g.RegisterEnvelope(servicePrincipal(), envelope); err != nil {
		t.Fatal(err)
	}
	run := startRun(t, g, 1)
	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: run.RunID, Condition: TripOperatorRequest}); err != nil {
		t.Fatal(err)
	}
	handoff, err := g.Handoff(servicePrincipal(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		StepRevokePermits, StepDisableInjectors, StepFenceDelegations,
		StepCancelPending, StepIdentifyUnknown, StepReconcile,
		StepCompensate, StepSandbox, StepCleanupVerifier, StepTerminalState,
	}
	if len(handoff.Steps) != len(want) {
		t.Fatalf("steps: %d", len(handoff.Steps))
	}
	for i, step := range handoff.Steps {
		if step.Name != want[i] {
			t.Fatalf("step %d: %s, want %s", i, step.Name, want[i])
		}
		if step.Status != "pending" {
			t.Fatalf("step %d already %s", i, step.Status)
		}
	}
	// Nothing is done because a worker exited (spec 13.3): the
	// verifier step is required and pending.
	last := handoff.Steps[len(handoff.Steps)-1]
	if !last.Required || last.Name != StepTerminalState {
		t.Fatalf("terminal state step: %+v", last)
	}
}

func TestEnvelopeRegistryIsAppendOnlyAndLocked(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	if code := refusalCode(t, registerErr(g)); code != "envelope_exists" {
		t.Fatalf("re-registration: %s", code)
	}
	startRun(t, g, 1)
	// A second experiment's envelope cannot be swapped in after runs
	// started — the envelope is immutable once work began.
	other := testEnvelope()
	other.ExperimentID = "exp_two0000000002"
	if _, err := g.RegisterEnvelope(servicePrincipal(), other); err != nil {
		t.Fatal(err)
	}
	if code := refusalCode(t, registerErr(g)); code != "envelope_exists" {
		t.Fatalf("widening re-registration: %s", code)
	}
}

func registerErr(g *Governor) error {
	_, err := g.RegisterEnvelope(servicePrincipal(), testEnvelope())
	return err
}

func TestTenantScopingHidesOtherTenants(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	startRun(t, g, 1)

	foreign := &Principal{ID: "act_runner-svc-02", TenantID: "tnt_beta000000002", Role: RoleService}
	// The same experiment id in the foreign tenant is a different
	// envelope: absence, not access.
	if _, err := g.Envelope(foreign, "exp_gate000000001"); err == nil {
		t.Fatal("cross-tenant envelope read")
	}
	if _, err := g.StartRun(foreign, "run_govtest000001", "exp_gate000000001"); err == nil {
		t.Fatal("cross-tenant run started")
	}
	if code := refusalCode(t, func() error {
		_, err := g.Heartbeat(foreign, beat("run_govtest000001"))
		return err
	}()); code != "run_unknown" {
		t.Fatalf("cross-tenant beat: %s", code)
	}
}

func TestRoleGuardsRefuseWorkers(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	worker := workerPrincipal()
	if err := registerErrAs(g, worker); err == nil {
		t.Fatal("worker registered an envelope")
	}
	if _, err := g.StartRun(worker, "run_govtest000009", "exp_gate000000001"); err == nil {
		t.Fatal("worker started a run")
	}
	if _, err := g.Heartbeat(worker, beat(run.RunID)); err == nil {
		t.Fatal("worker renewed a grant")
	}
	if err := g.ReportIncident(worker, &Incident{
		RunID: run.RunID, Condition: TripUnauthorizedEffect}); err == nil {
		t.Fatal("worker reported an incident")
	}
	if _, err := g.ReportCleanupState(worker, run.RunID, TerminalClean); err == nil {
		t.Fatal("worker reported a cleanup state")
	}
	// An unauthenticated caller is refused everywhere.
	if _, err := g.StartRun(nil, "run_govtest000010", "exp_gate000000001"); err == nil {
		t.Fatal("anonymous caller started a run")
	}
}

func registerErrAs(g *Governor, principal *Principal) error {
	_, err := g.RegisterEnvelope(principal, testEnvelope())
	return err
}

func TestStaleAndRetriedGenerations(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// A retried beat naming the previous generation is a no-op that
	// returns the current grant.
	first, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	retried, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID, Generation: 1})
	if err != nil {
		t.Fatalf("retried beat: %v", err)
	}
	if retried.Grant.Generation != first.Grant.Generation {
		t.Fatalf("retry renewed again: %d vs %d",
			retried.Grant.Generation, first.Grant.Generation)
	}
	// Renew once more, then replay the first generation: two windows
	// back is stale delivery, not a retry.
	clock.advance(time.Second)
	if _, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID, Generation: first.Grant.Generation}); err != nil {
		t.Fatal(err)
	}
	if code := refusalCode(t, func() error {
		_, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
			RunID: run.RunID, Generation: 1})
		return err
	}()); code != "stale_generation" {
		t.Fatalf("ancient beat: %s", code)
	}
}

func TestGrantExpirySurvivesRunnerOutage(t *testing.T) {
	// AC-006: a runner outage cannot prevent grant expiration. The
	// runner simply never calls; the sweep fences on the governor's
	// clock alone.
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	clock.advance(GrantLeaseTTL)
	if tripped := g.Sweep(); tripped != 1 {
		t.Fatalf("sweep: %d", tripped)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateFenced {
		t.Fatalf("state: %s", stored.State)
	}
}

func TestValidationRejectsMalformedEnvelopes(t *testing.T) {
	envelope := testEnvelope()
	envelope.Selectors[0].TargetIDs = []string{"not-a-target"}
	envelope.Budgets.MaxDurationS = 0
	envelope.StopRules = []StopRule{{Condition: "wild_condition", Action: ActionTerminate}}
	problems := envelope.ValidateEnvelopeRequest()
	if len(problems) < 3 {
		t.Fatalf("expected target, duration, and condition problems: %+v", problems)
	}
}

func TestValidationRejectsCrossedBudgetCurrencies(t *testing.T) {
	envelope := testEnvelope()
	envelope.Budgets.PerSessionCostMax = Money{Currency: "EUR", Micros: 1}
	problems := envelope.ValidateEnvelopeRequest()
	found := false
	for _, problem := range problems {
		if problem.Check == "currency_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("crossed currencies passed: %+v", problems)
	}
}
