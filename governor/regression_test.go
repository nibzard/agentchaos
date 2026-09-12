package governor

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

// TestEmittedEventsCarryTheirTenant pins the cross-language defect:
// evidence events built from run records used to serialize an empty
// tenant_id, which the shared EvidenceEvent contract rejects.
func TestEmittedEventsCarryTheirTenant(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)
	clock.advance(GrantLeaseTTL)
	g.Sweep()

	events := g.Events()
	if len(events) == 0 {
		t.Fatal("no events emitted")
	}
	for _, event := range events {
		if event.TenantID != run.TenantID {
			t.Fatalf("event %s tenant: %q", event.ID, event.TenantID)
		}
		// The inline payload decodes as JSON with the trip's condition.
		var payload map[string]any
		if err := json.Unmarshal([]byte(event.Payload.Content), &payload); err != nil {
			t.Fatalf("event %s payload: %v", event.ID, err)
		}
		if payload["component"] != "governor" {
			t.Fatalf("event %s component: %v", event.ID, payload["component"])
		}
	}
}

// TestAggregateCeilingUsesSubtractionForm pins the overflow hole:
// recorded spends near the int64 limit must read as over the ceiling,
// never as a wrapped negative total.
func TestAggregateCeilingUsesSubtractionForm(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	envelope := testEnvelope()
	huge := int64(math.MaxInt64 / 4 * 3)
	envelope.Budgets.PerSessionCostMax = Money{Currency: "USD", Micros: huge}
	envelope.Budgets.AggregateCostMax = Money{Currency: "USD", Micros: huge}
	if _, err := g.RegisterEnvelope(servicePrincipal(), envelope); err != nil {
		t.Fatal(err)
	}
	run := startRun(t, g, 1)

	// First session lands exactly at the ceiling: allowed.
	if _, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID,
		SessionSpends: []SessionSpend{{SessionID: "ses_big0000000001",
			Cost: Money{Currency: "USD", Micros: huge}}},
	}); err != nil {
		t.Fatalf("first session: %v", err)
	}
	// A second session at the same size sums past the int64 range: the
	// subtraction form must refuse where the wrapped sum read negative.
	_, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID,
		SessionSpends: []SessionSpend{{SessionID: "ses_big0000000002",
			Cost: Money{Currency: "USD", Micros: huge}}},
	})
	if code := refusalCode(t, err); code != "budget_exhausted" {
		t.Fatalf("wrapped aggregate passed: %v", err)
	}
}

// TestEmergencyStopOverridesStopRules pins the authority hierarchy:
// an envelope that maps operator_request to stop_injection cannot
// weaken the customer emergency control, which terminates.
func TestEmergencyStopOverridesStopRules(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g) // operator_request -> stop_injection
	run := startRun(t, g, 1)

	if _, err := g.EmergencyStop(customerPrincipal(), &EmergencyStopScope{
		Kind: "experiment", ExperimentID: "exp_gate000000001"}); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateStopped {
		t.Fatalf("emergency stop left the run %s", stored.State)
	}
	if !stored.InjectionStopped {
		// Termination implies injection stopped; the flag records it.
		t.Fatalf("terminated run still injects: %+v", stored.Trips)
	}
}

// TestTerminateImpliesInjectionStopped pins the flag on every
// terminating action.
func TestTerminateImpliesInjectionStopped(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	envelope := testEnvelope()
	envelope.StopRules = []StopRule{{Condition: TripEvidencePersistence, Action: ActionTerminate}}
	if _, err := g.RegisterEnvelope(servicePrincipal(), envelope); err != nil {
		t.Fatal(err)
	}
	run := startRun(t, g, 1)
	if err := g.ReportIncident(servicePrincipal(), &Incident{
		RunID: run.RunID, Condition: TripEvidencePersistence}); err != nil {
		t.Fatal(err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateStopped || !stored.InjectionStopped {
		t.Fatalf("terminate left injection live: %+v", stored)
	}
}

// TestFencedExperimentRefusesNewRuns pins the fence's persistence.
func TestFencedExperimentRefusesNewRuns(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	startRun(t, g, 1)

	if _, err := g.EmergencyStop(customerPrincipal(), &EmergencyStopScope{
		Kind: "experiment", ExperimentID: "exp_gate000000001"}); err != nil {
		t.Fatal(err)
	}
	if code := refusalCode(t, startErr(g, "run_govtest000009")); code != "experiment_fenced" {
		t.Fatalf("post-fence start: %s", code)
	}
	// An unknown experiment scope is refused, not silently ignored.
	if _, err := g.EmergencyStop(customerPrincipal(), &EmergencyStopScope{
		Kind: "experiment", ExperimentID: "exp_missing000001"}); err == nil {
		t.Fatal("unknown experiment stopped")
	}
}

// TestHandoffMissingBeforeAnyTrip pins the read: an active run has no
// stop handoff.
func TestHandoffMissingBeforeAnyTrip(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)
	if _, err := g.Handoff(servicePrincipal(), run.RunID); err == nil {
		t.Fatal("active run exposed a stop handoff")
	}
}

// TestOneConditionTripsOnce pins the dedupe across sources: a sweep
// and a late heartbeat cannot double-trip grant_expiry.
func TestOneConditionTripsOnce(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	clock.advance(GrantLeaseTTL + time.Second)
	g.Sweep()
	if _, err := g.Heartbeat(servicePrincipal(), beat(run.RunID)); err == nil {
		t.Fatal("late beat renewed")
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	count := 0
	for _, trip := range stored.Trips {
		if trip.Condition == TripGrantExpiry {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("grant_expiry tripped %d times", count)
	}
}

// TestRetriedBeatAfterExpiryTrips pins the ordering defect: the
// generation no-op used to run before the expiry check, so a retried
// beat arriving after expiry replayed a dead grant as a 200 instead of
// tripping grant_expiry.
func TestRetriedBeatAfterExpiryTrips(t *testing.T) {
	clock := newFixedClock()
	g := New(clock.Now)
	registerEnvelope(t, g)
	run := startRun(t, g, 1)

	// Renew once, let the new lease die, then replay the beat that
	// named the previous generation.
	if _, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	clock.advance(GrantLeaseTTL + time.Second)
	_, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID: run.RunID, Generation: 1})
	if code := refusalCode(t, err); code != "grant_expired" {
		t.Fatalf("retried beat after expiry: %v", err)
	}
	stored, _ := g.Run(servicePrincipal(), run.RunID)
	if stored.State != RunStateFenced {
		t.Fatalf("state: %s", stored.State)
	}
}

// TestEligibleSetExcludesAcrossSelectors pins the precomputed set's
// semantics: an exclusion in ANY selector removes the target, even one
// another selector names.
func TestEligibleSetExcludesAcrossSelectors(t *testing.T) {
	envelope := &Envelope{
		Selectors: []Selector{
			{TargetIDs: []string{"tgt_alpha00000001"}, Exclusions: []string{"tgt_beta000000002"}},
			{TargetIDs: []string{"tgt_beta000000002"}, Exclusions: nil},
		},
	}
	set := eligibleSet(envelope)
	if set["tgt_alpha00000001"] != true {
		t.Fatal("alpha is not eligible")
	}
	if set["tgt_beta000000002"] != false {
		t.Fatal("an excluded target stayed eligible")
	}
}
