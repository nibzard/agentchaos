package broker

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// stoppedOrder is a minimal valid stop order.
func stoppedOrder() *StopOrder {
	return &StopOrder{
		RunID:   testRun().RunID,
		Sandbox: SandboxPreserve,
		Reason:  "test stop",
	}
}

// commitFixture authorizes and commits the n-th fixture effect; the
// synthetic sink acknowledges, so the effect rests COMMITTED.
func commitFixture(t *testing.T, b *Broker, n int) *Effect {
	t.Helper()
	effect := testEffect()
	effect.ID = sprintfEffectID(n)
	if _, _, err := b.Authorize(servicePrincipal(), effect); err != nil {
		t.Fatal(err)
	}
	committed, err := b.Commit(servicePrincipal(), effect.ID, "idk_commit-"+fmt.Sprint(n))
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("fixture state: %s", committed.State)
	}
	return committed
}

// forceState moves a stored effect to a resting state the happy path
// cannot reach in-process (a crash window), using the lifecycle's own
// edges so the history stays honest.
func forceState(t *testing.T, b *Broker, effectID, state string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	effect, ok := b.effects[effectKey(servicePrincipal().TenantID, effectID)]
	if !ok {
		t.Fatalf("no effect %s", effectID)
	}
	b.transitionTo(effect, state, b.ClockUTC())
}

// stageForReal reproduces the crash window between an acknowledged
// preparation and its dispatch: the sink holds the staged write and
// the record rests PREPARED.
func stageForReal(t *testing.T, b *Broker, effectID string) {
	t.Helper()
	b.mu.Lock()
	effect, ok := b.effects[effectKey(servicePrincipal().TenantID, effectID)]
	if !ok {
		b.mu.Unlock()
		t.Fatalf("no effect %s", effectID)
	}
	preparer, ok := b.sinks[0].(PreparingSink)
	if !ok {
		b.mu.Unlock()
		t.Fatal("the test sink does not stage")
	}
	staged := cloneEffect(effect)
	staged.Dispatch = &Dispatch{IdempotencyKey: "idk_stage-00000001"}
	b.mu.Unlock()
	if result := preparer.Prepare(staged, testNow); result.Outcome != OutcomeAcknowledged {
		t.Fatalf("stage outcome: %s", result.Outcome)
	}
	forceState(t, b, effectID, StatePrepared)
}

func recoveryActions(b *Broker, action string) []EvidenceEvent {
	var found []EvidenceEvent
	for _, event := range b.Events() {
		var payload map[string]any
		if err := json.Unmarshal([]byte(event.Payload.Content), &payload); err != nil {
			continue
		}
		if event.EventKind == "recovery_action" && payload["action"] == action {
			found = append(found, event)
		}
	}
	return found
}

func TestStopFencesRunAndCancelsPending(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	committed := commitFixture(t, broker, 1) // committed A2, uncompensated
	pending := testEffect()
	pending.ID = sprintfEffectID(2)
	if _, _, err := broker.Authorize(servicePrincipal(), pending); err != nil {
		t.Fatal(err)
	}

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalDirty {
		t.Fatalf("terminal: %s (committed A2 without compensation is dirty)", report.TerminalState)
	}
	if len(report.Steps) != 10 || report.Steps[0].Name != StepRevokePermits {
		t.Fatalf("steps: %+v", report.Steps)
	}
	// The pending effect cancelled; the committed one stands.
	if len(report.Inventory.Cancelled) != 1 || report.Inventory.Cancelled[0] != pending.ID {
		t.Fatalf("cancelled inventory: %+v", report.Inventory.Cancelled)
	}
	if len(report.Inventory.Committed) != 1 || report.Inventory.Committed[0] != committed.ID {
		t.Fatalf("committed inventory: %+v", report.Inventory.Committed)
	}
	// New proposals deny: the fence is the permit revocation.
	late := testEffect()
	late.ID = sprintfEffectID(3)
	_, decision, err := broker.Authorize(servicePrincipal(), late)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "run_stopped" {
		t.Fatalf("late proposal: %+v", decision)
	}
	if late, _ := broker.Commit(servicePrincipal(), pending.ID, "idk_late-000001"); late != nil {
		t.Fatalf("pre-stop permit dispatched after the stop: %+v", late)
	}
}

func TestStopIsIdempotentPerRun(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	commitFixture(t, broker, 1)
	first, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	second, err := broker.Stop(servicePrincipal(), &StopOrder{
		RunID: testRun().RunID, Sandbox: SandboxTerminate, // different order, same run
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.TerminalState != first.TerminalState {
		t.Fatalf("replay returned a new report: %s vs %s", second.ID, first.ID)
	}
	if len(recoveryActions(broker, "stop_ordered")) != 1 {
		t.Fatal("a replayed stop re-journaled the order")
	}
}

func TestCleanStopWithCompensation(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	committed := commitFixture(t, broker, 1)
	order := stoppedOrder()
	order.Compensations = []CompensationPlan{{
		EffectID:        committed.ID,
		Operation:       "queue.publish",
		Resource:        "patch-export-beta",
		Destination:     "sink:patch-export-beta",
		ArgumentsDigest: committed.ProposedAction.ArgumentsDigest,
		ActionClass:     ClassA2,
		SizeBytes:       128,
	}}
	report, err := broker.Stop(servicePrincipal(), order)
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalClean {
		t.Fatalf("terminal: %s (%+v)", report.TerminalState, report.Compensations)
	}
	if len(report.Compensations) != 1 || report.Compensations[0].Outcome != StateCommitted {
		t.Fatalf("compensations: %+v", report.Compensations)
	}
	if len(report.Quarantined) != 0 {
		t.Fatalf("quarantined: %+v", report.Quarantined)
	}
	if len(report.Inventory.Compensations) != 1 {
		t.Fatalf("compensation effect missing from inventory: %+v", report.Inventory)
	}
}

func TestCompensationRunsAfterTheGrantEnded(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	committed := commitFixture(t, broker, 1)
	// The stop usually arrives after the experiment grant died.
	broker.mu.Lock()
	broker.runs[testRun().RunID].GrantExpiresAt = testNow
	broker.mu.Unlock()

	order := stoppedOrder()
	order.Compensations = []CompensationPlan{{
		EffectID:        committed.ID,
		Operation:       "queue.publish",
		Resource:        "patch-export-beta",
		Destination:     "sink:patch-export-beta",
		ArgumentsDigest: committed.ProposedAction.ArgumentsDigest,
		ActionClass:     ClassA2,
		SizeBytes:       128,
	}}
	report, err := broker.Stop(servicePrincipal(), order)
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalClean {
		t.Fatalf("terminal: %s (%+v)", report.TerminalState, report.Compensations)
	}
}

func TestDirtyArtifactsAreQuarantinedAndDenied(t *testing.T) {
	secondRun := &RunContext{
		RunID:          "run_2222222222222222",
		TenantID:       testRun().TenantID,
		TaskID:         "task_second-run-0001",
		GrantExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05Z"),
		AllowedClasses: []string{ClassA1, ClassA2},
	}
	broker := New(testPolicy(t), []*RunContext{testRun(), secondRun}, []Sink{&SyntheticSink{}})
	broker.now = fixedClock(t, testNow)
	commitFixture(t, broker, 1)

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalDirty {
		t.Fatalf("terminal: %s", report.TerminalState)
	}
	want := "patch-export-beta@sink:patch-export-beta"
	if len(report.Quarantined) != 1 || report.Quarantined[0] != want {
		t.Fatalf("quarantined: %+v", report.Quarantined)
	}
	if got := broker.Quarantined(servicePrincipal()); len(got) != 1 || got[0] != want {
		t.Fatalf("registry: %+v", got)
	}
	// A new experiment cannot reuse the dirty artifact.
	fresh := testEffect()
	fresh.ID = sprintfEffectID(7)
	fresh.RunID = secondRun.RunID
	_, decision, err := broker.Authorize(servicePrincipal(), fresh)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "resource_quarantined" {
		t.Fatalf("dirty artifact reassigned: %+v", decision)
	}
}

func TestUnresolvedEffectEndsUnknown(t *testing.T) {
	sink := &SyntheticSink{
		Responder:  func(*Effect) SinkResult { return SinkResult{Outcome: OutcomeTimeout} },
		Reconciler: func(*Effect) ReconcileResult { return ReconcileResult{Outcome: ReconciledUnknown} },
	}
	broker := testBroker(t, sink)
	effect := testEffect()
	effect.ID = sprintfEffectID(1)
	if _, _, err := broker.Authorize(servicePrincipal(), effect); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID, "idk_time-00000001"); err != nil {
		t.Fatal(err)
	}

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalUnknown {
		t.Fatalf("terminal: %s (an unresolved outcome cannot verify clean)", report.TerminalState)
	}
	if len(report.Inventory.Unknown) != 1 {
		t.Fatalf("unknown inventory: %+v", report.Inventory.Unknown)
	}
}

func TestPreparedEffectCancelsThroughTheSink(t *testing.T) {
	cancelling := &CancellingTestSink{}
	broker := testBroker(t, cancelling)
	effect := testEffect()
	effect.ID = sprintfEffectID(1)
	if _, _, err := broker.Authorize(servicePrincipal(), effect); err != nil {
		t.Fatal(err)
	}
	stageForReal(t, broker, effect.ID)

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalClean {
		t.Fatalf("terminal: %s (staged write cancelled)", report.TerminalState)
	}
	if len(report.Inventory.Cancelled) != 1 {
		t.Fatalf("inventory: %+v", report.Inventory)
	}
	if !cancelling.Cancelled {
		t.Fatal("the sink never saw the cancellation")
	}
}

func TestPreparedEffectWithoutSinkCancellationStaysUnknown(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{}) // no CancellingSink
	effect := testEffect()
	effect.ID = sprintfEffectID(1)
	if _, _, err := broker.Authorize(servicePrincipal(), effect); err != nil {
		t.Fatal(err)
	}
	stageForReal(t, broker, effect.ID)

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalUnknown {
		t.Fatalf("terminal: %s (a staged write may exist)", report.TerminalState)
	}
	if len(report.Inventory.Unknown) != 1 {
		t.Fatalf("inventory: %+v", report.Inventory)
	}
}

func TestLateReconciliationReopensTheReport(t *testing.T) {
	sink := &SyntheticSink{
		Responder:  func(*Effect) SinkResult { return SinkResult{Outcome: OutcomeTimeout} },
		Reconciler: func(*Effect) ReconcileResult { return ReconcileResult{Outcome: ReconciledUnknown} },
	}
	broker := testBroker(t, sink)
	effect := testEffect()
	effect.ID = sprintfEffectID(1)
	if _, _, err := broker.Authorize(servicePrincipal(), effect); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID, "idk_time-00000001"); err != nil {
		t.Fatal(err)
	}
	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalUnknown || report.Reopened {
		t.Fatalf("report: %s reopened=%v", report.TerminalState, report.Reopened)
	}

	// The service state becomes readable; a late reconciliation
	// resolves the effect and reopens the recorded result.
	sink.Reconciler = func(*Effect) ReconcileResult {
		return ReconcileResult{Outcome: ReconciledNoEffect}
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID, "idk_late-00000001"); err != nil {
		t.Fatal(err)
	}
	stored, err := broker.StopRecord(servicePrincipal(), effect.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Reopened {
		t.Fatal("a late event did not reopen the stop report")
	}
	if len(recoveryActions(broker, "stop_reopened")) != 1 {
		t.Fatal("reopen journaled more than once")
	}
}

func TestInFlightDispatchIsUnknownAndLateCompletionReopens(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	sink := &SyntheticSink{
		Responder: func(*Effect) SinkResult {
			closeOnce(&entered)
			<-release
			return SinkResult{Outcome: OutcomeAcknowledged, ReceiptDigest: "sha256:" + repeat("b", 64)}
		},
	}
	broker := testBroker(t, sink)
	effect := testEffect()
	effect.ID = sprintfEffectID(1)
	if _, _, err := broker.Authorize(servicePrincipal(), effect); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := broker.Commit(servicePrincipal(), effect.ID, "idk_hung-00000001")
		done <- err
	}()
	<-entered // the dispatch is in flight inside the sink

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalUnknown {
		t.Fatalf("terminal: %s (an in-flight send cannot be called off)", report.TerminalState)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stored, _ := broker.StopRecord(servicePrincipal(), effect.RunID)
	if !stored.Reopened {
		t.Fatal("the late completion did not reopen the report")
	}
}

func TestStopFencesDelegationGroups(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	root, err := broker.Delegate(servicePrincipal(), rootRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Stop(servicePrincipal(), stoppedOrder()); err != nil {
		t.Fatal(err)
	}
	stored, err := broker.RevokeDelegation(servicePrincipal(), root.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != DelegationRevoked {
		t.Fatalf("delegation state after stop: %s", stored.State)
	}
	// And no new delegation can be minted under the stopped run.
	nested := rootRequest()
	nested.ID = "dlg_after-stop-01"
	nested.ParentActor = root.ChildActor
	nested.ParentDelegationID = root.ID
	if _, err := broker.Delegate(servicePrincipal(), nested); err == nil {
		t.Fatal("a delegation was minted under a stopped run")
	}
}

func TestStopOrderValidationFailsClosed(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	missing := &StopOrder{RunID: testRun().RunID} // no sandbox
	if _, err := broker.Stop(servicePrincipal(), missing); err == nil {
		t.Fatal("a stop without a sandbox disposition executed")
	}
	badDigest := stoppedOrder()
	badDigest.Compensations = []CompensationPlan{{
		EffectID: "eff_1111111111111111", Operation: "queue.publish",
		Resource: "patch-export-beta", Destination: "sink:patch-export-beta",
		ArgumentsDigest: "not-a-digest", ActionClass: ClassA2,
	}}
	if _, err := broker.Stop(servicePrincipal(), badDigest); err == nil {
		t.Fatal("a plan with a malformed digest executed")
	}
	if _, err := broker.Stop(servicePrincipal(), &StopOrder{
		RunID: "run_unknown00000001", Sandbox: SandboxTerminate,
	}); err == nil {
		t.Fatal("an unknown run stopped")
	}
}

func TestStopRefusesWorkersAndOtherTenants(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	worker := &Principal{ID: "act_worker-reference-01",
		TenantID: testRun().TenantID, Role: RoleWorker}
	if _, err := broker.Stop(worker, stoppedOrder()); err == nil {
		t.Fatal("a worker ordered a stop")
	}
	outsider := &Principal{ID: "act_other-service-01",
		TenantID: "tnt_0000000000000000", Role: RoleService}
	if _, err := broker.Stop(outsider, stoppedOrder()); err == nil {
		t.Fatal("another tenant stopped the run")
	}
}

func TestCompensationTargetMustBeCommitted(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	pending := testEffect()
	pending.ID = sprintfEffectID(1)
	if _, _, err := broker.Authorize(servicePrincipal(), pending); err != nil {
		t.Fatal(err)
	}
	order := stoppedOrder()
	order.Compensations = []CompensationPlan{{
		EffectID:        pending.ID, // AUTHORIZED, not COMMITTED
		Operation:       "queue.publish",
		Resource:        "patch-export-beta",
		Destination:     "sink:patch-export-beta",
		ArgumentsDigest: pending.ProposedAction.ArgumentsDigest,
		ActionClass:     ClassA2,
	}}
	report, err := broker.Stop(servicePrincipal(), order)
	if err != nil {
		t.Fatal(err)
	}
	if report.Compensations[0].Outcome != "DENIED" {
		t.Fatalf("compensation of a non-committed effect: %+v", report.Compensations)
	}
	// The pending effect cancelled, so nothing rests dirty.
	if report.TerminalState != TerminalClean {
		t.Fatalf("terminal: %s", report.TerminalState)
	}
}

// CancellingTestSink is a synthetic sink that supports cancellation.
type CancellingTestSink struct {
	SyntheticSink
	Cancelled bool
}

// Cancel drops the staged write.
func (s *CancellingTestSink) Cancel(*Effect, string) SinkResult {
	s.Cancelled = true
	return SinkResult{Outcome: OutcomeAcknowledged, Detail: "stage dropped"}
}

// closeOnce closes a channel one time only.
func closeOnce(ch *chan struct{}) {
	select {
	case <-*ch:
	default:
		close(*ch)
	}
}
