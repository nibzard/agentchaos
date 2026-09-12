package broker

import (
	"strings"
	"testing"
	"time"
)

// alwaysCleanVerifier claims every stop is clean, whatever the records
// say. The floor merge must override it.
type alwaysCleanVerifier struct{ calls int }

func (v *alwaysCleanVerifier) Name() string { return "always-clean" }

func (v *alwaysCleanVerifier) Verify(report *StopReport) CleanupVerdict {
	v.calls++
	return CleanupVerdict{State: TerminalClean, Detail: "looked fine to me"}
}

// unknownVerifier says nothing can be verified.
type unknownVerifier struct{}

func (unknownVerifier) Name() string { return "cannot-verify" }

func (unknownVerifier) Verify(*StopReport) CleanupVerdict {
	return CleanupVerdict{State: TerminalUnknown, Detail: "no sight of the environment"}
}

func TestVerifierCannotBeatTheRecordsFloor(t *testing.T) {
	broker := New(testPolicy(t), []*RunContext{testRun()}, []Sink{&SyntheticSink{}},
		WithCleanupVerifier(&alwaysCleanVerifier{}))
	broker.now = fixedClock(t, testNow)
	commitFixture(t, broker, 1) // committed A2, uncompensated

	report, err := broker.Stop(servicePrincipal(), stoppedOrder())
	if err != nil {
		t.Fatal(err)
	}
	if report.TerminalState != TerminalDirty {
		t.Fatalf("terminal: %s (an optimistic verifier certified dirt clean)", report.TerminalState)
	}
	if report.Verifier != "always-clean" {
		t.Fatalf("verifier name: %s", report.Verifier)
	}
	if len(report.Quarantined) != 1 {
		t.Fatalf("quarantined: %+v", report.Quarantined)
	}
}

func TestUnknownVerifierWorsensACleanFloor(t *testing.T) {
	broker := New(testPolicy(t), []*RunContext{testRun()}, []Sink{&SyntheticSink{}},
		WithCleanupVerifier(unknownVerifier{}))
	broker.now = fixedClock(t, testNow)
	// Nothing committed and nothing pending: the records floor is clean.
	if _, err := broker.Stop(servicePrincipal(), stoppedOrder()); err != nil {
		t.Fatal(err)
	}
	stored, _ := broker.StopRecord(servicePrincipal(), testRun().RunID)
	if stored.TerminalState != TerminalUnknown {
		t.Fatalf("terminal: %s (cannot verify outranks clean)", stored.TerminalState)
	}
}

func TestQuarantineIsTenantScoped(t *testing.T) {
	otherTenant := "tnt_0000000000000000"
	otherRun := &RunContext{
		RunID:          "run_3333333333333333",
		TenantID:       otherTenant,
		TaskID:         "task_other-tenant-01",
		GrantExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05Z"),
		AllowedClasses: []string{ClassA1, ClassA2},
	}
	broker := New(testPolicy(t), []*RunContext{testRun(), otherRun}, []Sink{&SyntheticSink{}})
	broker.now = fixedClock(t, testNow)
	commitFixture(t, broker, 1)
	if _, err := broker.Stop(servicePrincipal(), stoppedOrder()); err != nil {
		t.Fatal(err)
	}

	// The other tenant starts clean and may still use the resource.
	other := &Principal{ID: "act_other-service-01", TenantID: otherTenant, Role: RoleService}
	if got := broker.Quarantined(other); len(got) != 0 {
		t.Fatalf("one tenant's dirt fenced another tenant: %+v", got)
	}
	proposal := testEffect()
	proposal.ID = sprintfEffectID(2)
	proposal.RunID = otherRun.RunID
	proposal.TenantID = otherTenant
	_, decision, err := broker.Authorize(other, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "allow" {
		t.Fatalf("cross-tenant quarantine leak: %+v", decision)
	}
	// The dirty tenant's own listing still holds the artifact.
	if got := broker.Quarantined(servicePrincipal()); len(got) != 1 {
		t.Fatalf("listing: %+v", got)
	}
}

func TestStopReplayNeverRejournals(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	commitFixture(t, broker, 1)
	if _, err := broker.Stop(servicePrincipal(), stoppedOrder()); err != nil {
		t.Fatal(err)
	}
	before := len(broker.Events())
	for i := 0; i < 3; i++ {
		if _, err := broker.Stop(servicePrincipal(), stoppedOrder()); err != nil {
			t.Fatal(err)
		}
	}
	if after := len(broker.Events()); after != before {
		t.Fatalf("replays appended %d events", after-before)
	}
}

func TestStopDoesNotWaitOnAHungSink(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	sink := &SyntheticSink{
		Responder: func(*Effect) SinkResult {
			closeOnce(&entered)
			<-release
			return SinkResult{Outcome: OutcomeAcknowledged}
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
		_, err := broker.Commit(servicePrincipal(), effect.ID, "idk_hung-00000002")
		done <- err
	}()
	<-entered

	// The stop must conclude while the dispatch hangs; it never blocks
	// on a sink (spec 10.2).
	stopped := make(chan *StopReport, 1)
	go func() {
		report, err := broker.Stop(servicePrincipal(), stoppedOrder())
		if err != nil {
			t.Error(err)
		}
		stopped <- report
	}()
	select {
	case report := <-stopped:
		if report.TerminalState != TerminalUnknown {
			t.Fatalf("terminal: %s (a hung send is unresolved)", report.TerminalState)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stop protocol waited on a hung sink")
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

func TestStopDeniesLateProposalsForEveryReason(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	if _, err := broker.Stop(servicePrincipal(), stoppedOrder()); err != nil {
		t.Fatal(err)
	}
	late := testEffect()
	late.ID = sprintfEffectID(9)
	denied, decision, err := broker.Authorize(servicePrincipal(), late)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "run_stopped" {
		t.Fatalf("late proposal: %+v", decision)
	}
	// Even a proposal that would pass the gate on its own merits denies:
	// the fence does not re-evaluate policy, the run is over.
	if denied.State != StateDenied {
		t.Fatalf("late proposal state: %s", denied.State)
	}
	if !strings.Contains(decision.PolicyRefs[0], "runs.") {
		t.Fatalf("policy refs: %+v", decision.PolicyRefs)
	}
}
