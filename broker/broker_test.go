package broker

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testBroker(t *testing.T, sink Sink) *Broker {
	t.Helper()
	b := New(testPolicy(t), []*RunContext{testRun()}, []Sink{sink})
	b.now = func() time.Time {
		parsed, err := time.Parse(time.RFC3339, testNow)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	return b
}

func servicePrincipal() *Principal {
	return &Principal{
		ID:       "act_harness-reference-01",
		TenantID: "tnt_9d4c1e2a3b4f5c67",
		Role:     RoleService,
	}
}

func TestAuthorizeIssuesABoundedPermit(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, decision, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "allow" {
		t.Fatalf("decision: %+v", decision)
	}
	if effect.State != StateAuthorized {
		t.Fatalf("state: %s", effect.State)
	}
	permit := effect.Authorization
	if permit == nil {
		t.Fatal("no permit")
	}
	if permit.TaskID != "task_fixture-close-issue" {
		t.Fatalf("task binding: %s", permit.TaskID)
	}
	if permit.Nonce == "" || !reNonce.MatchString(permit.Nonce) {
		t.Fatalf("nonce: %q", permit.Nonce)
	}
	if permit.SizeLimit == nil || *permit.SizeLimit != 262144 {
		t.Fatalf("size limit: %v", permit.SizeLimit)
	}
	if permit.PolicyDigest == "" || !reDigest.MatchString(permit.PolicyDigest) {
		t.Fatalf("policy digest: %q", permit.PolicyDigest)
	}
	// The grant window ends at 10:30, so the five-minute TTL governs.
	if permit.ExpiresAt != "2026-09-12T10:05:00Z" {
		t.Fatalf("expiry: %s (grant window is 10:30)", permit.ExpiresAt)
	}
	// A second authorization under a fresh id mints a fresh nonce:
	// permits are single-use bindings, not reusable tokens.
	reissued := testEffect()
	reissued.ID = "eff_" + "0f0e0d0c0b0a0908"
	second, _, err := broker.Authorize(servicePrincipal(), reissued)
	if err != nil {
		t.Fatal(err)
	}
	if second.Authorization.Nonce == permit.Nonce {
		t.Fatal("nonce reuse across permits")
	}
	if second.Authorization.SizeLimit == nil || *second.Authorization.SizeLimit != 262144 {
		t.Fatalf("size limit: %v", second.Authorization.SizeLimit)
	}
}

func TestAuthorizeDenialRecordsEffectAndEvent(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect := testEffect()
	effect.ProposedAction.Destination = "https://evil.example.com/exfil"
	denied, decision, err := broker.Authorize(servicePrincipal(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "destination_not_allowed" {
		t.Fatalf("decision: %+v", decision)
	}
	if denied.State != StateDenied {
		t.Fatalf("state: %s", denied.State)
	}
	if denied.Authorization != nil {
		t.Fatal("a denied effect carries no permit (AC-009)")
	}
	events := broker.Events()
	if len(events) != 1 {
		t.Fatalf("decision event count: %d", len(events))
	}
	if events[0].EventKind != "broker_decision" || events[0].EffectID != denied.ID {
		t.Fatalf("event: %+v", events[0])
	}
	if events[0].Sequence != 1 {
		t.Fatalf("sequence: %d", events[0].Sequence)
	}
	if events[0].ID != decision.EvidenceEventID {
		t.Fatal("decision and event id disagree")
	}
}

func TestAuthorizeRejectsWorkerPrincipal(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	worker := &Principal{
		ID: "act_worker-reference-01", TenantID: "tnt_9d4c1e2a3b4f5c67", Role: RoleWorker,
	}
	if _, _, err := broker.Authorize(worker, testEffect()); err == nil {
		t.Fatal("worker issued a permit; workers cannot drive broker authority (spec 18.3)")
	}
}

func TestAuthorizeRejectsTenantMismatch(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	outsider := &Principal{
		ID: "act_other-service-01", TenantID: "tnt_0000000000000000", Role: RoleService,
	}
	if _, _, err := broker.Authorize(outsider, testEffect()); err == nil {
		t.Fatal("cross-tenant authorization succeeded")
	}
}

func TestCommitAcknowledgesAndReconciles(t *testing.T) {
	sink := &SyntheticSink{}
	broker := testBroker(t, sink)
	effect, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	committed, err := broker.Commit(servicePrincipal(), effect.ID)
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("state: %s", committed.State)
	}
	if committed.Dispatch.Outcome != OutcomeAcknowledged {
		t.Fatalf("outcome: %s", committed.Dispatch.Outcome)
	}
	if committed.Receipt == nil || !committed.Receipt.Reconciled {
		t.Fatalf("receipt: %+v", committed.Receipt)
	}
	if !reEventID.MatchString(committed.Receipt.EvidenceEventID) {
		t.Fatalf("receipt event link: %q", committed.Receipt.EvidenceEventID)
	}
	if !reDigest.MatchString(committed.Receipt.Digest) {
		t.Fatalf("receipt digest: %q", committed.Receipt.Digest)
	}
	if len(sink.Receipts) != 1 {
		t.Fatalf("sink receipts: %d", len(sink.Receipts))
	}
	// Decision and receipt events, in order, with increasing sequences.
	events := broker.Events()
	if len(events) != 2 {
		t.Fatalf("events: %d", len(events))
	}
	if events[0].EventKind != "broker_decision" ||
		events[1].EventKind != "external_receipt" {
		t.Fatalf("event kinds: %s, %s", events[0].EventKind, events[1].EventKind)
	}
	if events[1].Sequence <= events[0].Sequence {
		t.Fatal("sequences must increase")
	}
}

func TestCommitTimeoutIsUnknownNotFailed(t *testing.T) {
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeTimeout}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	unknown, err := broker.Commit(servicePrincipal(), effect.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.State != StateUnknown {
		t.Fatalf("state: %s (a timeout is an unknown outcome)", unknown.State)
	}
	if unknown.Dispatch.Outcome != OutcomeTimeout {
		t.Fatalf("outcome: %s", unknown.Dispatch.Outcome)
	}
	if unknown.Receipt != nil && unknown.Receipt.Reconciled {
		t.Fatal("unreconciled timeout recorded as reconciled")
	}
}

func TestCommitFailureCancels(t *testing.T) {
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "connection refused"}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	cancelled, err := broker.Commit(servicePrincipal(), effect.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != StateCancelled {
		t.Fatalf("state: %s (the send never took effect)", cancelled.State)
	}
}

func TestCommitRejectsSecondCommit(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err == nil {
		t.Fatal("double commit accepted; lifecycle is append-only")
	}
}

func TestCommitOnDeniedEffectIsRefused(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect := testEffect()
	effect.ProposedAction.Destination = "https://evil.example.com/exfil"
	denied, _, _ := broker.Authorize(servicePrincipal(), effect)
	if _, err := broker.Commit(servicePrincipal(), denied.ID); err == nil {
		t.Fatal("denied effect committed")
	}
}

func TestCommitWithExpiredPermitTransitionsToExpired(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	broker.now = func() time.Time {
		parsed, _ := time.Parse(time.RFC3339, "2026-09-12T10:06:00Z")
		return parsed
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err == nil {
		t.Fatal("expired permit committed")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error: %v", err)
	}
	stored := broker.Effects()[0]
	if stored.State != StateExpired {
		t.Fatalf("state: %s", stored.State)
	}
}

func TestCommitWithoutSinkFailsClosed(t *testing.T) {
	broker := New(testPolicy(t), []*RunContext{testRun()}, nil) // no sinks
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err == nil {
		t.Fatal("dispatch without a sink succeeded; unsupported destinations fail closed")
	}
}

func TestCrossTenantEffectLookupIsNotFound(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	outsider := &Principal{
		ID: "act_other-service-01", TenantID: "tnt_0000000000000000", Role: RoleService,
	}
	if _, err := broker.Commit(outsider, effect.ID); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("cross-tenant lookup leaked: %v", err)
	}
}

func TestAuthorizeRejectsDuplicateEffectID(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	if _, _, err := broker.Authorize(servicePrincipal(), testEffect()); err != nil {
		t.Fatal(err)
	}
	// The lifecycle is append-only under one id: a re-proposal must
	// use a fresh effect id, or a COMMITTED record could be replaced.
	if _, _, err := broker.Authorize(servicePrincipal(), testEffect()); err == nil {
		t.Fatal("re-proposal under a used id accepted")
	}
	if len(broker.Effects()) != 1 {
		t.Fatalf("stored effects: %d", len(broker.Effects()))
	}
}

func TestEffectIDsDoNotCollideAcrossTenants(t *testing.T) {
	other := &RunContext{
		RunID:          "run_1111111111111111",
		TenantID:       "tnt_0000000000000000",
		TaskID:         "task_other-tenant-01",
		GrantExpiresAt: "2026-09-12T10:30:00Z",
		AllowedClasses: []string{ClassA1, ClassA2},
	}
	broker := New(testPolicy(t), []*RunContext{testRun(), other}, []Sink{&SyntheticSink{}})
	broker.now = fixedClock(t, testNow)

	ours := testEffect()
	if _, _, err := broker.Authorize(servicePrincipal(), ours); err != nil {
		t.Fatal(err)
	}
	theirs := testEffect()
	theirs.TenantID = other.TenantID
	theirs.RunID = other.RunID
	outsider := &Principal{ID: "act_other-service-01", TenantID: other.TenantID, Role: RoleService}
	if _, _, err := broker.Authorize(outsider, theirs); err != nil {
		t.Fatalf("same id under another tenant refused: %v", err)
	}
	if len(broker.Effects()) != 2 {
		t.Fatalf("expected two tenant-scoped records, got %d", len(broker.Effects()))
	}
}

func TestCommitWithNilPrincipalIsUnauthorized(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	// The nil guard must run before any principal field is read.
	if _, err := broker.Commit(nil, effect.ID); err == nil ||
		!strings.Contains(err.Error(), "unauthenticated") {
		t.Fatalf("nil principal: %v", err)
	}
}

func TestCommitAfterUnknownOutcomeIsRefused(t *testing.T) {
	// AC-010: a timeout after dispatch is fenced behind
	// reconciliation; a second commit never blindly reissues.
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeTimeout}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err == nil {
		t.Fatal("retry after UNKNOWN_EFFECT accepted")
	}
}

func TestCommitAfterCancellationIsRefused(t *testing.T) {
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "connection refused"}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err == nil {
		t.Fatal("second commit after CANCELLED accepted")
	}
}

func TestFailedDispatchRecordsAnEvent(t *testing.T) {
	// Every attempted dispatch lands in the evidence journal, even
	// when the send failed (spec 9.4: no silent gaps).
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "connection refused"}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID); err != nil {
		t.Fatal(err)
	}
	events := broker.Events()
	if len(events) != 2 {
		t.Fatalf("events: %d (decision and failed receipt expected)", len(events))
	}
	if events[1].EventKind != "external_receipt" {
		t.Fatalf("second event: %+v", events[1])
	}
}

func TestUnrecognizedSinkOutcomeStaysUnknown(t *testing.T) {
	// A sink reporting an outcome the broker does not recognize can
	// never be recorded as "no effect happened" (AC-010, AC-022).
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: "queued"}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	result, err := broker.Commit(servicePrincipal(), effect.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateUnknown {
		t.Fatalf("unrecognized outcome classified as %s", result.State)
	}
	if result.Dispatch.Outcome != OutcomeTimeout {
		t.Fatalf("dispatch outcome %q is outside the contract enum", result.Dispatch.Outcome)
	}
	if result.Receipt == nil || result.Receipt.Reconciled {
		t.Fatalf("receipt: %+v", result.Receipt)
	}
	// The raw sink report survives in the event payload.
	events := broker.Events()
	if len(events) != 2 {
		t.Fatalf("events: %d", len(events))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(events[1].Payload.Content), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["outcome"] != "queued" {
		t.Fatalf("raw outcome lost: %+v", payload)
	}
}

func TestAuthorizeClampsPermitToGrantWindow(t *testing.T) {
	run := testRun()
	run.GrantExpiresAt = "2026-09-12T10:02:00Z" // ends before the TTL
	broker := New(testPolicy(t), []*RunContext{run}, []Sink{&SyntheticSink{}})
	broker.now = fixedClock(t, testNow)
	effect, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	if effect.Authorization.ExpiresAt != "2026-09-12T10:02:00Z" {
		t.Fatalf("permit outlives the grant: %s", effect.Authorization.ExpiresAt)
	}
}

func TestAuthorizeDeniesUnknownRunAtBrokerLevel(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect := testEffect()
	effect.RunID = "run_1111111111111111"
	denied, decision, err := broker.Authorize(servicePrincipal(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "run_unknown" {
		t.Fatalf("decision: %+v", decision)
	}
	if denied.State != StateDenied {
		t.Fatalf("state: %s", denied.State)
	}
	if len(broker.Events()) != 1 {
		t.Fatalf("decision event missing: %d", len(broker.Events()))
	}
}

func TestConcurrentAuthorizeAndCommitAreRaceFree(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	const workers = 24
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			effect := testEffect()
			effect.ID = fmt.Sprintf("eff_%016d", i)
			if _, _, err := broker.Authorize(servicePrincipal(), effect); err != nil {
				t.Error(err)
				return
			}
			if i%2 == 0 {
				if _, err := broker.Commit(servicePrincipal(), effect.ID); err != nil {
					t.Error(err)
				}
			}
			_ = broker.Events()
			_ = broker.Effects()
		}(i)
	}
	group.Wait()
	if len(broker.Effects()) != workers {
		t.Fatalf("stored effects: %d", len(broker.Effects()))
	}
}

func fixedClock(t *testing.T, moment string) func() time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, moment)
	if err != nil {
		t.Fatal(err)
	}
	return func() time.Time { return parsed }
}
