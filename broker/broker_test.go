package broker

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	committed, err := broker.Commit(servicePrincipal(), effect.ID, "idk_commit-permit-01")
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("state: %s", committed.State)
	}
	if committed.Dispatch.Outcome != OutcomeAcknowledged {
		t.Fatalf("outcome: %s", committed.Dispatch.Outcome)
	}
	if committed.Dispatch.IdempotencyKey != "idk_commit-permit-01" {
		t.Fatalf("dispatch idempotency key: %q", committed.Dispatch.IdempotencyKey)
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
	// The synthetic service supports preparation, so the lifecycle
	// passes through PREPARED before COMMITTING (spec 10.1).
	if len(sink.Staged) != 1 || sink.Staged[0].IdempotencyKey != "idk_commit-permit-01" {
		t.Fatalf("staged writes: %+v", sink.Staged)
	}
	if !hasTransition(committed, StatePrepared) || !hasTransition(committed, StateCommitting) {
		t.Fatalf("transitions: %+v", committed.Transitions)
	}
	// Decision, stage, and receipt events, in order, with increasing
	// sequences.
	events := broker.Events()
	if len(events) != 3 {
		t.Fatalf("events: %d", len(events))
	}
	if events[0].EventKind != "broker_decision" ||
		events[1].EventKind != "tool_request" ||
		events[2].EventKind != "external_receipt" {
		t.Fatalf("event kinds: %s, %s, %s",
			events[0].EventKind, events[1].EventKind, events[2].EventKind)
	}
	for i := 1; i < len(events); i++ {
		if events[i].Sequence <= events[i-1].Sequence {
			t.Fatal("sequences must increase")
		}
	}
}

func hasTransition(effect *Effect, state string) bool {
	for _, transition := range effect.Transitions {
		if transition.State == state {
			return true
		}
	}
	return false
}

func TestCommitTimeoutIsUnknownNotFailed(t *testing.T) {
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeTimeout}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	unknown, err := broker.Commit(servicePrincipal(), effect.ID, "")
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
	cancelled, err := broker.Commit(servicePrincipal(), effect.ID, "")
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
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err == nil {
		t.Fatal("double commit accepted; lifecycle is append-only")
	}
}

func TestCommitOnDeniedEffectIsRefused(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect := testEffect()
	effect.ProposedAction.Destination = "https://evil.example.com/exfil"
	denied, _, _ := broker.Authorize(servicePrincipal(), effect)
	if _, err := broker.Commit(servicePrincipal(), denied.ID, ""); err == nil {
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
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err == nil {
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
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err == nil {
		t.Fatal("dispatch without a sink succeeded; unsupported destinations fail closed")
	}
}

func TestCrossTenantEffectLookupIsNotFound(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	outsider := &Principal{
		ID: "act_other-service-01", TenantID: "tnt_0000000000000000", Role: RoleService,
	}
	if _, err := broker.Commit(outsider, effect.ID, ""); err == nil ||
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
	if _, err := broker.Commit(nil, effect.ID, ""); err == nil ||
		!strings.Contains(err.Error(), "unauthenticated") {
		t.Fatalf("nil principal: %v", err)
	}
}

func TestRetryAfterUnknownReconcilesWithoutReissue(t *testing.T) {
	// AC-010: the retry on an UNKNOWN_EFFECT effect performs a state
	// read, never a second send. The default reconciler finds no
	// receipt, so the send never took effect: CANCELLED.
	dispatches := 0
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		dispatches++
		return SinkResult{Outcome: OutcomeTimeout}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	resolved, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != StateCancelled {
		t.Fatalf("reconciled state: %s (no receipt means no send)", resolved.State)
	}
	if resolved.Receipt == nil || resolved.Receipt.Reconciled {
		t.Fatalf("receipt after no_effect reconcile: %+v", resolved.Receipt)
	}
	if dispatches != 1 {
		t.Fatalf("reconcile reissued the send: %d dispatches", dispatches)
	}
	kinds := eventKinds(broker)
	if !contains(kinds, "recovery_action") {
		t.Fatalf("recovery_action event missing: %v", kinds)
	}
}

func TestReconcileFindsCommittedSend(t *testing.T) {
	// The state read finds the send took effect: the effect commits
	// with a reconciled receipt and no second dispatch.
	dispatches := 0
	sink := &SyntheticSink{
		Responder: func(*Effect) SinkResult {
			dispatches++
			return SinkResult{Outcome: OutcomeTimeout}
		},
		Reconciler: func(effect *Effect) ReconcileResult {
			return ReconcileResult{
				Outcome:       ReconciledCommitted,
				ReceiptDigest: receiptDigest(effect),
				Detail:        "service journal shows the write",
			}
		},
	}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	resolved, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != StateCommitted {
		t.Fatalf("state: %s", resolved.State)
	}
	if resolved.Receipt == nil || !resolved.Receipt.Reconciled {
		t.Fatalf("receipt: %+v", resolved.Receipt)
	}
	if !reDigest.MatchString(resolved.Receipt.Digest) {
		t.Fatalf("receipt digest: %q", resolved.Receipt.Digest)
	}
	if dispatches != 1 {
		t.Fatalf("reconcile dispatched again: %d dispatches", dispatches)
	}
}

func TestReconcileUnknownThenLaterResolved(t *testing.T) {
	// The read stays unresolved, then resolves: the chain keeps the
	// UNKNOWN_EFFECT state until the read answers, then commits.
	reads := 0
	sink := &SyntheticSink{
		Responder: func(*Effect) SinkResult {
			return SinkResult{Outcome: OutcomeTimeout}
		},
		Reconciler: func(effect *Effect) ReconcileResult {
			reads++
			if reads < 2 {
				return ReconcileResult{Outcome: ReconciledUnknown, Detail: "service still starting"}
			}
			return ReconcileResult{
				Outcome:       ReconciledCommitted,
				ReceiptDigest: receiptDigest(effect),
				Detail:        "service journal shows the write",
			}
		},
	}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		state, err := broker.Commit(servicePrincipal(), effect.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		want := StateUnknown
		if i == 1 {
			want = StateCommitted
		}
		if state.State != want {
			t.Fatalf("read %d: state %s, want %s", reads, state.State, want)
		}
	}
	if again, err := broker.Commit(servicePrincipal(), effect.ID, ""); err == nil {
		t.Fatalf("committed effect committed again: %+v", again)
	}
	if reads != 2 {
		t.Fatalf("state reads: %d", reads)
	}
}

func TestReconcileStillUnknownKeepsState(t *testing.T) {
	// The state read cannot resolve yet: the state stands and the
	// attempt is journaled as a recovery action.
	sink := &SyntheticSink{
		Responder: func(*Effect) SinkResult {
			return SinkResult{Outcome: OutcomeTimeout}
		},
		Reconciler: func(*Effect) ReconcileResult {
			return ReconcileResult{Outcome: ReconciledUnknown, Detail: "service still starting"}
		},
	}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	still, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if still.State != StateUnknown {
		t.Fatalf("state: %s", still.State)
	}
	kinds := eventKinds(broker)
	if !contains(kinds, "recovery_action") {
		t.Fatalf("recovery_action event missing: %v", kinds)
	}
}

func TestReconcileWithoutStateReadIsRefused(t *testing.T) {
	// A destination with no state read declares the limitation: the
	// reconciliation is manual and the commit refuses (spec 10.1).
	sink := &dispatchOnlySink{outcome: OutcomeTimeout}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err == nil || !strings.Contains(err.Error(), "reconciliation is manual") {
		t.Fatalf("retry without a state read: %v", err)
	}
}

func TestDispatchWithoutPreparingSinkSkipsStage(t *testing.T) {
	// Where the service supports no preparation, dispatch runs
	// directly from AUTHORIZED; the limitation is declared by the
	// absence of a stage event, not by a fabricated one.
	sink := &dispatchOnlySink{outcome: OutcomeAcknowledged}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	committed, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("state: %s", committed.State)
	}
	if hasTransition(committed, StatePrepared) {
		t.Fatalf("stage fabricated for a service without preparation: %+v",
			committed.Transitions)
	}
	kinds := eventKinds(broker)
	if contains(kinds, "tool_request") {
		t.Fatalf("stage event fabricated: %v", kinds)
	}
}

func TestPrepareFailureCancelsWithoutSending(t *testing.T) {
	sink := &SyntheticSink{Preparer: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "staging quota exceeded"}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	cancelled, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != StateCancelled {
		t.Fatalf("state: %s (nothing was sent)", cancelled.State)
	}
	if len(sink.Receipts) != 0 {
		t.Fatalf("failed stage still sent: %+v", sink.Receipts)
	}
	if !hasTransition(cancelled, StateCancelled) || hasTransition(cancelled, StateCommitting) {
		t.Fatalf("transitions: %+v", cancelled.Transitions)
	}
}

func TestPrepareTimeoutStaysUnknown(t *testing.T) {
	// A staged write may exist when the stage request times out, so
	// the effect is unknown, never cancelled (AC-010).
	sink := &SyntheticSink{Preparer: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeTimeout}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	unknown, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if unknown.State != StateUnknown {
		t.Fatalf("state: %s", unknown.State)
	}
	if unknown.Receipt != nil && unknown.Receipt.Reconciled {
		t.Fatalf("receipt: %+v", unknown.Receipt)
	}
	if len(sink.Receipts) != 0 {
		t.Fatalf("timed-out stage still sent: %+v", sink.Receipts)
	}
}

func TestCompensatingEffectLifecycle(t *testing.T) {
	// A compensation is a new authorized effect that references a
	// COMMITTED original (spec 10.1). It dispatches as COMPENSATING
	// and keeps its own state; the original is untouched.
	sink := &SyntheticSink{}
	broker := testBroker(t, sink)
	original, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), original.ID, ""); err != nil {
		t.Fatal(err)
	}

	compensation := testEffect()
	compensation.ID = "eff_1f1e1d1c1b1a1918"
	compensation.CompensationOf = original.ID
	authorized, decision, err := broker.Authorize(servicePrincipal(), compensation)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "allow" {
		t.Fatalf("decision: %+v", decision)
	}
	if authorized.CompensationOf != original.ID {
		t.Fatalf("compensation reference lost: %q", authorized.CompensationOf)
	}

	result, err := broker.Commit(servicePrincipal(), authorized.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateCommitted {
		t.Fatalf("state: %s", result.State)
	}
	if !hasTransition(result, StateCompensating) {
		t.Fatalf("no COMPENSATING phase: %+v", result.Transitions)
	}
	if len(sink.Receipts) != 2 {
		t.Fatalf("sends: %d (original and compensation)", len(sink.Receipts))
	}

	stillOriginal := false
	for _, effect := range broker.Effects() {
		if effect.ID == original.ID && effect.State == StateCommitted &&
			effect.CompensationOf == "" {
			stillOriginal = true
		}
	}
	if !stillOriginal {
		t.Fatal("the compensated original changed state")
	}
}

func TestCompensationOfCompensationIsAllowed(t *testing.T) {
	// The spec calls a compensation "a new authorized effect"; it puts
	// no restriction on what the COMMITTED original is. This pins the
	// behavior: a chain is allowed, and each link keeps its own
	// record and its own compensation_of reference.
	broker := testBroker(t, &SyntheticSink{})
	first, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), first.ID, ""); err != nil {
		t.Fatal(err)
	}

	second := testEffect()
	second.ID = "eff_7a7b7c7d7e7f7071"
	second.CompensationOf = first.ID
	secondAuthorized, _, err := broker.Authorize(servicePrincipal(), second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), secondAuthorized.ID, ""); err != nil {
		t.Fatal(err)
	}

	third := testEffect()
	third.ID = "eff_8a8b8c8d8e8f8081"
	third.CompensationOf = secondAuthorized.ID
	thirdAuthorized, decision, err := broker.Authorize(servicePrincipal(), third)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "allow" {
		t.Fatalf("chained compensation denied: %+v", decision)
	}
	committed, err := broker.Commit(servicePrincipal(), thirdAuthorized.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted ||
		committed.CompensationOf != secondAuthorized.ID {
		t.Fatalf("chained compensation: %+v", committed)
	}
}

func TestAuthorizeDeniesInvalidCompensationTarget(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})

	// A reference to an effect that does not exist.
	missing := testEffect()
	missing.ID = "eff_2f2e2d2c2b2a2928"
	missing.CompensationOf = "eff_0000000000000000"
	_, decision, err := broker.Authorize(servicePrincipal(), missing)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "compensation_target_invalid" {
		t.Fatalf("missing target decision: %+v", decision)
	}

	// A reference to an effect that exists but is not COMMITTED.
	denied := testEffect()
	denied.ID = "eff_3f3e3d3c3b3a3938"
	denied.ProposedAction.Destination = "https://evil.example.com/exfil"
	deniedEffect, _, err := broker.Authorize(servicePrincipal(), denied)
	if err != nil {
		t.Fatal(err)
	}
	deniedReference := testEffect()
	deniedReference.ID = "eff_4f4e4d4c4b4a4948"
	deniedReference.CompensationOf = deniedEffect.ID
	authorizedDenied, _, err := broker.Authorize(servicePrincipal(), deniedReference)
	if err != nil {
		t.Fatal(err)
	}
	if authorizedDenied.State != StateDenied {
		t.Fatalf("state: %s", authorizedDenied.State)
	}

	// Cross-tenant: another tenant's COMMITTED effect under the same
	// id never satisfies the reference (spec 18.3 tenant scoping).
	other := &RunContext{
		RunID:          "run_1111111111111111",
		TenantID:       "tnt_0000000000000000",
		TaskID:         "task_other-tenant-01",
		GrantExpiresAt: "2026-09-12T10:30:00Z",
		AllowedClasses: []string{ClassA1, ClassA2},
	}
	twoTenants := New(testPolicy(t), []*RunContext{testRun(), other}, []Sink{&SyntheticSink{}})
	twoTenants.now = fixedClock(t, testNow)
	sharedID := "eff_5f5e5d5c5b5a5958"
	theirs := testEffect()
	theirs.ID = sharedID
	theirs.TenantID = other.TenantID
	theirs.RunID = other.RunID
	outsider := &Principal{ID: "act_other-service-01", TenantID: other.TenantID, Role: RoleService}
	committed, _, err := twoTenants.Authorize(outsider, theirs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := twoTenants.Commit(outsider, committed.ID, ""); err != nil {
		t.Fatal(err)
	}
	ours := testEffect()
	ours.ID = "eff_6f6e6d6c6b6a6968"
	ours.CompensationOf = sharedID
	_, crossTenant, err := twoTenants.Authorize(servicePrincipal(), ours)
	if err != nil {
		t.Fatal(err)
	}
	if crossTenant.Verdict != "deny" || crossTenant.Reason != "compensation_target_invalid" {
		t.Fatalf("cross-tenant target decision: %+v", crossTenant)
	}
}

func TestCommitRejectsTaskBindingMismatch(t *testing.T) {
	// The permit binds the task; if the run's task changed, the
	// record is inconsistent and never dispatches (spec 10).
	broker := testBroker(t, &SyntheticSink{})
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	broker.runs[effect.RunID].TaskID = "task_reassigned-99"
	_, err := broker.Commit(servicePrincipal(), effect.ID, "")
	if err == nil || !strings.Contains(err.Error(), "task binding") {
		t.Fatalf("mismatched task binding dispatched: %v", err)
	}
}

func eventKinds(broker *Broker) []string {
	var kinds []string
	for _, event := range broker.Events() {
		kinds = append(kinds, event.EventKind)
	}
	return kinds
}

// dispatchOnlySink implements the base Sink contract only: no
// preparation, no state read. It stands for a service that supports
// neither (spec 10.1: declare the limitation).
type dispatchOnlySink struct {
	mu       sync.Mutex
	outcome  string
	dispatch int
}

func (s *dispatchOnlySink) Name() string { return "dispatch-only-sink" }

func (s *dispatchOnlySink) Supports(destination string) bool {
	return strings.HasPrefix(destination, "sink:")
}

func (s *dispatchOnlySink) Dispatch(effect *Effect, now string) SinkResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatch++
	return SinkResult{Outcome: s.outcome, ReceiptDigest: receiptDigest(effect)}
}

func TestCommitAfterCancellationIsRefused(t *testing.T) {
	sink := &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "connection refused"}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err == nil {
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
	if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
		t.Fatal(err)
	}
	events := broker.Events()
	if len(events) != 3 {
		t.Fatalf("events: %d (decision, stage, and failed receipt expected)", len(events))
	}
	if events[1].EventKind != "tool_request" ||
		events[2].EventKind != "external_receipt" {
		t.Fatalf("event kinds: %s, %s", events[1].EventKind, events[2].EventKind)
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
	result, err := broker.Commit(servicePrincipal(), effect.ID, "")
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
	if len(events) != 3 {
		t.Fatalf("events: %d", len(events))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(events[2].Payload.Content), &payload); err != nil {
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
				if _, err := broker.Commit(servicePrincipal(), effect.ID, ""); err != nil {
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

func TestConcurrentCommitsOfOneEffectDispatchOnce(t *testing.T) {
	// The per-effect dispatch gate serializes commit attempts: the
	// sink sees exactly one send no matter how many commits race.
	var dispatches atomic.Int64
	sink := &SyntheticSink{Responder: func(effect *Effect) SinkResult {
		dispatches.Add(1)
		return SinkResult{Outcome: OutcomeAcknowledged, ReceiptDigest: receiptDigest(effect)}
	}}
	broker := testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())

	const callers = 12
	var group sync.WaitGroup
	succeeded := atomic.Int64{}
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			if _, err := broker.Commit(servicePrincipal(), effect.ID,
				fmt.Sprintf("idk_race-commit-%02d", i)); err == nil {
				succeeded.Add(1)
			}
		}(i)
	}
	group.Wait()
	if got := dispatches.Load(); got != 1 {
		t.Fatalf("sink saw %d dispatches for one effect", got)
	}
	if succeeded.Load() != 1 {
		t.Fatalf("%d commits reported success", succeeded.Load())
	}
	stored := broker.Effects()[0]
	if stored.State != StateCommitted {
		t.Fatalf("state: %s", stored.State)
	}
}

func TestSinkCallingBackIntoBrokerDoesNotDeadlock(t *testing.T) {
	// Sink calls run with the broker lock released, so a sink that
	// reads the journal mid-dispatch cannot deadlock the broker
	// (sync.Mutex is not reentrant).
	var broker *Broker
	sink := &SyntheticSink{Responder: func(effect *Effect) SinkResult {
		_ = broker.Events()
		_ = broker.Effects()
		return SinkResult{Outcome: OutcomeAcknowledged, ReceiptDigest: receiptDigest(effect)}
	}}
	broker = testBroker(t, sink)
	effect, _, _ := broker.Authorize(servicePrincipal(), testEffect())

	done := make(chan error, 1)
	go func() {
		_, err := broker.Commit(servicePrincipal(), effect.ID, "")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch deadlocked: sink callbacks must not run under b.mu")
	}
}

func TestConcurrentDuplicateAuthorizeJournalsOneDecision(t *testing.T) {
	// Racing proposals under one effect id (the HTTP ledger only
	// serializes shared idempotency keys): exactly one decision event
	// and one stored record, so the journal never carries an orphaned
	// decision for an effect that was never stored.
	broker := testBroker(t, &SyntheticSink{})
	const callers = 12
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, _, _ = broker.Authorize(servicePrincipal(), testEffect())
		}()
	}
	group.Wait()
	if len(broker.Effects()) != 1 {
		t.Fatalf("stored effects: %d", len(broker.Effects()))
	}
	decisions := 0
	for _, event := range broker.Events() {
		if event.EventKind == "broker_decision" {
			decisions++
		}
	}
	if decisions != 1 {
		t.Fatalf("one effect id produced %d decision events", decisions)
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
