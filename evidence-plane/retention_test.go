package evidence

import (
	"fmt"
	"testing"
	"time"
)

// operatorPrincipal is the fixture retention authority.
func operatorPrincipal() *Principal {
	return &Principal{ID: "act_operator-ona01", TenantID: testTenant,
		Role: RoleOperator}
}

// servicePrincipal is the supervisor system.
func servicePrincipal() *Principal {
	return &Principal{ID: "act_service-governor", TenantID: testTenant,
		Role: RoleService}
}

// movableClock builds a recorder clock the test can advance, so a
// retention pass sees events that have aged past a window without
// fabricating stale observed_at stamps (which would raise clock
// findings of their own).
func movableClock(t *testing.T) (func() time.Time, *time.Time) {
	t.Helper()
	base, err := time.Parse(time.RFC3339Nano, testNow)
	if err != nil {
		t.Fatal(err)
	}
	current := base
	return func() time.Time { return current }, &current
}

// objectRefEvent is a valid collector fact carrying an object
// reference instead of inline content.
func objectRefEvent(n int) *Event {
	event := collectorEvent(n)
	event.Payload = EventPayload{
		Kind: PayloadObjectRef,
		StorageRef: fmt.Sprintf(
			"obj://runs/%s/blob-%d", testRunID, n),
		Digest:      fmt.Sprintf("sha256:%064d", n),
		SizeBytes:   4096,
		ContentType: "application/octet-stream",
	}
	return event
}

// metadataEvent carries nothing but its own shape.
func metadataEvent(n int) *Event {
	event := collectorEvent(n)
	event.Payload = EventPayload{Kind: PayloadMetadataOnly}
	return event
}

func ingest(t *testing.T, recorder *Recorder, events ...*Event) {
	t.Helper()
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: events}); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultRetentionWindowsMatchSpec(t *testing.T) {
	policy := DefaultRetentionPolicy()
	if policy.RawPayloads != 7*24*time.Hour {
		t.Fatalf("raw payload window: %v", policy.RawPayloads)
	}
	if policy.DetailedEvents != 30*24*time.Hour {
		t.Fatalf("detailed event window: %v", policy.DetailedEvents)
	}
}

func TestRetentionTombstonesObjectRefsPastTheRawWindow(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, objectRefEvent(0))
	head, length := mustChain(t, recorder)
	if length != 1 {
		t.Fatalf("chain length: %d", length)
	}

	*now = (*now).Add(8 * 24 * time.Hour)
	outcome, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		RetentionPolicy{RawPayloads: 7 * 24 * time.Hour,
			DetailedEvents: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.ObjectRefsTombstoned != 1 || outcome.InlineDowngraded != 0 {
		t.Fatalf("outcome: %+v", outcome)
	}

	events, err := recorder.Events(collectorPrincipal(),
		EventQuery{RunID: testRunID})
	if err != nil {
		t.Fatal(err)
	}
	live := events[0].Payload
	if !live.Tombstone {
		t.Fatal("the live reference is not tombstoned")
	}
	if live.Digest == "" || live.StorageRef == "" {
		t.Fatal("a tombstone must keep naming what existed")
	}

	// The chain is untouched by retention.
	headAfter, lengthAfter := mustChain(t, recorder)
	if headAfter != head || lengthAfter != length {
		t.Fatal("retention changed the chain")
	}
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact {
		t.Fatalf("verification broke: %+v", report)
	}
}

func TestRetentionDowngradesInlinePastTheDetailedWindow(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, collectorEvent(0)) // inline payload

	*now = (*now).Add(31 * 24 * time.Hour)
	outcome, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.InlineDowngraded != 1 || outcome.ObjectRefsTombstoned != 0 {
		t.Fatalf("outcome: %+v", outcome)
	}

	events, err := recorder.Events(collectorPrincipal(),
		EventQuery{RunID: testRunID})
	if err != nil {
		t.Fatal(err)
	}
	live := events[0]
	if live.Payload.Kind != PayloadMetadataOnly ||
		live.Payload.Content != "" || !live.Payload.Redacted {
		t.Fatalf("live payload not downgraded: %+v", live.Payload)
	}
	if errs := live.ValidateEvent(); len(errs) != 0 {
		t.Fatalf("downgraded event left the contract: %+v", errs)
	}

	// The chained original still proves what was captured.
	if recorder.tenants[testTenant].events[0].event.Payload.Content ==
		"" {
		t.Fatal("retention edited the chained original")
	}
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact {
		t.Fatalf("verification broke: %+v", report)
	}
}

func TestRetentionSkipsFreshContent(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, objectRefEvent(0), collectorEvent(1))

	*now = (*now).Add(2 * 24 * time.Hour)
	outcome, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.ObjectRefsTombstoned != 0 || outcome.InlineDowngraded != 0 ||
		outcome.Held != 0 {
		t.Fatalf("fresh content expired: %+v", outcome)
	}
	events, err := recorder.Events(collectorPrincipal(),
		EventQuery{RunID: testRunID})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Payload.Tombstone ||
			event.Payload.Kind == PayloadMetadataOnly &&
				event.ID == "evt_"+fmt.Sprintf("%016d", 1) {
			t.Fatalf("fresh event changed: %+v", event.Payload)
		}
	}
}

func TestMetadataOnlyEventsAreAlreadyMinimal(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, metadataEvent(0))

	*now = (*now).Add(365 * 24 * time.Hour)
	outcome, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.ObjectRefsTombstoned != 0 || outcome.InlineDowngraded != 0 {
		t.Fatalf("metadata-only event touched: %+v", outcome)
	}
}

func TestLegalHoldBlocksRetention(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, objectRefEvent(0), collectorEvent(1))

	if err := recorder.SetLegalHold(operatorPrincipal(), testRunID,
		"pending litigation", time.Time{}); err != nil {
		t.Fatal(err)
	}

	*now = (*now).Add(40 * 24 * time.Hour)
	outcome, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Held != 2 || outcome.ObjectRefsTombstoned != 0 ||
		outcome.InlineDowngraded != 0 {
		t.Fatalf("held content expired: %+v", outcome)
	}

	holds, err := recorder.LegalHolds(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 1 || holds[0].RunID != testRunID ||
		holds[0].Reason != "pending litigation" {
		t.Fatalf("holds: %+v", holds)
	}
	if holds[0].HeldBy != "act_operator-ona01" {
		t.Fatalf("hold actor: %+v", holds[0])
	}

	// Release, and the next pass expires the content.
	if err := recorder.ReleaseLegalHold(operatorPrincipal(),
		testRunID); err != nil {
		t.Fatal(err)
	}
	outcome, err = recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.ObjectRefsTombstoned != 1 || outcome.InlineDowngraded != 1 {
		t.Fatalf("release did not restore expiry: %+v", outcome)
	}
}

func TestAnExpiredHoldStopsProtecting(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, objectRefEvent(0))

	expires := recorder.now().Add(1 * time.Hour)
	if err := recorder.SetLegalHold(operatorPrincipal(), testRunID,
		"brief freeze", expires); err != nil {
		t.Fatal(err)
	}

	*now = (*now).Add(8 * 24 * time.Hour)
	holds, err := recorder.LegalHolds(operatorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 0 {
		t.Fatalf("expired hold still listed: %+v", holds)
	}
	outcome, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Held != 0 || outcome.ObjectRefsTombstoned != 1 {
		t.Fatalf("expired hold still protected: %+v", outcome)
	}
}

func TestHoldRules(t *testing.T) {
	recorder := testRecorder(t)

	if err := recorder.SetLegalHold(collectorPrincipal(), testRunID,
		"reason", time.Time{}); err == nil {
		t.Fatal("a collector froze retention")
	}
	if err := recorder.SetLegalHold(operatorPrincipal(), "run_bad",
		"reason", time.Time{}); err == nil {
		t.Fatal("a malformed run id was accepted")
	}
	if err := recorder.SetLegalHold(operatorPrincipal(), testRunID,
		"", time.Time{}); err == nil {
		t.Fatal("a hold without a reason was accepted")
	}
	past := recorder.now().Add(-time.Minute)
	if err := recorder.SetLegalHold(operatorPrincipal(), testRunID,
		"reason", past); err == nil {
		t.Fatal("a hold expiring in the past was accepted")
	}
	if err := recorder.SetLegalHold(servicePrincipal(), testRunID,
		"incident investigation", time.Time{}); err != nil {
		t.Fatalf("the supervisor system could not hold: %v", err)
	}
}

func TestRetentionRequiresAuthorityAndPositiveWindows(t *testing.T) {
	recorder := testRecorder(t)
	ingest(t, recorder, objectRefEvent(0))

	if _, err := recorder.ApplyRetentionPolicy(collectorPrincipal(),
		DefaultRetentionPolicy()); err == nil {
		t.Fatal("a collector ran a retention pass")
	}
	if _, err := recorder.ApplyRetentionPolicy(operatorPrincipal(),
		RetentionPolicy{}); err == nil {
		t.Fatal("a zero window was accepted")
	}
	events, err := recorder.Events(collectorPrincipal(),
		EventQuery{RunID: testRunID})
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Payload.Tombstone {
		t.Fatal("the refused pass still deleted content")
	}
}

func TestHoldsStayInsideTheirTenant(t *testing.T) {
	recorder, now := agedRecorder(t)
	ingest(t, recorder, objectRefEvent(0))
	if err := recorder.SetLegalHold(operatorPrincipal(), testRunID,
		"reason", time.Time{}); err != nil {
		t.Fatal(err)
	}

	other := &Principal{ID: "act_operator-other01",
		TenantID: "tnt_0000000000000002", Role: RoleOperator}
	holds, err := recorder.LegalHolds(other)
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 0 {
		t.Fatalf("holds leaked across tenants: %+v", holds)
	}
	*now = (*now).Add(40 * 24 * time.Hour)
	outcome, err := recorder.ApplyRetentionPolicy(other,
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Held != 0 {
		t.Fatalf("another tenant's hold blocked expiry: %+v", outcome)
	}
	// The holding tenant's own pass still respects its hold.
	outcome, err = recorder.ApplyRetentionPolicy(operatorPrincipal(),
		DefaultRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Held != 1 {
		t.Fatalf("the hold vanished: %+v", outcome)
	}
}

// agedRecorder builds a recorder whose clock the test can advance:
// now points at the current time; moving it ages every stored event.
func agedRecorder(t *testing.T) (*Recorder, *time.Time) {
	t.Helper()
	clock, current := movableClock(t)
	return testRecorder(t, WithClock(clock)), current
}

func mustChain(t *testing.T, recorder *Recorder) (string, int) {
	t.Helper()
	head, length, err := recorder.Chain(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	return head, length
}
