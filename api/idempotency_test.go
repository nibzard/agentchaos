package api

// Direct tests for the monolith's idempotency ledger (spec 18.3): one
// reply per (tenant, key), reuse with a different digest conflicts,
// reservations are atomic across concurrent callers, and a failed
// execution frees the key for a corrected retry.

import (
	"bytes"
	"sync"
	"testing"
)

func TestReplayReturnsTheSealedReply(t *testing.T) {
	ledger := newIdemLedger()
	digest := bodyDigest([]byte(`{"a":1}`))

	outcome, _, _, release := ledger.Reserve(testTenant, "idk_ledger-000001", digest)
	if outcome != outcomeExecute || release == nil {
		t.Fatalf("first reserve: %v", outcome)
	}
	ledger.Complete(testTenant, "idk_ledger-000001", digest, 201, []byte("reply"))

	outcome, status, body, release := ledger.Reserve(testTenant, "idk_ledger-000001", digest)
	if outcome != outcomeReplay || release != nil {
		t.Fatalf("replay: %v", outcome)
	}
	if status != 201 || !bytes.Equal(body, []byte("reply")) {
		t.Fatalf("sealed reply: %d %s", status, body)
	}
}

func TestReuseWithADifferentDigestConflicts(t *testing.T) {
	ledger := newIdemLedger()
	first := bodyDigest([]byte(`{"a":1}`))
	second := bodyDigest([]byte(`{"a":2}`))

	outcome, _, _, _ := ledger.Reserve(testTenant, "idk_ledger-000002", first)
	if outcome != outcomeExecute {
		t.Fatalf("first reserve: %v", outcome)
	}
	ledger.Complete(testTenant, "idk_ledger-000002", first, 201, []byte("reply"))

	outcome, _, _, _ = ledger.Reserve(testTenant, "idk_ledger-000002", second)
	if outcome != outcomeConflict {
		t.Fatalf("conflict: %v", outcome)
	}
	// The original reply is untouched: the same digest still replays.
	replayOutcome, replayStatus, _, _ := ledger.Reserve(testTenant,
		"idk_ledger-000002", first)
	if replayOutcome != outcomeReplay || replayStatus != 201 {
		t.Fatalf("original key disturbed: %v %d", replayOutcome, replayStatus)
	}
}

func TestKeysNeverCrossTenants(t *testing.T) {
	ledger := newIdemLedger()
	digest := bodyDigest([]byte(`{"a":1}`))
	if outcome, _, _, _ := ledger.Reserve(testTenant, "idk_ledger-000003",
		digest); outcome != outcomeExecute {
		t.Fatalf("first tenant: %v", outcome)
	}
	// Another tenant's caller with the same key is a different key.
	if outcome, _, _, _ := ledger.Reserve(otherTenant, "idk_ledger-000003",
		digest); outcome != outcomeExecute {
		t.Fatalf("tenant scoping: %v", outcome)
	}
}

func TestConcurrentCallersExecuteOnceAndShareTheReply(t *testing.T) {
	ledger := newIdemLedger()
	digest := bodyDigest([]byte(`{"a":1}`))

	const callers = 8
	// One caller wins the reservation; the rest wait for it to settle.
	winner, _, _, _ := ledger.Reserve(testTenant, "idk_ledger-000004", digest)
	if winner != outcomeExecute {
		t.Fatalf("no winner: %v", winner)
	}

	waitGroup := sync.WaitGroup{}
	results := make([]outcome, callers)
	for i := 0; i < callers; i++ {
		waitGroup.Add(1)
		go func(slot int) {
			defer waitGroup.Done()
			outcome, _, _, _ := ledger.Reserve(testTenant,
				"idk_ledger-000004", digest)
			results[slot] = outcome
		}(i)
	}
	// Give the waiters time to block, then settle the key.
	ledger.Complete(testTenant, "idk_ledger-000004", digest, 200, []byte("once"))
	waitGroup.Wait()

	for slot, outcome := range results {
		if outcome != outcomeReplay {
			t.Fatalf("waiter %d: %v (want replay)", slot, outcome)
		}
	}
}

func TestReleaseFreesTheKeyForACorrectedRetry(t *testing.T) {
	ledger := newIdemLedger()
	digest := bodyDigest([]byte(`{"a":1}`))

	outcome, _, _, release := ledger.Reserve(testTenant, "idk_ledger-000005", digest)
	if outcome != outcomeExecute || release == nil {
		t.Fatalf("reserve: %v", outcome)
	}
	// The handler failed before writing; the key is abandoned.
	release()

	// A corrected retry executes again — the failed attempt stored
	// nothing to replay.
	outcome, _, _, release = ledger.Reserve(testTenant, "idk_ledger-000005", digest)
	if outcome != outcomeExecute || release == nil {
		t.Fatalf("retry after release: %v", outcome)
	}
	ledger.Complete(testTenant, "idk_ledger-000005", digest, 201, []byte("ok"))

	// A late Complete from the abandoned attempt cannot seal a second
	// reply over the corrected one.
	outcome, status, body, _ := ledger.Reserve(testTenant, "idk_ledger-000005", digest)
	if outcome != outcomeReplay || status != 201 || string(body) != "ok" {
		t.Fatalf("late seal: %v %d %s", outcome, status, body)
	}
}

func TestAReleasedReservationWakesItsWaitersToReExecute(t *testing.T) {
	ledger := newIdemLedger()
	digest := bodyDigest([]byte(`{"a":1}`))

	winner, _, _, release := ledger.Reserve(testTenant, "idk_ledger-000006", digest)
	if winner != outcomeExecute {
		t.Fatalf("no winner: %v", winner)
	}

	waitGroup := sync.WaitGroup{}
	results := make([]outcome, 1)
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		outcome, _, _, _ := ledger.Reserve(testTenant, "idk_ledger-000006", digest)
		results[0] = outcome
	}()
	// The winner fails: the waiter must wake and re-execute rather
	// than block forever on a key that stores nothing.
	release()
	waitGroup.Wait()

	if results[0] != outcomeExecute {
		t.Fatalf("waiter after release: %v (want execute)", results[0])
	}
}
