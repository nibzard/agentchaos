package api

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// idemLedger keeps exactly one reply per (tenant, idempotency key)
// pair (spec 18.3). Reuse with the same body digest replays the stored
// reply; reuse with a different digest conflicts. Reservation is
// atomic, so concurrent requests sharing a key execute the mutation
// once.
type idemLedger struct {
	mu     sync.Mutex
	sealed map[string]*idemEntry // tenant + "\x00" + key
}

type idemEntry struct {
	digest  string
	done    bool
	status  int
	body    []byte
	waiters []chan struct{}
}

func newIdemLedger() *idemLedger {
	return &idemLedger{sealed: map[string]*idemEntry{}}
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// outcome tells the caller what happened to its idempotency key.
type outcome int

const (
	outcomeExecute    outcome = iota // the key is fresh; run the mutation
	outcomeReplay                    // a stored reply exists; return it
	outcomeConflict                  // the key was reused with a different body
	outcomeConcurrent                // another executor failed mid-flight; retry
)

// Reserve claims the key for one body digest. On outcomeExecute the
// returned release function abandons the reservation, so a body that
// fails validation frees the key for a corrected retry.
func (l *idemLedger) Reserve(tenantID, key, digest string) (result outcome,
	status int, body []byte, release func()) {
	sealed := tenantID + "\x00" + key

	l.mu.Lock()
	entry, exists := l.sealed[sealed]
	if exists && entry.digest != digest {
		l.mu.Unlock()
		return outcomeConflict, 0, nil, nil
	}
	if exists && entry.done {
		status, body := entry.status, entry.body
		l.mu.Unlock()
		return outcomeReplay, status, body, nil
	}
	if exists {
		// Another executor holds the key. Wait for it to settle, then
		// read its outcome — never execute twice.
		waiter := make(chan struct{})
		entry.waiters = append(entry.waiters, waiter)
		l.mu.Unlock()
		<-waiter
		l.mu.Lock()
		settled, still := l.sealed[sealed]
		l.mu.Unlock()
		if still && settled.done {
			return outcomeReplay, settled.status, settled.body, nil
		}
		return outcomeConcurrent, 0, nil, nil
	}
	l.sealed[sealed] = &idemEntry{digest: digest}
	l.mu.Unlock()

	release = func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		held, ok := l.sealed[sealed]
		if !ok || held.done || held.digest != digest {
			return
		}
		waiters := held.waiters
		delete(l.sealed, sealed)
		for _, waiter := range waiters {
			close(waiter)
		}
	}
	return outcomeExecute, 0, nil, release
}

// Complete seals the stored reply and wakes every waiter.
func (l *idemLedger) Complete(tenantID, key, digest string, status int, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sealed := tenantID + "\x00" + key
	entry, ok := l.sealed[sealed]
	if !ok || entry.digest != digest || entry.done {
		return
	}
	entry.done = true
	entry.status = status
	entry.body = body
	for _, waiter := range entry.waiters {
		close(waiter)
	}
	entry.waiters = nil
}
