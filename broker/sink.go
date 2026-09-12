package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// SyntheticSink owns `sink:` destinations (spec 9.2 effect sinks such
// as sink://patch-export-beta). It is the P0 dispatch path: real
// external services get their own sink adapters in later tasks. The
// sink, never the worker, holds any downstream credential.
type SyntheticSink struct {
	mu         sync.Mutex
	Receipts   []SyntheticReceipt
	Staged     []SyntheticStaged
	Responder  func(effect *Effect) SinkResult      // optional test hook
	Preparer   func(effect *Effect) SinkResult      // optional test hook
	Reconciler func(effect *Effect) ReconcileResult // optional test hook
}

// SyntheticReceipt is the recorded send.
type SyntheticReceipt struct {
	EffectID        string
	Destination     string
	ArgumentsDigest string
	At              string
}

// SyntheticStaged is the recorded preparation (spec 10.1: where a
// service supports transactional preparation, use it).
type SyntheticStaged struct {
	EffectID       string
	At             string
	IdempotencyKey string
}

// Name identifies the receipt source.
func (s *SyntheticSink) Name() string { return "synthetic-sink" }

// Supports claims every contract-shaped sink: destination.
func (s *SyntheticSink) Supports(destination string) bool {
	return strings.HasPrefix(destination, "sink:")
}

// Prepare stages the write without sending it: the synthetic service
// accepts conditional writes, so the two-phase path applies.
func (s *SyntheticSink) Prepare(effect *Effect, now string) SinkResult {
	if s.Preparer != nil {
		return s.Preparer(effect)
	}
	s.mu.Lock()
	s.Staged = append(s.Staged, SyntheticStaged{
		EffectID:       effect.ID,
		At:             now,
		IdempotencyKey: effect.Dispatch.IdempotencyKey,
	})
	s.mu.Unlock()
	return SinkResult{
		Outcome: OutcomeAcknowledged,
		Detail:  "staged; not sent",
	}
}

// Dispatch records the send and acknowledges it with a digest over
// what was dispatched. The digest lets a receipt be checked against
// the permit's arguments_digest binding (spec 10).
func (s *SyntheticSink) Dispatch(effect *Effect, now string) SinkResult {
	if s.Responder != nil {
		return s.Responder(effect)
	}
	s.mu.Lock()
	s.Receipts = append(s.Receipts, SyntheticReceipt{
		EffectID:        effect.ID,
		Destination:     effect.ProposedAction.Destination,
		ArgumentsDigest: effect.ProposedAction.ArgumentsDigest,
		At:              now,
	})
	s.mu.Unlock()
	return SinkResult{
		Outcome:       OutcomeAcknowledged,
		ReceiptDigest: receiptDigest(effect),
		Detail: fmt.Sprintf("sink accepted %s for %s",
			effect.ProposedAction.Operation, effect.ProposedAction.Destination),
	}
}

// Reconcile resolves an unknown outcome by reading the sink's own
// state: a recorded receipt means the send happened; no receipt means
// it never took effect (spec 10.1: a receipt or state read, never a
// blind reissue).
func (s *SyntheticSink) Reconcile(effect *Effect, now string) ReconcileResult {
	if s.Reconciler != nil {
		return s.Reconciler(effect)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, receipt := range s.Receipts {
		if receipt.EffectID == effect.ID {
			return ReconcileResult{
				Outcome:       ReconciledCommitted,
				ReceiptDigest: receiptDigest(effect),
				Detail:        fmt.Sprintf("state read at %s found the send", now),
			}
		}
	}
	return ReconcileResult{
		Outcome: ReconciledNoEffect,
		Detail:  fmt.Sprintf("state read at %s found no send", now),
	}
}

func receiptDigest(effect *Effect) string {
	basis := fmt.Sprintf("%s\n%s\n%s\n%s",
		effect.ID,
		effect.ProposedAction.Operation,
		effect.ProposedAction.Destination,
		effect.ProposedAction.ArgumentsDigest,
	)
	sum := sha256.Sum256([]byte(basis))
	return "sha256:" + hex.EncodeToString(sum[:])
}
