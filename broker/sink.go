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
	mu        sync.Mutex
	Receipts  []SyntheticReceipt
	Responder func(effect *Effect) SinkResult // optional test hook
}

// SyntheticReceipt is the recorded send.
type SyntheticReceipt struct {
	EffectID        string
	Destination     string
	ArgumentsDigest string
	At              string
}

// Name identifies the receipt source.
func (s *SyntheticSink) Name() string { return "synthetic-sink" }

// Supports claims every contract-shaped sink: destination.
func (s *SyntheticSink) Supports(destination string) bool {
	return strings.HasPrefix(destination, "sink:")
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
