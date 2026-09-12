package evidence

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// Fuzzing of the evidence batch decoder (T042, AC-001). The batch
// body is the trust boundary of the store: nothing it accepts may
// carry an unknown field, and nothing it rejects may crash it.
//
// Run the engine-backed fuzzer with:
//
//	go test -fuzz=FuzzDecodeBatch -fuzztime=30s

func validBatchJSON() string {
	return `{"events":[` + eventJSON(collectorEvent(0)) + `]}`
}

func FuzzDecodeBatch(f *testing.F) {
	f.Add([]byte(`{"events":[]}`))
	f.Add([]byte(validBatchJSON()))
	f.Add([]byte(replaceOnce(validBatchJSON(),
		`"truncated":false`, `"truncated":false,"encoding":"utf8"`)))
	f.Add([]byte(validBatchJSON()[:20])) // truncated document
	f.Add([]byte(`{"events":[`))         // unclosed
	f.Add([]byte(`nul`))                 // almost JSON
	f.Fuzz(func(t *testing.T, data []byte) {
		batch, err := DecodeBatch(data)
		if err == nil && batch == nil {
			t.Fatal("nil batch came back without an error")
		}
	})
}

// TestSeededBatchDamageNeverPanics applies random byte damage under a
// fixed seed. The decoder must always answer (batch, nil) or (nil,
// error); damage may never panic it.
func TestSeededBatchDamageNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(20261001))
	base := []byte(validBatchJSON())
	junk := [][]byte{
		[]byte(",\"extra\":1"), []byte("\x00"), []byte("{"), []byte("}"),
		[]byte("\\"), []byte(",null,"), []byte("é"),
	}
	for trial := 0; trial < 2000; trial++ {
		mutated := make([]byte, len(base))
		copy(mutated, base)
		switch rng.Intn(4) {
		case 0: // flip one byte
			mutated[rng.Intn(len(mutated))] = byte(rng.Intn(256))
		case 1: // truncate
			mutated = mutated[:rng.Intn(len(mutated))]
		case 2: // splice junk bytes in
			at := rng.Intn(len(mutated) + 1)
			chunk := junk[rng.Intn(len(junk))]
			spliced := make([]byte, 0, len(mutated)+len(chunk))
			spliced = append(spliced, mutated[:at]...)
			spliced = append(spliced, chunk...)
			spliced = append(spliced, mutated[at:]...)
			mutated = spliced
		case 3: // duplicate a slice of the body elsewhere
			from := rng.Intn(len(mutated))
			length := 1 + rng.Intn(16)
			if from+length > len(mutated) {
				length = len(mutated) - from
			}
			at := rng.Intn(len(mutated) + 1)
			mutated = append(
				append([]byte{}, mutated[:at]...),
				append(append([]byte{}, mutated[from:from+length]...),
					mutated[at:]...)...)
		}
		batch, err := DecodeBatch(mutated)
		if err == nil && batch == nil {
			t.Fatalf("trial %d: nil batch without error for %q",
				trial, mutated)
		}
	}
}

// TestUnknownKeysAreAlwaysRejectedAtEveryLevel injects adversarial
// key names as siblings at every nesting level of the batch contract:
// top level, event, source, and payload. Names deliberately include
// near-misses of real keys, case variants, and ingested_at — a field
// the recorder owns and the wire must never set. Every injection must
// fail closed.
func TestUnknownKeysAreAlwaysRejectedAtEveryLevel(t *testing.T) {
	adversarial := []string{
		"extra", "Extra", "debug", "override", "ingested_at",
		"truncated_", "redact", "content_type_hint", "vantage",
		"sequence_number", "correlation", "checkpoint_sig", "k",
	}
	// Anchors, one per nesting level. The tail anchor targets the
	// document end so the sibling lands at the top level, not inside
	// an empty nested array.
	anchors := []struct {
		pair    string
		fromEnd bool
	}{
		{`]}`, true},
		{`"kind":"EvidenceEvent"`, false},
		{`"component":"collector"`, false},
		{`"truncated":false`, false},
	}
	base := validBatchJSON()
	rng := rand.New(rand.NewSource(20261002))
	for _, anchor := range anchors {
		for round := 0; round < 50; round++ {
			key := adversarial[rng.Intn(len(adversarial))]
			value := []string{"1", `"x"`, "true", "null", "[]"}[rng.Intn(5)]
			mutated := injectSibling(base, anchor.pair, anchor.fromEnd,
				key, value)
			if mutated == "" {
				t.Fatalf("anchor %q not found in the fixture",
					anchor.pair)
			}
			if _, err := DecodeBatch([]byte(mutated)); err == nil {
				t.Fatalf("unknown key %q beside %q was accepted",
					key, anchor.pair)
			}
		}
	}
}

// injectSibling inserts `,"key":value` directly after the anchor
// substring, which lands inside the JSON object that carries the
// anchor. fromEnd searches from the document tail. Returns "" when
// the anchor is absent.
func injectSibling(haystack, anchor string, fromEnd bool,
	key, value string) string {
	at := bytes.Index([]byte(haystack), []byte(anchor))
	if fromEnd {
		at = bytes.LastIndex([]byte(haystack), []byte(anchor))
	}
	if at < 0 {
		return ""
	}
	cut := at + len(anchor)
	return haystack[:cut] + fmt.Sprintf(",\"%s\":%s", key, value) +
		haystack[cut:]
}
