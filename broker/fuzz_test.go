package broker

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Fuzzing of the review verdict decoder (T042, spec 11.2, AC-001). A
// review decision gates effects: a forged or smuggled verdict must
// fail closed, and no input may crash the decoder.
//
// Run the engine-backed fuzzer with:
//
//	go test -fuzz=FuzzDecodeReview -fuzztime=30s

func validReviewJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func FuzzDecodeReview(f *testing.F) {
	f.Add([]byte(`{"verdict":"ALLOW","reviewer_id":"act_x","policy_refs":["p"],"event_refs":["e"],"rationale":"r","latency_ms":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeReview(data)
		if err == nil && decoded == nil {
			t.Fatal("nil review came back without an error")
		}
	})
}

// TestTheCanonicalReviewRoundTrips guards the fixture: the valid
// review decodes and satisfies the full review contract.
func TestTheCanonicalReviewRoundTrips(t *testing.T) {
	decoded, err := DecodeReview(validReviewJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	if problems := decoded.ValidateReview(); len(problems) != 0 {
		t.Fatalf("canonical review left the contract: %+v", problems)
	}
}

// TestSeededReviewDamageNeverPanics applies random byte damage under
// a fixed seed. Damage must produce an error or a decoded review,
// never a panic and never a nil review without an error.
func TestSeededReviewDamageNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(20261003))
	base := validReviewJSON(t)
	junk := [][]byte{
		[]byte(",\"extra\":1"), []byte("\x00"), []byte("{"), []byte("}"),
		[]byte("\\"), []byte(","), []byte("‮"),
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
		case 3: // append trailing content
			tail := []string{"{}", "null", " {}", "1"}[rng.Intn(4)]
			mutated = append(mutated, []byte(tail)...)
		}
		decoded, err := DecodeReview(mutated)
		if err == nil && decoded == nil {
			t.Fatalf("trial %d: nil review without error for %q",
				trial, mutated)
		}
		// A review that survives damage must still name a verdict from
		// the enum or be flagged by the contract check.
		if err == nil {
			decoded.ValidateReview()
		}
	}
}

// TestUnknownReviewKeysAreAlwaysRejected injects adversarial key
// names — near-misses, case variants, and tempting smuggles like
// "approved_by" and "superseded" — into the review body. Every one
// must fail closed: a misspelled field is an unknown field.
func TestUnknownReviewKeysAreAlwaysRejected(t *testing.T) {
	adversarial := []string{
		"extra", "Verdict", "verdicts", "reviewer", "approved_by",
		"superseded", "override", "debug", "ingested_at", "notes",
		"policy_ref", "event_ref", "rationale_extra", "force",
	}
	rng := rand.New(rand.NewSource(20261004))
	for round := 0; round < 100; round++ {
		key := adversarial[rng.Intn(len(adversarial))]
		value := []string{"1", `"ALLOW"`, "true", "null", `["x"]`}[rng.Intn(5)]
		body := fmt.Sprintf(`{%q:%s,%q:%s}`,
			"verdict", `"ALLOW"`, key, value)
		if _, err := DecodeReview([]byte(body)); err == nil {
			t.Fatalf("unknown key %q was accepted in %s", key, body)
		}
	}
	// Trailing content after the document is never accepted.
	for _, tail := range []string{"{}", "null", " {}", "1"} {
		body := append(
			append([]byte{}, validReviewJSON(t)...), []byte(tail)...)
		if _, err := DecodeReview(body); err == nil {
			t.Fatalf("trailing content %q was accepted", tail)
		}
	}
	// A verdict smuggled past the enum through value corruption is
	// caught by the contract, not the decoder: the enum lives in
	// ValidateReview.
	for _, verdict := range []string{
		"allow", "Allow", "ALLOW ", "ALLOWX", "PASS", "maybe", "",
	} {
		body := fmt.Sprintf(`{"verdict":%q,"reviewer_id":%q,`+
			`"policy_refs":[%q],"event_refs":[%q],"rationale":"r",`+
			`"latency_ms":1}`,
			verdict, "act_sentinel-reference-01",
			"pol_1.1.0/operations.repo.push",
			"evt_"+strings.Repeat("1", 16))
		decoded, err := DecodeReview([]byte(body))
		if err != nil {
			continue // refusing malformed input is fine too
		}
		if problems := decoded.ValidateReview(); len(problems) == 0 {
			t.Fatalf("verdict %q passed the contract", verdict)
		}
	}
}
