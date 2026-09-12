package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEmittedDocumentsValidateAgainstSharedSchemas feeds every Effect
// and EvidenceEvent shape the broker emits through the shared Python
// validator (shared/schemas + shared/python/acx_schemas). The Go
// structs mirror the contracts; this test is the tripwire that keeps
// the mirror honest. It skips when python3 or the shared package is
// not available.
func TestEmittedDocumentsValidateAgainstSharedSchemas(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	sharedPython := filepath.Join(root, "shared", "python")
	if _, err := os.Stat(sharedPython); err != nil {
		t.Skip("shared python package not present")
	}

	documents := map[string]any{}

	// Allow, deny, and commit on one broker.
	main := testBroker(t, &SyntheticSink{})
	allowed, _, err := main.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_authorized"] = allowed

	denied := testEffect()
	denied.ID = "eff_100000000000000a"
	denied.ProposedAction.Destination = "https://evil.example.com/exfil"
	deniedEffect, _, err := main.Authorize(servicePrincipal(), denied)
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_denied"] = deniedEffect

	committed, err := main.Commit(servicePrincipal(), allowed.ID)
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_committed"] = committed

	// A costed permit (amount_limit instead of size_limit).
	costed := testEffect()
	costed.ID = "eff_100000000000000b"
	costed.ProposedAction.Operation = "repo.comment"
	costed.ProposedAction.Resource = "fixture-repo"
	costed.ProposedAction.Destination = "https://api.github.com/repos/fixture/hello"
	costedEffect, _, err := main.Authorize(servicePrincipal(), costed)
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_costed"] = costedEffect

	// Timeout dispatch reaches UNKNOWN_EFFECT.
	timeout := testBroker(t, &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeTimeout}
	}})
	timeoutEffect, _, _ := timeout.Authorize(servicePrincipal(), testEffect())
	unknown, err := timeout.Commit(servicePrincipal(), timeoutEffect.ID)
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_unknown"] = unknown

	// Failed dispatch reaches CANCELLED.
	failed := testBroker(t, &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "connection refused"}
	}})
	failedProposal, _, _ := failed.Authorize(servicePrincipal(), testEffect())
	cancelled, err := failed.Commit(servicePrincipal(), failedProposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_cancelled"] = cancelled

	// Every evidence event the broker can emit in these flows.
	for i, event := range main.Events() {
		documents[fmt.Sprintf("event_%02d", i)] = event
	}
	for i, event := range timeout.Events() {
		documents[fmt.Sprintf("event_timeout_%02d", i)] = event
	}
	for i, event := range failed.Events() {
		documents[fmt.Sprintf("event_failed_%02d", i)] = event
	}

	directory := t.TempDir()
	listPath := filepath.Join(directory, "documents.json")
	payload, err := json.Marshal(documents)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(directory, "check.py")
	if err := os.WriteFile(scriptPath, []byte(crosslangCheck), 0o644); err != nil {
		t.Fatal(err)
	}

	run := exec.Command("python3", scriptPath, sharedPython, listPath)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("cross-language validation failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}

// crosslangCheck validates every emitted document against its shared
// contract, fail closed.
const crosslangCheck = `
import json, sys

sys.path.insert(0, sys.argv[1])
from acx_schemas import validate

documents = json.load(open(sys.argv[2]))
for name, document in documents.items():
    validate(document, document["kind"])
print(f"{len(documents)} broker documents valid against shared schemas")
`
