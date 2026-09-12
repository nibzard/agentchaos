package governor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEmittedDocumentsValidateAgainstSharedSchemas feeds every
// EvidenceEvent shape the governor emits through the shared Python
// validator (shared/schemas + shared/python/gauntlet_schemas). The governor
// journals within the spec 9.4 event-kind set — recovery_action for
// enforcement, budget_change for accounting — and this test is the
// tripwire that keeps those documents contract-valid. It skips when
// python3 or the shared package is not available.
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

	clock := newFixedClock()
	g := New(clock.Now)
	documents := map[string]any{}

	if _, err := g.RegisterEnvelope(servicePrincipal(), testEnvelope()); err != nil {
		t.Fatal(err)
	}
	run, err := g.StartRun(servicePrincipal(), "run_crosslang00001", "exp_gate000000001")
	if err != nil {
		t.Fatal(err)
	}
	documents["run_active"] = run

	// A spend delta lands as a budget_change event.
	if _, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID:      run.RunID,
		Generation: 1,
		SessionSpends: []SessionSpend{{SessionID: "ses_crosslang0001",
			Cost: Money{Currency: "USD", Micros: 150_000}}},
	}); err != nil {
		t.Fatal(err)
	}

	// A target expansion trips; the trip and the stop handoff land as
	// recovery_action events.
	if _, err := g.Heartbeat(servicePrincipal(), &Heartbeat{
		RunID:           run.RunID,
		ObservedTargets: []string{"tgt_outside000001"},
	}); err == nil {
		t.Fatal("expansion passed")
	}

	// An incident + emergency stop + cleanup state on a second run
	// exercise the remaining event shapes.
	second := testEnvelope()
	second.ExperimentID = "exp_crosslang00001"
	if _, err := g.RegisterEnvelope(servicePrincipal(), second); err != nil {
		t.Fatal(err)
	}
	stopped, err := g.StartRun(servicePrincipal(), "run_crosslang00002", "exp_crosslang00001")
	if err != nil {
		t.Fatal(err)
	}
	documents["run_active2"] = stopped
	if _, err := g.EmergencyStop(customerPrincipal(), &EmergencyStopScope{
		Kind: "experiment", ExperimentID: "exp_crosslang00001"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ReportCleanupState(servicePrincipal(), stopped.RunID,
		TerminalDirtyQuarantined); err != nil {
		t.Fatal(err)
	}
	stored, err := g.Run(servicePrincipal(), stopped.RunID)
	if err != nil {
		t.Fatal(err)
	}
	documents["run_stopped"] = stored
	handoff, err := g.Handoff(servicePrincipal(), stopped.RunID)
	if err != nil {
		t.Fatal(err)
	}
	documents["stop_handoff"] = handoff // governor-local kind; validated below

	for i, event := range g.Events() {
		documents[fmt.Sprintf("event_%02d", i)] = event
	}

	// Validate EvidenceEvents through the shared registry; the run
	// records and the handoff are governor-local documents, so their
	// shape is pinned by the package tests, not the shared schemas.
	sharedDocuments := map[string]any{}
	for name, document := range documents {
		if event, ok := document.(EvidenceEvent); ok {
			sharedDocuments[name] = event
		}
	}
	if len(sharedDocuments) < 4 {
		t.Fatalf("too few events to validate: %d", len(sharedDocuments))
	}

	directory := t.TempDir()
	listPath := filepath.Join(directory, "documents.json")
	payload, err := json.Marshal(sharedDocuments)
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

	runCheck := exec.Command("python3", scriptPath, sharedPython, listPath)
	output, err := runCheck.CombinedOutput()
	if err != nil {
		t.Fatalf("cross-language validation failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)

	// The stop handoff must list every spec 13.3 step as JSON.
	encoded, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Steps []struct {
			Name string `json:"name"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil || len(decoded.Steps) != 10 {
		t.Fatalf("handoff steps: %d %v", len(decoded.Steps), err)
	}
}

// crosslangCheck validates every emitted event against its shared
// contract, fail closed.
const crosslangCheck = `
import json, sys

sys.path.insert(0, sys.argv[1])
from gauntlet_schemas import validate

documents = json.load(open(sys.argv[2]))
for name, document in documents.items():
    validate(document, document["kind"])
print(f"{len(documents)} governor documents valid against shared schemas")
`
