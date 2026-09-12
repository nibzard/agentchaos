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

	committed, err := main.Commit(servicePrincipal(), allowed.ID, "")
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
	unknown, err := timeout.Commit(servicePrincipal(), timeoutEffect.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_unknown"] = unknown

	// Failed dispatch reaches CANCELLED.
	failed := testBroker(t, &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "connection refused"}
	}})
	failedProposal, _, _ := failed.Authorize(servicePrincipal(), testEffect())
	cancelled, err := failed.Commit(servicePrincipal(), failedProposal.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_cancelled"] = cancelled

	// A compensating effect references the COMMITTED original and
	// commits through COMPENSATING (spec 10.1).
	compensation := testEffect()
	compensation.ID = "eff_100000000000000c"
	compensation.CompensationOf = allowed.ID
	compensating, _, err := main.Authorize(servicePrincipal(), compensation)
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_compensation"] = compensating
	compensated, err := main.Commit(servicePrincipal(), compensating.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_compensated"] = compensated

	// A refused preparation cancels before any send; the dispatch
	// record still completes with the outcome that says no send took
	// effect.
	stageRefused := testBroker(t, &SyntheticSink{Preparer: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeFailed, Detail: "staging quota exceeded"}
	}})
	refusedProposal, _, _ := stageRefused.Authorize(servicePrincipal(), testEffect())
	stageCancelled, err := stageRefused.Commit(servicePrincipal(), refusedProposal.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_stage_cancelled"] = stageCancelled

	// An unknown outcome resolved by a state read: the retry commits
	// through reconciliation, never a reissue (AC-010).
	reconcile := testBroker(t, &SyntheticSink{
		Responder: func(*Effect) SinkResult {
			return SinkResult{Outcome: OutcomeTimeout}
		},
		Reconciler: func(effect *Effect) ReconcileResult {
			return ReconcileResult{
				Outcome:       ReconciledCommitted,
				ReceiptDigest: receiptDigest(effect),
				Detail:        "service journal shows the write",
			}
		},
	})
	reconcileProposal, _, _ := reconcile.Authorize(servicePrincipal(), testEffect())
	if _, err := reconcile.Commit(servicePrincipal(), reconcileProposal.ID, ""); err != nil {
		t.Fatal(err)
	}
	reconciled, err := reconcile.Commit(servicePrincipal(), reconcileProposal.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_reconciled"] = reconciled

	// Delegation documents: a tree root, a nested child, and a
	// revoked node with its fence timestamp (spec 10).
	delegations := testBroker(t, &SyntheticSink{})
	treeRoot, err := delegations.Delegate(servicePrincipal(), rootRequest())
	if err != nil {
		t.Fatal(err)
	}
	documents["delegation_root"] = treeRoot
	nested, err := delegations.Delegate(servicePrincipal(), childRequest(treeRoot))
	if err != nil {
		t.Fatal(err)
	}
	documents["delegation_nested"] = nested
	revoked, err := delegations.RevokeDelegation(servicePrincipal(), treeRoot.ID, "stop condition met")
	if err != nil {
		t.Fatal(err)
	}
	documents["delegation_revoked"] = revoked

	// A delegation narrowed to nothing: the capability arrays are
	// empty, never null — null is not an array.
	denyAll := rootRequest()
	denyAll.ID = "dlg_denyall000001"
	denyAll.Capabilities.AllowedDestinations = []string{}
	denyAll.Capabilities.AllowedResources = nil
	empty, err := delegations.Delegate(servicePrincipal(), denyAll)
	if err != nil {
		t.Fatal(err)
	}
	documents["delegation_empty_caps"] = empty

	// Every evidence event the broker can emit in these flows.
	for i, event := range main.Events() {
		documents[fmt.Sprintf("event_%02d", i)] = event
	}
	for i, event := range delegations.Events() {
		documents[fmt.Sprintf("event_delegation_%02d", i)] = event
	}
	for i, event := range timeout.Events() {
		documents[fmt.Sprintf("event_timeout_%02d", i)] = event
	}
	for i, event := range failed.Events() {
		documents[fmt.Sprintf("event_failed_%02d", i)] = event
	}
	for i, event := range reconcile.Events() {
		documents[fmt.Sprintf("event_reconcile_%02d", i)] = event
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
