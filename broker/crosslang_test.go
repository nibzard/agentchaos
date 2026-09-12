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
// validator (shared/schemas + shared/python/gauntlet_schemas). The Go
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

	// Review-gated pushes (spec 10, 11.1, 11.2): a held effect, the
	// same effect authorized by an ALLOW review, a committed push with
	// the resource version bound into the permit, and a reviewer DENY.
	pushes := testBroker(t, &githubSink{current: "commit-7f3a"})
	held, heldDecision, err := pushes.Authorize(
		servicePrincipal(), pushEffect("eff_100000000000000f", "commit-7f3a"))
	if err != nil || heldDecision.Verdict != "hold" {
		t.Fatalf("review hold: %v %+v", err, heldDecision)
	}
	documents["effect_review_held"] = held
	reviewed, allowDecision, err := pushes.AttachReview(
		servicePrincipal(), "eff_100000000000000f", review(ReviewAllow))
	if err != nil || allowDecision.Verdict != "allow" {
		t.Fatalf("review allow: %v %+v", err, allowDecision)
	}
	documents["effect_review_allowed"] = reviewed
	pushed, err := pushes.Commit(servicePrincipal(), "eff_100000000000000f", "")
	if err != nil {
		t.Fatal(err)
	}
	documents["effect_push_committed"] = pushed
	refused, _, err := pushes.Authorize(
		servicePrincipal(), pushEffect("eff_1000000000000010", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	deniedByReview, _, err := pushes.AttachReview(
		servicePrincipal(), "eff_1000000000000010", review(ReviewDeny))
	if err != nil {
		t.Fatal(err)
	}
	_ = refused
	documents["effect_review_denied"] = deniedByReview
	for i, event := range pushes.Events() {
		documents[fmt.Sprintf("event_review_%02d", i)] = event
	}

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

	// Stop reports: a compensated clean stop and a dirty, quarantined
	// stop (spec 13.3).
	stops := testBroker(t, &SyntheticSink{})
	compensatedTarget := testEffect()
	compensatedTarget.ID = "eff_100000000000000d"
	if _, _, err := stops.Authorize(servicePrincipal(), compensatedTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := stops.Commit(servicePrincipal(), compensatedTarget.ID, ""); err != nil {
		t.Fatal(err)
	}
	cleanOrder := &StopOrder{RunID: testRun().RunID, Sandbox: SandboxPreserve, Reason: "crosslang"}
	cleanOrder.Compensations = []CompensationPlan{{
		EffectID:        compensatedTarget.ID,
		Operation:       compensatedTarget.ProposedAction.Operation,
		Resource:        compensatedTarget.ProposedAction.Resource,
		Destination:     compensatedTarget.ProposedAction.Destination,
		ArgumentsDigest: compensatedTarget.ProposedAction.ArgumentsDigest,
		ActionClass:     compensatedTarget.ActionClass,
		SizeBytes:       compensatedTarget.ProposedAction.SizeBytes,
	}}
	cleanReport, err := stops.Stop(servicePrincipal(), cleanOrder)
	if err != nil {
		t.Fatal(err)
	}
	documents["stop_report_clean"] = cleanReport

	// A second stop on the same broker would replay the recorded report,
	// so the dirty scenario runs on its own broker: a committed,
	// uncompensated A2 effect quarantines its artifact.
	dirtyBroker := testBroker(t, &SyntheticSink{})
	dirtyTarget := testEffect()
	dirtyTarget.ID = "eff_100000000000000e"
	if _, _, err := dirtyBroker.Authorize(servicePrincipal(), dirtyTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := dirtyBroker.Commit(servicePrincipal(), dirtyTarget.ID, ""); err != nil {
		t.Fatal(err)
	}
	dirtyReport, err := dirtyBroker.Stop(servicePrincipal(), &StopOrder{
		RunID: testRun().RunID, Sandbox: SandboxTerminate, HandoffID: "sgh_crosslang00001",
	})
	if err != nil {
		t.Fatal(err)
	}
	documents["stop_report_dirty"] = dirtyReport

	// Every evidence event the broker can emit in these flows.
	for i, event := range main.Events() {
		documents[fmt.Sprintf("event_%02d", i)] = event
	}
	for i, event := range delegations.Events() {
		documents[fmt.Sprintf("event_delegation_%02d", i)] = event
	}
	for i, event := range stops.Events() {
		documents[fmt.Sprintf("event_stop_%02d", i)] = event
	}
	for i, event := range dirtyBroker.Events() {
		documents[fmt.Sprintf("event_stop_dirty_%02d", i)] = event
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
from gauntlet_schemas import validate

documents = json.load(open(sys.argv[2]))
for name, document in documents.items():
    validate(document, document["kind"])
print(f"{len(documents)} broker documents valid against shared schemas")
`
