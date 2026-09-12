package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateEventAcceptsTheFixture(t *testing.T) {
	if problems := collectorEvent(0).ValidateEvent(); len(problems) > 0 {
		t.Fatalf("problems: %+v", problems)
	}
}

func TestValidateEventPayloadRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Event)
		check  string
	}{
		{
			name:   "collector source without coverage",
			mutate: func(e *Event) { e.Source.Coverage = "" },
			check:  "source.coverage",
		},
		{
			name: "metadata_only with inline content",
			mutate: func(e *Event) {
				e.Payload = EventPayload{Kind: PayloadMetadataOnly, Content: `{"x":1}`}
			},
			check: "payload.content",
		},
		{
			name: "metadata_only with a storage reference",
			mutate: func(e *Event) {
				e.Payload = EventPayload{Kind: PayloadMetadataOnly,
					StorageRef: "obj://evidence/raw-0001"}
			},
			check: "payload.storage_ref",
		},
		{
			name: "object_ref without a digest",
			mutate: func(e *Event) {
				e.Payload = EventPayload{Kind: PayloadObjectRef,
					StorageRef: "obj://evidence/raw-0001",
					SizeBytes:  128, ContentType: "application/octet-stream"}
			},
			check: "payload.digest",
		},
		{
			name: "object_ref with inline content",
			mutate: func(e *Event) {
				e.Payload = EventPayload{Kind: PayloadObjectRef,
					StorageRef: "obj://evidence/raw-0001",
					Digest:     "sha256:" + repeat("a", 64),
					SizeBytes:  128, ContentType: "application/octet-stream",
					Content: `{"x":1}`}
			},
			check: "payload.content",
		},
		{
			name:   "inline without content",
			mutate: func(e *Event) { e.Payload.Content = "" },
			check:  "payload.content",
		},
		{
			name: "inline with a parallel storage reference",
			mutate: func(e *Event) {
				e.Payload.StorageRef = "obj://evidence/raw-0001"
			},
			check: "payload.storage_ref",
		},
		{
			name:   "tombstone on an inline payload",
			mutate: func(e *Event) { e.Payload.Tombstone = true },
			check:  "payload.tombstone",
		},
		{
			name:   "unknown trust label",
			mutate: func(e *Event) { e.TrustLabel = "gospel_truth" },
			check:  "trust_label",
		},
		{
			name:   "unknown event kind",
			mutate: func(e *Event) { e.EventKind = "vibe_check" },
			check:  "event_kind",
		},
		{
			name:   "malformed observed_at",
			mutate: func(e *Event) { e.ObservedAt = "2026-09-12 12:00:00" },
			check:  "observed_at",
		},
		{
			name:   "clock uncertainty over the cap",
			mutate: func(e *Event) { e.ClockUncertaintyMS = 3600001 },
			check:  "clock_uncertainty_ms",
		},
		{
			name:   "correlation id off pattern",
			mutate: func(e *Event) { e.CorrelationIDs = []string{"correlation-7"} },
			check:  "correlation_ids",
		},
		{
			name:   "parent edge off pattern",
			mutate: func(e *Event) { e.ParentEventIDs = []string{"parent-1"} },
			check:  "parent_event_ids",
		},
		{
			name: "duplicate correlation ids",
			mutate: func(e *Event) {
				e.CorrelationIDs = []string{"cid_alpha00000001", "cid_alpha00000001"}
			},
			check: "correlation_ids",
		},
		{
			name: "worker component carrying a collector fact",
			mutate: func(e *Event) {
				e.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
			},
			check: "source.component",
		},
		{
			name: "monitor component carrying a worker claim",
			mutate: func(e *Event) {
				e.TrustLabel = TrustWorkerClaim
				e.Source = EventSource{ID: "src_supervisor-alpha-1", Component: ComponentMonitor}
			},
			check: "source.component",
		},
		{
			name: "broker decision labeled as a worker claim",
			mutate: func(e *Event) {
				e.EventKind = KindBrokerDecision
				e.TrustLabel = TrustWorkerClaim
				e.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
			},
			check: "trust_label",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			event := collectorEvent(0)
			testCase.mutate(event)
			problems := event.ValidateEvent()
			if len(problems) == 0 {
				t.Fatal("violation accepted")
			}
			if problems[0].Check != testCase.check {
				t.Fatalf("check: %s wanted %s (%+v)", problems[0].Check, testCase.check, problems)
			}
		})
	}
}

func TestDecodeBatchRejectsUnknownFieldsAtEveryLevel(t *testing.T) {
	cases := []string{
		`{"events":[]}`,              // fine, decoded below
		`{"event":[]}`,               // misspelled collection key
		`{"events":[],"batch":true}`, // unknown top-level key
	}
	if batch, err := DecodeBatch([]byte(cases[0])); err != nil || batch == nil {
		t.Fatalf("empty batch refused: %v", err)
	}
	if _, err := DecodeBatch([]byte(cases[1])); err == nil {
		t.Fatal("misspelled key accepted")
	}
	if _, err := DecodeBatch([]byte(cases[2])); err == nil {
		t.Fatal("unknown top-level key accepted")
	}

	event := eventJSON(collectorEvent(0))
	nested := []string{
		`{"events":[` + replaceOnce(event, `"kind":"EvidenceEvent"`, `"kind":"EvidenceEvent","extra":1`) + `]}`,
		`{"events":[` + replaceOnce(event, `"component":"collector"`, `"component":"collector","vantage":"edge"`) + `]}`,
		`{"events":[` + replaceOnce(event, `"truncated":false`, `"truncated":false,"encoding":"utf8"`) + `]}`,
	}
	for _, body := range nested {
		if _, err := DecodeBatch([]byte(body)); err == nil {
			t.Fatalf("unknown nested field accepted: %s", body)
		}
	}
}

func replaceOnce(haystack, old, new string) string {
	for i := 0; i+len(old) <= len(haystack); i++ {
		if haystack[i:i+len(old)] == old {
			return haystack[:i] + new + haystack[i+len(old):]
		}
	}
	return haystack
}

// TestEmittedDocumentsValidateAgainstSharedSchemas feeds every event
// and finding shape the plane emits and accepts through the shared
// Python validator. The Go structs mirror the contracts; this is the
// tripwire that keeps the mirror honest.
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
	recorder := testRecorder(t)

	// The three trust labels, each from its own component: worker
	// claim, collector fact, monitor interpretation (AC-012). The
	// claim and the fact share a correlation id and a parent edge —
	// the join metadata spec 9.4 asks the store to keep.
	claim := collectorEvent(0)
	claim.TrustLabel = TrustWorkerClaim
	claim.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	claim.EventKind = KindToolResponse
	claim.CorrelationIDs = []string{"cid_crosslang000001"}
	fact := collectorEvent(1)
	fact.EventKind = KindBrokerDecision
	fact.EffectID = "eff_1a2b3c4d5e6f7081"
	fact.CorrelationIDs = []string{"cid_crosslang000001"}
	fact.ParentEventIDs = []string{claim.ID}
	reading := collectorEvent(2)
	reading.TrustLabel = TrustMonitorReading
	reading.Source = EventSource{ID: "src_supervisor-alpha-1", Component: ComponentMonitor}
	reading.EventKind = KindResourceAccess
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{claim, fact, reading}}); err != nil {
		t.Fatal(err)
	}

	// An object-referenced payload (raw prompts stay in storage).
	stored := collectorEvent(3)
	stored.EventKind = KindInjectionReceipt
	stored.Payload = EventPayload{
		Kind: PayloadObjectRef, StorageRef: "obj://evidence/injection-0001",
		Digest: "sha256:" + repeat("b", 64), SizeBytes: 512,
		ContentType: "application/octet-stream", Redacted: true,
	}
	// Metadata-only: coverage declared, nothing captured.
	meta := collectorEvent(4)
	meta.EventKind = KindCollectorHeartbeat
	meta.Payload = EventPayload{Kind: PayloadMetadataOnly}
	// A gap (sequence 5 skips 4-to-5's predecessors) produces findings.
	jump := collectorEvent(7)
	jump.EventKind = KindRecoveryAction
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{stored, meta, jump}})
	if err != nil {
		t.Fatal(err)
	}

	events, err := recorder.Events(collectorPrincipal(), EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for i, event := range events {
		documents[fmt.Sprintf("event_%02d", i)] = event
	}
	for i, finding := range result.Findings {
		documents[fmt.Sprintf("finding_%02d", i)] = finding
	}
	findings, _ := recorder.Findings(collectorPrincipal())
	for i, finding := range findings {
		documents[fmt.Sprintf("stored_finding_%02d", i)] = finding
	}

	// An event that carries its own signed checkpoint (collectors may
	// re-emit the checkpoint embedded); shape must still validate.
	checkpointed := collectorEvent(8)
	checkpointed.EventKind = KindDelegation
	checkpointed.Checkpoint = testCheckpoint(t)
	documents["event_with_checkpoint"] = checkpointed

	// A silent collector becomes an explicit finding (spec 9.4); its
	// shape, coverage gap included, must validate too.
	silent := collectorEvent(0)
	silent.ID = "evt_silent0000000001"
	silent.Source = EventSource{
		ID: "src_collector-beta-1", Component: ComponentCollector,
		Coverage: CoverageObserved,
	}
	silent.EventKind = KindCollectorHeartbeat
	silent.ObservedAt = "2026-09-12T06:00:00Z" // six hours quiet
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{silent}}); err != nil {
		t.Fatal(err)
	}
	opened, err := recorder.CheckCollectorLiveness(collectorPrincipal(), time.Hour)
	if err != nil || len(opened) != 1 {
		t.Fatalf("liveness: %+v err: %v", opened, err)
	}
	documents["liveness_finding"] = opened[0]

	// Outcome reports (spec 9.5): a state-backed pass, and a
	// grader-only outcome that must stay unknown.
	receipt := collectorEvent(9)
	receipt.EventKind = KindExternalReceipt
	receipt.EffectID = "eff_8a9b0c1d2e3f4051"
	receipt.Payload.Content = `{"ack":"ok"}`
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{receipt}}); err != nil {
		t.Fatal(err)
	}
	state := &fakeState{readings: map[string]StateReading{
		"sink/run/9": {Observed: true, Detail: "bytes landed"},
	}}
	verifier := verifierFixture(t,
		WithEvidenceStore(recorder),
		WithStateSource("sink", state),
		WithGrader(&fakeGrader{results: map[string]GradeResult{
			"grade/final-essay": {Pass: true, Detail: "corroboration only"},
		}}))
	reports := []*OutcomeReport{}
	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{
		{EffectID: "eff_8a9b0c1d2e3f4051", Expectation: ExpectEffect},
		{EffectID: "eff_8a9b0c1d2e3f4052", Expectation: ExpectEffect,
			GraderKey: "grade/final-essay"},
		{EffectID: "eff_8a9b0c1d2e3f4053", Expectation: ExpectEffect,
			StateQueries: []StateQuery{{Source: "sink", Ref: "sink/run/9"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reports = append(reports, report)
	broken := NewOutcomeVerifier(
		WithFixtures(&fakeFixtures{results: map[string]FixtureResult{
			"fx_knowngood": {Pass: true}, "fx_knownbad": {Pass: true},
		}}, "fx_knowngood", "fx_knownbad"),
		WithVerifierClock(testClock(t)))
	unhealthy, err := broken.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{
		{EffectID: "eff_8a9b0c1d2e3f4054", Expectation: ExpectEffect},
	})
	if err != nil {
		t.Fatal(err)
	}
	reports = append(reports, unhealthy)
	for i, report := range reports {
		documents[fmt.Sprintf("outcome_report_%02d", i)] = report
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

// testCheckpoint signs a well-formed embedded checkpoint with a
// throwaway key; the shared schema checks shape, not cryptography.
func testCheckpoint(t *testing.T) *Checkpoint {
	t.Helper()
	digest := "sha256:" + repeat("c", 64)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(digest)))
	if len(public) != ed25519.PublicKeySize {
		t.Fatal("unexpected key size")
	}
	return &Checkpoint{
		SequenceFrom: 0, SequenceTo: 7, Digest: digest,
		Signature: Signature{Algorithm: "ed25519", KeyID: "key_collector-alpha-01", Value: value},
	}
}

const crosslangCheck = `
import json, sys

sys.path.insert(0, sys.argv[1])
from acx_schemas import validate

documents = json.load(open(sys.argv[2]))
for name, document in documents.items():
    validate(document, document["kind"])
print(f"{len(documents)} evidence documents valid against shared schemas")
`
