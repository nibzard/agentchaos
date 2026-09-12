package integration

// Fleet trajectory analysis across the evidence plane (T050, spec
// 10.1, AC-030). The analyzer lives in the analysis package as pure
// computation; this test proves the authoritative evidence store
// feeds it: contract-valid events are recorded, read back under a
// reader principal, and their metadata unmarshals into the analyzer's
// input shape as-is. Patterns come back with provenance that cites
// recorded event ids, and cross-tenant evidence never mixes.

import (
	"encoding/json"
	"strings"
	"testing"

	"gauntlet/analysis"
	"gauntlet/evidence"
)

func fleetCollector() *evidence.Principal {
	return &evidence.Principal{
		ID:       "idk_fleet-collector-1",
		TenantID: integrationTenant,
		Role:     evidence.RoleCollector,
	}
}

// fleetEvent builds one contract-valid collector event carrying the
// cross-run metadata surfaces: delegation identity, artifact
// reference, correlation, and parent lineage.
func fleetEvent(id string, seq int64, run, delegation string,
	parents []string, digest string) *evidence.Event {
	return &evidence.Event{
		Kind:           "EvidenceEvent",
		APIVersion:     "v1",
		ID:             id,
		TenantID:       integrationTenant,
		RunID:          run,
		EventKind:      evidence.KindResourceAccess,
		TrustLabel:     evidence.TrustCollectorFact,
		Source:         evidence.EventSource{ID: "src_fleet-collector-1",
			Component: evidence.ComponentCollector,
			Coverage:  evidence.CoverageObserved},
		Sequence:       seq,
		DelegationID:   delegation,
		CorrelationIDs: []string{"cid_fleet-" + run},
		ParentEventIDs: parents,
		ObservedAt:     "2026-09-12T00:00:00Z",
		Payload: evidence.EventPayload{
			Kind:        evidence.PayloadObjectRef,
			StorageRef:  "obj://fleet/" + digest[len(digest)-8:],
			Digest:      digest,
			SizeBytes:   128,
			ContentType: "application/json",
			Redacted:    true,
		},
	}
}

// TestFleetAnalysisFindsPatternsInRecordedEvidence records two linked
// runs and one isolated run, then reads the whole tenant back and
// analyzes it. The two linked runs must appear as one pattern whose
// provenance cites recorded event ids.
func TestFleetAnalysisFindsPatternsInRecordedEvidence(t *testing.T) {
	recorder := evidence.New()
	sharedDigest := "sha256:" + strings.Repeat("1", 64)
	batch := &evidence.Batch{Events: []*evidence.Event{
		fleetEvent("evt_"+strings.Repeat("a", 16), 1,
			"run_fleetalpha0001", "dlg_campaign000001", nil, sharedDigest),
		fleetEvent("evt_"+strings.Repeat("b", 16), 2,
			"run_fleetbeta00001", "dlg_campaign000001",
			[]string{"evt_" + strings.Repeat("a", 16)}, sharedDigest),
		fleetEvent("evt_"+strings.Repeat("c", 16), 3,
			"run_fleetgamma0001", "", nil, "sha256:"+strings.Repeat("2", 64)),
	}}
	if _, err := recorder.Ingest(fleetCollector(), batch); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	stored, err := recorder.Events(fleetCollector(), evidence.EventQuery{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(stored) != 3 {
		t.Fatalf("stored %d events, want 3", len(stored))
	}

	// The bridge: the analyzer's input shape mirrors the EvidenceEvent
	// contract tags, so recorded events cross as-is.
	fleet := make([]analysis.FleetEvent, 0, len(stored))
	recorded := map[string]bool{}
	for _, event := range stored {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var input analysis.FleetEvent
		if err := json.Unmarshal(data, &input); err != nil {
			t.Fatalf("unmarshal %s: %v", event.ID, err)
		}
		recorded[event.ID] = true
		fleet = append(fleet, input)
	}

	report, err := analysis.AnalyzeFleet(fleet)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if report.TenantID != integrationTenant || report.Events != 3 {
		t.Fatalf("report scope: %+v", report)
	}
	if len(report.Patterns) != 1 {
		t.Fatalf("patterns: %d, want the two linked runs only", len(report.Patterns))
	}
	pattern := report.Patterns[0]
	if len(pattern.Runs) != 2 ||
		pattern.Runs[0] != "run_fleetalpha0001" ||
		pattern.Runs[1] != "run_fleetbeta00001" {
		t.Fatalf("pattern runs: %v", pattern.Runs)
	}
	kinds := map[string]bool{}
	for _, edge := range pattern.Edges {
		kinds[edge.Kind] = true
		for _, id := range edge.Events {
			if !recorded[id] {
				t.Fatalf("edge cites unrecorded event %q", id)
			}
		}
	}
	// Delegation, artifact, lineage, and the shared correlation all
	// linked these runs. (The correlation ids differ per run here.)
	for _, kind := range []string{
		analysis.EdgeSharedDelegation, analysis.EdgeSharedArtifact,
		analysis.EdgeCrossRunLineage,
	} {
		if !kinds[kind] {
			t.Fatalf("missing %s edge; kinds: %v", kind, kinds)
		}
	}
	if err := analysis.AssertFleetProvenance(report, fleet); err != nil {
		t.Fatalf("provenance: %v", err)
	}
}

// TestFleetAnalysisRefusesCrossTenantEvidence records the same
// pattern into two tenants and proves the analyzer refuses to mix
// them: isolation is structural, not a filter.
func TestFleetAnalysisRefusesCrossTenantEvidence(t *testing.T) {
	recorder := evidence.New()
	other := "tnt_" + strings.Repeat("5", 16)
	first := fleetEvent("evt_"+strings.Repeat("a", 16), 1,
		"run_fleetalpha0001", "dlg_campaign000001", nil,
		"sha256:"+strings.Repeat("1", 64))
	second := fleetEvent("evt_"+strings.Repeat("b", 16), 1,
		"run_fleetbeta00001", "dlg_campaign000001", nil,
		"sha256:"+strings.Repeat("1", 64))
	second.TenantID = other
	if _, err := recorder.Ingest(fleetCollector(),
		&evidence.Batch{Events: []*evidence.Event{first}}); err != nil {
		t.Fatalf("ingest first tenant: %v", err)
	}
	crossTenant := fleetCollector()
	crossTenant.TenantID = other
	if _, err := recorder.Ingest(crossTenant,
		&evidence.Batch{Events: []*evidence.Event{second}}); err != nil {
		t.Fatalf("ingest second tenant: %v", err)
	}

	// Each tenant reads only its own events; combining both into one
	// analysis is what the analyzer must refuse.
	mixed := []analysis.FleetEvent{}
	for _, principal := range []*evidence.Principal{
		fleetCollector(), crossTenant,
	} {
		stored, err := recorder.Events(principal, evidence.EventQuery{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		for _, event := range stored {
			data, _ := json.Marshal(event)
			var input analysis.FleetEvent
			if err := json.Unmarshal(data, &input); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			mixed = append(mixed, input)
		}
	}
	if len(mixed) != 2 {
		t.Fatalf("read %d events across tenants, want 2", len(mixed))
	}
	if _, err := analysis.AnalyzeFleet(mixed); err == nil {
		t.Fatal("cross-tenant analysis was accepted")
	}
}
