// Fleet trajectory analysis (T050, spec 10.1, AC-030).
//
// Planted patterns with known provenance prove the analyzer finds
// what is there; clean fleets prove it stays silent; mixed tenants
// prove isolation fails closed.

package analysis

import (
	"encoding/json"
	"strings"
	"testing"
)

const tenant = "tnt_9d4c1e2a3b4f5c67"

// fleet builds a metadata event with the cross-run surfaces that
// matter: delegation identity, artifact references, correlation ids,
// and parent lineage.
type fleet struct {
	id         string
	run        string
	delegation string
	digest     string
	storageRef string
	correlates []string
	parents    []string
	trust      string
}

func event(f fleet) FleetEvent {
	if f.trust == "" {
		f.trust = "collector_fact"
	}
	return FleetEvent{
		TenantID:       tenant,
		RunID:          f.run,
		ID:             f.id,
		EventKind:      "resource_access",
		TrustLabel:     f.trust,
		Source:         FleetSource{Component: "collector"},
		Sequence:       1,
		ObservedAt:     "2026-09-12T00:00:00Z",
		DelegationID:   f.delegation,
		CorrelationIDs: f.correlates,
		ParentEventIDs: f.parents,
		Payload: FleetPayload{
			Kind:       "object_ref",
			Digest:     f.digest,
			StorageRef: f.storageRef,
		},
	}
}

func events(fs ...fleet) []FleetEvent {
	out := make([]FleetEvent, 0, len(fs))
	for _, f := range fs {
		out = append(out, event(f))
	}
	return out
}

// TestASharedDelegationAcrossRunsIsFoundWithProvenance plants the
// simplest campaign: two runs minted from one delegation identity.
func TestASharedDelegationAcrossRunsIsFoundWithProvenance(t *testing.T) {
	input := events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_1",
			delegation: "dlg_shared0000001"},
		fleet{id: "evt_" + strings.Repeat("b", 16), run: "run_2",
			delegation: "dlg_shared0000001"},
	)
	report, err := AnalyzeFleet(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Patterns) != 1 {
		t.Fatalf("patterns: %d, want 1", len(report.Patterns))
	}
	pattern := report.Patterns[0]
	if got := strings.Join(pattern.Runs, ","); got != "run_1,run_2" {
		t.Fatalf("runs: %v", pattern.Runs)
	}
	if len(pattern.Edges) != 1 || pattern.Edges[0].Kind != EdgeSharedDelegation {
		t.Fatalf("edges: %+v", pattern.Edges)
	}
	cited := pattern.Edges[0].Events
	if len(cited) != 2 {
		t.Fatalf("cited events: %v", cited)
	}
	for _, id := range cited {
		found := false
		for _, e := range input {
			found = found || e.ID == id
		}
		if !found {
			t.Fatalf("edge cites event %q that is not in the input", id)
		}
	}
}

// TestSharedArtifactsSeparateIntoSeparatePatterns plants two
// independent artifact channels: a digest shared by two runs and a
// storage reference shared by two other runs. Two patterns, one per
// channel; neither bleeds into the other.
func TestSharedArtifactsSeparateIntoSeparatePatterns(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("1", 16), run: "run_a",
			digest: "sha256:" + strings.Repeat("9", 64)},
		fleet{id: "evt_" + strings.Repeat("2", 16), run: "run_b",
			digest: "sha256:" + strings.Repeat("9", 64)},
		fleet{id: "evt_" + strings.Repeat("3", 16), run: "run_c",
			storageRef: "obj://bucket/9"},
		fleet{id: "evt_" + strings.Repeat("4", 16), run: "run_d",
			storageRef: "obj://bucket/9"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if report.Runs != 4 || report.Events != 4 {
		t.Fatalf("scope: runs %d events %d", report.Runs, report.Events)
	}
	if len(report.Patterns) != 2 {
		t.Fatalf("patterns: %d, want 2 (one per channel)", len(report.Patterns))
	}
	for _, pattern := range report.Patterns {
		if len(pattern.Runs) != 2 || len(pattern.Edges) != 1 {
			t.Fatalf("pattern: %+v", pattern)
		}
		if pattern.Edges[0].Kind != EdgeSharedArtifact {
			t.Fatalf("edge kind: %s", pattern.Edges[0].Kind)
		}
	}
}

// TestCrossRunLineageIsFoundThroughParentEventIds plants a direct
// lineage: run B cites an event that run A recorded.
func TestCrossRunLineageIsFoundThroughParentEventIds(t *testing.T) {
	parent := "evt_" + strings.Repeat("p", 16)
	report, err := AnalyzeFleet(events(
		fleet{id: parent, run: "run_origin"},
		fleet{id: "evt_" + strings.Repeat("c", 16), run: "run_child",
			parents: []string{parent}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Patterns) != 1 {
		t.Fatalf("patterns: %d", len(report.Patterns))
	}
	edge := report.Patterns[0].Edges[0]
	if edge.Kind != EdgeCrossRunLineage {
		t.Fatalf("edge kind: %s", edge.Kind)
	}
	if edge.Key != parent {
		t.Fatalf("edge key: %s, want the parent event id", edge.Key)
	}
	// Both sides are cited: the child and the origin.
	if len(edge.Events) != 2 {
		t.Fatalf("cited: %v", edge.Events)
	}
}

// TestSharedCorrelationIdsLinkRuns plants correlation ids as the
// coordination surface.
func TestSharedCorrelationIdsLinkRuns(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("x", 16), run: "run_1",
			correlates: []string{"corr_coord0001"}},
		fleet{id: "evt_" + strings.Repeat("y", 16), run: "run_2",
			correlates: []string{"corr_coord0001"}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Patterns) != 1 ||
		report.Patterns[0].Edges[0].Kind != EdgeSharedCorrelation {
		t.Fatalf("patterns: %+v", report.Patterns)
	}
}

// TestTransitiveEdgesFormOneCampaign links A-B by delegation and B-C
// by artifact: three runs, one connected pattern.
func TestTransitiveEdgesFormOneCampaign(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_a",
			delegation: "dlg_campaign001"},
		fleet{id: "evt_" + strings.Repeat("b", 16), run: "run_b",
			delegation: "dlg_campaign001",
			digest:     "sha256:" + strings.Repeat("c", 64)},
		fleet{id: "evt_" + strings.Repeat("d", 16), run: "run_c",
			digest: "sha256:" + strings.Repeat("c", 64)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Patterns) != 1 {
		t.Fatalf("patterns: %d, want one connected component", len(report.Patterns))
	}
	if got := len(report.Patterns[0].Runs); got != 3 {
		t.Fatalf("runs in campaign: %d, want 3", got)
	}
	if len(report.Patterns[0].Edges) != 2 {
		t.Fatalf("edges: %d, want 2", len(report.Patterns[0].Edges))
	}
}

// TestACleanFleetReportsNoPatterns keeps every identity inside its
// own run.
func TestACleanFleetReportsNoPatterns(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("1", 16), run: "run_1",
			delegation: "dlg_one000000001", digest: "sha256:" + strings.Repeat("1", 64)},
		fleet{id: "evt_" + strings.Repeat("2", 16), run: "run_2",
			delegation: "dlg_two000000001", digest: "sha256:" + strings.Repeat("2", 64)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Patterns) != 0 {
		t.Fatalf("patterns on a clean fleet: %+v", report.Patterns)
	}
	if report.Runs != 2 || report.Events != 2 {
		t.Fatalf("scope: %+v", report)
	}
}

// TestASharedIdentityInsideOneRunLinksNothing is the negative for
// same-run sharing: a delegation used twice by one run is ordinary.
func TestASharedIdentityInsideOneRunLinksNothing(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("1", 16), run: "run_1",
			delegation: "dlg_same0000001"},
		fleet{id: "evt_" + strings.Repeat("2", 16), run: "run_1",
			delegation: "dlg_same0000001"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Patterns) != 0 {
		t.Fatalf("intra-run sharing produced patterns: %+v", report.Patterns)
	}
}

// TestMixedTenantInputIsRefusedWhole is the isolation guarantee:
// one analysis covers exactly one tenant, or nothing runs.
func TestMixedTenantInputIsRefusedWhole(t *testing.T) {
	mixed := events(
		fleet{id: "evt_" + strings.Repeat("1", 16), run: "run_1"},
	)
	mixed = append(mixed, FleetEvent{
		TenantID: "tnt_0000000000000002", RunID: "run_2",
		ID: "evt_" + strings.Repeat("2", 16), TrustLabel: "collector_fact",
	})
	if _, err := AnalyzeFleet(mixed); err == nil {
		t.Fatal("mixed tenants were accepted")
	} else if !strings.Contains(err.Error(), "mix tenants") {
		t.Fatalf("error: %v", err)
	}
}

// TestMissingTenantOrIDsAreRefused fails closed on malformed input.
func TestMissingTenantOrIDsAreRefused(t *testing.T) {
	noTenant := events(fleet{id: "evt_" + strings.Repeat("1", 16), run: "run_1"})
	noTenant[0].TenantID = ""
	if _, err := AnalyzeFleet(noTenant); err == nil {
		t.Fatal("missing tenant accepted")
	}
	noID := events(fleet{id: "", run: "run_1"})
	if _, err := AnalyzeFleet(noID); err == nil {
		t.Fatal("missing event id accepted")
	}
	if _, err := AnalyzeFleet(nil); err == nil {
		t.Fatal("empty input accepted")
	}
}

// TestAtLeastOnceDeliveryDoesNotDoubleLink deduplicates repeated
// event ids and records how many were dropped.
func TestAtLeastOnceDeliveryDoesNotDoubleLink(t *testing.T) {
	base := events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_1",
			delegation: "dlg_shared0000001"},
		fleet{id: "evt_" + strings.Repeat("b", 16), run: "run_2",
			delegation: "dlg_shared0000001"},
	)
	input := append(append([]FleetEvent{}, base...), base...)
	report, err := AnalyzeFleet(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deduplicated != 2 || report.Events != 2 {
		t.Fatalf("dedup: %+v", report)
	}
	if len(report.Patterns) != 1 || len(report.Patterns[0].Edges[0].Events) != 2 {
		t.Fatalf("duplicates changed the pattern: %+v", report.Patterns)
	}
}

// TestWorkerClaimsAreMarkedOnTheEdge keeps the trust boundary of
// spec 9.4: an edge built from worker transcripts says so.
func TestWorkerClaimsAreMarkedOnTheEdge(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_1",
			delegation: "dlg_claimed0001", trust: "worker_claim"},
		fleet{id: "evt_" + strings.Repeat("b", 16), run: "run_2",
			delegation: "dlg_claimed0001", trust: "worker_claim"},
	))
	if err != nil {
		t.Fatal(err)
	}
	labels := report.Patterns[0].Edges[0].TrustLabels
	if len(labels) != 1 || labels[0] != "worker_claim" {
		t.Fatalf("trust labels: %v", labels)
	}
}

// TestAnalysisIsDeterministic runs the same input twice and compares
// the canonical JSON.
func TestAnalysisIsDeterministic(t *testing.T) {
	input := events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_1",
			delegation: "dlg_campaign001", correlates: []string{"corr_1"}},
		fleet{id: "evt_" + strings.Repeat("b", 16), run: "run_2",
			digest: "sha256:" + strings.Repeat("c", 64)},
		fleet{id: "evt_" + strings.Repeat("d", 16), run: "run_1",
			digest: "sha256:" + strings.Repeat("c", 64)},
	)
	first, err := AnalyzeFleet(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeFleet(input)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatalf("two runs of the same input differ:\n%s\n%s", a, b)
	}
}

// TestProvenanceNeverDangles lets AssertFleetProvenance pass on a
// real report and reject one with an invented citation.
func TestProvenanceNeverDangles(t *testing.T) {
	input := events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_1",
			delegation: "dlg_shared0000001"},
		fleet{id: "evt_" + strings.Repeat("b", 16), run: "run_2",
			delegation: "dlg_shared0000001"},
	)
	report, err := AnalyzeFleet(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertFleetProvenance(report, input); err != nil {
		t.Fatalf("real provenance rejected: %v", err)
	}
	report.Patterns[0].Edges[0].Events = append(
		report.Patterns[0].Edges[0].Events, "evt_invented000001",
	)
	if err := AssertFleetProvenance(report, input); err == nil {
		t.Fatal("dangling provenance accepted")
	}
}

// TestTheScopeNoteTravels keeps patterns labeled as review-routing,
// not verdicts.
func TestTheScopeNoteTravels(t *testing.T) {
	report, err := AnalyzeFleet(events(
		fleet{id: "evt_" + strings.Repeat("a", 16), run: "run_1"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.Scope, "not a verdict") {
		t.Fatalf("scope: %q", report.Scope)
	}
	if report.Kind != "FleetReport" || report.TenantID != tenant {
		t.Fatalf("report header: %+v", report)
	}
}
