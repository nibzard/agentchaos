package evidence

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// T012: ordering and integrity metadata — correlation joins, parent
// edges, clock uncertainty in the chain, and collector silence as an
// explicit finding.

func TestCorrelationJoinsEventsAcrossSources(t *testing.T) {
	recorder := testRecorder(t)
	// The worker claims a tool response; the collector records the
	// service receipt. One correlation id ties the two accounts of one
	// interaction together (spec 9.4).
	claim := collectorEvent(0)
	claim.TrustLabel = TrustWorkerClaim
	claim.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	claim.EventKind = KindToolResponse
	claim.CorrelationIDs = []string{"cid_interaction-01"}
	receipt := collectorEvent(1)
	receipt.EventKind = KindExternalReceipt
	receipt.CorrelationIDs = []string{"cid_interaction-01"}
	other := collectorEvent(2)
	other.EventKind = KindToolRequest
	other.CorrelationIDs = []string{"cid_interaction-02"}
	if _, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		claim, receipt, other,
	}}); err != nil {
		t.Fatal(err)
	}
	joined, err := recorder.Events(collectorPrincipal(),
		EventQuery{CorrelationID: "cid_interaction-01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(joined) != 2 {
		t.Fatalf("join: %+v", joined)
	}
	labels := map[string]bool{}
	for _, event := range joined {
		labels[event.TrustLabel] = true
	}
	if !labels[TrustWorkerClaim] || !labels[TrustCollectorFact] {
		t.Fatalf("the join must cross trust labels: %+v", joined)
	}
}

func TestEffectFilterPullsEveryRecordOfAnEffect(t *testing.T) {
	recorder := testRecorder(t)
	proposal := collectorEvent(0)
	proposal.EventKind = KindProposedAction
	proposal.EffectID = "eff_2b3c4d5e6f708192"
	decision := collectorEvent(1)
	decision.EventKind = KindBrokerDecision
	decision.EffectID = "eff_2b3c4d5e6f708192"
	unrelated := collectorEvent(2)
	if _, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		proposal, decision, unrelated,
	}}); err != nil {
		t.Fatal(err)
	}
	found, err := recorder.Events(collectorPrincipal(),
		EventQuery{EffectID: "eff_2b3c4d5e6f708192"})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("effect records: %+v", found)
	}
}

func TestParentEdgesRoundTripAndVerifyReportsTheDanglingOne(t *testing.T) {
	recorder := testRecorder(t)
	parent := collectorEvent(0)
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{parent}}); err != nil {
		t.Fatal(err)
	}
	child := collectorEvent(1)
	child.ParentEventIDs = []string{parent.ID, "evt_missingparent01"}
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{child}}); err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Events(collectorPrincipal(), EventQuery{})
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %+v err: %v", events, err)
	}
	if len(events[1].ParentEventIDs) != 2 ||
		events[1].ParentEventIDs[0] != parent.ID {
		t.Fatalf("parent edges did not round-trip: %+v", events[1].ParentEventIDs)
	}
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	// The chain holds — it proves content, not arrival — but the
	// dangling edge is reported, and a later delivery would resolve it.
	if !report.Intact {
		t.Fatalf("a missing parent is not tampering: %+v", report)
	}
	if len(report.UnresolvedParents) != 1 ||
		report.UnresolvedParents[0].EventID != child.ID ||
		report.UnresolvedParents[0].ParentID != "evt_missingparent01" {
		t.Fatalf("unresolved parents: %+v", report.UnresolvedParents)
	}
}

func TestChainCoversCorrelationAndParentEdges(t *testing.T) {
	recorder := testRecorder(t)
	event := collectorEvent(0)
	event.CorrelationIDs = []string{"cid_anchored0000001"}
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{event}}); err != nil {
		t.Fatal(err)
	}
	// Rewrite a correlation id after storage; the chain must break.
	recorder.mu.Lock()
	recorder.tenants[testTenant].events[0].event.CorrelationIDs[0] = "cid_forged000000001"
	recorder.mu.Unlock()
	report, _ := recorder.Verify(collectorPrincipal())
	if report.Intact {
		t.Fatal("a rewritten correlation id kept the chain intact")
	}
}

func TestCollectorSilenceBecomesAFinding(t *testing.T) {
	recorder := testRecorder(t)
	silent := collectorEvent(0)
	silent.EventKind = KindCollectorHeartbeat
	silent.ObservedAt = "2026-09-12T06:00:00Z" // six hours quiet
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{silent}}); err != nil {
		t.Fatal(err)
	}
	opened, err := recorder.CheckCollectorLiveness(collectorPrincipal(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 {
		t.Fatalf("silence has no finding: %+v", opened)
	}
	finding := opened[0]
	if finding.CoverageGap == nil ||
		finding.CoverageGap.ExpectedEventKind != KindCollectorHeartbeat ||
		finding.CoverageGap.SourceID != "src_collector-alpha-1" {
		t.Fatalf("coverage gap: %+v", finding.CoverageGap)
	}
	if finding.EvidenceRefs[0].EventID != silent.ID {
		t.Fatalf("the finding must cite the last heartbeat: %+v", finding.EvidenceRefs)
	}

	// Polling cannot stack findings: the second sweep stays quiet.
	opened, err = recorder.CheckCollectorLiveness(collectorPrincipal(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 0 {
		t.Fatalf("stacked findings: %+v", opened)
	}

	// A source that never heartbeated is not judged: nothing says a
	// heartbeat was due from it.
	other := collectorEvent(0)
	other.Source = EventSource{
		ID: "src_collector-beta-1", Component: ComponentCollector,
		Coverage: CoverageObserved,
	}
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{other}}); err != nil {
		t.Fatal(err)
	}
	opened, _ = recorder.CheckCollectorLiveness(collectorPrincipal(), time.Hour)
	if len(opened) != 0 {
		t.Fatalf("a heartbeat-less source was judged: %+v", opened)
	}

	// A new heartbeat clears the stale flag.
	recovered := collectorEvent(2)
	recovered.EventKind = KindCollectorHeartbeat
	recovered.ObservedAt = testNow
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{recovered}}); err != nil {
		t.Fatal(err)
	}
	opened, _ = recorder.CheckCollectorLiveness(collectorPrincipal(), time.Hour)
	if len(opened) != 0 {
		t.Fatalf("a recovered collector was still flagged: %+v", opened)
	}
}

func TestCollectorCheckOverHTTP(t *testing.T) {
	server, _ := testServer(t)
	silent := collectorEvent(0)
	silent.EventKind = KindCollectorHeartbeat
	silent.ObservedAt = "2026-09-12T06:00:00Z"
	batch, _ := json.Marshal(Batch{Events: []*Event{silent}})
	doJSON(t, "POST", server.URL+"/v1/evidence/events", batch,
		collectorHeaders("idk_liveness-0000001"))

	headers := map[string]string{
		HeaderActor: "act_analyst-reference-1", HeaderTenant: testTenant,
		HeaderRole: RoleOperator, HeaderIdem: "idk_liveness-0000002",
	}
	reply, body := doJSON(t, "POST", server.URL+"/v1/evidence/collector-check",
		[]byte(`{"max_quiet_seconds":3600}`), headers)
	if reply.StatusCode != http.StatusOK || body["opened"].(float64) != 1 {
		t.Fatalf("check: %d %+v", reply.StatusCode, body)
	}
	// Replay answers from the ledger.
	reply, replayBody := doJSON(t, "POST", server.URL+"/v1/evidence/collector-check",
		[]byte(`{"max_quiet_seconds":3600}`), headers)
	if reply.StatusCode != http.StatusOK || replayBody["opened"] != body["opened"] {
		t.Fatalf("replay: %d %+v", reply.StatusCode, replayBody)
	}
	// A different body under the same key conflicts.
	reply, problem := doJSON(t, "POST", server.URL+"/v1/evidence/collector-check",
		[]byte(`{"max_quiet_seconds":60}`), headers)
	if reply.StatusCode != http.StatusConflict || problem["code"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %+v", reply.StatusCode, problem)
	}
	// Unknown fields fail closed.
	unknown := map[string]string{HeaderIdem: "idk_liveness-0000003"}
	for key, value := range headers {
		if key != HeaderIdem {
			unknown[key] = value
		}
	}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/evidence/collector-check",
		[]byte(`{"max_quiet_seconds":3600,"window":"1h"}`), unknown)
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "collector_check_schema" {
		t.Fatalf("unknown field: %d %+v", reply.StatusCode, problem)
	}
	// Range guard.
	unknown[HeaderIdem] = "idk_liveness-0000004"
	reply, problem = doJSON(t, "POST", server.URL+"/v1/evidence/collector-check",
		[]byte(`{"max_quiet_seconds":0}`), unknown)
	if reply.StatusCode != http.StatusUnprocessableEntity ||
		problem["code"] != "max_quiet_seconds_invalid" {
		t.Fatalf("range: %d %+v", reply.StatusCode, problem)
	}
	// A worker cannot sweep.
	worker := map[string]string{
		HeaderActor: "act_worker-reference-01", HeaderTenant: testTenant,
		HeaderRole: RoleWorker, HeaderIdem: "idk_liveness-0000005",
	}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/evidence/collector-check",
		[]byte(`{"max_quiet_seconds":3600}`), worker)
	if reply.StatusCode != http.StatusForbidden || problem["code"] != "role_forbidden" {
		t.Fatalf("worker sweep: %d %+v", reply.StatusCode, problem)
	}
}

func TestEventFiltersOverHTTP(t *testing.T) {
	server, _ := testServer(t)
	claim := collectorEvent(0)
	claim.TrustLabel = TrustWorkerClaim
	claim.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	claim.EventKind = KindToolResponse
	claim.EffectID = "eff_3c4d5e6f7081920a"
	claim.CorrelationIDs = []string{"cid_filter00000001"}
	receipt := collectorEvent(1)
	receipt.EventKind = KindExternalReceipt
	receipt.EffectID = "eff_3c4d5e6f7081920a"
	receipt.CorrelationIDs = []string{"cid_filter00000001"}
	batch, _ := json.Marshal(Batch{Events: []*Event{claim, receipt}})
	doJSON(t, "POST", server.URL+"/v1/evidence/events", batch,
		collectorHeaders("idk_filters-0000001"))

	headers := map[string]string{
		HeaderActor: "act_analyst-reference-1", HeaderTenant: testTenant,
		HeaderRole: RoleOperator,
	}
	url := server.URL + "/v1/evidence/events?correlation_id=cid_filter00000001"
	reply, body := doJSON(t, "GET", url, nil, headers)
	if reply.StatusCode != http.StatusOK || len(body["events"].([]any)) != 2 {
		t.Fatalf("correlation filter: %d %+v", reply.StatusCode, body)
	}
	url = server.URL + "/v1/evidence/events?effect_id=eff_3c4d5e6f7081920a"
	reply, body = doJSON(t, "GET", url, nil, headers)
	if reply.StatusCode != http.StatusOK || len(body["events"].([]any)) != 2 {
		t.Fatalf("effect filter: %d %+v", reply.StatusCode, body)
	}
	// Both filters together narrow to nothing when they disagree.
	url = server.URL + "/v1/evidence/events?correlation_id=cid_filter00000001" +
		"&effect_id=eff_4d5e6f7081920a3b"
	reply, body = doJSON(t, "GET", url, nil, headers)
	if reply.StatusCode != http.StatusOK || len(body["events"].([]any)) != 0 {
		t.Fatalf("combined filters: %d %+v", reply.StatusCode, body)
	}
	// Off-pattern filter values are refused, not ignored.
	url = server.URL + "/v1/evidence/events?correlation_id=correlation-7"
	reply, problem := doJSON(t, "GET", url, nil, headers)
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "correlation_id_invalid" {
		t.Fatalf("bad filter: %d %+v", reply.StatusCode, problem)
	}
}
