package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testNow anchors the recorder clock so findings and stamps are
// deterministic.
const testNow = "2026-09-12T12:00:00Z"

func testClock(t *testing.T) func() time.Time {
	t.Helper()
	base, err := time.Parse(time.RFC3339Nano, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return func() time.Time { return base }
}

func testRecorder(t *testing.T, opts ...Option) *Recorder {
	t.Helper()
	all := append([]Option{WithClock(testClock(t))}, opts...)
	return New(all...)
}

// collectorPrincipal is the fixture collector.
func collectorPrincipal() *Principal {
	return &Principal{ID: "act_collector-alpha-1", TenantID: testTenant, Role: RoleCollector}
}

const testTenant = "tnt_9d4c1e2a3b4f5c67"
const testRunID = "run_0f1e2d3c4b5a6970"

// collectorEvent is a valid collector fact with the given id and
// sequence.
func collectorEvent(n int) *Event {
	return &Event{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         fmt.Sprintf("evt_%016d", n),
		TenantID:   testTenant,
		RunID:      testRunID,
		EventKind:  KindToolRequest,
		TrustLabel: TrustCollectorFact,
		Source: EventSource{
			ID: "src_collector-alpha-1", Component: ComponentCollector,
			Coverage: CoverageObserved,
		},
		Sequence:           int64(n),
		ObservedAt:         testNow,
		ClockUncertaintyMS: 100,
		Payload: EventPayload{
			Kind: PayloadInline, Content: `{"n":` + fmt.Sprint(n) + `}`,
			Redacted: false, Truncated: false,
		},
	}
}

func TestIngestStoresAndChains(t *testing.T) {
	recorder := testRecorder(t)
	result, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		collectorEvent(0), collectorEvent(1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 2 || result.ChainLength != 2 {
		t.Fatalf("result: %+v", result)
	}
	if result.ChainDigest == "" {
		t.Fatal("chain digest missing")
	}
	events, err := recorder.Events(collectorPrincipal(), EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].IngestedAt != testNow {
		t.Fatalf("events: %+v", events)
	}
}

func TestIngestDeduplicatesByEventID(t *testing.T) {
	recorder := testRecorder(t)
	batch := &Batch{Events: []*Event{collectorEvent(0)}}
	if _, err := recorder.Ingest(collectorPrincipal(), batch); err != nil {
		t.Fatal(err)
	}
	// At-least-once delivery replays sequence 0 under the same id.
	result, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		collectorEvent(0), collectorEvent(1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Duplicates != 1 || result.Accepted != 1 || result.ChainLength != 2 {
		t.Fatalf("result: %+v", result)
	}
}

func TestSequenceGapBecomesAFinding(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(0)}}); err != nil {
		t.Fatal(err)
	}
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(4)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings: %+v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Category != CategoryEvidenceGap || finding.Severity != SeverityH1 {
		t.Fatalf("finding: %+v", finding)
	}
	if finding.CoverageGap == nil ||
		finding.CoverageGap.ExpectedSequenceFrom != 1 ||
		finding.CoverageGap.ExpectedSequenceTo != 3 ||
		finding.CoverageGap.SourceID != "src_collector-alpha-1" {
		t.Fatalf("the gap must name what is absent: %+v", finding.CoverageGap)
	}
	if finding.EvidenceRefs[0].EventID != collectorEvent(4).ID {
		t.Fatalf("evidence ref: %+v", finding.EvidenceRefs)
	}
}

func TestFirstEventWithNonZeroSequenceIsAGap(t *testing.T) {
	recorder := testRecorder(t)
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(7)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("a source starting at 7 hides its first eight slots: %+v", result.Findings)
	}
}

func TestOutOfOrderDeliveryIsStoredAndFound(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		collectorEvent(0), collectorEvent(1), collectorEvent(3),
	}}); err != nil {
		t.Fatal(err)
	}
	// Sequence 2 arrives late, below the frontier at 3. No global total
	// order is assumed, so it is stored as delivered — and the anomaly
	// is an explicit finding, never a silent repair.
	straggler := collectorEvent(2)
	straggler.ID = "evt_straggler000001"
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{straggler}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 {
		t.Fatalf("the late event was not stored: %+v", result)
	}
	found := false
	for _, finding := range result.Findings {
		if finding.EvidenceRefs[0].EventID == straggler.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the out-of-order arrival has no finding: %+v", result.Findings)
	}
}

func TestSequenceReuseUnderFreshIDRefuses(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(0)}}); err != nil {
		t.Fatal(err)
	}
	rival := collectorEvent(0)
	rival.ID = "evt_rival00000000001"
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{rival}}); err == nil {
		t.Fatal("two events claimed one sequence slot")
	}
	// And nothing from the refused batch landed.
	if _, length, _ := recorder.Chain(collectorPrincipal()); length != 1 {
		t.Fatalf("chain length: %d", length)
	}
}

func TestClockDisagreementBecomesAFinding(t *testing.T) {
	recorder := testRecorder(t) // clock fixed at testNow
	skewed := collectorEvent(0)
	skewed.ObservedAt = "2026-09-11T02:00:00Z" // 34 hours stale
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{skewed}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings: %+v", result.Findings)
	}
	found := result.Findings[0]
	if found.Title == "" || found.EvidenceRefs[0].EventID != skewed.ID {
		t.Fatalf("finding: %+v", found)
	}
}

func TestFreshClockSkewPassesSilently(t *testing.T) {
	recorder := testRecorder(t)
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(0)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings: %+v", result.Findings)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		collectorEvent(0), collectorEvent(1), collectorEvent(2),
	}}); err != nil {
		t.Fatal(err)
	}
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil || !report.Intact || report.EventsChecked != 3 {
		t.Fatalf("report: %+v err: %v", report, err)
	}

	// Reach inside and rewrite history; the chain must notice.
	recorder.mu.Lock()
	recorder.tenants[testTenant].events[1].event.Payload.Content = `{"forged":true}`
	recorder.mu.Unlock()
	report, err = recorder.Verify(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact || report.FirstBreak == "" {
		t.Fatalf("tampering undetected: %+v", report)
	}
}

func TestVerifyDetectsTruncation(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		collectorEvent(0), collectorEvent(1),
	}}); err != nil {
		t.Fatal(err)
	}
	recorder.mu.Lock()
	store := recorder.tenants[testTenant]
	store.events = store.events[:1] // drop the tail
	recorder.mu.Unlock()
	report, _ := recorder.Verify(collectorPrincipal())
	// Truncating the tail still verifies over what remains — the chain
	// proves ordering and content, not completeness. Gaps find loss;
	// checkpoints bound it.
	if !report.Intact {
		t.Fatalf("chain over the remainder must still hold: %+v", report)
	}
}

func TestCheckpointsAreSignedAndVerifiable(t *testing.T) {
	recorder := testRecorder(t)
	result, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		collectorEvent(0), collectorEvent(1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Checkpoints) != 1 {
		t.Fatalf("checkpoints: %+v", result.Checkpoints)
	}
	checkpoint := result.Checkpoints[0]
	if checkpoint.SequenceFrom != 0 || checkpoint.SequenceTo != 1 {
		t.Fatalf("range: %+v", checkpoint)
	}
	if checkpoint.Digest == "" || checkpoint.Signature.Algorithm != "ed25519" {
		t.Fatalf("checkpoint: %+v", checkpoint)
	}
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil || !report.Intact || report.CheckpointsChecked != 1 {
		t.Fatalf("report: %+v err: %v", report, err)
	}

	// A forged checkpoint fails verification.
	recorder.mu.Lock()
	store := recorder.tenants[testTenant]
	store.checkpoints[0].SequenceTo = 9
	recorder.mu.Unlock()
	report, _ = recorder.Verify(collectorPrincipal())
	if report.Intact {
		t.Fatal("a forged checkpoint passed")
	}
}

func TestCheckpointNeverCoversAGap(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(2)}}); err != nil {
		t.Fatal(err)
	}
	recorder.mu.Lock()
	store := recorder.tenants[testTenant]
	state := store.sources["src_collector-alpha-1"]
	from, to := state.contiguousFrontier()
	recorder.mu.Unlock()
	if from != 2 || to != 2 {
		t.Fatalf("frontier: %d-%d (a gap at 0-1 must not be covered)", from, to)
	}
}

func TestRetentionTombstonesOldObjectsOnly(t *testing.T) {
	recorder := testRecorder(t)
	fresh := collectorEvent(0) // observed at testNow
	old := collectorEvent(1)
	old.Payload = EventPayload{
		Kind:        PayloadObjectRef,
		StorageRef:  "obj://evidence/raw-0001",
		Digest:      "sha256:" + repeat("a", 64),
		SizeBytes:   128,
		ContentType: "application/octet-stream",
	}
	old.ObservedAt = "2026-09-01T00:00:00Z"
	oldInline := collectorEvent(2)
	oldInline.ObservedAt = "2026-09-01T00:00:00Z" // old, but inline
	if _, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{
		fresh, old, oldInline,
	}}); err != nil {
		t.Fatal(err)
	}
	tombstoned, err := recorder.ApplyRetention(collectorPrincipal(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tombstoned != 1 {
		t.Fatalf("tombstoned: %d", tombstoned)
	}
	events, _ := recorder.Events(collectorPrincipal(), EventQuery{})
	var flagged int
	for _, event := range events {
		if event.Payload.Tombstone {
			flagged++
			if event.Payload.StorageRef == "" || event.Payload.Digest == "" {
				t.Fatal("a tombstone dropped its reference; evidence must name what existed")
			}
		}
	}
	if flagged != 1 {
		t.Fatalf("tombstones: %d", flagged)
	}
	// The chain still verifies: the originals never changed.
	report, _ := recorder.Verify(collectorPrincipal())
	if !report.Intact {
		t.Fatalf("retention broke the chain: %+v", report)
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	recorder := testRecorder(t)
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(0)}}); err != nil {
		t.Fatal(err)
	}
	other := &Principal{ID: "act_collector-beta-1",
		TenantID: "tnt_0000000000000000", Role: RoleCollector}
	otherEvent := collectorEvent(0)
	otherEvent.TenantID = other.TenantID
	if _, err := recorder.Ingest(other, &Batch{Events: []*Event{otherEvent}}); err != nil {
		t.Fatal(err)
	}
	digest, length, _ := recorder.Chain(collectorPrincipal())
	if length != 1 {
		t.Fatalf("cross-tenant leak: %d", length)
	}
	otherDigest, otherLength, _ := recorder.Chain(other)
	if otherLength != 1 || otherDigest == digest {
		t.Fatalf("chains are not separate: %d %s", otherLength, otherDigest)
	}
}

func TestBatchRefusesWrongTenantEvents(t *testing.T) {
	recorder := testRecorder(t)
	stray := collectorEvent(0)
	stray.TenantID = "tnt_0000000000000000"
	_, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{stray}})
	var refusal *IngestRefusal
	if err == nil {
		t.Fatal("a batch carrying another tenant's event was stored")
	}
	if !asRefusal(err, &refusal) {
		t.Fatalf("error type: %T", err)
	}
	if refusal.Errors[0].Check != "tenant_id" {
		t.Fatalf("refusal: %+v", refusal.Errors)
	}
}

func asRefusal(err error, out **IngestRefusal) bool {
	refusal, ok := err.(*IngestRefusal)
	if ok {
		*out = refusal
	}
	return ok
}

func TestWorkerCannotRecordCollectorFacts(t *testing.T) {
	recorder := testRecorder(t)
	worker := &Principal{ID: "act_worker-reference-01",
		TenantID: testTenant, Role: RoleWorker}
	_, err := recorder.Ingest(worker, &Batch{Events: []*Event{collectorEvent(0)}})
	if err == nil {
		t.Fatal("a worker recorded a collector fact")
	}

	// A worker claim from the worker is fine and stays worker-labeled.
	claim := collectorEvent(1)
	claim.TrustLabel = TrustWorkerClaim
	claim.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	if _, err := recorder.Ingest(worker, &Batch{Events: []*Event{claim}}); err != nil {
		t.Fatalf("worker claim refused: %v", err)
	}
}

func TestServiceCannotRecordCollectorFacts(t *testing.T) {
	recorder := testRecorder(t)
	service := &Principal{ID: "act_harness-reference-01",
		TenantID: testTenant, Role: RoleService}
	if _, err := recorder.Ingest(service, &Batch{Events: []*Event{
		collectorEvent(0),
	}}); err == nil {
		t.Fatal("a service identity recorded a collector fact")
	}
	reading := collectorEvent(1)
	reading.TrustLabel = TrustMonitorReading
	reading.Source = EventSource{ID: "src_supervisor-alpha-1", Component: ComponentMonitor}
	if _, err := recorder.Ingest(service, &Batch{Events: []*Event{reading}}); err != nil {
		t.Fatalf("monitor interpretation refused: %v", err)
	}
}

func TestWorkerComponentCannotCarryCollectorFact(t *testing.T) {
	recorder := testRecorder(t)
	confused := collectorEvent(0)
	confused.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	_, err := recorder.Ingest(collectorPrincipal(), &Batch{Events: []*Event{confused}})
	if err == nil {
		t.Fatal("a worker source carried a collector fact")
	}
}

func TestBrokerDecisionMustBeACollectorFact(t *testing.T) {
	recorder := testRecorder(t)
	claimed := collectorEvent(0)
	claimed.EventKind = KindBrokerDecision
	claimed.TrustLabel = TrustWorkerClaim
	claimed.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	worker := &Principal{ID: "act_worker-reference-01", TenantID: testTenant, Role: RoleWorker}
	if _, err := recorder.Ingest(worker, &Batch{Events: []*Event{claimed}}); err == nil {
		t.Fatal("a broker decision arrived as a worker claim")
	}
}

func TestCollectorHeartbeatCollects(t *testing.T) {
	recorder := testRecorder(t)
	heartbeat := collectorEvent(0)
	heartbeat.EventKind = KindCollectorHeartbeat
	result, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{heartbeat}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 {
		t.Fatalf("result: %+v", result)
	}
}

func TestReadsRefuseWorkers(t *testing.T) {
	recorder := testRecorder(t)
	worker := &Principal{ID: "act_worker-reference-01", TenantID: testTenant, Role: RoleWorker}
	if _, err := recorder.Events(worker, EventQuery{}); err == nil {
		t.Fatal("a worker read the authoritative store")
	}
	if _, err := recorder.Findings(worker); err == nil {
		t.Fatal("a worker read findings")
	}
	if _, err := recorder.Verify(worker); err == nil {
		t.Fatal("a worker ran verification")
	}
}

func TestEmptyTenantVerifiesIntact(t *testing.T) {
	recorder := testRecorder(t)
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil || !report.Intact {
		t.Fatalf("report: %+v err: %v", report, err)
	}
}

func repeat(char string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, char[0])
	}
	return string(out)
}

// HTTP tests share one server per case.
func testServer(t *testing.T, opts ...Option) (*httptest.Server, *Recorder) {
	t.Helper()
	recorder := testRecorder(t, opts...)
	server := httptest.NewServer((&Server{Recorder: recorder}).Handler())
	t.Cleanup(server.Close)
	return server, recorder
}

func doJSON(t *testing.T, method, url string, body []byte,
	headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	reply, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(reply.Body).Decode(&decoded)
	return reply, decoded
}

func collectorHeaders(key string) map[string]string {
	return map[string]string{
		HeaderActor:  "act_collector-alpha-1",
		HeaderTenant: testTenant,
		HeaderRole:   RoleCollector,
		HeaderIdem:   key,
	}
}

func TestIngestOverHTTP(t *testing.T) {
	server, recorder := testServer(t)
	batch := Batch{Events: []*Event{collectorEvent(0), collectorEvent(1)}}
	encoded, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	reply, body := doJSON(t, "POST", server.URL+"/v1/evidence/events",
		encoded, collectorHeaders("idk_ingest-00000001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, body)
	}
	if body["accepted"].(float64) != 2 || body["chain_digest"] == "" {
		t.Fatalf("body: %+v", body)
	}
	// The chain route answers with the same head.
	reply, chain := doJSON(t, "GET", server.URL+"/v1/evidence/chain", nil,
		map[string]string{
			HeaderActor: "act_analyst-reference-1", HeaderTenant: testTenant,
			HeaderRole: RoleOperator,
		})
	if reply.StatusCode != http.StatusOK || chain["event_count"].(float64) != 2 {
		t.Fatalf("chain: %d %+v", reply.StatusCode, chain)
	}
	// And verify passes.
	reply, verdict := doJSON(t, "GET", server.URL+"/v1/evidence/verify", nil,
		map[string]string{
			HeaderActor: "act_analyst-reference-1", HeaderTenant: testTenant,
			HeaderRole: RoleOperator,
		})
	if reply.StatusCode != http.StatusOK || verdict["intact"] != true {
		t.Fatalf("verify: %d %+v", reply.StatusCode, verdict)
	}
	_ = recorder
}

func TestIngestOverHTTPReplaysAndConflicts(t *testing.T) {
	server, _ := testServer(t)
	url := server.URL + "/v1/evidence/events"
	batch, _ := json.Marshal(Batch{Events: []*Event{collectorEvent(0)}})
	first, firstBody := doJSON(t, "POST", url, batch, collectorHeaders("idk_ingest-00000002"))
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first: %d", first.StatusCode)
	}
	again, againBody := doJSON(t, "POST", url, batch, collectorHeaders("idk_ingest-00000002"))
	if again.StatusCode != http.StatusOK || againBody["accepted"] != firstBody["accepted"] {
		t.Fatalf("replay: %d %+v", again.StatusCode, againBody)
	}
	changed, _ := json.Marshal(Batch{Events: []*Event{collectorEvent(5)}})
	conflict, problem := doJSON(t, "POST", url, changed, collectorHeaders("idk_ingest-00000002"))
	if conflict.StatusCode != http.StatusConflict || problem["code"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %+v", conflict.StatusCode, problem)
	}
}

func TestIngestOverHTTPRequiresKeyAndIdentity(t *testing.T) {
	server, _ := testServer(t)
	url := server.URL + "/v1/evidence/events"
	batch, _ := json.Marshal(Batch{Events: []*Event{collectorEvent(0)}})
	noKey := collectorHeaders("")
	delete(noKey, HeaderIdem)
	reply, problem := doJSON(t, "POST", url, batch, noKey)
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "idempotency_key_required" {
		t.Fatalf("no key: %d %+v", reply.StatusCode, problem)
	}
	reply, problem = doJSON(t, "POST", url, batch, nil)
	if reply.StatusCode != http.StatusUnauthorized || problem["code"] != "unauthenticated" {
		t.Fatalf("no identity: %d %+v", reply.StatusCode, problem)
	}
	worker := collectorHeaders("idk_ingest-00000003")
	worker[HeaderActor] = "act_worker-reference-01"
	worker[HeaderRole] = RoleWorker
	reply, problem = doJSON(t, "POST", url, batch, worker)
	if reply.StatusCode != http.StatusUnprocessableEntity || problem["code"] != "evidence_refused" {
		t.Fatalf("worker: %d %+v", reply.StatusCode, problem)
	}
}

func TestIngestOverHTTPUnknownFieldFailsClosed(t *testing.T) {
	server, _ := testServer(t)
	body := []byte(`{"events":[` + eventJSON(collectorEvent(0)) + `],"source":"direct"}`)
	reply, problem := doJSON(t, "POST", server.URL+"/v1/evidence/events",
		body, collectorHeaders("idk_ingest-00000004"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "evidence_schema" {
		t.Fatalf("reply: %d %+v", reply.StatusCode, problem)
	}
}

func TestFindingsOverHTTP(t *testing.T) {
	server, _ := testServer(t)
	batch, _ := json.Marshal(Batch{Events: []*Event{collectorEvent(9)}})
	ingestReply, ingestBody := doJSON(t, "POST", server.URL+"/v1/evidence/events",
		batch, collectorHeaders("idk_ingest-00000005"))
	if ingestReply.StatusCode != http.StatusOK || ingestBody["accepted"].(float64) != 1 {
		t.Fatalf("ingest: %d %+v", ingestReply.StatusCode, ingestBody)
	}
	headers := map[string]string{
		HeaderActor: "act_analyst-reference-1", HeaderTenant: testTenant,
		HeaderRole: RoleOperator,
	}
	reply, body := doJSON(t, "GET", server.URL+"/v1/evidence/findings", nil, headers)
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("findings: %d", reply.StatusCode)
	}
	found := body["findings"].([]any)
	if len(found) != 1 {
		t.Fatalf("findings: %+v", found)
	}
	first := found[0].(map[string]any)
	if first["category"] != CategoryEvidenceGap || first["state"] != FindingStateOpen {
		t.Fatalf("finding: %+v", first)
	}
}

func TestEventsOverHTTPFilterByRun(t *testing.T) {
	server, _ := testServer(t)
	batch, _ := json.Marshal(Batch{Events: []*Event{collectorEvent(0)}})
	doJSON(t, "POST", server.URL+"/v1/evidence/events",
		batch, collectorHeaders("idk_ingest-00000006"))
	headers := map[string]string{
		HeaderActor: "act_analyst-reference-1", HeaderTenant: testTenant,
		HeaderRole: RoleOperator,
	}
	url := server.URL + "/v1/evidence/events?run_id=" + testRunID
	reply, body := doJSON(t, "GET", url, nil, headers)
	if reply.StatusCode != http.StatusOK || len(body["events"].([]any)) != 1 {
		t.Fatalf("events: %d %+v", reply.StatusCode, body)
	}
	url = server.URL + "/v1/evidence/events?run_id=run_nosuchrun0001"
	reply, body = doJSON(t, "GET", url, nil, headers)
	if reply.StatusCode != http.StatusOK || len(body["events"].([]any)) != 0 {
		t.Fatalf("empty run: %d %+v", reply.StatusCode, body)
	}
	// A worker cannot read.
	worker := map[string]string{
		HeaderActor: "act_worker-reference-01", HeaderTenant: testTenant,
		HeaderRole: RoleWorker,
	}
	reply, problem := doJSON(t, "GET", server.URL+"/v1/evidence/events", nil, worker)
	if reply.StatusCode != http.StatusForbidden || problem["code"] != "role_forbidden" {
		t.Fatalf("worker read: %d %+v", reply.StatusCode, problem)
	}
}

// eventJSON marshals one event for hand-built bodies.
func eventJSON(event *Event) string {
	encoded, err := json.Marshal(event)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
