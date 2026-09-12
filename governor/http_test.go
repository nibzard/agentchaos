package governor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer(t *testing.T) (*httptest.Server, *Governor, *fixedClock) {
	t.Helper()
	clock := newFixedClock()
	g := New(clock.Now)
	server := httptest.NewServer((&Server{Governor: g}).Handler())
	t.Cleanup(server.Close)
	return server, g, clock
}

func doJSON(t *testing.T, method, url string, body []byte, headers map[string]string) (*http.Response, map[string]any) {
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

func serviceHeaders() map[string]string {
	return map[string]string{
		HeaderActor:  "act_runner-svc-01",
		HeaderTenant: "tnt_alpha00000001",
		HeaderRole:   RoleService,
	}
}

func headersWith(role string) map[string]string {
	headers := serviceHeaders()
	headers[HeaderRole] = role
	return headers
}

func customerHeaders() map[string]string {
	return map[string]string{
		HeaderActor:  "act_customer-admin1",
		HeaderTenant: "tnt_alpha00000001",
		HeaderRole:   RoleCustomer,
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func envelopeBody() *Envelope {
	return testEnvelope()
}

func TestEndpointsRoundTrip(t *testing.T) {
	server, _, _ := testServer(t)

	reply, body := doJSON(t, "POST", server.URL+"/v1/envelopes",
		mustJSON(t, envelopeBody()), serviceHeaders())
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("envelope: %d %+v", reply.StatusCode, body)
	}
	if body["kind"] != "SafetyEnvelope" {
		t.Fatalf("envelope kind: %v", body["kind"])
	}

	reply, body = doJSON(t, "POST", server.URL+"/v1/runs",
		mustJSON(t, map[string]string{
			"run_id":        "run_httptest000001",
			"experiment_id": "exp_gate000000001",
		}), serviceHeaders())
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("run: %d %+v", reply.StatusCode, body)
	}
	if body["state"] != RunStateActive {
		t.Fatalf("run state: %v", body["state"])
	}
	grant := body["grant"].(map[string]any)
	if grant["generation"] != float64(1) {
		t.Fatalf("generation: %v", grant["generation"])
	}

	reply, body = doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000001/heartbeats",
		mustJSON(t, map[string]any{
			"run_id":     "run_httptest000001",
			"generation": 1,
			"session_spends": []any{map[string]any{
				"session_id": "ses_http000000001",
				"cost":       map[string]any{"currency": "USD", "micros": 100},
			}},
			"observed_targets": []any{"tgt_alpha00000001"},
		}), serviceHeaders())
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: %d %+v", reply.StatusCode, body)
	}
	grant = body["grant"].(map[string]any)
	if grant["generation"] != float64(2) {
		t.Fatalf("renewed generation: %v", grant["generation"])
	}

	// The read endpoints agree.
	reply, body = doJSON(t, "GET", server.URL+"/v1/runs/run_httptest000001", nil, serviceHeaders())
	if reply.StatusCode != http.StatusOK || body["run_id"] != "run_httptest000001" {
		t.Fatalf("get run: %d %+v", reply.StatusCode, body)
	}
	reply, body = doJSON(t, "GET", server.URL+"/v1/envelopes/exp_gate000000001", nil, serviceHeaders())
	if reply.StatusCode != http.StatusOK || body["fenced"] != false {
		t.Fatalf("get envelope: %d %+v", reply.StatusCode, body)
	}
}

func TestSchemaProblemsFailClosed(t *testing.T) {
	server, _, _ := testServer(t)

	// Unknown fields are rejected at any nesting level.
	reply, body := doJSON(t, "POST", server.URL+"/v1/envelopes",
		[]byte(`{"experiment_id":"exp_gate000000001","budgets":{"max_duration_s":10,"widened":true}}`),
		serviceHeaders())
	if reply.StatusCode != http.StatusBadRequest || body["code"] != "envelope_schema" {
		t.Fatalf("unknown fields: %d %+v", reply.StatusCode, body)
	}

	// Pattern violations are 422 with per-field errors.
	envelope := envelopeBody()
	envelope.Selectors[0].TargetIDs = []string{"wildcard-*"}
	reply, body = doJSON(t, "POST", server.URL+"/v1/envelopes",
		mustJSON(t, envelope), serviceHeaders())
	if reply.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad selector: %d %+v", reply.StatusCode, body)
	}
	if _, ok := body["errors"]; !ok {
		t.Fatalf("no contract errors: %+v", body)
	}

	// A body's run id must match the path.
	reply, body = doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000001/heartbeats",
		mustJSON(t, map[string]any{"run_id": "run_other000000001"}), serviceHeaders())
	if reply.StatusCode != http.StatusBadRequest || body["code"] != "heartbeat_schema" {
		t.Fatalf("path mismatch: %d %+v", reply.StatusCode, body)
	}
}

func TestIncidentAndEmergencyStopOverHTTP(t *testing.T) {
	server, _, _ := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/envelopes", mustJSON(t, envelopeBody()), serviceHeaders())
	doJSON(t, "POST", server.URL+"/v1/runs", mustJSON(t, map[string]string{
		"run_id": "run_httptest000002", "experiment_id": "exp_gate000000001",
	}), serviceHeaders())

	reply, body := doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000002/incidents",
		mustJSON(t, map[string]any{
			"condition": TripUnauthorizedEffect,
			"reason":    "A2 write outside primitives",
		}), serviceHeaders())
	if reply.StatusCode != http.StatusOK || body["status"] != "recorded" {
		t.Fatalf("incident: %d %+v", reply.StatusCode, body)
	}

	// The stop handoff is fetchable, and the customer role can stop.
	reply, body = doJSON(t, "GET", server.URL+"/v1/runs/run_httptest000002/stop-handoff",
		nil, serviceHeaders())
	if reply.StatusCode != http.StatusOK || body["kind"] != "StopHandoff" {
		t.Fatalf("handoff: %d %+v", reply.StatusCode, body)
	}

	doJSON(t, "POST", server.URL+"/v1/runs", mustJSON(t, map[string]string{
		"run_id": "run_httptest000003", "experiment_id": "exp_gate000000001",
	}), serviceHeaders())
	reply, body = doJSON(t, "POST", server.URL+"/v1/emergency-stop",
		mustJSON(t, map[string]any{"kind": "tenant", "reason": "customer incident"}),
		customerHeaders())
	if reply.StatusCode != http.StatusOK || body["fenced_runs"] != float64(1) {
		t.Fatalf("emergency stop: %d %+v", reply.StatusCode, body)
	}

	// After the stop, no new run starts.
	reply, body = doJSON(t, "POST", server.URL+"/v1/runs", mustJSON(t, map[string]string{
		"run_id": "run_httptest000004", "experiment_id": "exp_gate000000001",
	}), serviceHeaders())
	if reply.StatusCode != http.StatusConflict || body["code"] != "tenant_fenced" {
		t.Fatalf("post-stop start: %d %+v", reply.StatusCode, body)
	}
}

func TestCleanupStateOverHTTP(t *testing.T) {
	server, g, clock := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/envelopes", mustJSON(t, envelopeBody()), serviceHeaders())
	doJSON(t, "POST", server.URL+"/v1/runs", mustJSON(t, map[string]string{
		"run_id": "run_httptest000005", "experiment_id": "exp_gate000000001",
	}), serviceHeaders())
	clock.advance(GrantLeaseTTL + time.Second)
	g.Sweep() // the daemon's tick trips the lapsed run

	reply, body := doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000005/cleanup-state",
		mustJSON(t, map[string]any{"terminal_state": "MOSTLY_FINE"}), serviceHeaders())
	if reply.StatusCode != http.StatusConflict || body["code"] != "terminal_state_invalid" {
		t.Fatalf("invalid state: %d %+v", reply.StatusCode, body)
	}

	reply, body = doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000005/cleanup-state",
		mustJSON(t, map[string]any{"terminal_state": "CLEAN"}), serviceHeaders())
	if reply.StatusCode != http.StatusOK || body["terminal_state"] != "CLEAN" {
		t.Fatalf("cleanup state: %d %+v", reply.StatusCode, body)
	}
}

func TestExpiredGrantIsGoneOverHTTP(t *testing.T) {
	server, _, clock := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/envelopes", mustJSON(t, envelopeBody()), serviceHeaders())
	doJSON(t, "POST", server.URL+"/v1/runs", mustJSON(t, map[string]string{
		"run_id": "run_httptest000006", "experiment_id": "exp_gate000000001",
	}), serviceHeaders())
	clock.advance(GrantLeaseTTL + time.Second)

	reply, body := doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000006/heartbeats",
		mustJSON(t, map[string]any{"run_id": "run_httptest000006"}), serviceHeaders())
	if reply.StatusCode != http.StatusGone || body["code"] != "grant_expired" {
		t.Fatalf("late beat: %d %+v", reply.StatusCode, body)
	}
}

func TestRoleGuardsOverHTTP(t *testing.T) {
	server, _, _ := testServer(t)

	// A worker never drives the authority path.
	reply, body := doJSON(t, "POST", server.URL+"/v1/envelopes",
		mustJSON(t, envelopeBody()), headersWith(RoleWorker))
	if reply.StatusCode != http.StatusForbidden || body["code"] != "role_forbidden" {
		t.Fatalf("worker envelope: %d %+v", reply.StatusCode, body)
	}

	// The customer role can stop but not register envelopes.
	reply, _ = doJSON(t, "POST", server.URL+"/v1/envelopes",
		mustJSON(t, envelopeBody()), customerHeaders())
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("customer envelope: %d", reply.StatusCode)
	}

	// Missing identity headers are unauthenticated.
	reply, body = doJSON(t, "POST", server.URL+"/v1/emergency-stop",
		mustJSON(t, map[string]any{"kind": "tenant"}), nil)
	if reply.StatusCode != http.StatusUnauthorized || body["code"] != "unauthenticated" {
		t.Fatalf("anonymous stop: %d %+v", reply.StatusCode, body)
	}
}

func TestHeartbeatRetryIsIdempotentOverHTTP(t *testing.T) {
	server, _, _ := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/envelopes", mustJSON(t, envelopeBody()), serviceHeaders())
	doJSON(t, "POST", server.URL+"/v1/runs", mustJSON(t, map[string]string{
		"run_id": "run_httptest000007", "experiment_id": "exp_gate000000001",
	}), serviceHeaders())

	beat := mustJSON(t, map[string]any{"run_id": "run_httptest000007", "generation": 1})
	first, body := doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000007/heartbeats",
		beat, serviceHeaders())
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first beat: %d %+v", first.StatusCode, body)
	}
	// A transport-level retry of the same beat replays the current
	// grant instead of renewing twice.
	retry, body := doJSON(t, "POST", server.URL+"/v1/runs/run_httptest000007/heartbeats",
		beat, serviceHeaders())
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retry beat: %d %+v", retry.StatusCode, body)
	}
	if grant := body["grant"].(map[string]any); grant["generation"] != float64(2) {
		t.Fatalf("retry renewed again: %v", grant["generation"])
	}
}
