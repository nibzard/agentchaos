package broker

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stopURL builds the stop route for the fixture run.
func stopURL(server *httptest.Server) string {
	return server.URL + "/v1/runs/" + testRun().RunID + "/stop"
}

// stopBody is a minimal valid order body.
func stopBody() map[string]any {
	return map[string]any{"sandbox": SandboxPreserve, "reason": "http test"}
}

func TestStopOverHTTP(t *testing.T) {
	server, broker := testServer(t)
	commitFixture(t, broker, 1) // committed A2, uncompensated: dirty

	reply, body := doJSON(t, "POST", stopURL(server),
		mustJSON(t, stopBody()), serviceHeaders("idk_http-stop-0001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, body)
	}
	if body["kind"] != "StopReport" || body["terminal_state"] != TerminalDirty {
		t.Fatalf("report: %+v", body)
	}
	steps := body["steps"].([]any)
	if len(steps) != 10 {
		t.Fatalf("steps: %d", len(steps))
	}

	// The read route returns the same report.
	readReply, read := doJSON(t, "GET", stopURL(server), nil,
		map[string]string{
			HeaderActor:  "act_harness-reference-01",
			HeaderTenant: testRun().TenantID,
			HeaderRole:   RoleService,
		})
	if readReply.StatusCode != http.StatusOK || read["id"] != body["id"] {
		t.Fatalf("read: %d %+v", readReply.StatusCode, read)
	}
}

func TestStopReadBeforeAnyStopIs404(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "GET", stopURL(server), nil, map[string]string{
		HeaderActor:  "act_harness-reference-01",
		HeaderTenant: testRun().TenantID,
		HeaderRole:   RoleService,
	})
	if reply.StatusCode != http.StatusNotFound || body["code"] != "stop_not_found" {
		t.Fatalf("reply: %d %+v", reply.StatusCode, body)
	}
}

func TestStopOverHTTPRequiresIdempotencyKey(t *testing.T) {
	server, _ := testServer(t)
	headers := serviceHeaders("")
	delete(headers, HeaderIdem)
	reply, body := doJSON(t, "POST", stopURL(server),
		mustJSON(t, stopBody()), headers)
	if reply.StatusCode != http.StatusBadRequest || body["code"] != "idempotency_key_required" {
		t.Fatalf("reply: %d %+v", reply.StatusCode, body)
	}
}

func TestStopOverHTTPReplaysPerRun(t *testing.T) {
	server, _ := testServer(t)
	url := stopURL(server)
	first, firstBody := doJSON(t, "POST", url,
		mustJSON(t, stopBody()), serviceHeaders("idk_http-stop-0002"))
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first: %d", first.StatusCode)
	}
	// The same key and body replays the stored reply.
	sameKey, sameBody := doJSON(t, "POST", url,
		mustJSON(t, stopBody()), serviceHeaders("idk_http-stop-0002"))
	if sameKey.StatusCode != http.StatusOK || sameBody["id"] != firstBody["id"] {
		t.Fatalf("same-key replay: %d %+v", sameKey.StatusCode, sameBody)
	}
	// A fresh key replays the run's report; only one stop exists.
	freshKey, freshBody := doJSON(t, "POST", url,
		mustJSON(t, stopBody()), serviceHeaders("idk_http-stop-0003"))
	if freshKey.StatusCode != http.StatusOK || freshBody["id"] != firstBody["id"] {
		t.Fatalf("fresh-key replay: %d %+v", freshKey.StatusCode, freshBody)
	}
	// The same key with a different body conflicts.
	changed := stopBody()
	changed["sandbox"] = SandboxTerminate
	conflict, problem := doJSON(t, "POST", url,
		mustJSON(t, changed), serviceHeaders("idk_http-stop-0002"))
	if conflict.StatusCode != http.StatusConflict || problem["code"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %+v", conflict.StatusCode, problem)
	}
}

func TestStopOverHTTPRefusesUnknownRuns(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "POST", server.URL+"/v1/runs/run_unknown00000001/stop",
		mustJSON(t, stopBody()), serviceHeaders("idk_http-stop-0004"))
	if reply.StatusCode != http.StatusNotFound || body["code"] != "run_not_found" {
		t.Fatalf("reply: %d %+v", reply.StatusCode, body)
	}
}

func TestStopOverHTTPRefusesWorkersAndOtherTenants(t *testing.T) {
	server, _ := testServer(t)
	worker := serviceHeaders("idk_http-stop-0005")
	worker[HeaderActor] = "act_worker-reference-01"
	worker[HeaderRole] = RoleWorker
	reply, body := doJSON(t, "POST", stopURL(server), mustJSON(t, stopBody()), worker)
	if reply.StatusCode != http.StatusForbidden || body["code"] != "role_forbidden" {
		t.Fatalf("worker: %d %+v", reply.StatusCode, body)
	}

	outsider := serviceHeaders("idk_http-stop-0006")
	outsider[HeaderTenant] = "tnt_0000000000000000"
	reply, body = doJSON(t, "POST", stopURL(server), mustJSON(t, stopBody()), outsider)
	if reply.StatusCode != http.StatusNotFound || body["code"] != "run_not_found" {
		t.Fatalf("outsider: %d %+v", reply.StatusCode, body)
	}
}

func TestStopOverHTTPSchemaFailsClosed(t *testing.T) {
	server, _ := testServer(t)
	url := stopURL(server)
	unknownField := stopBody()
	unknownField["run_id"] = testRun().RunID // the path owns the run id
	reply, body := doJSON(t, "POST", url,
		mustJSON(t, unknownField), serviceHeaders("idk_http-stop-0007"))
	if reply.StatusCode != http.StatusBadRequest || body["code"] != "stop_schema" {
		t.Fatalf("unknown field: %d %+v", reply.StatusCode, body)
	}

	missingSandbox := map[string]any{"reason": "no disposition"}
	reply, body = doJSON(t, "POST", url,
		mustJSON(t, missingSandbox), serviceHeaders("idk_http-stop-0008"))
	if reply.StatusCode != http.StatusUnprocessableEntity || body["code"] != "stop_schema" {
		t.Fatalf("missing sandbox: %d %+v", reply.StatusCode, body)
	}

	badPlan := stopBody()
	badPlan["compensations"] = []any{map[string]any{
		"effect_id": "eff_1a2b3c4d5e6f7081", "operation": "queue.publish",
		"resource": "patch-export-beta", "destination": "sink:patch-export-beta",
		"arguments_digest": "sha256:x", "action_class": ClassA2,
	}}
	reply, body = doJSON(t, "POST", url,
		mustJSON(t, badPlan), serviceHeaders("idk_http-stop-0009"))
	if reply.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad plan: %d %+v", reply.StatusCode, body)
	}
}

func TestQuarantineEndpointListsDirtyArtifacts(t *testing.T) {
	server, broker := testServer(t)
	commitFixture(t, broker, 1)
	reply, report := doJSON(t, "POST", stopURL(server),
		mustJSON(t, stopBody()), serviceHeaders("idk_http-stop-0010"))
	if reply.StatusCode != http.StatusOK || report["terminal_state"] != TerminalDirty {
		t.Fatalf("stop: %d %+v", reply.StatusCode, report)
	}

	reader := map[string]string{
		HeaderActor:  "act_harness-reference-01",
		HeaderTenant: testRun().TenantID,
		HeaderRole:   RoleService,
	}
	reply, listing := doJSON(t, "GET", server.URL+"/v1/quarantine", nil, reader)
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("listing: %d", reply.StatusCode)
	}
	entries := listing["quarantined"].([]any)
	if len(entries) != 1 || entries[0] != "patch-export-beta@sink:patch-export-beta" {
		t.Fatalf("quarantined: %+v", entries)
	}
	if listing["tenant_id"] != testRun().TenantID {
		t.Fatalf("tenant: %v", listing["tenant_id"])
	}

	missing := map[string]string{HeaderActor: "act_harness-reference-01", HeaderRole: RoleService}
	reply, body := doJSON(t, "GET", server.URL+"/v1/quarantine", nil, missing)
	if reply.StatusCode != http.StatusUnauthorized || body["code"] != "unauthenticated" {
		t.Fatalf("unauthenticated listing: %d %+v", reply.StatusCode, body)
	}
}
