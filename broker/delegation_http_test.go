package broker

import (
	"fmt"
	"net/http"
	"testing"
)

// delegationBody is a valid mint request document.
func delegationBody(id string) map[string]any {
	return map[string]any{
		"id":           id,
		"run_id":       testRun().RunID,
		"parent_actor": "act_orchestrator-01",
		"child_actor":  "act_planner-000001",
		"capabilities": map[string]any{
			"allowed_action_classes": []string{ClassA2},
			"allowed_destinations":   []string{"sink:patch-export-beta", "https://api.github.com/"},
			"allowed_resources":      []string{"patch-export-beta"},
		},
		"cumulative_budget": map[string]any{
			"max_total_cost":   map[string]any{"currency": "USD", "micros": 50000},
			"max_total_tokens": 1000000,
			"max_effects":      5,
		},
	}
}

func TestDelegateEndpointRoundTrip(t *testing.T) {
	server, broker := testServer(t)
	reply, body := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_http00000001")), serviceHeaders("idk_dlg-http-0001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, body)
	}
	if body["kind"] != "Delegation" || body["state"] != DelegationActive {
		t.Fatalf("body: %+v", body)
	}
	if body["tenant_id"] != "tnt_9d4c1e2a3b4f5c67" {
		t.Fatalf("tenant: %v", body["tenant_id"])
	}
	depth, ok := body["depth"].(float64)
	if !ok || depth != 1 {
		t.Fatalf("depth: %v", body["depth"])
	}

	// Replaying the same key and body returns the stored reply.
	replayReply, replay := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_http00000001")), serviceHeaders("idk_dlg-http-0001"))
	if replayReply.StatusCode != http.StatusOK || replay["id"] != "dlg_http00000001" {
		t.Fatalf("replay: %d %+v", replayReply.StatusCode, replay)
	}

	// The same key with a different body conflicts.
	conflictReply, problem := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_http00000002")), serviceHeaders("idk_dlg-http-0001"))
	if conflictReply.StatusCode != http.StatusConflict || problem["code"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %+v", conflictReply.StatusCode, problem)
	}

	// A second mint under a fresh key but a used id conflicts.
	duplicateReply, problem := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_http00000001")), serviceHeaders("idk_dlg-http-0002"))
	if duplicateReply.StatusCode != http.StatusConflict || problem["code"] != "delegation_exists" {
		t.Fatalf("duplicate: %d %+v", duplicateReply.StatusCode, problem)
	}

	// The mint is journaled.
	var mints int
	for _, event := range broker.Events() {
		if event.EventKind == "delegation" {
			mints++
		}
	}
	if mints != 1 {
		t.Fatalf("delegation events: %d", mints)
	}
}

func TestDelegateNarrowingRefusedOverHTTP(t *testing.T) {
	server, _ := testServer(t)
	if _, body := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_root00000001")), serviceHeaders("idk_narrow-0001")); body["state"] != DelegationActive {
		t.Fatalf("root mint: %+v", body)
	}

	// The child widens classes: 422 with the refusal's contract errors.
	widening := map[string]any{
		"id":                   "dlg_child00000001",
		"run_id":               testRun().RunID,
		"parent_actor":         "act_planner-000001",
		"child_actor":          "act_worker-narrowed-1",
		"parent_delegation_id": "dlg_root00000001",
		"capabilities": map[string]any{
			"allowed_action_classes": []string{ClassA1, ClassA2},
			"allowed_destinations":   []string{"sink:patch-export-beta"},
			"allowed_resources":      []string{"patch-export-beta"},
		},
		"cumulative_budget": map[string]any{
			"max_total_cost":   map[string]any{"currency": "USD", "micros": 30000},
			"max_total_tokens": 500000,
			"max_effects":      3,
		},
	}
	reply, problem := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, widening), serviceHeaders("idk_narrow-0002"))
	if reply.StatusCode != http.StatusUnprocessableEntity || problem["code"] != "delegation_refused" {
		t.Fatalf("widening: %d %+v", reply.StatusCode, problem)
	}
	errs, ok := problem["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatalf("problem errors: %+v", problem["errors"])
	}
	first := errs[0].(map[string]any)
	if first["check"] != "classes_widened" {
		t.Fatalf("first error: %+v", first)
	}
}

func TestDelegateSchemaProblemsOverHTTP(t *testing.T) {
	server, _ := testServer(t)

	// A misspelled key fails closed with 400.
	misspelled := delegationBody("dlg_schema0000001")
	misspelled["capabilites"] = misspelled["capabilities"]
	delete(misspelled, "capabilities")
	reply, problem := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, misspelled), serviceHeaders("idk_schema-0001"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "delegation_schema" {
		t.Fatalf("misspelled: %d %+v", reply.StatusCode, problem)
	}

	// A nested misspelling fails the same way.
	nested := delegationBody("dlg_schema0000002")
	nested["cumulative_budget"].(map[string]any)["max_total_cost"] = map[string]any{
		"currency": "USD", "micros": 100, "amount": 200,
	}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, nested), serviceHeaders("idk_schema-0002"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "delegation_schema" {
		t.Fatalf("nested: %d %+v", reply.StatusCode, problem)
	}

	// Pattern violations are 422 with field errors.
	badID := delegationBody("DIALOGUE-1")
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, badID), serviceHeaders("idk_schema-0003"))
	if reply.StatusCode != http.StatusUnprocessableEntity || problem["code"] != "delegation_schema" {
		t.Fatalf("bad id: %d %+v", reply.StatusCode, problem)
	}

	// An http destination with userinfo never validates.
	userinfo := delegationBody("dlg_schema0000003")
	userinfo["capabilities"].(map[string]any)["allowed_destinations"] = []string{
		"https://user@api.github.com/"}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, userinfo), serviceHeaders("idk_schema-0004"))
	if reply.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("userinfo: %d %+v", reply.StatusCode, problem)
	}

	// The idempotency key is required.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_schema0000004")),
		map[string]string{HeaderActor: "act_harness-reference-01",
			HeaderTenant: "tnt_9d4c1e2a3b4f5c67", HeaderRole: RoleService})
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "idempotency_key_required" {
		t.Fatalf("idem key: %d %+v", reply.StatusCode, problem)
	}
}

func TestRevokeDelegationOverHTTP(t *testing.T) {
	server, broker := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_rev0000000001")), serviceHeaders("idk_rev-http-001"))

	reply, body := doJSON(t, "POST", server.URL+"/v1/delegations/dlg_rev0000000001/revocation",
		mustJSON(t, map[string]any{"reason": "stop condition met"}), serviceHeaders("idk_rev-http-002"))
	if reply.StatusCode != http.StatusOK || body["state"] != DelegationRevoked {
		t.Fatalf("revoke: %d %+v", reply.StatusCode, body)
	}
	if body["revoked_at"] == "" {
		t.Fatal("no revoked_at")
	}

	// An unknown id is a tenant-safe miss.
	reply, problem := doJSON(t, "POST", server.URL+"/v1/delegations/dlg_missing000001/revocation",
		nil, serviceHeaders("idk_rev-http-003"))
	if reply.StatusCode != http.StatusNotFound || problem["code"] != "delegation_not_found" {
		t.Fatalf("unknown: %d %+v", reply.StatusCode, problem)
	}

	// A malformed id never reaches the registry.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations/not-an-id/revocation",
		nil, serviceHeaders("idk_rev-http-004"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "delegation_id_invalid" {
		t.Fatalf("bad id: %d %+v", reply.StatusCode, problem)
	}

	// An unknown field in the body fails closed.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations/dlg_rev0000000001/revocation",
		mustJSON(t, map[string]any{"reason": "x", "state": "active"}), serviceHeaders("idk_rev-http-005"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "delegation_schema" {
		t.Fatalf("unknown field: %d %+v", reply.StatusCode, problem)
	}

	// Replaying the revoke with the same key and body replays the reply.
	reply, body = doJSON(t, "POST", server.URL+"/v1/delegations/dlg_rev0000000001/revocation",
		mustJSON(t, map[string]any{"reason": "stop condition met"}), serviceHeaders("idk_rev-http-002"))
	if reply.StatusCode != http.StatusOK || body["state"] != DelegationRevoked {
		t.Fatalf("replay: %d %+v", reply.StatusCode, body)
	}

	var revokes int
	for _, event := range broker.Events() {
		if event.EventKind == "delegation" {
			revokes++
		}
	}
	if revokes != 2 { // one mint, one revoke
		t.Fatalf("delegation events: %d", revokes)
	}
}

func TestDelegationRoleGuardsOverHTTP(t *testing.T) {
	server, _ := testServer(t)

	worker := map[string]string{
		HeaderActor:  "act_worker-reference-01",
		HeaderTenant: "tnt_9d4c1e2a3b4f5c67",
		HeaderRole:   RoleWorker,
		HeaderIdem:   "idk_role-guard-001",
	}
	reply, problem := doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_role000000001")), worker)
	if reply.StatusCode != http.StatusForbidden || problem["code"] != "role_forbidden" {
		t.Fatalf("worker mint: %d %+v", reply.StatusCode, problem)
	}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations/dlg_role000000001/revocation",
		nil, worker)
	if reply.StatusCode != http.StatusForbidden || problem["code"] != "role_forbidden" {
		t.Fatalf("worker revoke: %d %+v", reply.StatusCode, problem)
	}

	// Unauthenticated calls never reach the ledger.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_role000000002")),
		map[string]string{HeaderIdem: "idk_role-guard-002"})
	if reply.StatusCode != http.StatusUnauthorized || problem["code"] != "unauthenticated" {
		t.Fatalf("unauthenticated: %d %+v", reply.StatusCode, problem)
	}
}

func TestDelegatedEffectOverHTTP(t *testing.T) {
	server, _ := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_root00000001")), serviceHeaders("idk_deff-http-001"))

	// A delegated proposal carries delegation_id and the holder actor.
	proposal := validProposalJSON()
	proposal["id"] = fmt.Sprintf("eff_%016x", 0xde)
	proposal["actor"] = "act_planner-000001"
	proposal["delegation_id"] = "dlg_root00000001"
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, proposal), serviceHeaders("idk_deff-http-002"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, body)
	}
	if nested(body, "effect", "state") != StateAuthorized {
		t.Fatalf("effect: %+v", body["effect"])
	}
	if nested(body, "effect", "delegation_id") != "dlg_root00000001" {
		t.Fatalf("delegation: %v", nested(body, "effect", "delegation_id"))
	}

	// The wrong actor is denied with the mismatch reason.
	wrongActor := validProposalJSON()
	wrongActor["id"] = fmt.Sprintf("eff_%016x", 0xdf)
	wrongActor["actor"] = "act_someone-else-01"
	wrongActor["delegation_id"] = "dlg_root00000001"
	reply, body = doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, wrongActor), serviceHeaders("idk_deff-http-003"))
	if reply.StatusCode != http.StatusOK || nested(body, "decision", "verdict") != "deny" {
		t.Fatalf("wrong actor: %d %+v", reply.StatusCode, body)
	}
	if nested(body, "decision", "reason") != "delegation_actor_mismatch" {
		t.Fatalf("reason: %v", nested(body, "decision", "reason"))
	}
	if nested(body, "effect", "state") != StateDenied {
		t.Fatalf("denied state: %v", nested(body, "effect", "state"))
	}
}
