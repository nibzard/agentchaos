package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func testServer(t *testing.T) (*httptest.Server, *Broker) {
	t.Helper()
	broker := testBroker(t, &SyntheticSink{})
	server := httptest.NewServer((&Server{Broker: broker}).Handler())
	t.Cleanup(server.Close)
	return server, broker
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

func serviceHeaders(key string) map[string]string {
	return map[string]string{
		HeaderActor:  "act_harness-reference-01",
		HeaderTenant: "tnt_9d4c1e2a3b4f5c67",
		HeaderRole:   RoleService,
		HeaderIdem:   key,
	}
}

func TestAuthorizeEndpointRoundTrip(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), serviceHeaders("idk_authorize-0001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, body)
	}
	effect := body["effect"].(map[string]any)
	if effect["state"] != StateAuthorized {
		t.Fatalf("state: %v", effect["state"])
	}
	decision := body["decision"].(map[string]any)
	if decision["verdict"] != "allow" {
		t.Fatalf("verdict: %v", decision["verdict"])
	}
	permit := effect["authorization"].(map[string]any)
	if _, hasNonce := permit["nonce"]; !hasNonce {
		t.Fatal("permit missing nonce")
	}
}

func TestAuthorizeDenialIsAResultNotAnError(t *testing.T) {
	server, _ := testServer(t)
	proposal := validProposalJSON()
	proposal["proposed_action"].(map[string]any)["destination"] = "https://evil.example.com/x"
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, proposal), serviceHeaders("idk_authorize-0002"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("a deny is a successful evaluation; status: %d", reply.StatusCode)
	}
	if body["decision"].(map[string]any)["reason"] != "destination_not_allowed" {
		t.Fatalf("reason: %v", body["decision"])
	}
	if body["effect"].(map[string]any)["state"] != StateDenied {
		t.Fatal("denied state missing")
	}
}

func TestAuthorizeRequiresIdempotencyKey(t *testing.T) {
	server, _ := testServer(t)
	headers := serviceHeaders("")
	delete(headers, HeaderIdem)
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), headers)
	if reply.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "idempotency_key_required" {
		t.Fatalf("code: %v", body["code"])
	}
	if body["request_id"] == "" {
		t.Fatal("problem missing request id")
	}
}

func TestIdempotencyKeyReuseWithDifferentBodyConflicts(t *testing.T) {
	server, _ := testServer(t)
	url := server.URL + "/v1/effects/authorizations"
	headers := serviceHeaders("idk_authorize-0003")
	first, _ := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), headers)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status: %d", first.StatusCode)
	}
	changed := validProposalJSON()
	changed["proposed_action"].(map[string]any)["destination"] = "sink:another-sink"
	reply, body := doJSON(t, "POST", url, mustJSON(t, changed), headers)
	if reply.StatusCode != http.StatusConflict {
		t.Fatalf("conflict status: %d", reply.StatusCode)
	}
	if body["code"] != "idempotency_conflict" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestIdempotencyKeyReplayReturnsFirstReply(t *testing.T) {
	server, _ := testServer(t)
	url := server.URL + "/v1/effects/authorizations"
	headers := serviceHeaders("idk_authorize-0004")
	first, firstBody := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), headers)
	second, secondBody := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), headers)
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK {
		t.Fatalf("statuses: %d %d", first.StatusCode, second.StatusCode)
	}
	firstNonce := nested(firstBody, "effect", "authorization", "nonce")
	secondNonce := nested(secondBody, "effect", "authorization", "nonce")
	if firstNonce != secondNonce {
		t.Fatalf("replay minted a new permit: %v vs %v", firstNonce, secondNonce)
	}
}

func nested(document map[string]any, path ...string) any {
	var current any = document
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}

func TestAuthorizeRejectsUnknownField(t *testing.T) {
	server, _ := testServer(t)
	proposal := validProposalJSON()
	proposal["injected"] = true
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, proposal), serviceHeaders("idk_authorize-0005"))
	if reply.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "effect_schema" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestAuthorizeRejectsContractViolationsWithDetail(t *testing.T) {
	server, _ := testServer(t)
	proposal := validProposalJSON()
	proposal["action_class"] = "A3"
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, proposal), serviceHeaders("idk_authorize-0006"))
	if reply.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "effect_schema" {
		t.Fatalf("code: %v", body["code"])
	}
	if _, hasErrors := body["errors"]; !hasErrors {
		t.Fatal("problem missing contract errors")
	}
}

func TestWorkerPrincipalIsForbidden(t *testing.T) {
	server, _ := testServer(t)
	headers := serviceHeaders("idk_authorize-0007")
	headers[HeaderRole] = RoleWorker
	headers[HeaderActor] = "act_worker-reference-01"
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), headers)
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "role_forbidden" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestCommitEndpointRoundTrip(t *testing.T) {
	server, broker := testServer(t)
	_, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), serviceHeaders("idk_authorize-0010"))
	effectID := nested(body, "effect", "id").(string)

	reply, committed := doJSON(t, "POST",
		fmt.Sprintf("%s/v1/effects/%s/commit", server.URL, effectID),
		nil, serviceHeaders("idk_commit-0010"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, committed)
	}
	if committed["state"] != StateCommitted {
		t.Fatalf("state: %v", committed["state"])
	}
	receipt := committed["receipt"].(map[string]any)
	if receipt["reconciled"] != true {
		t.Fatalf("receipt: %+v", receipt)
	}
	// Commit replay with the same key returns the first reply.
	replay, replayed := doJSON(t, "POST",
		fmt.Sprintf("%s/v1/effects/%s/commit", server.URL, effectID),
		nil, serviceHeaders("idk_commit-0010"))
	if replay.StatusCode != http.StatusOK {
		t.Fatalf("replay status: %d", replay.StatusCode)
	}
	if replayed["state"] != StateCommitted {
		t.Fatalf("replay state: %v", replayed["state"])
	}
	if len(broker.Events()) != 2 {
		t.Fatalf("events: %d", len(broker.Events()))
	}
}

func TestCommitRejectsInvalidEffectID(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/nope/commit",
		nil, serviceHeaders("idk_commit-0020"))
	if reply.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "effect_id_invalid" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestCommitForUnknownEffectIsNotFound(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "POST",
		server.URL+"/v1/effects/eff_0000000000000000/commit",
		nil, serviceHeaders("idk_commit-0021"))
	if reply.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "effect_not_found" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestCrossTenantAuthorizeIsForbidden(t *testing.T) {
	server, _ := testServer(t)
	headers := serviceHeaders("idk_authorize-0030")
	headers[HeaderTenant] = "tnt_0000000000000000"
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), headers)
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "tenant_forbidden" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestUnauthenticatedCallerIsRejected(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), map[string]string{HeaderIdem: "idk_authorize-0040"})
	if reply.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", reply.StatusCode)
	}
	if body["code"] != "unauthenticated" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestHealthEndpoint(t *testing.T) {
	server, _ := testServer(t)
	reply, body := doJSON(t, "GET", server.URL+"/healthz", nil, nil)
	if reply.StatusCode != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("health: %d %+v", reply.StatusCode, body)
	}
}

func TestIdempotentReplayStillRequiresAuthentication(t *testing.T) {
	// The ledger replays the first reply only after authentication
	// and role checks; a replay from an unauthenticated caller, a
	// different tenant, or a worker never surfaces it (spec 18.3).
	server, _ := testServer(t)
	url := server.URL + "/v1/effects/authorizations"
	key := serviceHeaders("idk_replay-auth-01")
	if reply, _ := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), key); reply.StatusCode != http.StatusOK {
		t.Fatalf("first status: %d", reply.StatusCode)
	}

	bare := map[string]string{HeaderIdem: "idk_replay-auth-01"}
	if reply, body := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), bare); reply.StatusCode != http.StatusUnauthorized || body["code"] != "unauthenticated" {
		t.Fatalf("unauthenticated replay: %d %+v", reply.StatusCode, body)
	}

	other := serviceHeaders("idk_replay-auth-01")
	other[HeaderTenant] = "tnt_0000000000000000"
	if reply, body := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), other); reply.StatusCode != http.StatusForbidden || body["code"] != "tenant_forbidden" {
		t.Fatalf("cross-tenant replay: %d %+v", reply.StatusCode, body)
	}

	worker := serviceHeaders("idk_replay-auth-01")
	worker[HeaderRole] = RoleWorker
	worker[HeaderActor] = "act_worker-reference-01"
	if reply, body := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), worker); reply.StatusCode != http.StatusForbidden || body["code"] != "role_forbidden" {
		t.Fatalf("worker replay: %d %+v", reply.StatusCode, body)
	}
}

func TestConcurrentIdempotentAuthorizeExecutesOnce(t *testing.T) {
	server, broker := testServer(t)
	url := server.URL + "/v1/effects/authorizations"
	body := mustJSON(t, validProposalJSON())
	headers := serviceHeaders("idk_concurrent-01")

	const callers = 8
	nonces := make([]string, callers)
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			reply, decoded := doJSON(t, "POST", url, body, headers)
			if reply.StatusCode != http.StatusOK {
				t.Errorf("caller %d: status %d", i, reply.StatusCode)
				return
			}
			nonces[i] = nested(decoded, "effect", "authorization", "nonce").(string)
		}(i)
	}
	group.Wait()
	for i := 1; i < callers; i++ {
		if nonces[i] == "" || nonces[i] != nonces[0] {
			t.Fatalf("caller %d minted a different permit: %q vs %q", i, nonces[i], nonces[0])
		}
	}
	if len(broker.Events()) != 1 {
		t.Fatalf("one idempotent mutation produced %d events", len(broker.Events()))
	}
}

func TestAuthorizeDuplicateEffectIDConflicts(t *testing.T) {
	server, _ := testServer(t)
	url := server.URL + "/v1/effects/authorizations"
	first, _ := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), serviceHeaders("idk_dup-0001"))
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status: %d", first.StatusCode)
	}
	// Same effect id under a different key: the lifecycle is
	// append-only, so a re-proposal conflicts instead of replacing.
	reply, body := doJSON(t, "POST", url, mustJSON(t, validProposalJSON()), serviceHeaders("idk_dup-0002"))
	if reply.StatusCode != http.StatusConflict {
		t.Fatalf("status: %d body: %+v", reply.StatusCode, body)
	}
	if body["code"] != "effect_exists" {
		t.Fatalf("code: %v", body["code"])
	}
}

func TestCommitWithoutIdentityHeadersIsUnauthorized(t *testing.T) {
	server, _ := testServer(t)
	_, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), serviceHeaders("idk_nilcommit-01"))
	effectID := nested(body, "effect", "id").(string)
	reply, problem := doJSON(t, "POST",
		fmt.Sprintf("%s/v1/effects/%s/commit", server.URL, effectID),
		nil, map[string]string{HeaderIdem: "idk_nilcommit-02"})
	if reply.StatusCode != http.StatusUnauthorized || problem["code"] != "unauthenticated" {
		t.Fatalf("reply: %d %+v (this path used to panic)", reply.StatusCode, problem)
	}
}

// freshProposal clones the fixture proposal under a fresh effect id
// so several authorizes in one test do not collide.
func freshProposal(n int) map[string]any {
	proposal := validProposalJSON()
	proposal["id"] = fmt.Sprintf("eff_%016x", n)
	return proposal
}

func TestCommitTransitionProblemsOverHTTP(t *testing.T) {
	server, broker := testServer(t)
	authorize := func(key string, n int) map[string]any {
		_, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
			mustJSON(t, freshProposal(n)), serviceHeaders(key))
		return body
	}
	commit := func(id, key string) (*http.Response, map[string]any) {
		return doJSON(t, "POST", fmt.Sprintf("%s/v1/effects/%s/commit", server.URL, id),
			nil, serviceHeaders(key))
	}

	// A second commit is an invalid_transition conflict.
	created := authorize("idk_trans-0001", 1)
	effectID := nested(created, "effect", "id").(string)
	if reply, _ := commit(effectID, "idk_trans-0002"); reply.StatusCode != http.StatusOK {
		t.Fatalf("first commit: %d", reply.StatusCode)
	}
	reply, problem := commit(effectID, "idk_trans-0003")
	if reply.StatusCode != http.StatusConflict || problem["code"] != "invalid_transition" {
		t.Fatalf("double commit: %d %+v", reply.StatusCode, problem)
	}
	if problem["state"] != StateCommitted {
		t.Fatalf("problem state: %v", problem["state"])
	}

	// A denied effect cannot commit.
	deniedProposal := freshProposal(2)
	deniedProposal["proposed_action"].(map[string]any)["destination"] = "https://evil.example.com/exfil"
	_, deniedBody := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, deniedProposal), serviceHeaders("idk_trans-0010"))
	reply, problem = commit(nested(deniedBody, "effect", "id").(string), "idk_trans-0011")
	if reply.StatusCode != http.StatusConflict || problem["state"] != StateDenied {
		t.Fatalf("denied commit: %d %+v", reply.StatusCode, problem)
	}

	// An expired permit is 410 Gone with the EXPIRED state.
	expired := authorize("idk_trans-0020", 3)
	expiredID := nested(expired, "effect", "id").(string)
	broker.now = fixedClock(t, "2026-09-12T10:06:00Z")
	reply, problem = commit(expiredID, "idk_trans-0021")
	if reply.StatusCode != http.StatusGone || problem["code"] != "invalid_transition" {
		t.Fatalf("expired commit: %d %+v", reply.StatusCode, problem)
	}
	if problem["state"] != StateExpired {
		t.Fatalf("problem state: %v", problem["state"])
	}

	// A destination no sink owns fails closed as a transition refusal.
	read := freshProposal(4)
	read["action_class"] = ClassA1
	read["proposed_action"].(map[string]any)["operation"] = "http.request"
	read["proposed_action"].(map[string]any)["resource"] = "repos/fixture/hello"
	read["proposed_action"].(map[string]any)["destination"] = "https://api.github.com/repos/fixture/hello"
	_, readBody := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, read), serviceHeaders("idk_trans-0030"))
	reply, problem = commit(nested(readBody, "effect", "id").(string), "idk_trans-0031")
	if reply.StatusCode != http.StatusConflict || problem["code"] != "invalid_transition" {
		t.Fatalf("no-sink commit: %d %+v", reply.StatusCode, problem)
	}
}

func TestCommitAfterUnknownOutcomeConflictsOverHTTP(t *testing.T) {
	// AC-010 over HTTP: a timeout stays fenced behind reconciliation.
	broker := testBroker(t, &SyntheticSink{Responder: func(*Effect) SinkResult {
		return SinkResult{Outcome: OutcomeTimeout}
	}})
	server := httptest.NewServer((&Server{Broker: broker}).Handler())
	t.Cleanup(server.Close)
	_, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), serviceHeaders("idk_unknown-0001"))
	effectID := nested(body, "effect", "id").(string)
	if reply, first := doJSON(t, "POST",
		fmt.Sprintf("%s/v1/effects/%s/commit", server.URL, effectID),
		nil, serviceHeaders("idk_unknown-0002")); reply.StatusCode != http.StatusOK || first["state"] != StateUnknown {
		t.Fatalf("first commit: %d %+v", reply.StatusCode, first)
	}
	reply, problem := doJSON(t, "POST",
		fmt.Sprintf("%s/v1/effects/%s/commit", server.URL, effectID),
		nil, serviceHeaders("idk_unknown-0003"))
	if reply.StatusCode != http.StatusConflict || problem["state"] != StateUnknown {
		t.Fatalf("retry after UNKNOWN_EFFECT: %d %+v", reply.StatusCode, problem)
	}
}

func TestDenyReasonsSurfaceOverHTTP(t *testing.T) {
	server, _ := testServer(t)
	url := server.URL + "/v1/effects/authorizations"

	// A run the broker does not know denies as a result, not an error.
	unknown := validProposalJSON()
	unknown["run_id"] = "run_1111111111111111"
	reply, body := doJSON(t, "POST", url, mustJSON(t, unknown), serviceHeaders("idk_deny-0001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("run_unknown status: %d", reply.StatusCode)
	}
	if nested(body, "decision", "reason") != "run_unknown" ||
		nested(body, "effect", "state") != StateDenied {
		t.Fatalf("run_unknown reply: %+v", body)
	}

	// A grant past its window denies the same way.
	run := testRun()
	run.GrantExpiresAt = "2026-09-12T09:30:00Z"
	broker := New(testPolicy(t), []*RunContext{run}, []Sink{&SyntheticSink{}})
	broker.now = fixedClock(t, testNow)
	expiredServer := httptest.NewServer((&Server{Broker: broker}).Handler())
	t.Cleanup(expiredServer.Close)
	reply, body = doJSON(t, "POST", expiredServer.URL+"/v1/effects/authorizations",
		mustJSON(t, validProposalJSON()), serviceHeaders("idk_deny-0002"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("grant_expired status: %d", reply.StatusCode)
	}
	if nested(body, "decision", "reason") != "grant_expired" ||
		nested(body, "effect", "state") != StateDenied {
		t.Fatalf("grant_expired reply: %+v", body)
	}
}
