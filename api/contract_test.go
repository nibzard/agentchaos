package api

// Spec 18.3 / T028: the API contract, pinned end to end through the
// monolith front end. Every mutation requires an idempotency key; key
// reuse with a different body digest conflicts on every plane; every
// error carries a stable code, a safe message, a retryability flag,
// and a request id; worker identities cannot reach authoritative
// surfaces; and error bodies never echo credentials.

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var reRequestID = regexp.MustCompile(`^req_[0-9a-f]{16}$`)

// mutationRoute is one mutation surface with a principal that may use
// it and a body that passes the envelope gates.
type mutationRoute struct {
	name string
	path string
	role string
	body map[string]any
}

func mutationRoutes() []mutationRoute {
	scrap := map[string]any{"kind": "scrap"}
	return []mutationRoute{
		{"create experiment", "/v1/experiments", RoleService, scrap},
		{"validate experiment", "/v1/experiments/" + testExperimentID +
			"/validation", RoleService, scrap},
		{"start run", "/v1/experiments/" + testExperimentID + "/runs",
			RoleService, scrap},
		{"stop run", "/v1/runs/" + brokerRunID + "/stop", RoleOperator, scrap},
		{"assess claim", "/v1/assurance-claims", RoleService, scrap},
		{"invalidate claims", "/v1/assurance-claims/invalidations",
			RoleOperator, scrap},
		{"engage lever", "/v1/safety-levers/global/engage", RoleOperator, scrap},
		{"ingest evidence", "/v1/evidence/events", RoleCollector, scrap},
		{"authorize effect", "/v1/effects/authorizations", RoleService, scrap},
		{"commit effect", "/v1/effects/eff_1a2b3c4d5e6f7081/commit",
			RoleService, scrap},
	}
}

func TestEveryMutationRouteRequiresAnIdempotencyKey(t *testing.T) {
	env := newTestEnv(t)
	for _, route := range mutationRoutes() {
		// A valid principal and role, but no key: the route must
		// refuse before touching any state.
		reply, problem := doJSON(t, "POST", env.api.URL+route.path,
			mustBody(t, route.body), map[string]string{
				"Authorization": "Bearer " + tokenFor(
					"act_platform-control-01", testTenant, route.role),
			})
		if reply.StatusCode != http.StatusBadRequest ||
			problem["code"] != "idempotency_key_required" {
			t.Fatalf("%s: %d %v", route.name, reply.StatusCode, problem)
		}
	}
}

func TestKeyReuseWithADifferentDigestConflictsOnEveryPlane(t *testing.T) {
	env := newTestEnv(t)

	// API-owned route.
	createDraftExperiment(t, env, "idk_contract-api-0001")
	changed := draftExperiment(t)
	changed["revision"] = 99
	reply, problem := doJSON(t, "POST", env.api.URL+"/v1/experiments",
		mustBody(t, changed), headers(RoleService, "idk_contract-api-0001"))
	if reply.StatusCode != http.StatusConflict ||
		problem["code"] != "idempotency_conflict" {
		t.Fatalf("api plane conflict: %d %v", reply.StatusCode, problem)
	}
	if problem["retryable"] != false {
		t.Fatalf("conflict retryability: %v", problem)
	}

	// Evidence plane route.
	first := map[string]any{"events": []any{collectorEvent(101)}}
	reply, body := doJSON(t, "POST", env.api.URL+"/v1/evidence/events",
		mustBody(t, first), headers(RoleCollector, "idk_contract-evid-001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("evidence first call: %d %v", reply.StatusCode, body)
	}
	second := map[string]any{"events": []any{collectorEvent(102)}}
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/evidence/events",
		mustBody(t, second), headers(RoleCollector, "idk_contract-evid-001"))
	if reply.StatusCode != http.StatusConflict ||
		problem["code"] != "idempotency_conflict" {
		t.Fatalf("evidence plane conflict: %d %v", reply.StatusCode, problem)
	}

	// Broker route through the proxy.
	reply, body = doJSON(t, "POST", env.api.URL+"/v1/effects/authorizations",
		mustBody(t, effectProposal("eff_"+"1111111111111111")),
		headers(RoleService, "idk_contract-brk-00001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("broker first call: %d %v", reply.StatusCode, body)
	}
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/effects/authorizations",
		mustBody(t, effectProposal("eff_"+"2222222222222222")),
		headers(RoleService, "idk_contract-brk-00001"))
	if reply.StatusCode != http.StatusConflict ||
		problem["code"] != "idempotency_conflict" {
		t.Fatalf("broker plane conflict: %d %v", reply.StatusCode, problem)
	}
}

func TestTheErrorEnvelopeHoldsTheContract(t *testing.T) {
	env := newTestEnv(t)
	scrap := mustBody(t, map[string]any{"kind": "scrap"})

	cases := []struct {
		name       string
		method     string
		path       string
		body       []byte
		headers    map[string]string
		wantStatus int
		wantCode   string
		wantRetry  bool
	}{
		{
			name: "unauthenticated", method: "POST", path: "/v1/experiments",
			body: scrap, headers: map[string]string{},
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated",
		},
		{
			name: "unauthenticated on the proxy", method: "POST",
			path: "/v1/effects/authorizations", body: scrap,
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated",
		},
		{
			name: "unauthenticated read", method: "GET",
			path: "/v1/assurance-claims/clm_0123456789abcdef", body: nil,
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated",
		},
		{
			name: "worker cannot create experiments", method: "POST",
			path: "/v1/experiments", body: scrap,
			headers:    headers(RoleWorker, "idk_contract-worker-1"),
			wantStatus: http.StatusForbidden, wantCode: "role_forbidden",
		},
		{
			name: "worker cannot drive broker authority", method: "POST",
			path: "/v1/effects/authorizations", body: scrap,
			headers:    headers(RoleWorker, "idk_contract-worker-2"),
			wantStatus: http.StatusForbidden, wantCode: "role_forbidden",
		},
		{
			name: "missing idempotency key", method: "POST",
			path: "/v1/experiments", body: scrap,
			headers: map[string]string{
				"Authorization": "Bearer " + tokenFor(
					"act_platform-control-01", testTenant, RoleService)},
			wantStatus: http.StatusBadRequest,
			wantCode:   "idempotency_key_required",
		},
		{
			name: "malformed idempotency key", method: "POST",
			path: "/v1/experiments", body: scrap,
			headers: map[string]string{
				"Authorization": "Bearer " + tokenFor(
					"act_platform-control-01", testTenant, RoleService),
				HeaderIdem: "key-without-a-namespace"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "idempotency_key_required",
		},
		{
			name: "unknown claim", method: "GET",
			path: "/v1/assurance-claims/clm_ffffffffffffffff", body: nil,
			headers:    headers(RoleService, ""),
			wantStatus: http.StatusNotFound, wantCode: "claim_unknown",
		},
		{
			name: "malformed claim id", method: "GET",
			path: "/v1/assurance-claims/not-a-claim", body: nil,
			headers:    headers(RoleService, ""),
			wantStatus: http.StatusBadRequest, wantCode: "claim_id_invalid",
		},
		{
			name: "unknown run", method: "GET",
			path: "/v1/runs/run_ffffffffffffffff", body: nil,
			headers:    headers(RoleService, ""),
			wantStatus: http.StatusNotFound, wantCode: "run_unknown",
		},
		{
			name: "unknown experiment", method: "POST",
			path: "/v1/experiments/exp_ffffffffffffffff/validation",
			body: mustBody(t, map[string]any{
				"records": fixtureRecords(t), "now": fixtureNow}),
			headers:    headers(RoleService, "idk_contract-unknow1"),
			wantStatus: http.StatusNotFound, wantCode: "experiment_unknown",
		},
		{
			name: "claim schema violation", method: "POST",
			path:       "/v1/assurance-claims",
			body:       mustBody(t, map[string]any{"vibes": true}),
			headers:    headers(RoleService, "idk_contract-schema-1"),
			wantStatus: http.StatusBadRequest, wantCode: "claim_schema",
		},
		{
			name: "invalidation refused", method: "POST",
			path:       "/v1/assurance-claims/invalidations",
			body:       mustBody(t, map[string]any{"kind": "vibe_shift"}),
			headers:    headers(RoleOperator, "idk_contract-inval-01"),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "invalidation_refused",
		},
	}

	for _, testCase := range cases {
		reply, problem := doJSON(t, testCase.method,
			env.api.URL+testCase.path, testCase.body, testCase.headers)
		if reply.StatusCode != testCase.wantStatus ||
			problem["code"] != testCase.wantCode {
			t.Fatalf("%s: %d %v (want %d %s)", testCase.name,
				reply.StatusCode, problem, testCase.wantStatus,
				testCase.wantCode)
		}
		if problem["retryable"] != testCase.wantRetry {
			t.Fatalf("%s retryability: %v", testCase.name, problem)
		}
		if message, _ := problem["message"].(string); message == "" {
			t.Fatalf("%s has no message: %v", testCase.name, problem)
		}
		if id, _ := problem["request_id"].(string); !reRequestID.MatchString(id) {
			t.Fatalf("%s request id: %v", testCase.name, problem)
		}
	}
}

func TestErrorBodiesNeverEchoCredentials(t *testing.T) {
	env := newTestEnv(t)
	// A planted secret in a body that will fail validation, and a
	// bearer token an attacker would love to see reflected back.
	const secret = "sk-live-DO-NOT-ECHO-7f3a9b"
	leaky := map[string]any{"kind": "scrap", "token": secret}

	checks := []struct {
		method  string
		path    string
		body    []byte
		headers map[string]string
	}{
		{"POST", "/v1/experiments", mustBody(t, leaky),
			headers(RoleService, "idk_contract-leak-001")},
		{"POST", "/v1/assurance-claims", mustBody(t, leaky),
			headers(RoleService, "idk_contract-leak-002")},
		{"POST", "/v1/effects/authorizations", mustBody(t, leaky),
			headers(RoleService, "idk_contract-leak-003")},
		{"POST", "/v1/evidence/events", mustBody(t, leaky),
			headers(RoleCollector, "idk_contract-leak-004")},
	}
	for _, check := range checks {
		reply, problem := doJSON(t, check.method, env.api.URL+check.path,
			check.body, check.headers)
		encoded := fmt.Sprint(problem)
		if strings.Contains(encoded, secret) {
			t.Fatalf("%s echoed the planted secret: %s", check.path, encoded)
		}
		if strings.Contains(encoded,
			strings.TrimPrefix(check.headers["Authorization"], "Bearer ")) {
			t.Fatalf("%s echoed the bearer token: %s", check.path, encoded)
		}
		if reply.StatusCode < 400 {
			t.Fatalf("%s unexpectedly succeeded: %d", check.path,
				reply.StatusCode)
		}
	}
}

func TestRequestIdsAreFreshPerCall(t *testing.T) {
	env := newTestEnv(t)
	ids := map[string]bool{}
	for i := 0; i < 3; i++ {
		reply, problem := doJSON(t, "GET",
			env.api.URL+"/v1/assurance-claims/clm_ffffffffffffffff",
			nil, headers(RoleService, ""))
		if reply.StatusCode != http.StatusNotFound {
			t.Fatalf("unexpected status: %d", reply.StatusCode)
		}
		id, _ := problem["request_id"].(string)
		if !reRequestID.MatchString(id) {
			t.Fatalf("request id shape: %v", problem)
		}
		if ids[id] {
			t.Fatalf("request id %s reused", id)
		}
		ids[id] = true
	}
}

func TestWorkerIdentitiesCannotMutateAuthoritativeSurfaces(t *testing.T) {
	env := newTestEnv(t)
	scrap := mustBody(t, map[string]any{"kind": "scrap"})
	cases := []struct {
		name string
		path string
	}{
		{"alter experiments", "/v1/experiments"},
		{"issue effect permits", "/v1/effects/authorizations"},
		{"engage a safety lever", "/v1/safety-levers/global/engage"},
		{"stop a run", "/v1/runs/" + brokerRunID + "/stop"},
	}
	for _, testCase := range cases {
		reply, problem := doJSON(t, "POST", env.api.URL+testCase.path, scrap,
			headers(RoleWorker, "idk_contract-wrole-"+testCase.name[:4]))
		if reply.StatusCode != http.StatusForbidden ||
			problem["code"] != "role_forbidden" {
			t.Fatalf("%s: %d %v", testCase.name, reply.StatusCode, problem)
		}
	}
	// Ingesting authoritative collector events is refused by the
	// evidence plane itself (spec 18.3), with nothing stored.
	reply, problem := doJSON(t, "POST", env.api.URL+"/v1/evidence/events",
		mustBody(t, map[string]any{"events": []any{collectorEvent(201)}}),
		headers(RoleWorker, "idk_contract-wrole-evid"))
	if reply.StatusCode != http.StatusUnprocessableEntity ||
		problem["code"] != "evidence_refused" {
		t.Fatalf("worker ingest: %d %v", reply.StatusCode, problem)
	}
}
