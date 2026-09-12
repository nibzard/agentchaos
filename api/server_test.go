package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentchaos/broker"
	"agentchaos/control"
	"agentchaos/evidence"
	"agentchaos/governor"
)

// The fixtures mirror control-plane/tests/conftest.py: the same shared
// valid records, the same derived baseline profile, the same compile
// timestamp.
const (
	fixtureNow       = "2026-09-11T21:00:00Z"
	testTenant       = "tnt_9d4c1e2a3b4f5c67"
	otherTenant      = "tnt_ffffffffffffffff"
	brokerRunID      = "run_0f1e2d3c4b5a6970"
	testExperimentID = "exp_2e7b4d1c8a3f5092"
)

var fixtureDir = filepath.Join("..", "shared", "fixtures", "valid")

func loadFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name+".json"))
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

// fixtureRecords assembles the compiler input records exactly the way
// the Python suite does.
func fixtureRecords(t *testing.T) map[string][]map[string]any {
	baseline := loadFixture(t, "autonomy-profile")
	baseline["id"] = "aup_1a2b3c4d5e6f7081"
	baseline["name"] = "hard-controls-only"
	baseline["version"] = "1.0.0"
	delete(baseline, "supersedes")
	delete(baseline, "description")
	baseline["controls"].(map[string]any)["allowed_action_classes"] = []string{"A0", "A1"}
	baseline["supervision"].(map[string]any)["contextual_reviewer"].(map[string]any)["enabled"] = false

	credentials := []map[string]any{
		{
			"kind": "Credential", "id": "cred_fixture-github-token",
			"tenant_id": testTenant, "credential_kind": "fixture-github-token",
			"refreshed_at": "2026-09-11T20:30:00Z",
		},
		{
			"kind": "Credential", "id": "cred_model-gateway",
			"tenant_id": testTenant, "credential_kind": "model-gateway",
			"refreshed_at": "2026-09-11T20:45:00Z",
		},
	}
	return map[string][]map[string]any{
		"workloads":   {loadFixture(t, "workload-version")},
		"profiles":    {baseline, loadFixture(t, "autonomy-profile")},
		"scenarios":   {loadFixture(t, "scenario-version")},
		"targets":     {enrolledTarget("tgt_4a5b6c7d8e9f0a1b"), enrolledTarget("tgt_0f1e2d3c4b5a6978")},
		"credentials": credentials,
	}
}

func enrolledTarget(id string) map[string]any {
	return map[string]any{
		"kind": "Target", "api_version": "v1", "id": id,
		"tenant_id": testTenant, "class": "synthetic-repo", "status": "enrolled",
		"enrollment": map[string]any{
			"enrolled_at":  "2026-09-01T10:00:00Z",
			"enrolled_by":  "act_platform-operator-01",
			"opt_in_modes": []string{"production_synthetic"},
		},
	}
}

func draftExperiment(t *testing.T) map[string]any {
	experiment := loadFixture(t, "experiment")
	experiment["status"] = "draft"
	delete(experiment, "plan")
	return experiment
}

// testEnv is a fully wired monolith: governor, evidence plane, assurer,
// real Python compiler, and a live broker upstream.
type testEnv struct {
	api *httptest.Server
	gov *governor.Governor
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	gov := governor.New(nil)
	evidenceServer := &evidence.Server{Recorder: evidence.New()}

	policy, err := broker.LoadPolicy(broker.DefaultPolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	brokerInstance := broker.New(policy, []*broker.RunContext{brokerRun()},
		[]broker.Sink{&broker.SyntheticSink{}})
	brokerHTTP := httptest.NewServer((&broker.Server{Broker: brokerInstance}).Handler())
	t.Cleanup(brokerHTTP.Close)

	brokerURL, err := url.Parse(brokerHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := New(gov, evidenceServer, control.NewAssurer(),
		NewPythonCompiler(filepath.Join("..", "control-plane")), brokerURL)
	apiServer := httptest.NewServer(server.Handler())
	t.Cleanup(apiServer.Close)
	return &testEnv{api: apiServer, gov: gov}
}

func brokerRun() *broker.RunContext {
	return &broker.RunContext{
		RunID:    brokerRunID,
		TenantID: testTenant,
		TaskID:   "task_fixture-close-issue",
		GrantExpiresAt: time.Now().UTC().Add(24 * time.Hour).
			Format("2006-01-02T15:04:05Z"),
		AllowedClasses: []string{"A1", "A2"},
	}
}

func headers(role, key string) map[string]string {
	return map[string]string{
		HeaderActor:  "act_platform-control-01",
		HeaderTenant: testTenant,
		HeaderRole:   role,
		HeaderIdem:   key,
	}
}

// doJSON performs one request against the monolith.
func doJSON(t *testing.T, method, url string, body []byte,
	headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	reply, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	raw, _ := io.ReadAll(reply.Body)
	var document map[string]any
	if len(raw) > 0 && strings.Contains(strings.ToLower(
		reply.Header.Get("Content-Type")), "json") {
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("%s %s: reply is not JSON: %s", method, url, raw)
		}
	}
	return reply, document
}

func mustBody(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// createDraftExperiment stores the fixture draft through the API.
func createDraftExperiment(t *testing.T, env *testEnv, key string) map[string]any {
	t.Helper()
	reply, body := doJSON(t, "POST", env.api.URL+"/v1/experiments",
		mustBody(t, draftExperiment(t)), headers(RoleService, key))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("create experiment: %d %v", reply.StatusCode, body)
	}
	return body["experiment"].(map[string]any)
}

// validateExperiment drives the stored draft through the real compiler.
func validateExperiment(t *testing.T, env *testEnv, id, key string) map[string]any {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	request := map[string]any{"records": fixtureRecords(t), "now": fixtureNow}
	reply, body := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+id+"/validation",
		mustBody(t, request), headers(RoleService, key))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("validate experiment: %d %v", reply.StatusCode, body)
	}
	return body
}

func TestExperimentLifecycleThroughTheCoreRoutes(t *testing.T) {
	env := newTestEnv(t)
	stored := createDraftExperiment(t, env, "idk_create-lifecycle-1")
	if stored["status"] != "draft" {
		t.Fatalf("stored status: %v", stored["status"])
	}

	validation := validateExperiment(t, env, testExperimentID, "idk_validate-lifecycle-1")
	if validation["risk_classification"] == "" {
		t.Fatalf("validation: %+v", validation)
	}
	experiment := validation["experiment"].(map[string]any)
	if experiment["status"] != "compiled" {
		t.Fatalf("post-validation status: %v", experiment["status"])
	}
	plan := experiment["plan"].(map[string]any)
	if !strings.HasPrefix(plan["plan_digest"].(string), "sha256:") {
		t.Fatalf("plan digest: %v", plan["plan_digest"])
	}

	// The run request names the allowed primitives: the Experiment
	// contract carries no operation names, so the control plane does.
	runRequest := map[string]any{
		"run_id":             brokerRunID, // the broker upstream knows this run
		"allowed_primitives": []string{"queue.publish", "http.request"},
	}
	reply, body := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, runRequest), headers(RoleService, "idk_run-lifecycle-0001"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("start run: %d %v", reply.StatusCode, body)
	}
	run := body["run"].(map[string]any)
	if run["run_id"] != brokerRunID || run["state"] != "active" {
		t.Fatalf("run: %+v", run)
	}

	// Run reads come from the governor through the monolith.
	reply, body = doJSON(t, "GET", env.api.URL+"/v1/runs/"+brokerRunID,
		nil, headers(RoleService, ""))
	if reply.StatusCode != http.StatusOK || body["state"] != "active" {
		t.Fatalf("get run: %d %v", reply.StatusCode, body)
	}

	// The envelope registered from the compiled plan carries the
	// fixture's selectors, budgets, stop rules, and sessions.
	principal := &governor.Principal{ID: "act_platform-control-01",
		TenantID: testTenant, Role: RoleService}
	envelope, err := env.gov.Envelope(principal, testExperimentID)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Budgets.MaxDurationS != 1800 ||
		envelope.Budgets.MaxConcurrentSessions != 2 ||
		envelope.Budgets.AggregateCostMax.Micros != 12000000 {
		t.Fatalf("envelope budgets: %+v", envelope.Budgets)
	}
	if len(envelope.Selectors) != 1 ||
		len(envelope.Selectors[0].TargetIDs) != 1 ||
		envelope.Selectors[0].TargetIDs[0] != "tgt_4a5b6c7d8e9f0a1b" ||
		len(envelope.Selectors[0].Exclusions) != 1 {
		t.Fatalf("envelope selectors: %+v", envelope.Selectors)
	}
	if len(envelope.StopRules) != 3 || envelope.MaxSessions != 1000 {
		t.Fatalf("envelope rules %d sessions %d",
			len(envelope.StopRules), envelope.MaxSessions)
	}
	if len(envelope.AllowedPrimitives) != 2 {
		t.Fatalf("envelope primitives: %v", envelope.AllowedPrimitives)
	}

	// A second run reuses the immutable envelope instead of colliding.
	reply, body = doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, map[string]any{"allowed_primitives": []string{"queue.publish"}}),
		headers(RoleService, "idk_run-lifecycle-0002"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("second run: %d %v", reply.StatusCode, body)
	}
	if body["run"].(map[string]any)["run_id"] == brokerRunID {
		t.Fatal("the second run reused the first run's id")
	}
}

func TestARunRequiresACompilationFirst(t *testing.T) {
	env := newTestEnv(t)
	createDraftExperiment(t, env, "idk_create-uncompiled-1")
	reply, problem := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, map[string]any{"allowed_primitives": []string{"queue.publish"}}),
		headers(RoleService, "idk_run-uncompiled-01"))
	if reply.StatusCode != http.StatusConflict || problem["code"] != "validation_required" {
		t.Fatalf("uncompiled run: %d %v", reply.StatusCode, problem)
	}
}

func TestCreateExperimentFailsClosed(t *testing.T) {
	env := newTestEnv(t)
	cases := map[string]func(*map[string]any){
		"unknown field": func(document *map[string]any) {
			(*document)["sneaky"] = true
		},
		"smuggled plan": func(document *map[string]any) {
			(*document)["plan"] = map[string]any{"plan_digest": "sha256:x"}
		},
	}
	keys := map[string]string{
		"unknown field": "idk_create-bad-unknown1",
		"smuggled plan": "idk_create-bad-plan0001",
	}
	for name, mutate := range cases {
		document := draftExperiment(t)
		mutate(&document)
		reply, problem := doJSON(t, "POST", env.api.URL+"/v1/experiments",
			mustBody(t, document), headers(RoleService, keys[name]))
		if reply.StatusCode != http.StatusBadRequest || problem["code"] != "experiment_schema" {
			t.Fatalf("%s: %d %v", name, reply.StatusCode, problem)
		}
	}

	// A draft that is not a draft, and a tenant claim that disagrees
	// with the authenticated tenant, fail closed too.
	running := draftExperiment(t)
	running["status"] = "running"
	reply, problem := doJSON(t, "POST", env.api.URL+"/v1/experiments",
		mustBody(t, running), headers(RoleService, "idk_create-running-1"))
	if reply.StatusCode != http.StatusUnprocessableEntity || problem["code"] != "experiment_schema" {
		t.Fatalf("non-draft: %d %v", reply.StatusCode, problem)
	}
	crossTenant := draftExperiment(t)
	crossTenant["tenant_id"] = otherTenant
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/experiments",
		mustBody(t, crossTenant), headers(RoleService, "idk_create-cross-1"))
	if reply.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("cross-tenant claim: %d %v", reply.StatusCode, problem)
	}

	// A worker cannot alter experiments (spec 18.3), and the refusal
	// comes before any key accounting.
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/experiments",
		mustBody(t, draftExperiment(t)), headers(RoleWorker, "idk_create-worker-01"))
	if reply.StatusCode != http.StatusForbidden || problem["code"] != "role_forbidden" {
		t.Fatalf("worker create: %d %v", reply.StatusCode, problem)
	}
}

func TestValidationRefusesABrokenManifest(t *testing.T) {
	env := newTestEnv(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	createDraftExperiment(t, env, "idk_create-broken-01")
	records := fixtureRecords(t)
	delete(records, "targets") // selection fails closed without targets
	reply, problem := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/validation",
		mustBody(t, map[string]any{"records": records, "now": fixtureNow}),
		headers(RoleService, "idk_validate-broken1"))
	if reply.StatusCode != http.StatusUnprocessableEntity ||
		problem["code"] != "compile_failed" {
		t.Fatalf("broken manifest compiled: %d %v", reply.StatusCode, problem)
	}
	// Nothing was compiled: the experiment is still a draft, and a run
	// start still refuses.
	reply, problem = doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, map[string]any{"allowed_primitives": []string{"queue.publish"}}),
		headers(RoleService, "idk_run-broken-000001"))
	if reply.StatusCode != http.StatusConflict {
		t.Fatalf("run after failed compile: %d %v", reply.StatusCode, problem)
	}
}

func TestTenantIsolationOnExperiments(t *testing.T) {
	env := newTestEnv(t)
	createDraftExperiment(t, env, "idk_create-isolated-1")
	other := map[string]string{
		HeaderActor:  "act_other-operator-001",
		HeaderTenant: otherTenant,
		HeaderRole:   RoleOperator,
		HeaderIdem:   "idk_validate-cross-tenant",
	}
	reply, problem := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/validation",
		mustBody(t, map[string]any{"records": fixtureRecords(t), "now": fixtureNow}),
		other)
	if reply.StatusCode != http.StatusNotFound || problem["code"] != "experiment_unknown" {
		t.Fatalf("cross-tenant validation: %d %v", reply.StatusCode, problem)
	}
}

func TestEvidenceIngestThroughTheMonolith(t *testing.T) {
	env := newTestEnv(t)
	batch := map[string]any{"events": []any{collectorEvent(1), collectorEvent(2)}}
	reply, body := doJSON(t, "POST", env.api.URL+"/v1/evidence/events",
		mustBody(t, batch), headers(RoleCollector, "idk_ingest-monolith-1"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("ingest: %d %v", reply.StatusCode, body)
	}

	reply, body = doJSON(t, "GET", env.api.URL+"/v1/evidence/events?run_id="+brokerRunID,
		nil, headers(RoleService, ""))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("list events: %d %v", reply.StatusCode, body)
	}
	if events, ok := body["events"].([]any); !ok || len(events) != 2 {
		t.Fatalf("events through the monolith: %v", body)
	}

	// A worker cannot ingest authoritative events: the evidence plane
	// itself refuses a collector fact from a non-collector identity,
	// and nothing was stored (spec 18.3).
	reply, problem := doJSON(t, "POST", env.api.URL+"/v1/evidence/events",
		mustBody(t, map[string]any{"events": []any{collectorEvent(3)}}),
		headers(RoleWorker, "idk_ingest-worker-0001"))
	if reply.StatusCode != http.StatusUnprocessableEntity ||
		problem["code"] != "evidence_refused" {
		t.Fatalf("worker ingest: %d %v", reply.StatusCode, problem)
	}
}

func collectorEvent(n int) map[string]any {
	return map[string]any{
		"kind": "EvidenceEvent", "api_version": "v1",
		"id": fmt.Sprintf("evt_%016d", n), "tenant_id": testTenant,
		"run_id": brokerRunID, "event_kind": "tool_request",
		"trust_label": "collector_fact",
		"source": map[string]any{
			"id": "src_collector-alpha-1", "component": "collector",
			"coverage": "observed",
		},
		"sequence": n, "observed_at": fixtureNow, "clock_uncertainty_ms": 100,
		"payload": map[string]any{
			"kind": "inline", "content": fmt.Sprintf(`{"n":%d}`, n),
			"redacted": false, "truncated": false,
		},
	}
}

func TestEffectsForwardToTheIsolatedBroker(t *testing.T) {
	env := newTestEnv(t)
	proposal := map[string]any{
		"kind": "Effect", "api_version": "v1",
		"id":        "eff_" + "1a2b3c4d5e6f7081",
		"tenant_id": testTenant, "run_id": brokerRunID,
		"actor": "act_worker-reference-01", "action_class": "A2",
		"proposed_action": map[string]any{
			"operation": "queue.publish", "resource": "patch-export-beta",
			"destination":      "sink:patch-export-beta",
			"arguments_digest": "sha256:" + strings.Repeat("a", 64),
			"size_bytes":       128,
		},
		"state": "PROPOSED",
		"transitions": []map[string]any{
			{"state": "PROPOSED", "at": fixtureNow},
		},
		"created_at": fixtureNow,
	}
	reply, body := doJSON(t, "POST", env.api.URL+"/v1/effects/authorizations",
		mustBody(t, proposal), headers(RoleService, "idk_authorize-proxy-1"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("authorize through the monolith: %d %v", reply.StatusCode, body)
	}
	if body["effect"].(map[string]any)["state"] != "AUTHORIZED" {
		t.Fatalf("proxied decision: %+v", body)
	}

	// An unauthenticated caller never reaches the broker.
	unauthenticated := map[string]string{HeaderIdem: "idk_authorize-anon-01"}
	reply, problem := doJSON(t, "POST", env.api.URL+"/v1/effects/authorizations",
		mustBody(t, proposal), unauthenticated)
	if reply.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated proxy: %d %v", reply.StatusCode, problem)
	}
}

func TestStopRunFencesGovernorAndExecutesBrokerStop(t *testing.T) {
	env := newTestEnv(t)
	createDraftExperiment(t, env, "idk_create-stop-00001")
	validateExperiment(t, env, testExperimentID, "idk_validate-stop-001")
	reply, body := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, map[string]any{
			"run_id": brokerRunID, "allowed_primitives": []string{"queue.publish"},
		}), headers(RoleService, "idk_run-stop-000000001"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("start run: %d %v", reply.StatusCode, body)
	}

	order := map[string]any{"sandbox": "terminate", "reason": "operator request"}
	reply, body = doJSON(t, "POST", env.api.URL+"/v1/runs/"+brokerRunID+"/stop",
		mustBody(t, order), headers(RoleService, "idk_stop-00000000001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("stop run: %d %v", reply.StatusCode, body)
	}
	if body["run"].(map[string]any)["state"] != "fenced" {
		t.Fatalf("governor run after stop: %v", body["run"])
	}
	brokerReply := body["broker"].(map[string]any)
	if brokerReply["terminal_state"] != "CLEAN" {
		t.Fatalf("broker stop terminal state: %v", brokerReply["terminal_state"])
	}

	// The replay of the same stop returns the stored reply.
	reply, replay := doJSON(t, "POST", env.api.URL+"/v1/runs/"+brokerRunID+"/stop",
		mustBody(t, order), headers(RoleService, "idk_stop-00000000001"))
	if reply.StatusCode != http.StatusOK ||
		fmt.Sprint(replay) != fmt.Sprint(body) {
		t.Fatalf("stop replay: %d %v", reply.StatusCode, replay)
	}

	// The governor run is fenced, and the broker fence denies any new
	// authorization on the run.
	reply, body = doJSON(t, "GET", env.api.URL+"/v1/runs/"+brokerRunID,
		nil, headers(RoleService, ""))
	if reply.StatusCode != http.StatusOK || body["state"] == "active" {
		t.Fatalf("run after stop: %d %v", reply.StatusCode, body)
	}
	proposal := map[string]any{
		"kind": "Effect", "api_version": "v1",
		"id":        "eff_" + "2b3c4d5e6f708102",
		"tenant_id": testTenant, "run_id": brokerRunID,
		"actor": "act_worker-reference-01", "action_class": "A2",
		"proposed_action": map[string]any{
			"operation": "queue.publish", "resource": "patch-export-beta",
			"destination":      "sink:patch-export-beta",
			"arguments_digest": "sha256:" + strings.Repeat("a", 64),
			"size_bytes":       128,
		},
		"state": "PROPOSED",
		"transitions": []map[string]any{
			{"state": "PROPOSED", "at": fixtureNow},
		},
		"created_at": fixtureNow,
	}
	reply, body = doJSON(t, "POST", env.api.URL+"/v1/effects/authorizations",
		mustBody(t, proposal), headers(RoleService, "idk_authorize-fenced"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("post-stop authorize status: %d %v", reply.StatusCode, body)
	}
	decision := body["decision"].(map[string]any)
	if decision["verdict"] != "deny" || decision["reason"] != "run_stopped" {
		t.Fatalf("post-stop decision: %+v", decision)
	}
}

func TestSafetyLeversFenceTheApplicableAuthority(t *testing.T) {
	env := newTestEnv(t)
	createDraftExperiment(t, env, "idk_create-lever-0001")
	validateExperiment(t, env, testExperimentID, "idk_validate-lever-01")
	reply, body := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, map[string]any{
			"run_id": brokerRunID, "allowed_primitives": []string{"queue.publish"},
		}),
		headers(RoleService, "idk_run-lever-00000001"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("start run: %d %v", reply.StatusCode, body)
	}

	// The experiment lever fences the experiment's runs; the customer
	// can pull it without any operator in the loop (spec 13.3).
	reply, body = doJSON(t, "POST",
		env.api.URL+"/v1/safety-levers/"+testExperimentID+"/engage",
		mustBody(t, map[string]any{"reason": "containment drift"}),
		headers(RoleCustomer, "idk_lever-experiment-01"))
	if reply.StatusCode != http.StatusOK || body["engaged"] != true ||
		body["fenced_runs"].(float64) < 1 {
		t.Fatalf("experiment lever: %d %v", reply.StatusCode, body)
	}
	reply, body = doJSON(t, "GET", env.api.URL+"/v1/runs/"+brokerRunID,
		nil, headers(RoleService, ""))
	if body["state"] != "stopped" {
		t.Fatalf("run after lever: %v", body["state"])
	}

	// The tenant lever fences everything, including new runs.
	reply, body = doJSON(t, "POST", env.api.URL+"/v1/safety-levers/tenant/engage",
		mustBody(t, map[string]any{"reason": "customer incident"}),
		headers(RoleCustomer, "idk_lever-tenant-000001"))
	if reply.StatusCode != http.StatusOK || body["scope"] != "tenant" {
		t.Fatalf("tenant lever: %d %v", reply.StatusCode, body)
	}
	reply, problem := doJSON(t, "POST",
		env.api.URL+"/v1/experiments/"+testExperimentID+"/runs",
		mustBody(t, map[string]any{"allowed_primitives": []string{"queue.publish"}}),
		headers(RoleService, "idk_run-lever-00000002"))
	if reply.StatusCode != http.StatusConflict || problem["code"] != "tenant_fenced" {
		t.Fatalf("run after tenant lever: %d %v", reply.StatusCode, problem)
	}

	// A worker never engages a lever (spec 18.3), and a bad scope is a
	// client error.
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/safety-levers/tenant/engage",
		mustBody(t, map[string]any{}), headers(RoleWorker, "idk_lever-worker-0001"))
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("worker lever: %d %v", reply.StatusCode, problem)
	}
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/safety-levers/everything/engage",
		mustBody(t, map[string]any{}), headers(RoleOperator, "idk_lever-bad-000001"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "lever_scope_invalid" {
		t.Fatalf("bad scope: %d %v", reply.StatusCode, problem)
	}
}

func TestClaimsAssessStoreAndRead(t *testing.T) {
	env := newTestEnv(t)
	request := claimFixture()
	reply, claim := doJSON(t, "POST", env.api.URL+"/v1/assurance-claims",
		mustBody(t, request), headers(RoleService, "idk_claim-00000000001"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("assess claim: %d %v", reply.StatusCode, claim)
	}
	if claim["status"] != control.ClaimSupported {
		t.Fatalf("claim status: %v", claim["status"])
	}
	claimID := claim["id"].(string)

	reply, fetched := doJSON(t, "GET",
		env.api.URL+"/v1/assurance-claims/"+claimID, nil, headers(RoleService, ""))
	if reply.StatusCode != http.StatusOK || fetched["id"] != claimID {
		t.Fatalf("get claim: %d %v", reply.StatusCode, fetched)
	}

	// Another tenant sees nothing.
	reply, problem := doJSON(t, "GET",
		env.api.URL+"/v1/assurance-claims/"+claimID,
		nil, map[string]string{
			HeaderActor: "act_other-operator-001", HeaderTenant: otherTenant,
			HeaderRole: RoleOperator,
		})
	if reply.StatusCode != http.StatusNotFound || problem["code"] != "claim_unknown" {
		t.Fatalf("cross-tenant claim: %d %v", reply.StatusCode, problem)
	}

	// Unknown fields and impossible cohorts fail closed.
	bad := claimFixture()
	bad["vibes"] = true
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/assurance-claims",
		mustBody(t, bad), headers(RoleService, "idk_claim-unknown-field"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "claim_schema" {
		t.Fatalf("unknown claim field: %d %v", reply.StatusCode, problem)
	}
	impossible := claimFixture()
	impossible["failures"] = 99
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/assurance-claims",
		mustBody(t, impossible), headers(RoleService, "idk_claim-impossible1"))
	if reply.StatusCode != http.StatusUnprocessableEntity || problem["code"] != "claim_refused" {
		t.Fatalf("impossible cohort: %d %v", reply.StatusCode, problem)
	}
}

// claimFixture mirrors the assurer suite's cohort fixture.
func claimFixture() map[string]any {
	digest := "sha256:" + strings.Repeat("a", 64)
	return map[string]any{
		"claim_id": "clm_0123456789abcdef",
		"hazard": map[string]any{
			"description":         "credential exfiltration under injected file faults",
			"severity":            "H2",
			"failure_event":       "a secret lands outside the approved destination",
			"unit_of_observation": "task",
		},
		"workload_version_id": "wlv_0a1b2c3d4e5f6071",
		"fingerprints": map[string]any{
			"model": digest, "harness": digest, "tools": digest, "policy": digest,
			"monitor": digest, "scenario_distribution": digest, "environment": digest,
		},
		"evidence_category": "challenge_set_failure",
		"observation_window": map[string]any{
			"from": "2026-09-01T00:00:00Z", "to": "2026-09-08T00:00:00Z",
		},
		"selection_procedure": "preregistered fixed cohort of 22 tasks; no additions after unblinding",
		"label_source":        "independent outcome verifier (spec 9.5); no grader-only labels",
		"data_sources":        []string{"evt_0123456789abcdef"},
		"injection_funnel": map[string]any{
			"selected": 30, "eligible": 24, "triggered": 22, "untriggered": 2,
			"harness_error": 1, "verified_outcomes": 22,
		},
		"failures": 0, "eligible": 22, "unresolved": 0,
		"confidence_level": 0.95, "acceptance_threshold": 0.2,
		"dependence_model":         "independent_bernoulli",
		"dependence_description":   "tasks draw independent fault templates; no shared state",
		"population_applicability": "this workload version under this harness only",
		"invalidation_triggers":    []string{"model_identity_change", "prompt_change", "tool_change"},
		"created_at":               "2026-09-10T00:00:00Z",
	}
}

func TestIdempotencyReplayAndConflict(t *testing.T) {
	env := newTestEnv(t)
	document := mustBody(t, draftExperiment(t))
	reply, first := doJSON(t, "POST", env.api.URL+"/v1/experiments",
		document, headers(RoleService, "idk_replay-0000000001"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %v", reply.StatusCode, first)
	}
	reply, replay := doJSON(t, "POST", env.api.URL+"/v1/experiments",
		document, headers(RoleService, "idk_replay-0000000001"))
	if reply.StatusCode != http.StatusCreated {
		t.Fatalf("replay: %d %v", reply.StatusCode, replay)
	}
	if fmt.Sprint(replay) != fmt.Sprint(first) {
		t.Fatalf("replay differs:\n%v\n%v", first, replay)
	}

	changed := draftExperiment(t)
	changed["revision"] = 2
	reply, problem := doJSON(t, "POST", env.api.URL+"/v1/experiments",
		mustBody(t, changed), headers(RoleService, "idk_replay-0000000001"))
	if reply.StatusCode != http.StatusConflict || problem["code"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %v", reply.StatusCode, problem)
	}

	// A mutation without a key is a client error.
	reply, problem = doJSON(t, "POST", env.api.URL+"/v1/experiments",
		document, map[string]string{
			HeaderActor: "act_platform-control-01", HeaderTenant: testTenant,
			HeaderRole: RoleService,
		})
	if reply.StatusCode != http.StatusBadRequest ||
		problem["code"] != "idempotency_key_required" {
		t.Fatalf("missing key: %d %v", reply.StatusCode, problem)
	}
}
