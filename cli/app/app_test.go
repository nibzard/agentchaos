package app

// Tests for the gauntlet CLI (spec 17.7 / T029) against a scripted stub
// API. The stub records every request so the tests can pin headers
// (bearer token, idempotency key per mutation) and paths, and the
// exit-code table: 0 gate passed, 2 gate failed, 3 inconclusive,
// 4 invalid configuration, 5 harness or infrastructure failure.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// stubServer is a scriptable stand-in for the API monolith.
type stubServer struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []string // "METHOD path" per request, in order
	keys     []string // Idempotency-Key values, in order
	tokens   []string // Authorization values, in order
	bodies   []string // raw bodies, in order
}

// stubReply is one scripted response.
type stubReply struct {
	match   string // respond when method+path equals this
	status  int
	body    string
	headers map[string]string
}

// newStubServer serves the given replies in order of declaration when
// their match string hits; anything unmatched gets a 500 so a wrong
// path fails loudly.
func newStubServer(t *testing.T, replies ...stubReply) *stubServer {
	t.Helper()
	stub := &stubServer{}
	stub.server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			stub.mu.Lock()
			stub.requests = append(stub.requests, r.Method+" "+r.URL.RequestURI())
			stub.keys = append(stub.keys, r.Header.Get("Idempotency-Key"))
			stub.tokens = append(stub.tokens, r.Header.Get("Authorization"))
			buf := &bytes.Buffer{}
			_, _ = buf.ReadFrom(r.Body)
			stub.bodies = append(stub.bodies, buf.String())
			stub.mu.Unlock()

			for _, reply := range replies {
				if reply.match == r.Method+" "+r.URL.Path {
					for key, value := range reply.headers {
						w.Header().Set(key, value)
					}
					w.WriteHeader(reply.status)
					_, _ = w.Write([]byte(reply.body))
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"stub_miss","message":` +
				`"no scripted reply","retryable":false,` +
				`"request_id":"req_0000000000000000"}`))
		}))
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *stubServer) url() string { return s.server.URL }

func (s *stubServer) request(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[i]
}

func (s *stubServer) key(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[i]
}

func (s *stubServer) bearer(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[i]
}

func (s *stubServer) body(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[i]
}

func (s *stubServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// run invokes Main with a token and captures the exit code.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	code := Main(args, out, errOut)
	return code, out.String(), errOut.String()
}

// runAt is run with --api and --token already wired.
func runAt(t *testing.T, api, token string, args ...string) (int, string, string) {
	t.Helper()
	return run(t, append([]string{"--api", api, "--token", token},
		args...)...)
}

const cliToken = "gauntlet1.test-token"

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// problemBody builds an API problem envelope.
func problemBody(code, message string) string {
	return fmt.Sprintf(`{"code":%q,"message":%q,"retryable":false,`+
		`"request_id":"req_0123456789abcdef"}`, code, message)
}

const draftReply = `{"experiment":{"id":"exp_cli000000000001",` +
	`"status":"draft"}}`
const compiledReply = `{"experiment":{"id":"exp_cli000000000001",` +
	`"status":"compiled"},"risk_classification":"elevated"}`
const startedReply = `{"run":{"run_id":"run_cli000000000001",` +
	`"experiment_id":"exp_cli000000000001","state":"active",` +
	`"terminal_state":"",` +
	`"grant":{"expires_at":"2026-09-12T01:00:00Z"},"trips":[]}}`

func TestValidateStoresADraftAndExitsZero(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match: "POST /v1/experiments", status: http.StatusCreated,
		body: draftReply,
	})
	manifest := writeFile(t, "manifest.json", `{"kind":"experiment"}`)

	code, out, errOut := runAt(t, stub.url(), cliToken,
		"validate", manifest)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "exp_cli000000000001") {
		t.Fatalf("output missing experiment id: %s", out)
	}
	if key := stub.key(0); !strings.HasPrefix(key, "idk_cli-") {
		t.Fatalf("idempotency key: %q", key)
	}
	if stub.bearer(0) != "Bearer "+cliToken {
		t.Fatalf("authorization: %q", stub.bearer(0))
	}
}

func TestValidateCompilesWhenRecordsAreGiven(t *testing.T) {
	stub := newStubServer(t,
		stubReply{match: "POST /v1/experiments",
			status: http.StatusCreated, body: draftReply},
		stubReply{match: "POST /v1/experiments/exp_cli000000000001/validation",
			status: http.StatusOK, body: compiledReply},
	)
	manifest := writeFile(t, "manifest.json", `{"kind":"experiment"}`)
	records := writeFile(t, "records.json", `{"workloads":[]}`)

	code, out, errOut := runAt(t, stub.url(), cliToken, "validate",
		manifest, "--records", records)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "risk elevated") {
		t.Fatalf("compile output: %s", out)
	}
	if !strings.Contains(stub.body(1), `"now"`) {
		t.Fatalf("validation body carries no now: %s", stub.body(1))
	}
	// Both mutations carry distinct fresh idempotency keys.
	if stub.key(0) == stub.key(1) {
		t.Fatalf("idempotency keys reused: %q", stub.key(0))
	}
}

func TestConfigurationErrorsExitFour(t *testing.T) {
	stub := newStubServer(t)
	manifest := writeFile(t, "manifest.json", `{"kind":"experiment"}`)
	records := writeFile(t, "records.json", `{}`)

	cases := []struct {
		name string
		args []string
	}{
		{"no command", []string{}},
		{"unknown command", []string{"frobnicate"}},
		{"unknown flag", []string{"--wibble", "inspect", "run_x"}},
		{"bad format", []string{"report", "run_x", "--format", "yaml"}},
		{"no token", nil}, // handled below: token stripped
		{"missing manifest file", []string{"validate",
			filepath.Join(t.TempDir(), "absent.json")}},
		{"manifest is not json", []string{"validate",
			writeFile(t, "bad.json", "not json")},
		},
		{"run without records", []string{"run", manifest}},
		{"run without primitives", []string{"run", manifest,
			"--records", records}},
		{"validate takes one path", []string{"validate", manifest, manifest}},
		{"compare takes two runs", []string{"compare", "run_a"}},
		{"compare takes two runs 2", []string{"compare",
			"run_a", "run_b", "run_c"}},
		{"inspect takes one run", []string{}},
		{"assurance needs explain", []string{"assurance",
			"clm_cli000000000001"}},
	}
	for _, testCase := range cases {
		args := append([]string{"--api", stub.url(), "--token", cliToken},
			testCase.args...)
		if testCase.name == "no token" {
			args = append([]string{"--api", stub.url()},
				"inspect", "run_cli000000000001")
		}
		code, _, errOut := run(t, args...)
		if code != ExitConfig {
			t.Fatalf("%s: exit %d, stderr %s", testCase.name, code, errOut)
		}
		if errOut == "" {
			t.Fatalf("%s: no diagnostic", testCase.name)
		}
	}
	if stub.count() != 0 {
		t.Fatalf("configuration errors reached the API: %v", stub.requests)
	}
}

func TestRunCompilesStartsAndWritesArtifacts(t *testing.T) {
	stub := newStubServer(t,
		stubReply{match: "POST /v1/experiments",
			status: http.StatusCreated, body: draftReply},
		stubReply{match: "POST /v1/experiments/exp_cli000000000001/validation",
			status: http.StatusOK, body: compiledReply},
		stubReply{match: "POST /v1/experiments/exp_cli000000000001/runs",
			status: http.StatusCreated, body: startedReply},
	)
	manifest := writeFile(t, "manifest.json", `{"kind":"experiment"}`)
	records := writeFile(t, "records.json", `{"workloads":[]}`)
	output := filepath.Join(t.TempDir(), "artifacts")

	code, out, errOut := runAt(t, stub.url(), cliToken, "run", manifest,
		"--records", records, "--primitive", "read_file",
		"--primitive", "net_connect", "--output", output)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "run run_cli000000000001 started") {
		t.Fatalf("output: %s", out)
	}
	if !strings.Contains(stub.body(2), `"read_file"`) ||
		!strings.Contains(stub.body(2), `"net_connect"`) {
		t.Fatalf("primitives: %s", stub.body(2))
	}
	for _, name := range []string{"experiment.json", "run.json"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatalf("artifact %s: %v", name, err)
		}
	}
}

func TestRefusedRequestsExitFourWithTheProblemCode(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match: "POST /v1/experiments", status: http.StatusConflict,
		body: problemBody("idempotency_conflict", "key reuse with a new body"),
	})
	manifest := writeFile(t, "manifest.json", `{"kind":"experiment"}`)

	code, _, errOut := runAt(t, stub.url(), cliToken, "validate", manifest)
	if code != ExitConfig {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	for _, want := range []string{"idempotency_conflict",
		"key reuse with a new body", "req_0123456789abcdef"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("stderr missing %q: %s", want, errOut)
		}
	}
}

func TestInfrastructureFailuresExitFive(t *testing.T) {
	// A dead endpoint is a transport failure.
	dead := "http://127.0.0.1:1"
	if code, _, _ := runAt(t, dead, cliToken, "inspect",
		"run_cli000000000001"); code != ExitInfra {
		t.Fatalf("transport failure exit: %d", code)
	}

	fiveHundred := newStubServer(t, stubReply{
		match:  "GET /v1/runs/run_cli000000000001",
		status: http.StatusInternalServerError,
		body:   problemBody("internal", "the monolith failed"),
	})
	if code, _, errOut := runAt(t, fiveHundred.url(), cliToken, "inspect",
		"run_cli000000000001"); code != ExitInfra {
		t.Fatalf("server error exit: %d, stderr %s", code, errOut)
	}

	// Authentication and role failures mean the harness path is
	// broken, not the operator's input.
	for _, code40x := range []int{http.StatusUnauthorized,
		http.StatusForbidden} {
		denied := newStubServer(t, stubReply{
			match:  "GET /v1/runs/run_cli000000000001",
			status: code40x,
			body:   problemBody("unauthenticated", "no token"),
		})
		exitCode, _, _ := runAt(t, denied.url(), cliToken, "inspect",
			"run_cli000000000001")
		if exitCode != ExitInfra {
			t.Fatalf("status %d exit: %d", code40x, exitCode)
		}
	}
}

// runDocument builds a run reply for gate tests.
func runDocument(state, terminal string) string {
	return fmt.Sprintf(`{"run_id":"run_cli000000000001",`+
		`"experiment_id":"exp_cli000000000001","state":%q,`+
		`"terminal_state":%q,`+
		`"grant":{"expires_at":"2026-09-12T01:00:00Z"},"trips":[]}`,
		state, terminal)
}

func TestInspectMapsRunGatesToExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		terminal string
		want     int
	}{
		{"clean stop", "stopped", "CLEAN", ExitOK},
		{"dirty quarantine", "stopped", "DIRTY_QUARANTINED", ExitGateFailed},
		{"fenced", "fenced", "", ExitGateFailed},
		{"unknown terminal", "stopped", "UNKNOWN", ExitInconclusive},
		{"stopped without terminal", "stopped", "", ExitInconclusive},
		{"still active", "active", "", ExitInconclusive},
	}
	for _, testCase := range cases {
		stub := newStubServer(t, stubReply{
			match:  "GET /v1/runs/run_cli000000000001",
			status: http.StatusOK,
			body:   runDocument(testCase.state, testCase.terminal),
		})
		code, out, errOut := runAt(t, stub.url(), cliToken, "inspect",
			"run_cli000000000001")
		if code != testCase.want {
			t.Fatalf("%s: exit %d (want %d), stderr %s", testCase.name,
				code, testCase.want, errOut)
		}
		if !strings.Contains(out, "exp_cli000000000001") {
			t.Fatalf("%s output: %s", testCase.name, out)
		}
		// Reads never carry an idempotency key.
		if stub.key(0) != "" {
			t.Fatalf("%s read carried key %q", testCase.name, stub.key(0))
		}
	}
}

func TestInspectCountsEvidenceWhenAsked(t *testing.T) {
	stub := newStubServer(t,
		stubReply{match: "GET /v1/runs/run_cli000000000001",
			status: http.StatusOK, body: runDocument("stopped", "CLEAN")},
		stubReply{match: "GET /v1/evidence/events",
			status: http.StatusOK,
			body:   `{"events":[{"seq":1},{"seq":2},{"seq":3}]}`},
	)
	code, out, errOut := runAt(t, stub.url(), cliToken, "inspect",
		"run_cli000000000001", "--evidence")
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "evidence   3 events") {
		t.Fatalf("evidence line: %s", out)
	}
	if !strings.Contains(stub.request(1),
		"/v1/evidence/events?run_id=run_cli000000000001") {
		t.Fatalf("evidence query: %s", stub.request(1))
	}
}

func TestCompareRefusesRunsFromDifferentExperiments(t *testing.T) {
	other := strings.Replace(runDocument("stopped", "CLEAN"),
		"exp_cli000000000001", "exp_other00000000001", 1)
	stub := newStubServer(t,
		stubReply{match: "GET /v1/runs/run_baseline00001",
			status: http.StatusOK, body: runDocument("stopped", "CLEAN")},
		stubReply{match: "GET /v1/runs/run_treatment001",
			status: http.StatusOK, body: other},
	)
	code, _, errOut := runAt(t, stub.url(), cliToken, "compare",
		"run_baseline00001", "run_treatment001")
	if code != ExitConfig {
		t.Fatalf("unmatched pair exit: %d, stderr %s", code, errOut)
	}
}

func TestCompareReportsBothGatesAndExitsOnTheTreatment(t *testing.T) {
	stub := newStubServer(t,
		stubReply{match: "GET /v1/runs/run_baseline00001",
			status: http.StatusOK, body: runDocument("stopped", "CLEAN")},
		stubReply{match: "GET /v1/runs/run_treatment001",
			status: http.StatusOK,
			body:   runDocument("stopped", "DIRTY_QUARANTINED")},
	)
	code, out, errOut := runAt(t, stub.url(), cliToken, "compare",
		"run_baseline00001", "run_treatment001")
	if code != ExitGateFailed {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "baseline") ||
		!strings.Contains(out, "treatment") {
		t.Fatalf("comparison output: %s", out)
	}
}

func TestStopSendsTheReasonAndExitsZero(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match:  "POST /v1/runs/run_cli000000000001/stop",
		status: http.StatusOK,
		body:   `{"run":{"run_id":"run_cli000000000001","state":"fenced"}}`,
	})
	code, out, errOut := runAt(t, stub.url(), cliToken, "stop",
		"run_cli000000000001", "--reason", "operator_request")
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "stop executed") {
		t.Fatalf("output: %s", out)
	}
	if !strings.Contains(stub.body(0), `"terminate"`) ||
		!strings.Contains(stub.body(0), "operator_request") {
		t.Fatalf("stop body: %s", stub.body(0))
	}
	if !strings.HasPrefix(stub.key(0), "idk_cli-") {
		t.Fatalf("idempotency key: %q", stub.key(0))
	}
}

func TestReportRendersTextAndJSON(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match: "GET /v1/runs/run_cli000000000001", status: http.StatusOK,
		body: runDocument("stopped", "CLEAN"),
	})
	_, out, _ := runAt(t, stub.url(), cliToken, "report",
		"run_cli000000000001")
	if !strings.Contains(out, "run report run_cli000000000001") ||
		!strings.Contains(out, "state: stopped") {
		t.Fatalf("text report: %s", out)
	}

	jsonStub := newStubServer(t, stubReply{
		match: "GET /v1/runs/run_cli000000000001", status: http.StatusOK,
		body: runDocument("stopped", "CLEAN"),
	})
	code, out, _ := runAt(t, jsonStub.url(), cliToken, "report",
		"run_cli000000000001", "--format", "json")
	if code != ExitOK {
		t.Fatalf("json exit: %d", code)
	}
	if !strings.Contains(out, `"run_id": "run_cli000000000001"`) {
		t.Fatalf("json report: %s", out)
	}
}

// claimDocument builds an assurance claim reply.
func claimDocument(status string) string {
	return fmt.Sprintf(`{"kind":"AssuranceClaim","id":"clm_cli000000000001",`+
		`"status":%q,`+
		`"hazard":{"description":"unreviewed outbound effect",`+
		`"severity":"major"},`+
		`"scope":{"workload_version_id":"wlv_1",`+
		`"fingerprints":{"model":"m1","policy":"p1"}},`+
		`"estimate":{"failures":0,"eligible_observations":120,`+
		`"unresolved":3,"confidence_level":0.95,"upper_bound":0.04,`+
		`"acceptance_threshold":0.05},`+
		`"assumptions":{"dependence_model":"cluster",`+
		`"population_applicability":"tenant workloads of record"},`+
		`"freshness":{"valid_until":"2026-09-30T00:00:00Z",`+
		`"invalidation_triggers":["model_identity_change"]}}`, status)
}

func TestAssuranceExplainMapsStatusesToExitCodes(t *testing.T) {
	cases := []struct {
		status string
		want   int
	}{
		{"SUPPORTED_WITHIN_SCOPE", ExitOK},
		{"VIOLATED", ExitGateFailed},
		{"TARGET_NOT_DEMONSTRATED", ExitGateFailed},
		{"INSUFFICIENT_EVIDENCE", ExitInconclusive},
		{"STALE", ExitInconclusive},
	}
	for _, testCase := range cases {
		stub := newStubServer(t, stubReply{
			match:  "GET /v1/assurance-claims/clm_cli000000000001",
			status: http.StatusOK,
			body:   claimDocument(testCase.status),
		})
		code, out, errOut := runAt(t, stub.url(), cliToken, "assurance",
			"explain", "clm_cli000000000001")
		if code != testCase.want {
			t.Fatalf("%s: exit %d (want %d), stderr %s", testCase.status,
				code, testCase.want, errOut)
		}
		// The card always shows the bound, the cohort, and the
		// scope boundary sentence.
		for _, want := range []string{"failures", "bound",
			"population", "expires", "dependence"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s card missing %q: %s", testCase.status, want, out)
			}
		}
	}
}

func TestAssuranceExplainNeverCallsZeroUniversalSafety(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match:  "GET /v1/assurance-claims/clm_cli000000000001",
		status: http.StatusOK,
		body:   claimDocument("SUPPORTED_WITHIN_SCOPE"),
	})
	code, out, _ := runAt(t, stub.url(), cliToken, "assurance", "explain",
		"clm_cli000000000001")
	if code != ExitOK {
		t.Fatalf("exit: %d", code)
	}
	if !strings.Contains(out, "not universal safety") {
		t.Fatalf("scope sentence missing: %s", out)
	}
}

func TestUnknownClaimIsAConfigurationExit(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match:  "GET /v1/assurance-claims/clm_ffffffffffffffff",
		status: http.StatusNotFound,
		body:   problemBody("claim_unknown", "no such claim"),
	})
	code, _, errOut := runAt(t, stub.url(), cliToken, "assurance",
		"explain", "clm_ffffffffffffffff")
	if code != ExitConfig {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(errOut, "claim_unknown") {
		t.Fatalf("stderr: %s", errOut)
	}
}

func TestFlagsAndEnvironmentResolve(t *testing.T) {
	stub := newStubServer(t, stubReply{
		match: "GET /v1/runs/run_cli000000000001", status: http.StatusOK,
		body: runDocument("stopped", "CLEAN"),
	})
	t.Setenv("GAUNTLET_API", stub.url())
	t.Setenv("GAUNTLET_TOKEN", cliToken)
	code, _, errOut := run(t, "inspect", "run_cli000000000001")
	if code != ExitOK {
		t.Fatalf("environment exit %d, stderr %s", code, errOut)
	}
	if stub.bearer(0) != "Bearer "+cliToken {
		t.Fatalf("authorization: %q", stub.bearer(0))
	}

	// An explicit --api overrides the environment.
	other := newStubServer(t)
	code, _, _ = runAt(t, other.url(), cliToken, "inspect",
		"run_cli000000000001")
	if code != ExitInfra || other.count() != 1 {
		t.Fatalf("flag override: %d requests %d", code, other.count())
	}
}

func TestPrimitiveFlagAcceptsCommaLists(t *testing.T) {
	stub := newStubServer(t,
		stubReply{match: "POST /v1/experiments",
			status: http.StatusCreated, body: draftReply},
		stubReply{match: "POST /v1/experiments/exp_cli000000000001/validation",
			status: http.StatusOK, body: compiledReply},
		stubReply{match: "POST /v1/experiments/exp_cli000000000001/runs",
			status: http.StatusCreated, body: startedReply},
	)
	manifest := writeFile(t, "manifest.json", `{"kind":"experiment"}`)
	records := writeFile(t, "records.json", `{}`)
	code, _, errOut := runAt(t, stub.url(), cliToken, "run", manifest,
		"--records", records, "--primitive", "read_file,net_connect")
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(stub.body(2), `"read_file","net_connect"`) {
		t.Fatalf("primitives: %s", stub.body(2))
	}
}

func TestUsageStatesTheExitContract(t *testing.T) {
	_, _, errOut := run(t)
	for _, want := range []string{"validate", "run", "compare", "inspect",
		"stop", "report", "assurance explain"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("usage missing %q", want)
		}
	}
	if !strings.Contains(errOut, "never shorthand for universal safety") {
		t.Fatalf("usage scope sentence: %s", errOut)
	}
}
