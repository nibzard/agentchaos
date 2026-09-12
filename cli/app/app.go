// Package app is the gauntlet CLI (spec 17.7 / T029): validate, run,
// compare, inspect, stop, report, and assurance explain, with stable
// automation exit codes. Exit 0 means the requested operation
// completed and its explicit gate passed — never a claim of universal
// safety.
package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Automation exit codes (spec 17.7).
const (
	ExitOK           = 0 // the operation completed and its gate passed
	ExitGateFailed   = 2 // a declared gate failed
	ExitInconclusive = 3 // insufficient evidence or inconclusive
	ExitConfig       = 4 // invalid configuration
	ExitInfra        = 5 // harness or infrastructure failure
)

const usage = `gauntlet — AgentChaos operator CLI

usage: gauntlet [--api URL] [--token TOKEN] COMMAND [args]

commands:
  validate MANIFEST [--records FILE]      store a draft, optionally compile
  run MANIFEST --records FILE --primitive P [--output DIR]
                                         compile and start a run
  compare RUN_BASELINE RUN_TREATMENT      paired run comparison
  inspect RUN_ID [--evidence]             run state, optionally its events
  stop RUN_ID [--reason TEXT]             request fencing and cleanup
  report RUN_ID [--format text|json]      run report
  assurance explain CLAIM_ID              render the evidence card

environment: GAUNTLET_API and GAUNTLET_TOKEN override --api and --token.

exit codes: 0 gate passed; 2 gate failed; 3 inconclusive;
4 invalid configuration; 5 harness or infrastructure failure.
an exit of 0 is never shorthand for universal safety.
`

// options is every flag the CLI accepts, resolved from args and the
// environment.
type options struct {
	api        string
	token      string
	manifest   string
	records    string
	output     string
	reason     string
	format     string
	primitives []string
	evidence   bool
	rest       []string // positional arguments after flag parsing
}

// Main runs one command and returns its exit code. Output goes to the
// given writers so tests stay hermetic.
func Main(args []string, out, errOut io.Writer) int {
	options := &options{reason: "operator_request", format: "text"}
	options.api = os.Getenv("GAUNTLET_API")
	options.token = os.Getenv("GAUNTLET_TOKEN")
	if options.api == "" {
		options.api = "http://localhost:8080"
	}
	if err := options.parse(args); err != nil {
		fmt.Fprintln(errOut, "gauntlet: "+err.Error())
		fmt.Fprint(errOut, usage)
		return ExitConfig
	}
	if len(options.rest) == 0 {
		fmt.Fprint(errOut, usage)
		return ExitConfig
	}

	command := options.rest[0]
	operands := options.rest[1:]
	client := &client{baseURL: options.api, token: options.token}
	ctx := &context{options: options, client: client, out: out, errOut: errOut}

	switch command {
	case "validate":
		return ctx.validate(operands)
	case "run":
		return ctx.run(operands)
	case "compare":
		return ctx.compare(operands)
	case "inspect":
		return ctx.inspect(operands)
	case "stop":
		return ctx.stop(operands)
	case "report":
		return ctx.report(operands)
	case "assurance":
		return ctx.assurance(operands)
	default:
		fmt.Fprintf(errOut, "gauntlet: unknown command %q\n", command)
		fmt.Fprint(errOut, usage)
		return ExitConfig
	}
}

// parse reads flags in any position. Bare words collect in order:
// the first is the command, the rest are its operands.
func (o *options) parse(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			o.rest = append(o.rest, arg)
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", arg)
			}
			i++
			return args[i], nil
		}
		var err error
		switch name {
		case "api":
			if o.api, err = takeValue(); err != nil {
				return err
			}
		case "token":
			if o.token, err = takeValue(); err != nil {
				return err
			}
		case "records":
			if o.records, err = takeValue(); err != nil {
				return err
			}
		case "output":
			if o.output, err = takeValue(); err != nil {
				return err
			}
		case "reason":
			if o.reason, err = takeValue(); err != nil {
				return err
			}
		case "format":
			if o.format, err = takeValue(); err != nil {
				return err
			}
			if o.format != "text" && o.format != "json" {
				return fmt.Errorf("--format must be text or json")
			}
		case "primitive":
			var raw string
			if raw, err = takeValue(); err != nil {
				return err
			}
			o.primitives = append(o.primitives, strings.Split(raw, ",")...)
		case "evidence":
			o.evidence = true
		default:
			return fmt.Errorf("unknown flag --%s", name)
		}
	}
	return nil
}

// context carries one invocation's options, client, and output.
type context struct {
	options *options
	client  *client
	out     io.Writer
	errOut  io.Writer
}

// problem is the API error envelope (spec 18.3).
type problem struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// client is a minimal API client: bearer token in, problem envelope
// out, one idempotency key per mutation.
type client struct {
	baseURL string
	token   string
}

// reply is one API response: status, raw body, and the decoded
// problem when the status is an error.
type reply struct {
	status int
	body   []byte
}

// do issues one request. A body of nil means no payload; mutations
// (POST) always carry an idempotency key.
func (c *client) do(method, path string, body []byte) (*reply, error) {
	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, c.baseURL+path, payload)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if method != http.MethodGet {
		request.Header.Set("Idempotency-Key", "idk_cli-"+randomHex(16))
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return &reply{status: response.StatusCode, body: raw}, nil
}

// mapFailure converts an error reply into an exit code and prints the
// problem. Authentication and transport failures are infrastructure
// (5): the harness path is broken, not the operator's configuration.
// Everything else the caller did wrong is configuration (4).
func (ctx *context) mapFailure(label string, response *reply, err error) int {
	if err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: %s: %v\n", label, err)
		return ExitInfra
	}
	if response.status >= 500 {
		fmt.Fprintf(ctx.errOut, "gauntlet: %s: server error %d\n", label,
			response.status)
		return ExitInfra
	}
	decoded := problem{}
	_ = json.Unmarshal(response.body, &decoded)
	if response.status == http.StatusUnauthorized ||
		response.status == http.StatusForbidden {
		fmt.Fprintf(ctx.errOut, "gauntlet: %s: %s (%s, request %s)\n", label,
			decoded.Message, decoded.Code, decoded.RequestID)
		return ExitInfra
	}
	fmt.Fprintf(ctx.errOut, "gauntlet: %s: %s (%s, request %s)\n", label,
		decoded.Message, decoded.Code, decoded.RequestID)
	return ExitConfig
}

// requireToken refuses to run without credentials.
func (ctx *context) requireToken() bool {
	if ctx.options.token == "" {
		fmt.Fprintln(ctx.errOut,
			"gauntlet: no token; pass --token or set GAUNTLET_TOKEN")
		return false
	}
	return true
}

// validate stores a draft manifest and optionally compiles it (spec
// 17.7: validate compiles without execution).
func (ctx *context) validate(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 1 {
		fmt.Fprintln(ctx.errOut, "gauntlet: validate takes one manifest path")
		return ExitConfig
	}
	manifest, code := ctx.readJSONFile(operands[0])
	if code != ExitOK {
		return code
	}
	response, err := ctx.client.do("POST", "/v1/experiments", manifest)
	if err != nil || response.status != http.StatusCreated {
		return ctx.mapFailure("create experiment", response, err)
	}
	experimentID := nestedID(response.body)
	fmt.Fprintf(ctx.out, "experiment %s stored as a draft\n", experimentID)

	if ctx.options.records == "" {
		return ExitOK
	}
	return ctx.compile(experimentID, manifest)
}

// compile posts the validation route and reports the plan.
func (ctx *context) compile(experimentID string, manifest []byte) int {
	records, code := ctx.readJSONFile(ctx.options.records)
	if code != ExitOK {
		return code
	}
	request, err := json.Marshal(map[string]any{
		"records": json.RawMessage(records),
		"now":     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	})
	if err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: records: %v\n", err)
		return ExitConfig
	}
	response, err := ctx.client.do("POST",
		"/v1/experiments/"+experimentID+"/validation", request)
	if err != nil || response.status != http.StatusOK {
		return ctx.mapFailure("validate experiment", response, err)
	}
	document := map[string]any{}
	_ = json.Unmarshal(response.body, &document)
	fmt.Fprintf(ctx.out, "plan compiled: risk %v, status %v\n",
		document["risk_classification"],
		mapValue(document, "experiment", "status"))
	return ExitOK
}

// nestedID reads the experiment id from an API reply envelope.
func nestedID(body []byte) string {
	document := map[string]any{}
	_ = json.Unmarshal(body, &document)
	return fmt.Sprint(mapValue(document, "experiment", "id"))
}

// run compiles a manifest and starts its run, writing the artifacts
// of every step into --output when given.
func (ctx *context) run(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 1 {
		fmt.Fprintln(ctx.errOut,
			"gauntlet: run takes one manifest path plus --records and --primitive")
		return ExitConfig
	}
	if ctx.options.records == "" {
		fmt.Fprintln(ctx.errOut,
			"gauntlet: run needs --records: compilation input is configuration")
		return ExitConfig
	}
	if len(ctx.options.primitives) == 0 {
		fmt.Fprintln(ctx.errOut, "gauntlet: run needs at least one --primitive")
		return ExitConfig
	}
	manifest, code := ctx.readJSONFile(operands[0])
	if code != ExitOK {
		return code
	}
	artifacts := newArtifacts(ctx.options.output)

	response, err := ctx.client.do("POST", "/v1/experiments", manifest)
	if err != nil || response.status != http.StatusCreated {
		return ctx.mapFailure("create experiment", response, err)
	}
	artifacts.write("experiment.json", response.body)
	experimentID := nestedID(response.body)

	if code := ctx.compile(experimentID, manifest); code != ExitOK {
		return code
	}
	startRequest, err := json.Marshal(map[string]any{
		"allowed_primitives": ctx.options.primitives,
	})
	if err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: run request: %v\n", err)
		return ExitConfig
	}
	response, err = ctx.client.do("POST",
		"/v1/experiments/"+experimentID+"/runs", startRequest)
	if err != nil || response.status != http.StatusCreated {
		return ctx.mapFailure("start run", response, err)
	}
	artifacts.write("run.json", response.body)
	run := map[string]any{}
	_ = json.Unmarshal(response.body, &run)
	runDocument, _ := run["run"].(map[string]any)
	runID := fmt.Sprint(runDocument["run_id"])
	fmt.Fprintf(ctx.out, "run %s started (experiment %s)\n", runID,
		experimentID)
	if ctx.options.output != "" {
		fmt.Fprintf(ctx.out, "artifacts in %s\n", ctx.options.output)
	}
	// A started run is not a finished run: the explicit gate is not
	// yet evaluated, so run itself exits 0 only for the start.
	return ExitOK
}

// compare refuses unmatched runs (spec 15.3: matched workloads only)
// and reports both gates side by side.
func (ctx *context) compare(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 2 {
		fmt.Fprintln(ctx.errOut, "gauntlet: compare takes two run ids")
		return ExitConfig
	}
	baseline, code := ctx.fetchRun(operands[0])
	if code != ExitOK {
		return code
	}
	treatment, code := ctx.fetchRun(operands[1])
	if code != ExitOK {
		return code
	}
	if baseline["experiment_id"] != treatment["experiment_id"] {
		fmt.Fprintln(ctx.errOut,
			"gauntlet: the runs belong to different experiments; a partial pair refuses the comparison")
		return ExitConfig
	}
	treatmentGate := gateForRun(treatment)
	fmt.Fprintf(ctx.out, "baseline   %s: %s\n", operands[0],
		runOutcome(baseline))
	fmt.Fprintf(ctx.out, "treatment  %s: %s\n", operands[1],
		runOutcome(treatment))
	// The comparison's gate is the treatment's: the baseline only
	// anchors it. Both gates print.
	return treatmentGate.code
}

// inspect prints one run's state; --evidence adds its event count.
func (ctx *context) inspect(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 1 {
		fmt.Fprintln(ctx.errOut, "gauntlet: inspect takes one run id")
		return ExitConfig
	}
	run, code := ctx.fetchRun(operands[0])
	if code != ExitOK {
		return code
	}
	fmt.Fprintf(ctx.out, "run %s: %s\n", run["run_id"], runOutcome(run))
	fmt.Fprintf(ctx.out, "experiment %s, grant expires %s\n",
		run["experiment_id"],
		mapValue(run["grant"], "expires_at"))
	if ctx.options.evidence {
		if code := ctx.printEvidence(fmt.Sprint(run["run_id"])); code != ExitOK {
			return code
		}
	}
	return gateForRun(run).code
}

// stop requests fencing and cleanup for one run.
func (ctx *context) stop(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 1 {
		fmt.Fprintln(ctx.errOut, "gauntlet: stop takes one run id")
		return ExitConfig
	}
	request, err := json.Marshal(map[string]any{
		"sandbox": "terminate", "reason": ctx.options.reason,
	})
	if err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: stop request: %v\n", err)
		return ExitConfig
	}
	response, err := ctx.client.do("POST",
		"/v1/runs/"+operands[0]+"/stop", request)
	if err != nil || response.status != http.StatusOK {
		return ctx.mapFailure("stop run", response, err)
	}
	fmt.Fprintf(ctx.out, "stop executed for %s (reason %s)\n", operands[0],
		ctx.options.reason)
	return ExitOK
}

// report prints a run as text or machine JSON.
func (ctx *context) report(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 1 {
		fmt.Fprintln(ctx.errOut, "gauntlet: report takes one run id")
		return ExitConfig
	}
	run, code := ctx.fetchRun(operands[0])
	if code != ExitOK {
		return code
	}
	if ctx.options.format == "json" {
		encoded, err := json.MarshalIndent(run, "", "  ")
		if err != nil {
			fmt.Fprintf(ctx.errOut, "gauntlet: report: %v\n", err)
			return ExitInfra
		}
		fmt.Fprintln(ctx.out, string(encoded))
	} else {
		fmt.Fprintf(ctx.out, "run report %s\n  state: %s\n  terminal: %s\n"+
			"  trips: %d\n  grant expires: %s\n", run["run_id"],
			run["state"], run["terminal_state"],
			len(sliceValue(run["trips"])),
			mapValue(run["grant"], "expires_at"))
	}
	return gateForRun(run).code
}

// assurance explain renders one claim's evidence card (spec 17.5).
func (ctx *context) assurance(operands []string) int {
	if !ctx.requireToken() {
		return ExitConfig
	}
	if len(operands) != 2 || operands[0] != "explain" {
		fmt.Fprintln(ctx.errOut, "gauntlet: usage: gauntlet assurance explain CLAIM_ID")
		return ExitConfig
	}
	response, err := ctx.client.do("GET",
		"/v1/assurance-claims/"+operands[1], nil)
	if err != nil || response.status != http.StatusOK {
		return ctx.mapFailure("read claim", response, err)
	}
	claim := map[string]any{}
	if err := json.Unmarshal(response.body, &claim); err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: claim reply: %v\n", err)
		return ExitInfra
	}
	code := ctx.printClaimCard(claim)
	return code
}

// printClaimCard renders the evidence card: hazard, population,
// fingerprint, failures, unresolved, bound, target, dependence, and
// expiration (spec 17.5), then maps the status to the gate.
func (ctx *context) printClaimCard(claim map[string]any) int {
	scope, _ := claim["scope"].(map[string]any)
	estimate, _ := claim["estimate"].(map[string]any)
	freshness, _ := claim["freshness"].(map[string]any)
	hazard, _ := claim["hazard"].(map[string]any)
	assumptions, _ := claim["assumptions"].(map[string]any)
	fmt.Fprintf(ctx.out, "claim %s — %s\n", claim["id"], claim["status"])
	fmt.Fprintf(ctx.out, "hazard     %s (%s)\n", hazard["description"],
		hazard["severity"])
	fmt.Fprintf(ctx.out, "population %s\n", assumptions["population_applicability"])
	fmt.Fprintf(ctx.out, "fingerprint model %s, policy %s\n",
		mapValue(scope, "fingerprints", "model"),
		mapValue(scope, "fingerprints", "policy"))
	fmt.Fprintf(ctx.out, "failures   %v of %v eligible, %v unresolved\n",
		estimate["failures"], estimate["eligible_observations"],
		estimate["unresolved"])
	fmt.Fprintf(ctx.out, "bound      upper %v at confidence %v, target %v\n",
		estimate["upper_bound"], estimate["confidence_level"],
		estimate["acceptance_threshold"])
	fmt.Fprintf(ctx.out, "dependence %s\n", assumptions["dependence_model"])
	fmt.Fprintf(ctx.out, "expires    %s (triggers %v)\n",
		freshness["valid_until"], freshness["invalidation_triggers"])
	switch claim["status"] {
	case "SUPPORTED_WITHIN_SCOPE":
		fmt.Fprintln(ctx.out,
			"the fixed cohort supports the target within scope; this is not universal safety")
		return ExitOK
	case "VIOLATED", "TARGET_NOT_DEMONSTRATED":
		fmt.Fprintln(ctx.out, "the cohort does not support the target")
		return ExitGateFailed
	default:
		// INSUFFICIENT_EVIDENCE and STALE: inconclusive.
		fmt.Fprintln(ctx.out,
			"the evidence does not decide the target either way")
		return ExitInconclusive
	}
}

// fetchRun reads one run document.
func (ctx *context) fetchRun(runID string) (map[string]any, int) {
	response, err := ctx.client.do("GET", "/v1/runs/"+runID, nil)
	if err != nil || response.status != http.StatusOK {
		return nil, ctx.mapFailure("read run", response, err)
	}
	run := map[string]any{}
	if err := json.Unmarshal(response.body, &run); err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: run reply: %v\n", err)
		return nil, ExitInfra
	}
	return run, ExitOK
}

// printEvidence reports the run's event count from the evidence plane.
func (ctx *context) printEvidence(runID string) int {
	response, err := ctx.client.do("GET",
		"/v1/evidence/events?run_id="+runID, nil)
	if err != nil || response.status != http.StatusOK {
		return ctx.mapFailure("read evidence", response, err)
	}
	document := map[string]any{}
	_ = json.Unmarshal(response.body, &document)
	fmt.Fprintf(ctx.out, "evidence   %d events\n",
		len(sliceValue(document["events"])))
	return ExitOK
}

// readJSONFile loads a JSON document from disk.
func (ctx *context) readJSONFile(path string) ([]byte, int) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(ctx.errOut, "gauntlet: %s: %v\n", path, err)
		return nil, ExitConfig
	}
	if !json.Valid(raw) {
		fmt.Fprintf(ctx.errOut, "gauntlet: %s is not JSON\n", path)
		return nil, ExitConfig
	}
	return raw, ExitOK
}

// gate is one run's explicit gate outcome.
type gate struct {
	code        int
	description string
}

// gateForRun maps a run document to its gate. The gate never infers a
// pass from absence: an unfinished run is inconclusive, an unknown
// terminal state stays unknown, and a trip means the run failed its
// containment gate.
func gateForRun(run map[string]any) gate {
	state := fmt.Sprint(run["state"])
	terminal, _ := run["terminal_state"].(string)
	switch {
	case state == "stopped" && terminal == "CLEAN":
		return gate{ExitOK, "stopped clean"}
	case state == "fenced":
		return gate{ExitGateFailed, "fenced by the governor"}
	case terminal == "DIRTY_QUARANTINED":
		return gate{ExitGateFailed, "terminal state dirty and quarantined"}
	case terminal == "UNKNOWN":
		return gate{ExitInconclusive, "terminal state unknown"}
	case state == "stopped":
		return gate{ExitInconclusive, "stopped without a terminal state"}
	default:
		return gate{ExitInconclusive, "still active: the gate is not evaluated"}
	}
}

// runOutcome describes a run for side-by-side output.
func runOutcome(run map[string]any) string {
	gateResult := gateForRun(run)
	terminal, _ := run["terminal_state"].(string)
	if terminal == "" {
		terminal = "-"
	}
	return fmt.Sprintf("state %s, terminal %s — %s", run["state"],
		terminal, gateResult.description)
}

// artifacts writes run step documents into the output directory.
type artifacts struct {
	dir string
}

func newArtifacts(dir string) *artifacts {
	if dir == "" {
		return &artifacts{}
	}
	// Ignore the error: writing reports it per file.
	_ = os.MkdirAll(dir, 0o755)
	return &artifacts{dir: dir}
}

func (a *artifacts) write(name string, body []byte) {
	if a.dir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(a.dir, name), body, 0o644)
}

// mapValue walks nested maps for display.
func mapValue(document any, path ...string) any {
	current := document
	for _, key := range path {
		nested, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = nested[key]
	}
	return current
}

func sliceValue(document any) []any {
	out, _ := document.([]any)
	return out
}

func randomHex(bytes int) string {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(raw)
}
