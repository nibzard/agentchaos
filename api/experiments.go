package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"agentchaos/governor"
)

// Experiment statuses from the Experiment contract: draft to compiled
// moves only through the deterministic compiler (spec 9.1).
const (
	statusDraft    = "draft"
	statusCompiled = "compiled"
	statusRunning  = "running"
)

// experiment is one stored experiment and everything the API derived
// from it. The document is the contract-shaped Experiment record; the
// plan block and plan document arrive only through validation.
type experiment struct {
	ID                 string
	TenantID           string
	Status             string
	Document           map[string]any // Experiment record, plan attached after validation
	Plan               map[string]any // plan block: digest, artifacts, risk, grant
	Envelope           map[string]any // digest-covered plan document, envelope source
	Runs               []string
	EnvelopeRegistered bool
	CreatedAt          string
	UpdatedAt          string
}

// experimentStore is the in-memory experiment registry for the beta
// monolith. Keys are tenant-scoped; a cross-tenant read is
// indistinguishable from absence.
type experimentStore struct {
	mu          sync.Mutex
	experiments map[string]*experiment // tenant + "\x00" + id
}

func newExperimentStore() *experimentStore {
	return &experimentStore{experiments: map[string]*experiment{}}
}

func (s *experimentStore) put(exp *experiment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.experiments[exp.TenantID+"\x00"+exp.ID] = exp
}

func (s *experimentStore) get(tenantID, id string) *experiment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.experiments[tenantID+"\x00"+id]
}

// claimEnvelope atomically marks the envelope as being registered and
// reports whether this caller is the first. The claim rolls back with
// releaseEnvelope when registration fails.
func (s *experimentStore) claimEnvelope(tenantID, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := s.experiments[tenantID+"\x00"+id]
	if exp == nil || exp.EnvelopeRegistered {
		return false
	}
	exp.EnvelopeRegistered = true
	return true
}

func (s *experimentStore) releaseEnvelope(tenantID, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp := s.experiments[tenantID+"\x00"+id]; exp != nil {
		exp.EnvelopeRegistered = false
	}
}

func (s *experimentStore) addRun(tenantID, id, runID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := s.experiments[tenantID+"\x00"+id]
	if exp != nil {
		exp.Runs = append(exp.Runs, runID)
		exp.Status = statusRunning
		exp.UpdatedAt = stamp(time.Now())
	}
}

// Top-level keys the Experiment contract allows. A draft cannot arrive
// with a plan: only the compiler attaches one (AC-001, spec 9.1).
var experimentKeys = map[string]bool{
	"kind": true, "api_version": true, "id": true, "tenant_id": true,
	"status": true, "revision": true, "created_at": true, "manifest": true,
}

// createExperiment stores a draft manifest (spec 18.2: POST
// /v1/experiments). The compiler owns deep validation; this route
// enforces the contract shape it can check without compiling.
func (s *Server) createExperiment(w http.ResponseWriter, r *http.Request) {
	principal, requestID, ok := requireMutationPrincipal(w, r,
		supervisorRoles, "create an experiment")
	if !ok {
		return
	}
	body, ok := readBody(w, requestID, r)
	if !ok {
		return
	}
	var document map[string]any
	if problems := decodeStrict(body, &document, experimentKeys); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusBadRequest, "experiment_schema",
			"the experiment record violates the top-level Experiment contract",
			false, problems...)
		return
	}
	if err := checkExperimentDraft(document, principal.TenantID); err != nil {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "experiment_schema",
			err.Error(), false)
		return
	}
	if existing := s.Experiments.get(principal.TenantID, document["id"].(string)); existing != nil {
		writeProblem(w, requestID, http.StatusConflict, "experiment_exists",
			"the experiment id already exists in this tenant", false)
		return
	}
	s.Experiments.put(&experiment{
		ID:        document["id"].(string),
		TenantID:  principal.TenantID,
		Status:    statusDraft,
		Document:  document,
		CreatedAt: stamp(time.Now()),
		UpdatedAt: stamp(time.Now()),
	})
	writeJSON(w, http.StatusCreated, map[string]any{"experiment": document})
}

// checkExperimentDraft enforces what a draft must look like before the
// compiler sees it. The authenticated tenant wins over any body claim
// (spec 18.3).
func checkExperimentDraft(document map[string]any, tenantID string) error {
	var problems []string
	if document["kind"] != "Experiment" {
		problems = append(problems, "kind must be Experiment")
	}
	if document["api_version"] != "v1" {
		problems = append(problems, "api_version must be v1")
	}
	id, _ := document["id"].(string)
	if !reExperiment.MatchString(id) {
		problems = append(problems, "id must match exp_[a-z0-9]{8,64}")
	}
	if claimed, _ := document["tenant_id"].(string); claimed != "" && claimed != tenantID {
		problems = append(problems,
			"tenant_id cannot override the authenticated tenant (spec 18.3)")
	}
	if status, _ := document["status"].(string); status != statusDraft {
		problems = append(problems, "a new experiment starts as draft")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	document["tenant_id"] = tenantID
	return nil
}

// validateExperiment compiles the stored manifest without execution
// (spec 18.2: POST /v1/experiments/{id}/validation). The referenced
// records travel with the request: workloads, profiles, scenarios,
// targets, credentials.
func (s *Server) validateExperiment(w http.ResponseWriter, r *http.Request) {
	principal, requestID, ok := requireMutationPrincipal(w, r,
		supervisorRoles, "validate an experiment")
	if !ok {
		return
	}
	exp := s.Experiments.get(principal.TenantID, r.PathValue("id"))
	if exp == nil {
		writeProblem(w, requestID, http.StatusNotFound, "experiment_unknown",
			"no such experiment in this tenant", false)
		return
	}
	body, ok := readBody(w, requestID, r)
	if !ok {
		return
	}
	var request struct {
		Records map[string][]map[string]any `json:"records"`
		Now     string                      `json:"now"`
	}
	if problems := decodeStrict(body, &request,
		map[string]bool{"records": true, "now": true}); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusBadRequest, "validation_schema",
			"the validation request violates its contract", false, problems...)
		return
	}
	now := request.Now
	if now == "" {
		now = stamp(time.Now())
	} else if !reTimestampZ.MatchString(now) {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "validation_schema",
			"now must be an RFC 3339 UTC timestamp with Z", false)
		return
	}

	result, failures, err := s.Compiler.Compile(exp.Document, request.Records, now)
	if err != nil {
		writeProblem(w, requestID, http.StatusInternalServerError, "compiler_unavailable",
			"the compiler could not run; nothing was compiled", true)
		return
	}
	if failures != nil {
		messages := make([]string, len(failures))
		for i, failure := range failures {
			messages[i] = fmt.Sprintf("%s at %s: %s",
				failure.Code, failure.Path, failure.Message)
		}
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "compile_failed",
			"compilation failed closed; nothing was compiled", false, messages...)
		return
	}

	exp.Plan = result.Plan
	exp.Envelope = result.PlanDocument
	exp.Status = statusCompiled
	exp.UpdatedAt = stamp(time.Now())
	exp.Document["plan"] = result.Plan
	exp.Document["status"] = statusCompiled
	risk, _ := result.Plan["risk_classification"].(string)
	writeJSON(w, http.StatusOK, map[string]any{
		"experiment":          exp.Document,
		"risk_classification": risk,
	})
}

// startRun registers the safety envelope from the compiled plan and
// starts an authorized run (spec 18.2: POST
// /v1/experiments/{id}/runs). Envelopes are immutable, so the first
// run registers one and later runs reuse it.
func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	principal, requestID, ok := requireMutationPrincipal(w, r,
		supervisorRoles, "start a run")
	if !ok {
		return
	}
	exp := s.Experiments.get(principal.TenantID, r.PathValue("id"))
	if exp == nil {
		writeProblem(w, requestID, http.StatusNotFound, "experiment_unknown",
			"no such experiment in this tenant", false)
		return
	}
	if exp.Status == statusDraft || exp.Envelope == nil {
		writeProblem(w, requestID, http.StatusConflict, "validation_required",
			"an experiment compiles before any run starts", false)
		return
	}
	body, ok := readBody(w, requestID, r)
	if !ok {
		return
	}
	var request struct {
		RunID             string   `json:"run_id"`
		AllowedPrimitives []string `json:"allowed_primitives"`
	}
	if len(body) > 0 {
		if problems := decodeStrict(body, &request,
			map[string]bool{"run_id": true, "allowed_primitives": true}); len(problems) > 0 {
			writeProblem(w, requestID, http.StatusBadRequest, "run_request_schema",
				"the run request violates its contract", false, problems...)
			return
		}
	}
	runID := request.RunID
	if runID == "" {
		runID = mintID("run_")
	}
	if !reRunID.MatchString(runID) {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "run_id_invalid",
			"run id must match run_[a-z0-9]{8,64}", false)
		return
	}
	if len(request.AllowedPrimitives) < 1 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "run_request_schema",
			"a run names one to 128 allowed primitives (spec 13.1)", false)
		return
	}

	if s.Experiments.claimEnvelope(principal.TenantID, exp.ID) {
		envelope, err := buildEnvelope(exp, request.AllowedPrimitives)
		if err == nil {
			_, err = s.Governor.RegisterEnvelope(governorPrincipal(principal), envelope)
		}
		if err != nil {
			s.Experiments.releaseEnvelope(principal.TenantID, exp.ID)
			writeProblem(w, requestID, http.StatusUnprocessableEntity, "envelope_refused",
				err.Error(), false)
			return
		}
	}

	run, err := s.Governor.StartRun(governorPrincipal(principal), runID, exp.ID)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	s.Experiments.addRun(principal.TenantID, exp.ID, runID)
	writeJSON(w, http.StatusCreated, map[string]any{"run": run})
}

// buildEnvelope translates a compiled plan document into the governor
// safety envelope. Everything but the primitives comes from the
// digest-covered plan; the primitives arrive with the run request
// because the Experiment contract carries no operation names.
func buildEnvelope(exp *experiment, primitives []string) (*governor.Envelope, error) {
	document := exp.Envelope
	envelope := &governor.Envelope{
		ExperimentID:      exp.ID,
		AllowedPrimitives: append([]string{}, primitives...),
	}

	rawSelectors, err := objectList(document["selectors"], "selectors")
	if err != nil {
		return nil, err
	}
	for _, raw := range rawSelectors {
		selected, err := stringList(raw["selected"], "selectors.selected")
		if err != nil {
			return nil, err
		}
		excluded, err := stringList(raw["excluded"], "selectors.excluded")
		if err != nil {
			return nil, err
		}
		seed, err := number(raw["recorded_seed"], "selectors.recorded_seed")
		if err != nil {
			return nil, err
		}
		envelope.Selectors = append(envelope.Selectors, governor.Selector{
			Kind:         "enrolled_targets",
			TargetIDs:    selected,
			Exclusions:   excluded,
			RecordedSeed: seed,
		})
	}

	rawBudgets, err := object(document["budgets"], "budgets")
	if err != nil {
		return nil, err
	}
	duration, err := number(rawBudgets["max_duration_s"], "budgets.max_duration_s")
	if err != nil {
		return nil, err
	}
	sessions, err := number(rawBudgets["max_concurrent_sessions"], "budgets.max_concurrent_sessions")
	if err != nil {
		return nil, err
	}
	perSession, err := money(rawBudgets["per_session_cost_max"], "budgets.per_session_cost_max")
	if err != nil {
		return nil, err
	}
	aggregate, err := money(rawBudgets["aggregate_cost_max"], "budgets.aggregate_cost_max")
	if err != nil {
		return nil, err
	}
	envelope.Budgets = governor.Budgets{
		MaxDurationS:          duration,
		MaxConcurrentSessions: sessions,
		PerSessionCostMax:     perSession,
		AggregateCostMax:      aggregate,
	}

	rawIdentities, err := object(document["identities"], "identities")
	if err != nil {
		return nil, err
	}
	maxSessions, err := number(rawIdentities["max_sessions"], "identities.max_sessions")
	if err != nil {
		return nil, err
	}
	envelope.MaxSessions = maxSessions

	rawRules, err := objectList(document["stop_rules"], "stop_rules")
	if err != nil {
		return nil, err
	}
	for _, raw := range rawRules {
		condition, err := text(raw["condition"], "stop_rules.condition")
		if err != nil {
			return nil, err
		}
		action, err := text(raw["action"], "stop_rules.action")
		if err != nil {
			return nil, err
		}
		rule := governor.StopRule{Condition: condition, Action: action}
		if raw["threshold"] != nil {
			threshold, err := floatNumber(raw["threshold"], "stop_rules.threshold")
			if err != nil {
				return nil, err
			}
			rule.Threshold = threshold
		}
		envelope.StopRules = append(envelope.StopRules, rule)
	}
	return envelope, nil
}

// Plan-document extraction helpers. Any shape surprise is an error: the
// plan document is digest-covered compiler output, so a malformed one
// is an inconsistency, never a default.
func object(value any, where string) (map[string]any, error) {
	cast, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plan document %s is not an object", where)
	}
	return cast, nil
}

func objectList(value any, where string) ([]map[string]any, error) {
	raw, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("plan document %s is not an array", where)
	}
	list := make([]map[string]any, 0, len(raw))
	for i, item := range raw {
		cast, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("plan document %s[%d] is not an object", where, i)
		}
		list = append(list, cast)
	}
	return list, nil
}

func stringList(value any, where string) ([]string, error) {
	raw, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("plan document %s is not an array", where)
	}
	list := make([]string, 0, len(raw))
	for i, item := range raw {
		cast, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("plan document %s[%d] is not a string", where, i)
		}
		list = append(list, cast)
	}
	return list, nil
}

func text(value any, where string) (string, error) {
	cast, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("plan document %s is not a string", where)
	}
	return cast, nil
}

func number(value any, where string) (int64, error) {
	cast, ok := value.(float64)
	if !ok || cast != float64(int64(cast)) {
		return 0, fmt.Errorf("plan document %s is not an integer", where)
	}
	return int64(cast), nil
}

func floatNumber(value any, where string) (float64, error) {
	cast, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("plan document %s is not a number", where)
	}
	return cast, nil
}

func money(value any, where string) (governor.Money, error) {
	raw, err := object(value, where)
	if err != nil {
		return governor.Money{}, err
	}
	currency, err := text(raw["currency"], where+".currency")
	if err != nil {
		return governor.Money{}, err
	}
	micros, err := number(raw["micros"], where+".micros")
	if err != nil {
		return governor.Money{}, err
	}
	return governor.Money{Currency: currency, Micros: micros}, nil
}

// readBody reads a bounded request body.
func readBody(w http.ResponseWriter, requestID string, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return nil, false
	}
	return body, true
}

// stamp formats a clock reading the way the contracts write timestamps.
func stamp(now time.Time) string {
	return now.UTC().Format("2006-01-02T15:04:05Z")
}

// decodeStrict decodes a JSON object and rejects keys outside the
// allowed set (AC-001). Unknown fields fail closed.
func decodeStrict(body []byte, target any, allowed map[string]bool) []string {
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		return []string{"body is not a JSON object"}
	}
	var problems []string
	for key := range probe {
		if !allowed[key] {
			problems = append(problems,
				fmt.Sprintf("unknown field %q fails closed", key))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return problems
	}
	if err := json.Unmarshal(body, target); err != nil {
		return []string{"body does not match the expected shape: " + err.Error()}
	}
	return nil
}
