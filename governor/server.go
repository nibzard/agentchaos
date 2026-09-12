package governor

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Principal headers, set by the deployment's authentication front end.
// A tenant in a request body never overrides the authenticated tenant
// (spec 18.3).
const (
	HeaderActor  = "X-Gauntlet-Actor"
	HeaderTenant = "X-Gauntlet-Tenant"
	HeaderRole   = "X-Gauntlet-Role"
)

// Problem is the error envelope (spec 18.3): a stable code, a safe
// message, retryability, and a request id.
type Problem struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Retryable bool            `json:"retryable"`
	RequestID string          `json:"request_id"`
	Errors    []ContractError `json:"errors,omitempty"`
}

// Server exposes the governor over HTTP. The emergency-stop route is
// the customer-accessible control: it depends on nothing but this
// service and the caller's credentials — never the main UI or the
// model provider (spec 13.2).
type Server struct {
	Governor *Governor
}

// Handler builds the governor's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/envelopes", s.registerEnvelope)
	mux.HandleFunc("GET /v1/envelopes/{id}", s.getEnvelope)
	mux.HandleFunc("POST /v1/runs", s.startRun)
	mux.HandleFunc("GET /v1/runs/{id}", s.getRun)
	mux.HandleFunc("POST /v1/runs/{id}/heartbeats", s.heartbeat)
	mux.HandleFunc("POST /v1/runs/{id}/incidents", s.incident)
	mux.HandleFunc("POST /v1/runs/{id}/cleanup-state", s.cleanupState)
	mux.HandleFunc("GET /v1/runs/{id}/stop-handoff", s.stopHandoff)
	mux.HandleFunc("POST /v1/emergency-stop", s.emergencyStop)
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// registerEnvelope records an experiment's safety envelope.
func (s *Server) registerEnvelope(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	principal := principalFrom(r)
	var envelope Envelope
	if err := decodeStrict(body, &envelope); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "envelope_schema",
			err.Error(), false)
		return
	}
	if problems := envelope.ValidateEnvelopeRequest(); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "envelope_schema",
			"envelope violates the safety-envelope contract", false,
			WithErrors(problems))
		return
	}
	stored, err := s.Governor.RegisterEnvelope(principal, &envelope)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// getEnvelope reads one registered envelope.
func (s *Server) getEnvelope(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	envelope, err := s.Governor.Envelope(principalFrom(r), r.PathValue("id"))
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

// startRunRequest is the run-start body.
type startRunRequest struct {
	RunID        string `json:"run_id"`
	ExperimentID string `json:"experiment_id"`
}

// startRun issues a run's first grant.
func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	var request startRunRequest
	if err := decodeStrict(body, &request); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "run_schema",
			err.Error(), false)
		return
	}
	var problems []ContractError
	if !reRunID.MatchString(request.RunID) {
		problems = append(problems, ContractError{Check: "run_id", Path: "$.run_id",
			Detail: "must match run_[a-z0-9]{8,64}"})
	}
	if !reExperimentID.MatchString(request.ExperimentID) {
		problems = append(problems, ContractError{Check: "experiment_id", Path: "$.experiment_id",
			Detail: "must match exp_[a-z0-9]{8,64}"})
	}
	if len(problems) > 0 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "run_schema",
			"run start violates the id contracts", false, WithErrors(problems))
		return
	}
	run, err := s.Governor.StartRun(principalFrom(r), request.RunID, request.ExperimentID)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// getRun reads one run's governor record.
func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	run, err := s.Governor.Run(principalFrom(r), r.PathValue("id"))
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// heartbeat renews a run's grant lease. The path names the run; a run
// id in the body must agree with it.
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	runID := r.PathValue("id")
	var beat Heartbeat
	if err := decodeStrict(body, &beat); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "heartbeat_schema",
			err.Error(), false)
		return
	}
	if beat.RunID == "" {
		beat.RunID = runID
	}
	if beat.RunID != runID {
		writeProblem(w, requestID, http.StatusBadRequest, "heartbeat_schema",
			"the body's run id must match the path", false)
		return
	}
	if problems := beat.ValidateHeartbeat(); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "heartbeat_schema",
			"heartbeat violates the contract", false, WithErrors(problems))
		return
	}
	run, err := s.Governor.Heartbeat(principalFrom(r), &beat)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// incident records an externally observed trip condition.
func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	runID := r.PathValue("id")
	var report Incident
	if err := decodeStrict(body, &report); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "incident_schema",
			err.Error(), false)
		return
	}
	if report.RunID == "" {
		report.RunID = runID
	}
	if report.RunID != runID {
		writeProblem(w, requestID, http.StatusBadRequest, "incident_schema",
			"the body's run id must match the path", false)
		return
	}
	if problems := report.ValidateIncident(); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "incident_schema",
			"incident violates the contract", false, WithErrors(problems))
		return
	}
	if err := s.Governor.ReportIncident(principalFrom(r), &report); err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

// cleanupStateRequest is the cleanup terminal-state report.
type cleanupStateRequest struct {
	TerminalState string `json:"terminal_state"`
}

// cleanupState records the independent cleanup verifier's terminal
// state (spec 13.3).
func (s *Server) cleanupState(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	var request cleanupStateRequest
	if err := decodeStrict(body, &request); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "cleanup_schema",
			err.Error(), false)
		return
	}
	run, err := s.Governor.ReportCleanupState(principalFrom(r), r.PathValue("id"),
		request.TerminalState)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// stopHandoff fetches the run's stop handoff for the stop controller.
func (s *Server) stopHandoff(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	handoff, err := s.Governor.Handoff(principalFrom(r), r.PathValue("id"))
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, handoff)
}

// emergencyStop revokes experiment authority. Operator or customer
// role only.
func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	var scope EmergencyStopScope
	if err := decodeStrict(body, &scope); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "emergency_stop_schema",
			err.Error(), false)
		return
	}
	if problems := scope.ValidateEmergencyStop(); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "emergency_stop_schema",
			"emergency stop violates the contract", false, WithErrors(problems))
		return
	}
	fenced, err := s.Governor.EmergencyStop(principalFrom(r), &scope)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fenced_runs": fenced})
}

// refusalStatus maps a refusal code to its HTTP status.
func refusalStatus(code string) int {
	switch code {
	case "unauthenticated":
		return http.StatusUnauthorized
	case "role_forbidden":
		return http.StatusForbidden
	case "run_unknown", "envelope_unknown", "handoff_unknown":
		return http.StatusNotFound
	case "tenant_fenced", "experiment_fenced", "envelope_exists", "run_exists",
		"stale_generation", "concurrency_exhausted",
		"envelope_locked", "budget_exhausted", "target_expansion", "run_fenced",
		"run_stopped", "run_active", "terminal_state_invalid":
		return http.StatusConflict
	case "grant_expired":
		return http.StatusGone
	default:
		return http.StatusInternalServerError
	}
}

// writeRefusal turns a governor refusal into a problem body.
func writeRefusal(w http.ResponseWriter, requestID string, err error) {
	var denied *refusal
	if !errors.As(err, &denied) {
		writeProblem(w, requestID, http.StatusInternalServerError, "internal",
			"governor refused the request", false)
		return
	}
	writeProblem(w, requestID, refusalStatus(denied.Code), denied.Code,
		denied.Detail, false)
}

// principalFrom reads the identity headers. Missing headers mean an
// unauthenticated caller.
func principalFrom(r *http.Request) *Principal {
	actor := r.Header.Get(HeaderActor)
	tenant := r.Header.Get(HeaderTenant)
	role := r.Header.Get(HeaderRole)
	if actor == "" || tenant == "" || role == "" {
		return nil
	}
	return &Principal{ID: actor, TenantID: tenant, Role: role}
}

// decodeStrict parses a body with exact fields: unknown or misspelled
// keys fail closed (AC-001).
func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("unknown or malformed field: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("trailing content after JSON document")
	}
	return nil
}

// problemOption decorates a problem body.
type problemOption func(*Problem)

// WithErrors attaches contract violations.
func WithErrors(errs []ContractError) problemOption {
	return func(p *Problem) { p.Errors = errs }
}

func writeProblem(w http.ResponseWriter, requestID string, status int,
	code, message string, retryable bool, opts ...problemOption) {
	problem := Problem{
		Code:      code,
		Message:   message,
		Retryable: retryable,
		RequestID: requestID,
	}
	for _, opt := range opts {
		opt(&problem)
	}
	writeJSON(w, status, problem)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newRequestID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "req_" + hex.EncodeToString(raw)
}
