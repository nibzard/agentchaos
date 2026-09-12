package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Principal headers, resolved by the deployment's authentication
// front end (spec 18.3). A tenant in a body never overrides them.
const (
	HeaderActor  = "X-ACX-Actor"
	HeaderTenant = "X-ACX-Tenant"
	HeaderRole   = "X-ACX-Role"
	HeaderIdem   = "Idempotency-Key"
)

var reIdemKey = regexp.MustCompile(`^idk_[A-Za-z0-9_-]{8,128}$`)

// Problem is the error envelope (spec 18.3): a stable code, a safe
// message, retryability, and a request id. No credentials, no
// reviewer internals.
type Problem struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Retryable bool            `json:"retryable"`
	RequestID string          `json:"request_id"`
	Errors    []ContractError `json:"errors,omitempty"`
}

// Server exposes the evidence plane over HTTP (spec 18.2).
type Server struct {
	Recorder *Recorder
}

// Handler builds the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/evidence/events", s.ingest)
	mux.HandleFunc("GET /v1/evidence/events", s.listEvents)
	mux.HandleFunc("GET /v1/evidence/chain", s.chain)
	mux.HandleFunc("GET /v1/evidence/verify", s.verify)
	mux.HandleFunc("GET /v1/evidence/findings", s.findings)
	mux.HandleFunc("POST /v1/evidence/collector-check", s.collectorCheck)
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ingest accepts an authenticated collector batch (spec 18.2: POST
// /v1/evidence/events). The batch is all-or-nothing; duplicates from
// at-least-once delivery are deduplicated by event id. Role checks run
// before the idempotency ledger, so a replay from an unauthenticated
// or wrong-role caller never surfaces a stored reply.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	digest := bodyDigest(body)
	reply, replay, err := s.Recorder.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	batch, err := DecodeBatch(body)
	if err != nil {
		s.Recorder.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "evidence_schema", err.Error(), false)
		return
	}
	result, err := s.Recorder.Ingest(principal, batch)
	if err != nil {
		s.Recorder.Release(principal.TenantID, key, digest)
		var refusal *IngestRefusal
		switch {
		case errors.As(err, &refusal):
			writeProblem(w, requestID, http.StatusUnprocessableEntity, "evidence_refused",
				"batch refused; nothing was stored", false, WithErrors(refusal.Errors))
		case isAuthProblem(err):
			writeAuthProblem(w, requestID, err)
		default:
			writeProblem(w, requestID, http.StatusInternalServerError, "internal",
				"evidence plane refused the batch", false)
		}
		return
	}
	s.Recorder.Complete(principal.TenantID, key, digest, result)
	writeJSON(w, http.StatusOK, result)
}

// listEvents returns the tenant's events. Filters combine: run_id
// narrows to a run, correlation_id joins events across sources (spec
// 9.4), and effect_id pulls every record of one effect — the worker's
// claim next to the collector's receipt.
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	query := r.URL.Query()
	runID := query.Get("run_id")
	if runID != "" && !reRunID.MatchString(runID) {
		writeProblem(w, requestID, http.StatusBadRequest, "run_id_invalid",
			"run id must match run_[a-z0-9]{8,64}", false)
		return
	}
	correlationID := query.Get("correlation_id")
	if correlationID != "" && !reCorrelation.MatchString(correlationID) {
		writeProblem(w, requestID, http.StatusBadRequest, "correlation_id_invalid",
			"correlation id must match cid_[A-Za-z0-9_-]{4,128}", false)
		return
	}
	effectID := query.Get("effect_id")
	if effectID != "" && !reEffectID.MatchString(effectID) {
		writeProblem(w, requestID, http.StatusBadRequest, "effect_id_invalid",
			"effect id must match eff_[a-z0-9]{8,64}", false)
		return
	}
	principal := principalFrom(r)
	events, err := s.Recorder.Events(principal, EventQuery{
		RunID: runID, CorrelationID: correlationID, EffectID: effectID,
	})
	if err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": principal.TenantID,
		"events":    events,
	})
}

// chain reports the tenant's chain head.
func (s *Server) chain(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	principal := principalFrom(r)
	digest, length, err := s.Recorder.Chain(principal)
	if err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":    principal.TenantID,
		"chain_digest": digest,
		"event_count":  length,
	})
}

// verify walks the chain and the checkpoint signatures.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return
	}
	// Verification is a read; the same roles that read the store read
	// its integrity answer.
	if err := checkReader(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	report, err := s.Recorder.Verify(principal)
	if err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// findings lists the tenant's derived findings.
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	principal := principalFrom(r)
	found, err := s.Recorder.Findings(principal)
	if err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": principal.TenantID,
		"findings":  found,
	})
}

// checkKeys are the exact accepted spellings of the collector-check
// body (AC-001: contract keys are exact).
var checkKeys = map[string]bool{"max_quiet_seconds": true}

// collectorCheck sweeps collector heartbeats and opens a finding per
// silent source (spec 9.4: collector failures become explicit
// findings). It mutates — findings land in the store — so it follows
// the same authentication and idempotency contract as ingest.
func (s *Server) collectorCheck(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	digest := bodyDigest(body)
	reply, replay, err := s.Recorder.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}
	raw, err := decodeExact(body, checkKeys)
	if err != nil {
		s.Recorder.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "collector_check_schema",
			err.Error(), false)
		return
	}
	secondsRaw, ok := raw["max_quiet_seconds"]
	if !ok {
		s.Recorder.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "collector_check_schema",
			"max_quiet_seconds is required", false)
		return
	}
	var seconds int64
	if err := json.Unmarshal(secondsRaw, &seconds); err != nil || seconds < 1 || seconds > 86400 {
		s.Recorder.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "max_quiet_seconds_invalid",
			"max_quiet_seconds must be an integer from 1 to 86400", false)
		return
	}
	findings, err := s.Recorder.CheckCollectorLiveness(principal,
		time.Duration(seconds)*time.Second)
	if err != nil {
		s.Recorder.Release(principal.TenantID, key, digest)
		writeAuthProblem(w, requestID, err)
		return
	}
	result := map[string]any{
		"tenant_id": principal.TenantID, "max_quiet_seconds": seconds,
		"findings": findings, "opened": len(findings),
	}
	s.Recorder.Complete(principal.TenantID, key, digest, result)
	writeJSON(w, http.StatusOK, result)
}

func principalFrom(r *http.Request) *Principal {
	actor := r.Header.Get(HeaderActor)
	tenant := r.Header.Get(HeaderTenant)
	role := r.Header.Get(HeaderRole)
	if actor == "" || tenant == "" || role == "" {
		return nil
	}
	return &Principal{ID: actor, TenantID: tenant, Role: role}
}

// isAuthProblem separates identity failures from refusal failures.
func isAuthProblem(err error) bool {
	message := err.Error()
	return message == "unauthenticated caller cannot ingest evidence"
}

func writeAuthProblem(w http.ResponseWriter, requestID string, err error) {
	message := err.Error()
	switch {
	case message == "unauthenticated caller cannot ingest evidence",
		message == "unauthenticated caller":
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
	case strings.Contains(message, "cannot ingest evidence"),
		strings.Contains(message, "cannot read the evidence store"),
		strings.Contains(message, "cannot verify evidence"):
		writeProblem(w, requestID, http.StatusForbidden, "role_forbidden", message, false)
	default:
		writeProblem(w, requestID, http.StatusInternalServerError, "internal",
			"evidence plane refused the request", false)
	}
}

// writeReservationProblem maps the two reservation failures.
func writeReservationProblem(w http.ResponseWriter, requestID string, err error) {
	if errors.Is(err, errIdempotencyConflict) {
		writeProblem(w, requestID, http.StatusConflict, "idempotency_conflict",
			"idempotency key reused with a different body", false)
		return
	}
	writeProblem(w, requestID, http.StatusServiceUnavailable, "idempotency_pending",
		"idempotency key is still executing; retry", true)
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

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newRequestID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "req_" + hex.EncodeToString(raw)
}
