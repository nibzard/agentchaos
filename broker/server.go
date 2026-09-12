package broker

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Principal headers. In a deployment a real authentication front end
// sets these from a verified credential; the broker never derives a
// tenant from a body (spec 18.3).
const (
	HeaderActor  = "X-ACX-Actor"
	HeaderTenant = "X-ACX-Tenant"
	HeaderRole   = "X-ACX-Role"
	HeaderIdem   = "Idempotency-Key"
)

// Problem is the error envelope (spec 18.3): a stable code, a safe
// message, retryability, and a request ID. No credentials, no
// reviewer internals.
type Problem struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Retryable bool            `json:"retryable"`
	RequestID string          `json:"request_id"`
	Errors    []ContractError `json:"errors,omitempty"`
	State     string          `json:"state,omitempty"` // current effect state on lifecycle refusals
}

// Server exposes the broker over HTTP (spec 18.2).
type Server struct {
	Broker *Broker
}

// Handler builds the broker's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/effects/authorizations", s.authorize)
	mux.HandleFunc("POST /v1/effects/{id}/commit", s.commit)
	mux.HandleFunc("POST /v1/effects/{id}/review", s.review)
	mux.HandleFunc("POST /v1/delegations", s.delegate)
	mux.HandleFunc("POST /v1/delegations/{id}/revocation", s.revokeDelegation)
	mux.HandleFunc("POST /v1/runs/{id}/stop", s.stopRun)
	mux.HandleFunc("GET /v1/runs/{id}/stop", s.readStop)
	mux.HandleFunc("POST /v1/evidence-fence/engage", s.engageEvidenceFence)
	mux.HandleFunc("POST /v1/evidence-fence/release", s.releaseEvidenceFence)
	mux.HandleFunc("GET /v1/quarantine", s.quarantine)
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authorize evaluates a broker-originated request: the worker's
// proposal goes in, the broker's bound decision comes out. Denials
// are successful evaluations and return 200 with a DENIED effect.
// Authentication and role checks run before the idempotency ledger,
// so a replay from an unauthenticated or wrong-role caller never
// surfaces a stored reply (spec 18.3).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	digest := bodyDigest(body)
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	proposal, err := DecodeProposal(body)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "effect_schema",
			err.Error(), false)
		return
	}
	if problems := proposal.ValidateProposal(); len(problems) > 0 {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "effect_schema",
			"proposal violates the Effect contract", false,
			WithErrors(problems))
		return
	}
	effect, decision, err := s.Broker.Authorize(principal, proposal)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		if errors.Is(err, errEffectExists) {
			writeProblem(w, requestID, http.StatusConflict, "effect_exists",
				"effect id already has a record; propose under a fresh id", false)
			return
		}
		writeAuthProblem(w, requestID, err)
		return
	}
	authorizationReplyValue := authorizationReply{Effect: effect, Decision: decision}
	s.Broker.Complete(principal.TenantID, key, digest, authorizationReplyValue)
	writeJSON(w, http.StatusOK, authorizationReplyValue)
}

// commit dispatches a bound effect through the authorized broker.
func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	effectID := r.PathValue("id")
	if !reEffectID.MatchString(effectID) {
		writeProblem(w, requestID, http.StatusBadRequest, "effect_id_invalid",
			"effect id must match eff_[a-z0-9]{8,64}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	digest := bodyDigest([]byte(effectID))
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	effect, err := s.Broker.Commit(principal, effectID, key)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		var transition *TransitionError
		switch {
		case errors.Is(err, errNotFound):
			writeProblem(w, requestID, http.StatusNotFound, "effect_not_found",
				"no such effect for this tenant", false)
		case errors.Is(err, ErrEvidenceFenced):
			writeProblem(w, requestID, http.StatusConflict, "evidence_fenced",
				err.Error(), false)
		case errors.As(err, &transition):
			status := http.StatusConflict
			if transition.From == StateExpired {
				status = http.StatusGone
			}
			writeProblem(w, requestID, status, "invalid_transition",
				transition.Error(), false, WithState(transition.From))
		default:
			writeAuthProblem(w, requestID, err)
		}
		return
	}
	s.Broker.Complete(principal.TenantID, key, digest, effect)
	writeJSON(w, http.StatusOK, effect)
}

// review attaches a machine-review decision to a held effect and
// re-runs the deterministic decision (spec 10, 11.1, 11.2). Reviews
// come from the supervisor system, never the worker.
func (s *Server) review(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	effectID := r.PathValue("id")
	if !reEffectID.MatchString(effectID) {
		writeProblem(w, requestID, http.StatusBadRequest, "effect_id_invalid",
			"effect id must match eff_[a-z0-9]{8,64}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	digest := bodyDigest(body)
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	review, err := DecodeReview(body)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "review_schema",
			err.Error(), false)
		return
	}
	effect, decision, err := s.Broker.AttachReview(principal, effectID, review)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		var contract *ReviewContractError
		var transition *TransitionError
		switch {
		case errors.Is(err, errNotFound):
			writeProblem(w, requestID, http.StatusNotFound, "effect_not_found",
				"no such effect for this tenant", false)
		case errors.Is(err, errReviewDenyFinal):
			writeProblem(w, requestID, http.StatusConflict, "review_deny_final",
				err.Error(), false)
		case errors.Is(err, errReviewNotRequired):
			writeProblem(w, requestID, http.StatusConflict, "review_not_required",
				err.Error(), false)
		case errors.As(err, &contract):
			writeProblem(w, requestID, http.StatusUnprocessableEntity, "review_schema",
				"review violates the decision contract (spec 11.2)", false,
				WithErrors(contract.Problems))
		case errors.As(err, &transition):
			writeProblem(w, requestID, http.StatusConflict, "invalid_transition",
				transition.Error(), false, WithState(transition.From))
		default:
			writeAuthProblem(w, requestID, err)
		}
		return
	}
	replyValue := authorizationReply{Effect: effect, Decision: decision}
	s.Broker.Complete(principal.TenantID, key, digest, replyValue)
	writeJSON(w, http.StatusOK, replyValue)
}

// delegate mints a child delegation after the narrowing rules
// (spec 10, AC-008). Service and operator roles only: a worker never
// mints capability for itself.
func (s *Server) delegate(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	digest := bodyDigest(body)
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	request, err := DecodeDelegationRequest(body)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "delegation_schema",
			err.Error(), false)
		return
	}
	if problems := request.ValidateDelegationRequest(); len(problems) > 0 {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "delegation_schema",
			"delegation request violates the Delegation contract", false,
			WithErrors(problems))
		return
	}
	delegation, err := s.Broker.Delegate(principal, request)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		var refusal *DelegationRefusal
		switch {
		case errors.Is(err, errDelegationExists):
			writeProblem(w, requestID, http.StatusConflict, "delegation_exists",
				"delegation id already exists; mint under a fresh id", false)
		case errors.As(err, &refusal):
			writeProblem(w, requestID, http.StatusUnprocessableEntity, "delegation_refused",
				"delegation would widen; children can only narrow (AC-008)", false,
				WithErrors(refusal.Errors))
		default:
			writeAuthProblem(w, requestID, err)
		}
		return
	}
	s.Broker.Complete(principal.TenantID, key, digest, delegation)
	writeJSON(w, http.StatusOK, delegation)
}

// revokeDelegation fences a delegation group. The body carries an
// optional reason.
func (s *Server) revokeDelegation(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	delegationID := r.PathValue("id")
	if !matches(`^dlg_[a-z0-9]{8,64}$`, delegationID) {
		writeProblem(w, requestID, http.StatusBadRequest, "delegation_id_invalid",
			"delegation id must match dlg_[a-z0-9]{8,64}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	// The digest binds the delegation id and the body with a separator
	// the id pattern cannot produce: a bare concatenation would let a
	// different (id, body) pair replay this key's stored reply.
	digest := bodyDigest(append(append([]byte(delegationID), 0), body...))
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	reason := ""
	if len(bytes.TrimSpace(body)) > 0 {
		revocation, err := DecodeRevocation(body)
		if err != nil {
			s.Broker.Release(principal.TenantID, key, digest)
			writeProblem(w, requestID, http.StatusBadRequest, "delegation_schema",
				err.Error(), false)
			return
		}
		reason = revocation.Reason
	}
	delegation, err := s.Broker.RevokeDelegation(principal, delegationID, reason)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		if errors.Is(err, errDelegationNotFound) {
			writeProblem(w, requestID, http.StatusNotFound, "delegation_not_found",
				"no such delegation for this tenant", false)
			return
		}
		writeAuthProblem(w, requestID, err)
		return
	}
	s.Broker.Complete(principal.TenantID, key, digest, delegation)
	writeJSON(w, http.StatusOK, delegation)
}

// stopRun executes the stop protocol (spec 13.3) for one run. The
// order states the sandbox disposition and any preapproved
// compensations; the reply is the stop report with its terminal
// state. Idempotent by construction: the first stop records the
// report and every later stop replays it.
func (s *Server) stopRun(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	runID := r.PathValue("id")
	if !reRunID.MatchString(runID) {
		writeProblem(w, requestID, http.StatusBadRequest, "run_id_invalid",
			"run id must match run_[a-z0-9]{8,64}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	digest := bodyDigest(append(append([]byte(runID), 0), body...))
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	order, err := DecodeStopOrder(runID, body)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusBadRequest, "stop_schema", err.Error(), false)
		return
	}
	if problems := order.ValidateStopOrder(); len(problems) > 0 {
		s.Broker.Release(principal.TenantID, key, digest)
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "stop_schema",
			"stop order violates the stop contract", false, WithErrors(problems))
		return
	}
	report, err := s.Broker.Stop(principal, order)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		var refusal *StopRefusal
		switch {
		case errors.Is(err, errStopRunUnknown):
			writeProblem(w, requestID, http.StatusNotFound, "run_not_found",
				"no such run in the caller's tenant", false)
		case errors.As(err, &refusal):
			writeProblem(w, requestID, http.StatusUnprocessableEntity, "stop_refused",
				"stop order refused", false, WithErrors(refusal.Errors))
		default:
			writeAuthProblem(w, requestID, err)
		}
		return
	}
	s.Broker.Complete(principal.TenantID, key, digest, report)
	writeJSON(w, http.StatusOK, report)
}

// readStop returns a run's stop report, or 404 when the run never
// stopped. Any authenticated principal of the tenant may read it.
func (s *Server) readStop(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	runID := r.PathValue("id")
	if !reRunID.MatchString(runID) {
		writeProblem(w, requestID, http.StatusBadRequest, "run_id_invalid",
			"run id must match run_[a-z0-9]{8,64}", false)
		return
	}
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return
	}
	report, err := s.Broker.StopRecord(principal, runID)
	if err != nil {
		writeProblem(w, requestID, http.StatusNotFound, "stop_not_found",
			"no stop report for this run", false)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// engageEvidenceFence fences new external effects while mandatory
// evidence capture is down (spec 10.2). Service and operator
// principals only.
func (s *Server) engageEvidenceFence(w http.ResponseWriter, r *http.Request) {
	s.serveEvidenceFence(w, r, true)
}

// releaseEvidenceFence lifts the fence.
func (s *Server) releaseEvidenceFence(w http.ResponseWriter, r *http.Request) {
	s.serveEvidenceFence(w, r, false)
}

func (s *Server) serveEvidenceFence(w http.ResponseWriter, r *http.Request, engage bool) {
	requestID := newRequestID()
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return
	}
	principal := principalFrom(r)
	if err := s.Broker.CheckAuthority(principal); err != nil {
		writeAuthProblem(w, requestID, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
			"request body could not be read", false)
		return
	}
	if _, err := decodeExact(body, map[string]bool{"reason": true}); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "fence_schema",
			err.Error(), false)
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "fence_schema",
			"the fence request violates its contract", false)
		return
	}
	engageTag := []byte{0}
	if engage {
		engageTag[0] = 1
	}
	digest := bodyDigest(append(engageTag, body...))
	reply, replay, err := s.Broker.Reserve(principal.TenantID, key, digest)
	if err != nil {
		writeReservationProblem(w, requestID, err)
		return
	}
	if replay {
		writeJSON(w, http.StatusOK, reply)
		return
	}
	if engage {
		err = s.Broker.EngageEvidenceFence(principal, request.Reason)
	} else {
		err = s.Broker.ReleaseEvidenceFence(principal, request.Reason)
	}
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		switch {
		case errors.Is(err, errFenceState):
			writeProblem(w, requestID, http.StatusConflict, "fence_state",
				err.Error(), false)
		default:
			writeAuthProblem(w, requestID, err)
		}
		return
	}
	state := s.Broker.EvidenceFence()
	s.Broker.Complete(principal.TenantID, key, digest, state)
	writeJSON(w, http.StatusOK, state)
}

// quarantine lists the tenant's dirty artifacts. A quarantined
// artifact cannot be reassigned to a new experiment (spec 13.3).
func (s *Server) quarantine(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":   principal.TenantID,
		"quarantined": s.Broker.Quarantined(principal),
	})
}

// stopOrderKeys are the exact accepted spellings of a stop order.
var stopOrderKeys = map[string]bool{
	"handoff_id": true, "reason": true, "sandbox": true, "compensations": true,
}

// DecodeStopOrder parses a stop order body bound to its run path.
func DecodeStopOrder(runID string, data []byte) (*StopOrder, error) {
	raw, err := decodeExact(data, stopOrderKeys)
	if err != nil {
		return nil, err
	}
	if plans, ok := raw["compensations"]; ok {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(plans, &entries); err != nil {
			return nil, fmt.Errorf("malformed compensations: %w", err)
		}
		for _, entry := range entries {
			if _, err := decodeExact(mustRemarshal(entry), planKeys); err != nil {
				return nil, fmt.Errorf("compensations: %w", err)
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var body struct {
		HandoffID     string             `json:"handoff_id"`
		Reason        string             `json:"reason"`
		Sandbox       string             `json:"sandbox"`
		Compensations []CompensationPlan `json:"compensations"`
	}
	if err := decoder.Decode(&body); err != nil {
		return nil, fmt.Errorf("unknown or malformed field: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("trailing content after JSON document")
	}
	return &StopOrder{
		RunID:         runID,
		HandoffID:     body.HandoffID,
		Reason:        body.Reason,
		Sandbox:       body.Sandbox,
		Compensations: body.Compensations,
	}, nil
}

// planKeys are the exact accepted spellings of a compensation plan.
var planKeys = map[string]bool{
	"effect_id": true, "operation": true, "resource": true,
	"destination": true, "arguments_digest": true, "action_class": true,
	"size_bytes": true,
}

func mustRemarshal(value map[string]json.RawMessage) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte("{}")
	}
	return encoded
}

// Exact key sets for delegation decoding. Non-contract spellings
// fail closed, exactly like proposals (AC-001, spec 18.3).
var (
	delegationRequestKeys = map[string]bool{
		"id": true, "run_id": true, "parent_actor": true,
		"child_actor": true, "parent_delegation_id": true,
		"capabilities": true, "cumulative_budget": true,
	}
	capabilityKeys = map[string]bool{
		"allowed_action_classes": true, "allowed_destinations": true,
		"allowed_resources": true,
	}
	budgetKeys = map[string]bool{
		"max_total_cost": true, "max_total_tokens": true, "max_effects": true,
	}
	moneyKeys = map[string]bool{"currency": true, "micros": true}
)

// DecodeDelegationRequest parses a mint request body with exact-key
// validation at every nesting level.
func DecodeDelegationRequest(data []byte) (*DelegationRequest, error) {
	strict, err := decodeExact(data, delegationRequestKeys)
	if err != nil {
		return nil, err
	}
	if raw, ok := strict["capabilities"]; ok {
		if _, err := decodeExact(raw, capabilityKeys); err != nil {
			return nil, fmt.Errorf("capabilities: %w", err)
		}
	}
	if raw, ok := strict["cumulative_budget"]; ok {
		budget, err := decodeExact(raw, budgetKeys)
		if err != nil {
			return nil, fmt.Errorf("cumulative_budget: %w", err)
		}
		if cost, ok := budget["max_total_cost"]; ok {
			if _, err := decodeExact(cost, moneyKeys); err != nil {
				return nil, fmt.Errorf("max_total_cost: %w", err)
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request DelegationRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("unknown or malformed field: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("trailing content after JSON document")
	}
	return &request, nil
}

// MaxRevocationReason bounds the advisory revoke reason: the evidence
// plane keeps minimized payloads (spec 19).
const MaxRevocationReason = 512

// revocationRequest is the revoke body.
type revocationRequest struct {
	Reason string `json:"reason"`
}

// DecodeRevocation parses a revoke request body.
func DecodeRevocation(data []byte) (revocationRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return revocationRequest{}, fmt.Errorf("malformed revocation body: %w", err)
	}
	for key := range raw {
		if key != "reason" {
			return revocationRequest{}, fmt.Errorf(
				"unknown or misspelled field %q: only reason is accepted", key)
		}
	}
	var revocation revocationRequest
	if err := json.Unmarshal(data, &revocation); err != nil {
		return revocationRequest{}, fmt.Errorf("malformed revocation body: %w", err)
	}
	if len(revocation.Reason) > MaxRevocationReason {
		return revocationRequest{}, fmt.Errorf(
			"reason exceeds %d characters; keep it short", MaxRevocationReason)
	}
	return revocation, nil
}

// decodeExact decodes one object level and rejects any key outside
// the allowed set.
func decodeExact(data []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("malformed object: %w", err)
	}
	for key := range raw {
		if !allowed[key] {
			return nil, fmt.Errorf(
				"unknown or misspelled field %q: contract keys are exact snake_case", key)
		}
	}
	return raw, nil
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

type authorizationReply struct {
	Effect   *Effect         `json:"effect"`
	Decision *BrokerDecision `json:"decision"`
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

func writeAuthProblem(w http.ResponseWriter, requestID string, err error) {
	message := err.Error()
	switch {
	case strings.Contains(message, "unauthenticated"):
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
	case strings.Contains(message, "cannot act on tenant"):
		writeProblem(w, requestID, http.StatusForbidden, "tenant_forbidden",
			"authenticated tenant does not match the record", false)
	case strings.Contains(message, "cannot authorize"),
		strings.Contains(message, "cannot commit"),
		strings.Contains(message, "cannot delegate"),
		strings.Contains(message, "cannot revoke"),
		strings.Contains(message, "cannot stop"),
		strings.Contains(message, "cannot drive broker authority"):
		writeProblem(w, requestID, http.StatusForbidden, "role_forbidden",
			message, false)
	default:
		writeProblem(w, requestID, http.StatusInternalServerError, "internal",
			"broker refused the request", false)
	}
}

// problemOption decorates a problem body.
type problemOption func(*Problem)

// WithErrors attaches contract violations.
func WithErrors(errs []ContractError) problemOption {
	return func(p *Problem) { p.Errors = errs }
}

// WithState reports the current lifecycle state.
func WithState(state string) problemOption {
	return func(p *Problem) { p.State = state }
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
