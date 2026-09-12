package broker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	effect, err := s.Broker.Commit(principal, effectID)
	if err != nil {
		s.Broker.Release(principal.TenantID, key, digest)
		var transition *TransitionError
		switch {
		case errors.Is(err, errNotFound):
			writeProblem(w, requestID, http.StatusNotFound, "effect_not_found",
				"no such effect for this tenant", false)
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
