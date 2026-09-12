package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"agentchaos/control"
	"agentchaos/evidence"
	"agentchaos/governor"
)

// Server is the beta API monolith (spec 8.1, 18.2, T026). The governor
// and the evidence plane run in process; the broker stays a separately
// isolated service, and effect traffic forwards to it unchanged.
type Server struct {
	Governor    *governor.Governor
	Evidence    *evidence.Server
	Assurer     *control.Assurer
	Compiler    Compiler
	BrokerURL   *url.URL // the separately deployed broker upstream
	Experiments *experimentStore
	Claims      *claimStore
	idem        *idemLedger
}

// New builds the monolith with fresh in-memory stores.
func New(gov *governor.Governor, evidenceServer *evidence.Server,
	assurer *control.Assurer, compiler Compiler, brokerURL *url.URL) *Server {
	return &Server{
		Governor:    gov,
		Evidence:    evidenceServer,
		Assurer:     assurer,
		Compiler:    compiler,
		BrokerURL:   brokerURL,
		Experiments: newExperimentStore(),
		Claims:      newClaimStore(),
		idem:        newIdemLedger(),
	}
}

// Handler routes the fixed core surface of spec 18.2 plus the broker's
// extended effect routes, forwarded as-is.
func (s *Server) Handler() http.Handler {
	// The governor serves run reads from its own handler so the API and
	// the governor never disagree about run state.
	governorHandler := (&governor.Server{Governor: s.Governor}).Handler()
	mux := http.NewServeMux()

	// Experiment lifecycle: API-owned.
	mux.HandleFunc("POST /v1/experiments",
		s.withIdempotency(supervisorRoles, "create an experiment", s.createExperiment))
	mux.HandleFunc("POST /v1/experiments/{id}/validation",
		s.withIdempotency(supervisorRoles, "validate an experiment", s.validateExperiment))
	mux.HandleFunc("POST /v1/experiments/{id}/runs",
		s.withIdempotency(supervisorRoles, "start a run", s.startRun))

	// Run reads come straight from the governor; the stop route is
	// API-owned because it spans the governor and the broker.
	mux.Handle("GET /v1/runs/{id}", governorHandler)
	mux.HandleFunc("POST /v1/runs/{id}/stop",
		s.withIdempotency(stopRoles, "stop a run", s.stopRun))
	mux.Handle("GET /v1/runs/{id}/stop", s.brokerProxy())

	// Evidence ingest and reads: the evidence plane, in process.
	mux.Handle("/v1/evidence/", s.Evidence.Handler())

	// Effect traffic and the broker's extended routes: forwarded to the
	// separately isolated broker, which enforces its own roles,
	// idempotency, and policy.
	mux.Handle("/v1/effects/", s.brokerProxy())
	mux.Handle("/v1/delegations", s.brokerProxy())
	mux.Handle("/v1/delegations/", s.brokerProxy())
	mux.Handle("/v1/quarantine", s.brokerProxy())

	// Assurance claims and safety levers: API-owned.
	mux.HandleFunc("POST /v1/assurance-claims",
		s.withIdempotency(supervisorRoles, "assess an assurance claim", s.assessClaim))
	mux.HandleFunc("GET /v1/assurance-claims/{id}", s.getClaim)
	mux.HandleFunc("POST /v1/safety-levers/{scope}/engage",
		s.withIdempotency(leverRoles, "engage a safety lever", s.engageSafetyLever))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

// brokerProxy forwards a request to the broker upstream unchanged:
// identity headers, idempotency key, and body pass through, and the
// broker's decision — including its problem envelopes — comes back as
// the reply. The broker is the enforcement point; the proxy never
// widens anything.
func (s *Server) brokerProxy() http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(s.BrokerURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unauthenticated traffic never leaves the monolith.
		if principalFrom(r) == nil {
			writeProblem(w, newRequestID(), http.StatusUnauthorized, "unauthenticated",
				"caller identity headers are required", false)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// stopRun requests fencing and cleanup for one run (spec 18.2, 13.3).
// The governor trips the run on an operator request — the routine stop,
// distinct from the emergency control — and emits the stop handoff; the
// broker executes the stop protocol against its own records. Both
// happen on this route so one request fences everything.
func (s *Server) stopRun(w http.ResponseWriter, r *http.Request) {
	principal, requestID, ok := requireMutationPrincipal(w, r,
		stopRoles, "stop a run")
	if !ok {
		return
	}
	runID := r.PathValue("id")
	if !reRunID.MatchString(runID) {
		writeProblem(w, requestID, http.StatusBadRequest, "run_id_invalid",
			"run id must match run_[a-z0-9]{8,64}", false)
		return
	}
	body, ok := readBody(w, requestID, r)
	if !ok {
		return
	}

	// The run must exist in the caller's tenant before anything trips.
	if _, err := s.Governor.Run(governorPrincipal(principal), runID); err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	err := s.Governor.ReportIncident(governorPrincipal(principal),
		&governor.Incident{
			RunID:     runID,
			Condition: governor.TripOperatorRequest,
			Reason:    "stop request for run " + runID,
		})
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	run, err := s.Governor.Run(governorPrincipal(principal), runID)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}

	// The broker executes the stop protocol with the caller's stop
	// order (sandbox disposition, compensations). The caller's identity
	// and idempotency key travel with it.
	brokerBody, ok := s.doBrokerStop(r, body, runID, requestID, w)
	if !ok {
		return
	}
	brokerReply := map[string]any{}
	if err := json.Unmarshal(brokerBody, &brokerReply); err != nil {
		brokerReply = map[string]any{"raw": string(brokerBody)}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run":    run,
		"broker": brokerReply,
	})
}

// doBrokerStop posts the stop order to the broker and reports whether
// the reply was written to the client.
func (s *Server) doBrokerStop(r *http.Request, body []byte, runID,
	requestID string, w http.ResponseWriter) ([]byte, bool) {
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.BrokerURL.JoinPath("/v1/runs/", runID, "/stop").String(),
		strings.NewReader(string(body)))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadGateway, "broker_unreachable",
			"the stop order could not reach the broker", true)
		return nil, false
	}
	request.Header.Set(HeaderActor, r.Header.Get(HeaderActor))
	request.Header.Set(HeaderTenant, r.Header.Get(HeaderTenant))
	request.Header.Set(HeaderRole, r.Header.Get(HeaderRole))
	request.Header.Set(HeaderIdem, r.Header.Get(HeaderIdem))
	request.Header.Set("Content-Type", "application/json")
	reply, err := http.DefaultClient.Do(request)
	if err != nil {
		writeProblem(w, requestID, http.StatusBadGateway, "broker_unreachable",
			"the stop order could not reach the broker; the governor fence stands",
			true)
		return nil, false
	}
	defer reply.Body.Close()
	brokerBody, _ := io.ReadAll(io.LimitReader(reply.Body, 1<<20))
	if reply.StatusCode >= 400 {
		writeRaw(w, reply.StatusCode, brokerBody)
		return nil, false
	}
	return brokerBody, true
}

// writeRaw re-emits a broker reply verbatim.
func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// engageSafetyLever fences the applicable authority (spec 18.2: POST
// /v1/safety-levers/{scope}/engage). The scope path segment is
// "tenant" or an experiment id.
func (s *Server) engageSafetyLever(w http.ResponseWriter, r *http.Request) {
	principal, requestID, ok := requireMutationPrincipal(w, r,
		leverRoles, "engage a safety lever")
	if !ok {
		return
	}
	scope := r.PathValue("scope")
	var stopScope governor.EmergencyStopScope
	switch {
	case scope == "tenant":
		stopScope.Kind = "tenant"
	case reExperiment.MatchString(scope):
		stopScope.Kind = "experiment"
		stopScope.ExperimentID = scope
	default:
		writeProblem(w, requestID, http.StatusBadRequest, "lever_scope_invalid",
			"scope must be 'tenant' or an experiment id exp_[a-z0-9]{8,64}", false)
		return
	}

	body, ok := readBody(w, requestID, r)
	if !ok {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if len(body) > 0 {
		if problems := decodeStrict(body, &request,
			map[string]bool{"reason": true}); len(problems) > 0 {
			writeProblem(w, requestID, http.StatusBadRequest, "lever_schema",
				"the engage request violates its contract", false, problems...)
			return
		}
	}
	stopScope.Reason = request.Reason

	fenced, err := s.Governor.EmergencyStop(governorPrincipal(principal), &stopScope)
	if err != nil {
		writeRefusal(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"engaged":     true,
		"scope":       stopScope.Kind,
		"fenced_runs": fenced,
	})
}

// stopRoles may request a run stop.
func stopRoles(role string) bool {
	return role == RoleService || role == RoleOperator || role == RoleCustomer
}

// leverRoles may engage a safety lever: the customer control must
// never depend on the main UI or the operator being reachable (spec
// 13.3).
func leverRoles(role string) bool {
	return role == RoleService || role == RoleOperator || role == RoleCustomer
}

// governorPrincipal converts an API principal into a governor
// principal.
func governorPrincipal(principal *Principal) *governor.Principal {
	return &governor.Principal{
		ID:       principal.ID,
		TenantID: principal.TenantID,
		Role:     principal.Role,
	}
}

// writeRefusal maps a governor refusal onto the API problem envelope.
func writeRefusal(w http.ResponseWriter, requestID string, err error) {
	code, detail, ok := governor.AsRefusal(err)
	if !ok {
		writeProblem(w, requestID, http.StatusInternalServerError, "internal",
			"the request could not be served", false)
		return
	}
	status := http.StatusConflict
	switch code {
	case "unauthenticated":
		status = http.StatusUnauthorized
	case "role_forbidden":
		status = http.StatusForbidden
	case "run_unknown", "envelope_unknown", "handoff_unknown":
		status = http.StatusNotFound
	case "grant_expired":
		status = http.StatusGone
	}
	writeProblem(w, requestID, status, code, detail, false)
}

// withIdempotency wraps an API-owned mutation with authentication, the
// role gate, and the monolith's per-tenant reply ledger (spec 18.3).
// Authentication and role checks run before the ledger, so a replay
// from an unauthenticated or wrong-role caller never surfaces a stored
// reply. Delegated routes keep their own component's ledger — one
// mutation, one ledger.
func (s *Server) withIdempotency(allowed func(role string) bool, action string,
	next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := newRequestID()
		principal := principalFrom(r)
		if principal == nil {
			writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
				"caller identity headers are required", false)
			return
		}
		if !allowed(principal.Role) {
			writeProblem(w, requestID, http.StatusForbidden, "role_forbidden",
				fmt.Sprintf("the %s role cannot %s", principal.Role, action), false)
			return
		}
		key := r.Header.Get(HeaderIdem)
		if !reIdemKey.MatchString(key) {
			writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
				"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeProblem(w, requestID, http.StatusBadRequest, "body_unreadable",
				"request body could not be read", false)
			return
		}
		outcome, status, stored, release := s.idem.Reserve(
			principal.TenantID, key, bodyDigest(body))
		switch outcome {
		case outcomeReplay:
			writeRaw(w, status, stored)
			return
		case outcomeConflict:
			writeProblem(w, newRequestID(), http.StatusConflict, "idempotency_conflict",
				"the idempotency key was reused with a different body", false)
			return
		case outcomeConcurrent:
			writeProblem(w, newRequestID(), http.StatusConflict, "idempotency_in_flight",
				"another request holding this idempotency key failed; retry", true)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		recorder := &replyRecorder{ResponseWriter: w}
		next(recorder, r)
		if !recorder.wrote {
			release()
			return
		}
		s.idem.Complete(principal.TenantID, key, bodyDigest(body),
			recorder.status, recorder.body)
	}
}

// replyRecorder captures the reply a mutation produced so the ledger
// can replay it verbatim.
type replyRecorder struct {
	http.ResponseWriter
	wrote  bool
	status int
	body   []byte
}

func (c *replyRecorder) WriteHeader(status int) {
	c.status = status
	c.wrote = true
	c.ResponseWriter.WriteHeader(status)
}

func (c *replyRecorder) Write(body []byte) (int, error) {
	if !c.wrote {
		c.status = http.StatusOK
		c.wrote = true
	}
	c.body = append(c.body, body...)
	return c.ResponseWriter.Write(body)
}
