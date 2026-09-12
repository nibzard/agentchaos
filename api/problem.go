// Package api is the beta API monolith (spec 8.1, 18.2, T026): one Go
// service that mounts the governor and the evidence plane in process,
// owns the experiment lifecycle routes, computes assurance claims, and
// forwards effect traffic to the separately deployed broker.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// Identity headers, set by the deployment's authentication front end
// (spec 18.3). A tenant in a request body never overrides the
// authenticated tenant.
const (
	HeaderActor  = "X-Gauntlet-Actor"
	HeaderTenant = "X-Gauntlet-Tenant"
	HeaderRole   = "X-Gauntlet-Role"
	HeaderIdem   = "Idempotency-Key"
)

// Roles the platform authenticates (spec 18.3).
const (
	RoleWorker    = "worker"
	RoleService   = "service"
	RoleOperator  = "operator"
	RoleCustomer  = "customer"
	RoleCollector = "collector"
)

// Principal is the authenticated caller, derived from identity headers.
type Principal struct {
	ID       string
	TenantID string
	Role     string
}

// Problem is the error envelope every API route returns on failure
// (spec 18.3): a stable code, a safe message, a retryability flag, and
// a request id. It never carries credentials or reviewer internals.
type Problem struct {
	Code      string   `json:"code"`
	Message   string   `json:"message"`
	Retryable bool     `json:"retryable"`
	RequestID string   `json:"request_id"`
	Errors    []string `json:"errors,omitempty"`
}

var (
	reTenantID   = regexp.MustCompile(`^tnt_[a-z0-9]{8,64}$`)
	reExperiment = regexp.MustCompile(`^exp_[a-z0-9]{8,64}$`)
	reRunID      = regexp.MustCompile(`^run_[a-z0-9]{8,64}$`)
	reClaimID    = regexp.MustCompile(`^clm_[a-z0-9]{8,64}$`)
	reIdemKey    = regexp.MustCompile(`^idk_[A-Za-z0-9_-]{8,128}$`)
	reTimestampZ = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
)

// principalFrom reads the identity headers. All three are required:
// a request without a full principal is unauthenticated, whatever its
// body claims.
func principalFrom(r *http.Request) *Principal {
	principal := &Principal{
		ID:       r.Header.Get(HeaderActor),
		TenantID: r.Header.Get(HeaderTenant),
		Role:     r.Header.Get(HeaderRole),
	}
	if principal.ID == "" || principal.TenantID == "" || principal.Role == "" {
		return nil
	}
	return principal
}

// writeProblem emits the error envelope with the status the code maps
// to. Safe message only: no internals, no credentials.
func writeProblem(w http.ResponseWriter, requestID string, status int,
	code, message string, retryable bool, problems ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := Problem{Code: code, Message: message, Retryable: retryable,
		RequestID: requestID, Errors: problems}
	encoded, err := json.Marshal(body)
	if err != nil {
		return
	}
	_, _ = w.Write(encoded)
}

// writeJSON emits a success body.
func writeJSON(w http.ResponseWriter, status int, document any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoded, err := json.Marshal(document)
	if err != nil {
		return
	}
	_, _ = w.Write(encoded)
}

// newRequestID mints a request identifier for the Problem envelope.
func newRequestID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(raw)
}

// mintID mints an identifier with the given prefix (run_, exp_ scoped
// by the caller).
func mintID(prefix string) string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(raw)
}

// requireMutationPrincipal enforces the two gates every API mutation
// shares: a full authenticated principal and a valid idempotency key
// (spec 18.3). Role policy stays with each route.
func requireMutationPrincipal(w http.ResponseWriter, r *http.Request,
	allowed func(role string) bool, action string) (*Principal, string, bool) {
	requestID := newRequestID()
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return nil, requestID, false
	}
	if !allowed(principal.Role) {
		writeProblem(w, requestID, http.StatusForbidden, "role_forbidden",
			fmt.Sprintf("the %s role cannot %s", principal.Role, action), false)
		return nil, requestID, false
	}
	key := r.Header.Get(HeaderIdem)
	if !reIdemKey.MatchString(key) {
		writeProblem(w, requestID, http.StatusBadRequest, "idempotency_key_required",
			"mutations require an Idempotency-Key matching idk_[A-Za-z0-9_-]{8,128}", false)
		return nil, requestID, false
	}
	return principal, requestID, true
}

// supervisorRoles may alter experiments, engage safety levers, and stop
// runs (spec 18.3). Worker and collector identities cannot.
func supervisorRoles(role string) bool {
	return role == RoleService || role == RoleOperator
}
