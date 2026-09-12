package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The principal token (T027, spec 18.3). The deployment's
// authentication front end verifies the human or service login and
// issues a short-lived signed token that binds actor, tenant, and role.
// The API verifies the token and derives identity itself; identity
// headers a client sends are never trusted.
//
// Wire format:
//
//	Authorization: Bearer gauntlet1.<base64url payload>.<base64url signature>
//
// The payload is JSON {"actor","tenant","role","exp"} and the signature
// is Ed25519 over the exact payload bytes as transmitted, so nothing
// depends on JSON canonicalization. The API holds public keys only; the
// private key never leaves the front end.
const (
	tokenPrefix  = "gauntlet1."
	tokenVersion = "gauntlet1"
)

// Authenticator verifies principal tokens against the front end's
// public keys. Several keys are accepted so rotation can overlap.
type Authenticator struct {
	publicKeys []ed25519.PublicKey
}

// NewAuthenticator builds an authenticator that trusts the given
// public keys. At least one key is required.
func NewAuthenticator(publicKeys ...ed25519.PublicKey) *Authenticator {
	return &Authenticator{publicKeys: publicKeys}
}

// tokenPayload is the signed claim set. exp is RFC 3339 UTC.
type tokenPayload struct {
	Actor  string `json:"actor"`
	Tenant string `json:"tenant"`
	Role   string `json:"role"`
	Exp    string `json:"exp"`
}

var reActorID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// knownRole reports whether the role is one the platform authenticates.
func knownRole(role string) bool {
	switch role {
	case RoleWorker, RoleService, RoleOperator, RoleCustomer, RoleCollector:
		return true
	}
	return false
}

// MintPrincipalToken signs a principal token. The authentication front
// end owns the private key; this helper exists so the front end's
// reference implementation and the test suite share one format.
func MintPrincipalToken(private ed25519.PrivateKey, actor, tenant,
	role, expiresAt string) string {
	payload, _ := json.Marshal(tokenPayload{
		Actor: actor, Tenant: tenant, Role: role, Exp: expiresAt,
	})
	signature := ed25519.Sign(private, payload)
	return tokenVersion + "." + encodeTokenSegment(payload) +
		"." + encodeTokenSegment(signature)
}

func encodeTokenSegment(segment []byte) string {
	return base64.RawURLEncoding.EncodeToString(segment)
}

func decodeTokenSegment(segment string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	return raw, err == nil
}

// Verify checks a token and returns the principal it binds. Every
// failure is a credential problem: a bad signature, an expired or
// malformed token, or claims outside their contracts.
func (a *Authenticator) Verify(token string, now time.Time) (*Principal, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return nil, fmt.Errorf("the Authorization bearer token must start with %s", tokenPrefix)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return nil, fmt.Errorf("the principal token must have three segments")
	}
	payload, ok := decodeTokenSegment(parts[1])
	if !ok {
		return nil, fmt.Errorf("the principal token payload is not base64url")
	}
	signature, ok := decodeTokenSegment(parts[2])
	if !ok {
		return nil, fmt.Errorf("the principal token signature is not base64url")
	}
	verified := false
	for _, key := range a.publicKeys {
		if len(key) == 0 || len(signature) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(key, payload, signature) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("the principal token signature does not verify")
	}

	var claims tokenPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("the principal token payload is not valid JSON")
	}
	if !reActorID.MatchString(claims.Actor) {
		return nil, fmt.Errorf("the principal token actor is invalid")
	}
	if !reTenantID.MatchString(claims.Tenant) {
		return nil, fmt.Errorf("the principal token tenant is invalid")
	}
	if !knownRole(claims.Role) {
		return nil, fmt.Errorf("the principal token carries an unknown role")
	}
	expiresAt, err := time.Parse(time.RFC3339, claims.Exp)
	if err != nil {
		return nil, fmt.Errorf("the principal token expiry is not RFC 3339")
	}
	if now.After(expiresAt) {
		return nil, fmt.Errorf("the principal token has expired")
	}
	return &Principal{ID: claims.Actor, TenantID: claims.Tenant,
		Role: claims.Role}, nil
}

// bearerToken extracts the Authorization bearer value.
func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	const scheme = "Bearer "
	if len(value) <= len(scheme) || !strings.HasPrefix(value, scheme) {
		return ""
	}
	return strings.TrimSpace(value[len(scheme):])
}

// authenticate verifies the caller's token and rewrites the request's
// identity headers with the verified values. Downstream components —
// the governor, the evidence plane, the broker proxy — read identity
// from headers the API itself set, so a client cannot speak an identity
// the token does not carry (T027: binding is server-side).
func (a *Authenticator) authenticate(r *http.Request) (*Principal, error) {
	token := bearerToken(r)
	if token == "" {
		return nil, fmt.Errorf("an Authorization: Bearer principal token is required")
	}
	principal, err := a.Verify(token, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	r.Header.Set(HeaderActor, principal.ID)
	r.Header.Set(HeaderTenant, principal.TenantID)
	r.Header.Set(HeaderRole, principal.Role)
	return principal, nil
}

// middleware authenticates every route except liveness. Fail closed:
// without a configured authenticator the API serves nothing.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if s.Auth == nil || len(s.Auth.publicKeys) == 0 {
			writeProblem(w, newRequestID(), http.StatusInternalServerError,
				"authentication_unconfigured",
				"the API has no principal token keys; it serves nothing", false)
			return
		}
		if _, err := s.Auth.authenticate(r); err != nil {
			writeProblem(w, newRequestID(), http.StatusUnauthorized,
				"unauthenticated", err.Error(), false)
			return
		}
		// The verified token traveled this far; the broker and the other
		// components never need it. Strip it before any proxying.
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r)
	})
}
