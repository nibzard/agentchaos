package integration

// Cross-plane fault harness (T041). The tests compose the monolith the
// way spec 8.1 draws it: the API front end verifies principal tokens,
// the broker sits behind it as an isolated upstream, and the governor
// and evidence plane run in-process. Faults enter through the seams
// the production wiring leaves open: the synthetic sink's responder
// hooks for dispatch faults, the supervisor's deadline reviewer for
// reviewer outages, and the wire itself for everything else.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gauntlet/api"
	"gauntlet/broker"
	"gauntlet/control"
	"gauntlet/evidence"
	"gauntlet/governor"
	"gauntlet/supervisor"
)

const (
	integrationTenant = "tnt_9d4c1e2a3b4f5c67"
	integrationRun    = "run_0f1e2d3c4b5a6970"
	integrationNow    = "2026-09-12T12:00:00Z"

	actorService   = "act_platform-control-01"
	actorWorker    = "act_worker-reference-01"
	actorCollector = "act_collector-alpha-1"
	actorOperator  = "act_platform-operator-01"
)

// testEnv is one fully wired monolith: live broker upstream, governor,
// evidence plane, and the API front end that verifies tokens.
type testEnv struct {
	api        *httptest.Server
	broker     *httptest.Server
	brokerInst *broker.Broker
	sink       *broker.SyntheticSink
	gov        *governor.Governor
	recorder   *evidence.Recorder

	authOnce  sync.Once
	authKey   ed25519.PrivateKey
	forgeOnce sync.Once
	forgeKey  ed25519.PrivateKey
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	env := &testEnv{
		gov:      governor.New(nil),
		recorder: evidence.New(),
		sink:     &broker.SyntheticSink{},
	}

	policy, err := broker.LoadPolicy(broker.DefaultPolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	env.brokerInst = broker.New(policy, []*broker.RunContext{brokerRun()},
		[]broker.Sink{env.sink})
	env.broker = httptest.NewServer(
		(&broker.Server{Broker: env.brokerInst}).Handler())
	t.Cleanup(env.broker.Close)

	brokerURL, err := url.Parse(env.broker.URL)
	if err != nil {
		t.Fatal(err)
	}
	evidenceServer := &evidence.Server{Recorder: env.recorder}
	server := api.New(env.gov, evidenceServer, control.NewAssurer(),
		api.NewPythonCompiler(filepath.Join("..", "control-plane")),
		brokerURL, api.NewAuthenticator(env.privateKey().Public().(ed25519.PublicKey)))
	env.api = httptest.NewServer(server.Handler())
	t.Cleanup(env.api.Close)
	return env
}

// privateKey is the token-signing key for one environment.
func (e *testEnv) privateKey() ed25519.PrivateKey {
	e.authOnce.Do(func() {
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		e.authKey = key
	})
	return e.authKey
}

// forgedKey signs tokens the front end does not trust.
func (e *testEnv) forgedKey() ed25519.PrivateKey {
	e.forgeOnce.Do(func() {
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		e.forgeKey = key
	})
	return e.forgeKey
}

// token mints a principal token that expires in an hour.
func (e *testEnv) token(actor, role string) string {
	return api.MintPrincipalToken(e.privateKey(), actor, integrationTenant,
		role, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
}

// apiHeaders carries a verified token for the given role.
func (e *testEnv) apiHeaders(role, idemKey string) map[string]string {
	return map[string]string{
		"Authorization":   "Bearer " + e.token(actorForRole(role), role),
		"Idempotency-Key": idemKey,
	}
}

// brokerHeaders speaks the isolated broker's header protocol directly,
// the way the API proxy does after it verified a token.
func brokerHeaders(actor, role, idemKey string) map[string]string {
	return map[string]string{
		broker.HeaderActor:  actor,
		broker.HeaderTenant: integrationTenant,
		broker.HeaderRole:   role,
		broker.HeaderIdem:   idemKey,
	}
}

func actorForRole(role string) string {
	switch role {
	case evidence.RoleWorker:
		return actorWorker
	case evidence.RoleCollector:
		return actorCollector
	case evidence.RoleOperator:
		return actorOperator
	default:
		return actorService
	}
}

// brokerRun is the run the broker already knows about.
func brokerRun() *broker.RunContext {
	return &broker.RunContext{
		RunID:    integrationRun,
		TenantID: integrationTenant,
		TaskID:   "task_fixture-close-issue",
		GrantExpiresAt: time.Now().UTC().Add(24 * time.Hour).
			Format("2006-01-02T15:04:05Z"),
		AllowedClasses: []string{"A1", "A2"},
	}
}

// collectorPrincipal reads the recorder in-process.
func collectorPrincipal() *evidence.Principal {
	return &evidence.Principal{ID: actorCollector,
		TenantID: integrationTenant, Role: evidence.RoleCollector}
}

// doJSON performs one request and decodes the JSON reply.
func doJSON(t *testing.T, method, target string, body []byte,
	headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	reply, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	raw, _ := io.ReadAll(reply.Body)
	document := map[string]any{}
	if len(raw) > 0 && strings.Contains(strings.ToLower(
		reply.Header.Get("Content-Type")), "json") {
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("%s %s: reply is not JSON: %s", method, target, raw)
		}
	}
	return reply, document
}

func mustBody(t *testing.T, value map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// effectProposal builds a contract-valid proposal the policy allows:
// a class A2 queue publish to a synthetic sink.
func effectProposal(effectID string) map[string]any {
	return map[string]any{
		"kind":         "Effect",
		"api_version":  "v1",
		"id":           effectID,
		"tenant_id":    integrationTenant,
		"run_id":       integrationRun,
		"actor":        actorWorker,
		"action_class": "A2",
		"proposed_action": map[string]any{
			"operation":        "queue.publish",
			"resource":         "patch-export-beta",
			"destination":      "sink:patch-export-beta",
			"arguments_digest": "sha256:" + strings.Repeat("a", 64),
			"size_bytes":       128,
		},
		"state": "PROPOSED",
		"transitions": []map[string]any{
			{"state": "PROPOSED", "at": integrationNow},
		},
		"created_at": integrationNow,
	}
}

// authorize posts one proposal through the API front end.
func (e *testEnv) authorize(t *testing.T, effectID, idemKey string,
	headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	return doJSON(t, http.MethodPost,
		e.api.URL+"/v1/effects/authorizations",
		mustBody(t, effectProposal(effectID)), headers)
}

// authorizedEffect asserts the deterministic gate allowed a proposal
// and returns the reply.
func (e *testEnv) authorizedEffect(t *testing.T, effectID, idemKey string) map[string]any {
	t.Helper()
	reply, body := e.authorize(t, effectID, idemKey, e.apiHeaders("service", idemKey))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("authorize %s: status %d body %v", effectID, reply.StatusCode, body)
	}
	effect := body["effect"].(map[string]any)
	if effect["state"] != broker.StateAuthorized {
		t.Fatalf("authorize %s: state %v decision %v", effectID,
			effect["state"], body["decision"])
	}
	return body
}

// storedEffect reads one effect from the broker in-process.
func (e *testEnv) storedEffect(t *testing.T, effectID string) *broker.Effect {
	t.Helper()
	for _, effect := range e.brokerInst.Effects() {
		if effect.ID == effectID {
			return effect
		}
	}
	t.Fatalf("effect %s not found", effectID)
	return nil
}

// evidenceEvent builds one contract-valid EvidenceEvent body. The
// source id follows the component so per-source sequences stay apart.
func evidenceEvent(id string, seq int64, eventKind, trustLabel,
	component, content, observedAt string) map[string]any {
	source := map[string]any{
		"id":        "src_" + component + "-reference-1",
		"component": component,
	}
	if component == evidence.ComponentCollector {
		source["coverage"] = evidence.CoverageObserved
	}
	return map[string]any{
		"kind":                 "EvidenceEvent",
		"api_version":          "v1",
		"id":                   id,
		"tenant_id":            integrationTenant,
		"run_id":               integrationRun,
		"event_kind":           eventKind,
		"trust_label":          trustLabel,
		"source":               source,
		"sequence":             seq,
		"observed_at":          observedAt,
		"clock_uncertainty_ms": 100,
		"payload": map[string]any{
			"kind":      evidence.PayloadInline,
			"content":   content,
			"redacted":  false,
			"truncated": false,
		},
	}
}

// ingest posts a batch through the API front end as the collector.
func (e *testEnv) ingest(t *testing.T, idemKey string,
	events ...map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	return doJSON(t, http.MethodPost, e.api.URL+"/v1/evidence/events",
		mustBody(t, map[string]any{"events": events}),
		e.apiHeaders("collector", idemKey))
}

// recordedEvents reads the store back in-process for the supervisor.
func (e *testEnv) recordedEvents(t *testing.T) []evidence.Event {
	t.Helper()
	stored, err := e.recorder.Events(collectorPrincipal(), evidence.EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]evidence.Event, len(stored))
	for i := range stored {
		events[i] = *stored[i]
	}
	return events
}

// proposedAction mirrors the wire proposal for the supervisor layers.
func proposedAction() broker.ProposedAction {
	return broker.ProposedAction{
		Operation:       "queue.publish",
		Resource:        "patch-export-beta",
		Destination:     "sink:patch-export-beta",
		ArgumentsDigest: "sha256:" + strings.Repeat("a", 64),
		SizeBytes:       128,
	}
}

// deniedRetryTranscript is the dishonest record: the collector
// observed the broker deny a queue publish, then observed the worker
// propose the same operation again.
func deniedRetryTranscript() []map[string]any {
	return []map[string]any{
		evidenceEvent("evt_"+strings.Repeat("d", 16), 1,
			evidence.KindBrokerDecision, evidence.TrustCollectorFact,
			evidence.ComponentCollector,
			"deny:queue.publish destination_not_allowed", recentNow()),
		evidenceEvent("evt_"+strings.Repeat("e", 16), 2,
			evidence.KindProposedAction, evidence.TrustWorkerClaim,
			evidence.ComponentCollector,
			`{"operation":"queue.publish","attempt":2}`, recentNow()),
	}
}

// slowReviewer models a contextual reviewer that cannot answer in
// time: an outage on the review path (spec 10.2).
type slowReviewer struct {
	delay time.Duration
}

func (s *slowReviewer) Review(ctx context.Context,
	task supervisor.ReviewTask) (broker.Review, error) {
	select {
	case <-time.After(s.delay):
		return broker.Review{}, nil
	case <-ctx.Done():
		return broker.Review{}, ctx.Err()
	}
}

var _ supervisor.ContextualReviewer = (*slowReviewer)(nil)
