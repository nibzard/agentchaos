package broker

// Spec 10.2 outage behavior (T020): when mandatory evidence capture
// fails, the broker fences new external effects rather than executing
// them silently. The fence outranks proposals, review releases, and
// stop compensations; authority to toggle it belongs to service and
// operator principals only.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvidenceFenceDeniesNewProposals(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	if err := broker.EngageEvidenceFence(servicePrincipal(), "recorder unreachable"); err != nil {
		t.Fatal(err)
	}
	effect, decision, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "evidence_capture_fenced" {
		t.Fatalf("decision: %+v", decision)
	}
	if effect.State != StateDenied {
		t.Fatalf("state: %s", effect.State)
	}
}

func TestEvidenceFenceRefusesCommitsAndKeepsThePermit(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	authorized, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	if authorized.State != StateAuthorized {
		t.Fatalf("setup state: %s", authorized.State)
	}

	if err := broker.EngageEvidenceFence(servicePrincipal(), "recorder unreachable"); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Commit(servicePrincipal(), authorized.ID, "idk_fence-commit-0001"); !errors.Is(err, ErrEvidenceFenced) {
		t.Fatalf("a permitted effect dispatched under the fence: %v", err)
	}
	var stored *Effect
	for _, effect := range broker.Effects() {
		if effect.ID == authorized.ID {
			stored = effect
		}
	}
	if stored == nil || stored.State != StateAuthorized {
		t.Fatalf("the fence mutated the permit's state: %+v", stored)
	}

	// Release restores dispatch under the same permit.
	if err := broker.ReleaseEvidenceFence(servicePrincipal(), "capture restored"); err != nil {
		t.Fatal(err)
	}
	committed, err := broker.Commit(servicePrincipal(), authorized.ID, "idk_fence-commit-0002")
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("post-release state: %s", committed.State)
	}
}

func TestEvidenceFenceDeniesReviewReleases(t *testing.T) {
	broker := testBroker(t, &githubSink{})
	held, _, err := broker.Authorize(servicePrincipal(),
		pushEffect("eff_"+"0a0b0c0d0e0f0114", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.EngageEvidenceFence(servicePrincipal(), "recorder unreachable"); err != nil {
		t.Fatal(err)
	}
	effect, decision, err := broker.AttachReview(servicePrincipal(), held.ID, review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Reason != "evidence_capture_fenced" || effect.State != StateDenied {
		t.Fatalf("an ALLOW review released an effect under the fence: %+v %s",
			decision, effect.State)
	}
}

func TestEvidenceFenceStateTransitionsAreExplicit(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	if err := broker.EngageEvidenceFence(servicePrincipal(), "outage"); err != nil {
		t.Fatal(err)
	}
	if err := broker.EngageEvidenceFence(servicePrincipal(), "again"); !errors.Is(err, errFenceState) {
		t.Fatalf("double engage: %v", err)
	}
	if err := broker.ReleaseEvidenceFence(servicePrincipal(), "restored"); err != nil {
		t.Fatal(err)
	}
	if err := broker.ReleaseEvidenceFence(servicePrincipal(), "again"); !errors.Is(err, errFenceState) {
		t.Fatalf("double release: %v", err)
	}
	state := broker.EvidenceFence()
	if state.Engaged || state.ReleasedAt == "" {
		t.Fatalf("fence state: %+v", state)
	}

	// Both transitions are journaled as recovery actions.
	kinds := map[string]int{}
	for _, event := range broker.Events() {
		if event.EventKind == "recovery_action" {
			kinds[event.Payload.Content]++
		}
	}
	if len(kinds) != 2 {
		t.Fatalf("fence journal entries: %v", kinds)
	}
}

func TestOnlyAuthorityMayToggleTheFence(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	if err := broker.EngageEvidenceFence(workerPrincipal(), "worker call"); err == nil {
		t.Fatal("a worker engaged the evidence fence")
	}
	collector := &Principal{
		ID: "act_collector-refere01", TenantID: testRun().TenantID, Role: "collector",
	}
	if err := broker.EngageEvidenceFence(collector, "collector call"); err == nil {
		t.Fatal("a collector engaged the evidence fence")
	}
	if broker.EvidenceFence().Engaged {
		t.Fatal("a refused call changed the fence")
	}
}

func TestEvidenceFenceHTTPSurface(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	server := httptest.NewServer((&Server{Broker: broker}).Handler())
	defer server.Close()

	// A worker cannot engage the fence.
	reply, problem := doJSON(t, "POST", server.URL+"/v1/evidence-fence/engage",
		mustJSON(t, map[string]any{"reason": "recorder unreachable"}), map[string]string{
			HeaderActor: "act_worker-reference-01", HeaderTenant: testRun().TenantID,
			HeaderRole: RoleWorker, HeaderIdem: "idk_fence-http-0001",
		})
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("worker engage: %d %+v", reply.StatusCode, problem)
	}

	// A malformed body is a schema problem, not a toggle.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/evidence-fence/engage",
		mustJSON(t, map[string]any{"reason": "x", "force": true}), serviceHeaders("idk_fence-http-0002"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "fence_schema" {
		t.Fatalf("malformed engage: %d %+v", reply.StatusCode, problem)
	}

	// A permit earned while the fence is open...
	authorized, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}

	engage := func(key string) {
		t.Helper()
		reply, body := doJSON(t, "POST", server.URL+"/v1/evidence-fence/engage",
			mustJSON(t, map[string]any{"reason": "recorder unreachable"}), serviceHeaders(key))
		if reply.StatusCode != http.StatusOK || body["engaged"] != true {
			t.Fatalf("engage: %d %+v", reply.StatusCode, body)
		}
	}
	engage("idk_fence-http-0003")

	// Idempotent replay returns the stored reply.
	reply, body := doJSON(t, "POST", server.URL+"/v1/evidence-fence/engage",
		mustJSON(t, map[string]any{"reason": "recorder unreachable"}), serviceHeaders("idk_fence-http-0003"))
	if reply.StatusCode != http.StatusOK || body["engaged"] != true {
		t.Fatalf("replay: %d %+v", reply.StatusCode, body)
	}

	// A commit under the fence is a 409 with a stable code.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/effects/"+authorized.ID+"/commit",
		nil, serviceHeaders("idk_fence-commit-0003"))
	if reply.StatusCode != http.StatusConflict || problem["code"] != "evidence_fenced" {
		t.Fatalf("fenced commit: %d %+v", reply.StatusCode, problem)
	}

	reply, body = doJSON(t, "POST", server.URL+"/v1/evidence-fence/release",
		mustJSON(t, map[string]any{"reason": "capture restored"}), serviceHeaders("idk_fence-http-0004"))
	if reply.StatusCode != http.StatusOK || body["engaged"] != false {
		t.Fatalf("release: %d %+v", reply.StatusCode, body)
	}
}
