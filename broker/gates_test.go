package broker

// Deterministic supervision gates (spec 11.1 layer 1, T017): hard
// denies, review-required holds, version binding at dispatch, and the
// rule that no review ever widens what the gate allows.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// githubSink owns the policy's api.github.com destinations and
// verifies resource versions, so the repo.push rule exercises the
// conditional-write path.
type githubSink struct {
	SyntheticSink
	current    string
	verifyErr  error
	verifySeen int
}

func (g *githubSink) Name() string { return "github-sink" }

func (g *githubSink) Supports(destination string) bool {
	return strings.HasPrefix(destination, "https://api.github.com/")
}

func (g *githubSink) VerifyResourceVersion(effect *Effect) (string, error) {
	g.verifySeen++
	return g.current, g.verifyErr
}

func pushEffect(id, version string) *Effect {
	effect := testEffect()
	effect.ID = id
	effect.ProposedAction.Operation = "repo.push"
	effect.ProposedAction.Resource = "repos/acme/demo"
	effect.ProposedAction.Destination = "https://api.github.com/repos/acme/demo/git/refs/heads/fix-1"
	effect.ProposedAction.ResourceVersion = version
	effect.ProposedAction.SizeBytes = 512
	return effect
}

func paymentEffect(id string) *Effect {
	effect := testEffect()
	effect.ID = id
	effect.ProposedAction.Operation = "payment.send"
	effect.ProposedAction.Resource = "accounts/payments"
	effect.ProposedAction.Destination = "https://payments.example.com/v1/send"
	effect.ProposedAction.SizeBytes = 64
	return effect
}

func review(verdict string) *Review {
	return &Review{
		Verdict:     verdict,
		ReviewerID:  "act_sentinel-reference-01",
		PolicyRefs:  []string{"pol_1.1.0/operations.repo.push"},
		EventRefs:   []string{"evt_" + strings.Repeat("1", 16)},
		Rationale:   "the push matches the approved plan",
		Limitations: "reviewed the arguments digest only",
		LatencyMS:   120,
	}
}

func workerPrincipal() *Principal {
	return &Principal{
		ID: "act_worker-reference-01", TenantID: testRun().TenantID, Role: RoleWorker,
	}
}

func TestHardDenyDeniesBeforeAnyOtherCheck(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, decision, err := broker.Authorize(servicePrincipal(), paymentEffect("eff_"+"0a0b0c0d0e0f0102"))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "operation_hard_denied" {
		t.Fatalf("decision: %+v", decision)
	}
	if effect.State != StateDenied {
		t.Fatalf("state: %s", effect.State)
	}
	// A review cannot lift a hard deny (spec 11.2): the effect is
	// terminal, and the attach refuses.
	_, _, err = broker.AttachReview(servicePrincipal(), effect.ID, review(ReviewAllow))
	if !errors.Is(err, errReviewDenyFinal) {
		t.Fatalf("a review reached a hard-denied effect: %v", err)
	}
}

func TestReviewRequiredHoldsTheEffectWithoutAPermit(t *testing.T) {
	broker := testBroker(t, &githubSink{})

	// The rule pins resource versions: a proposal without one denies
	// deterministically, before any review is spent.
	_, decision, err := broker.Authorize(servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0102", ""))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Reason != "resource_version_required" {
		t.Fatalf("unpinned proposal decision: %+v", decision)
	}

	effect, decision, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0103", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "hold" || decision.Reason != "review_required" {
		t.Fatalf("decision: %+v", decision)
	}
	if effect.State != StateProposed {
		t.Fatalf("a held effect moved: %s", effect.State)
	}
	if effect.Authorization != nil {
		t.Fatal("a held effect carries a permit; a replayed hold could look pre-authorized")
	}
	if _, err := broker.Commit(servicePrincipal(), effect.ID, "idk_commit-hold-0001"); err == nil {
		t.Fatal("a held effect dispatched without a permit")
	}
}

func TestReviewAllowAuthorizesAndDispatches(t *testing.T) {
	sink := &githubSink{current: "commit-7f3a"}
	broker := testBroker(t, sink)
	held, _, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0104", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}

	effect, decision, err := broker.AttachReview(
		servicePrincipal(), held.ID, review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "allow" || effect.State != StateAuthorized {
		t.Fatalf("decision %+v state %s", decision, effect.State)
	}
	permit := effect.Authorization
	if permit == nil {
		t.Fatal("no permit after an ALLOW review")
	}
	if permit.PolicyVersion != broker.policy.Version {
		t.Fatalf("permit policy version: %s", permit.PolicyVersion)
	}
	if permit.ResourceVersion != "commit-7f3a" {
		t.Fatalf("permit resource binding: %q", permit.ResourceVersion)
	}
	if effect.Review == nil || effect.Review.Verdict != ReviewAllow {
		t.Fatal("the decision review is not on the record")
	}

	committed, err := broker.Commit(servicePrincipal(), effect.ID, "idk_commit-okay-0001")
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("state: %s", committed.State)
	}
	if sink.verifySeen != 1 {
		t.Fatalf("resource version checks: %d", sink.verifySeen)
	}
	if len(sink.Receipts) != 1 {
		t.Fatalf("receipts: %d", len(sink.Receipts))
	}
}

func TestReviewAllowDoesNotOverrideTheGate(t *testing.T) {
	broker := testBroker(t, &githubSink{})
	held, _, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0105", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	// The policy is replaced between the hold and the review: the
	// operation is no longer registered at all.
	broker.ReplacePolicy(replacementPolicy(t))

	effect, decision, err := broker.AttachReview(
		servicePrincipal(), held.ID, review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "unknown_operation" {
		t.Fatalf("an ALLOW review authorized past the gate: %+v", decision)
	}
	if effect.State != StateDenied {
		t.Fatalf("state: %s", effect.State)
	}
}

func TestReviewDenyIsFinalAndCannotBeOutvoted(t *testing.T) {
	broker := testBroker(t, &githubSink{})
	held, _, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0106", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	effect, decision, err := broker.AttachReview(
		servicePrincipal(), held.ID, review(ReviewDeny))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "deny" || decision.Reason != "review_denied" {
		t.Fatalf("decision: %+v", decision)
	}
	if effect.State != StateDenied {
		t.Fatalf("state: %s", effect.State)
	}
	_, _, err = broker.AttachReview(servicePrincipal(), held.ID, review(ReviewAllow))
	if !errors.Is(err, errReviewDenyFinal) {
		t.Fatalf("a second review outvoted a deny: %v", err)
	}
}

func TestWatchAndAbstainKeepTheHold(t *testing.T) {
	broker := testBroker(t, &githubSink{})
	held, _, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0107", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	for _, verdict := range []string{ReviewWatch, ReviewAbstain} {
		effect, decision, err := broker.AttachReview(
			servicePrincipal(), held.ID, review(verdict))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Verdict != "hold" {
			t.Fatalf("%s decided %+v", verdict, decision)
		}
		if effect.State != StateProposed {
			t.Fatalf("%s moved the effect to %s; ABSTAIN is not benign", verdict, effect.State)
		}
	}
	// Only ALLOW releases the hold.
	effect, decision, err := broker.AttachReview(
		servicePrincipal(), held.ID, review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "allow" || effect.State != StateAuthorized {
		t.Fatalf("final decision %+v state %s", decision, effect.State)
	}
}

func TestOnlySupervisorsAttachReviews(t *testing.T) {
	broker := testBroker(t, &githubSink{})
	held, _, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0108", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := broker.AttachReview(workerPrincipal(), held.ID, review(ReviewAllow)); err == nil {
		t.Fatal("a worker attached its own review")
	}
	collector := &Principal{
		ID: "src_collector-beta-01", TenantID: testRun().TenantID, Role: "collector",
	}
	if _, _, err := broker.AttachReview(collector, held.ID, review(ReviewAllow)); err == nil {
		t.Fatal("a collector attached a review")
	}
	// The refused attaches left the hold standing.
	stored, _, err := broker.AttachReview(servicePrincipal(), held.ID, review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != StateAuthorized {
		t.Fatalf("state after refusal then ALLOW: %s", stored.State)
	}
}

func TestMalformedReviewDecisionsAreRefused(t *testing.T) {
	broker := testBroker(t, &githubSink{})
	held, _, err := broker.Authorize(
		servicePrincipal(), pushEffect("eff_"+"0a0b0c0d0e0f0109", "commit-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*Review{
		"verdict":     {Verdict: "MAYBE", ReviewerID: "act_sentinel-reference-01", Rationale: "x", LatencyMS: 1},
		"reviewer":    {Verdict: ReviewAllow, ReviewerID: "worker-1", Rationale: "x", LatencyMS: 1},
		"rationale":   {Verdict: ReviewAllow, ReviewerID: "act_sentinel-reference-01", Rationale: "", LatencyMS: 1},
		"latency":     {Verdict: ReviewAllow, ReviewerID: "act_sentinel-reference-01", Rationale: "x", LatencyMS: -1},
		"policy_refs": {Verdict: ReviewAllow, ReviewerID: "act_sentinel-reference-01", Rationale: "x", LatencyMS: 1, EventRefs: []string{"evt_" + strings.Repeat("1", 16)}},
		"event_refs":  {Verdict: ReviewAllow, ReviewerID: "act_sentinel-reference-01", Rationale: "x", LatencyMS: 1, PolicyRefs: []string{"pol_1.1.0/operations.repo.push"}},
		"bad_ref":     {Verdict: ReviewAllow, ReviewerID: "act_sentinel-reference-01", Rationale: "x", LatencyMS: 1, PolicyRefs: []string{"the push policy"}, EventRefs: []string{"event-42"}},
	}
	for name, bad := range cases {
		_, _, err := broker.AttachReview(servicePrincipal(), held.ID, bad)
		var contract *ReviewContractError
		if !errors.As(err, &contract) {
			t.Fatalf("%s: expected a contract error, got %v", name, err)
		}
	}
	// The malformed attaches never touched the record.
	stored, _, err := broker.AttachReview(servicePrincipal(), held.ID, review(ReviewAllow))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Review == nil || stored.Review.ReviewerID != "act_sentinel-reference-01" {
		t.Fatalf("a malformed review stuck to the record: %+v", stored.Review)
	}
}

func TestReviewRefusedWhenTheRuleDoesNotRequireOne(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	effect, _, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = broker.AttachReview(servicePrincipal(), effect.ID, review(ReviewAllow))
	if !errors.Is(err, errReviewNotRequired) {
		t.Fatalf("a reviewer reached an unruled effect: %v", err)
	}
}

func TestPolicyChangeFencesOutstandingPermits(t *testing.T) {
	sink := &SyntheticSink{}
	broker := testBroker(t, sink)
	effect, decision, err := broker.Authorize(servicePrincipal(), testEffect())
	if err != nil || decision.Verdict != "allow" {
		t.Fatalf("authorize: %v %+v", err, decision)
	}
	// The deployment replaces the policy. The minted permit still
	// carries the old digest; at dispatch the stale binding fences it
	// instead of dispatching under rules nobody re-approved.
	broker.ReplacePolicy(replacementPolicy(t))
	_, err = broker.Commit(servicePrincipal(), effect.ID, "idk_commit-fence-01")
	if err == nil {
		t.Fatal("a stale permit dispatched")
	}
	var transition *TransitionError
	if !errors.As(err, &transition) || transition.From != StateExpired {
		t.Fatalf("fence error: %v", err)
	}
	if !strings.Contains(err.Error(), "policy changed") {
		t.Fatalf("fence reason: %v", err)
	}
	if len(sink.Receipts) != 0 {
		t.Fatalf("the stale permit still sent: %+v", sink.Receipts)
	}
	stored := broker.effects[effectKey(effect.TenantID, effect.ID)]
	if stored.State != StateExpired {
		t.Fatalf("state: %s", stored.State)
	}
}

func TestResourceVersionMismatchCancelsBeforeDispatch(t *testing.T) {
	// holdAndAllow drives one effect to AUTHORIZED on the given broker.
	holdAndAllow := func(t *testing.T, broker *Broker, id string) *Effect {
		t.Helper()
		_, decision, err := broker.Authorize(servicePrincipal(), pushEffect(id, "commit-7f3a"))
		if err != nil || decision.Verdict != "hold" {
			t.Fatalf("authorize: %v %+v", err, decision)
		}
		effect, decision, err := broker.AttachReview(servicePrincipal(), id, review(ReviewAllow))
		if err != nil || decision.Verdict != "allow" {
			t.Fatalf("review: %v %+v", err, decision)
		}
		return effect
	}

	t.Run("mismatch", func(t *testing.T) {
		sink := &githubSink{current: "commit-9999"} // swapped after approval
		broker := testBroker(t, sink)
		holdAndAllow(t, broker, "eff_"+"0a0b0c0d0e0f0110")
		committed, err := broker.Commit(servicePrincipal(), "eff_"+"0a0b0c0d0e0f0110", "idk_commit-swap-0001")
		if err == nil {
			t.Fatal("a swapped payload dispatched")
		}
		if !strings.Contains(err.Error(), "resource changed") {
			t.Fatalf("reason: %v", err)
		}
		if committed != nil {
			t.Fatalf("returned effect: %+v", committed)
		}
		if len(sink.Receipts) != 0 {
			t.Fatal("the send happened despite the mismatch")
		}
		stored := broker.effects[effectKey(testRun().TenantID, "eff_"+"0a0b0c0d0e0f0110")]
		if stored.State != StateCancelled {
			t.Fatalf("state: %s", stored.State)
		}
	})

	t.Run("check failure is not a pass", func(t *testing.T) {
		sink := &githubSink{current: "commit-7f3a", verifyErr: fmt.Errorf("api down")}
		broker := testBroker(t, sink)
		holdAndAllow(t, broker, "eff_"+"0a0b0c0d0e0f0111")
		_, err := broker.Commit(servicePrincipal(), "eff_"+"0a0b0c0d0e0f0111", "idk_commit-apierr-001")
		if err == nil || !strings.Contains(err.Error(), "check failed") {
			t.Fatalf("an unverifiable binding dispatched: %v", err)
		}
		if len(sink.Receipts) != 0 {
			t.Fatal("the send happened despite the unverifiable binding")
		}
	})

	t.Run("matching version dispatches", func(t *testing.T) {
		sink := &githubSink{current: "commit-7f3a"}
		broker := testBroker(t, sink)
		holdAndAllow(t, broker, "eff_"+"0a0b0c0d0e0f0112")
		committed, err := broker.Commit(servicePrincipal(), "eff_"+"0a0b0c0d0e0f0112", "idk_commit-match-0001")
		if err != nil {
			t.Fatal(err)
		}
		if committed.State != StateCommitted {
			t.Fatalf("state: %s", committed.State)
		}
	})
}

// replacementPolicy loads a v2 policy that keeps only queue.publish.
func replacementPolicy(t *testing.T) *Policy {
	t.Helper()
	document := map[string]any{
		"kind":        "BrokerPolicy",
		"api_version": "v1",
		"version":     "2.0.0",
		"operations": []map[string]any{
			{"name": "queue.publish", "action_class": "A2", "semantics": "mutate",
				"destinations": []string{"sink:"}, "max_size_bytes": 262144},
		},
	}
	policy, err := LoadPolicy(mustJSON(t, document))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestReviewEndpointRoundTripAndGuards(t *testing.T) {
	server, broker := testServerWithSink(t, &githubSink{current: "commit-7f3a"})
	headers := serviceHeaders("idk_authorize-push-01")
	proposal := validProposalJSON()
	proposal["id"] = "eff_" + "0a0b0c0d0e0f0113"
	action := proposal["proposed_action"].(map[string]any)
	action["operation"] = "repo.push"
	action["destination"] = "https://api.github.com/repos/acme/demo/git/refs/heads/fix-2"
	action["resource"] = "repos/acme/demo"
	action["resource_version"] = "commit-7f3a"

	reply, body := doJSON(t, "POST", server.URL+"/v1/effects/authorizations",
		mustJSON(t, proposal), headers)
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("authorize: %d %+v", reply.StatusCode, body)
	}
	effect := body["effect"].(map[string]any)
	if effect["state"] != StateProposed {
		t.Fatalf("held state: %v", effect["state"])
	}
	if body["decision"].(map[string]any)["verdict"] != "hold" {
		t.Fatalf("decision: %+v", body["decision"])
	}

	// A worker cannot attach the review that releases its own effect.
	workerHeaders := map[string]string{
		HeaderActor:  "act_worker-reference-01",
		HeaderTenant: testRun().TenantID,
		HeaderRole:   RoleWorker,
		HeaderIdem:   "idk_review-push-0001",
	}
	reply, problem := doJSON(t, "POST", server.URL+"/v1/effects/eff_"+"0a0b0c0d0e0f0113/review",
		mustJSON(t, map[string]any{
			"verdict": "ALLOW", "reviewer_id": "act_sentinel-reference-01",
			"policy_refs": []any{"pol_1.1.0/operations.repo.push"},
			"event_refs":  []string{"evt_1111111111111111"},
			"rationale":   "matches the plan", "latency_ms": 90,
		}), workerHeaders)
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("worker review: %d %+v", reply.StatusCode, problem)
	}

	reviewHeaders := serviceHeaders("idk_review-push-0002")
	reply, body = doJSON(t, "POST", server.URL+"/v1/effects/eff_"+"0a0b0c0d0e0f0113/review",
		mustJSON(t, map[string]any{
			"verdict": "ALLOW", "reviewer_id": "act_sentinel-reference-01",
			"policy_refs": []any{"pol_1.1.0/operations.repo.push"},
			"event_refs":  []string{"evt_1111111111111111"},
			"rationale":   "matches the plan", "latency_ms": 90,
		}), reviewHeaders)
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("review: %d %+v", reply.StatusCode, body)
	}
	if body["effect"].(map[string]any)["state"] != StateAuthorized {
		t.Fatalf("post-review state: %+v", body["effect"])
	}
	if body["decision"].(map[string]any)["verdict"] != "allow" {
		t.Fatalf("post-review decision: %+v", body["decision"])
	}

	// Replay returns the stored reply; a different body conflicts.
	reply, body = doJSON(t, "POST", server.URL+"/v1/effects/eff_"+"0a0b0c0d0e0f0113/review",
		mustJSON(t, map[string]any{
			"verdict": "ALLOW", "reviewer_id": "act_sentinel-reference-01",
			"policy_refs": []any{"pol_1.1.0/operations.repo.push"},
			"event_refs":  []string{"evt_1111111111111111"},
			"rationale":   "matches the plan", "latency_ms": 90,
		}), reviewHeaders)
	if reply.StatusCode != http.StatusOK ||
		body["decision"].(map[string]any)["verdict"] != "allow" {
		t.Fatalf("replay: %d %+v", reply.StatusCode, body)
	}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/effects/eff_"+"0a0b0c0d0e0f0113/review",
		mustJSON(t, map[string]any{
			"verdict": "DENY", "reviewer_id": "act_sentinel-reference-01",
			"rationale": "changed my mind", "latency_ms": 90,
		}), reviewHeaders)
	if reply.StatusCode != http.StatusConflict || problem["code"] != "idempotency_conflict" {
		t.Fatalf("conflict: %d %+v", reply.StatusCode, problem)
	}

	// Unknown fields and malformed verdicts fail closed with distinct
	// problem codes.
	reply, problem = doJSON(t, "POST", server.URL+"/v1/effects/eff_"+"0a0b0c0d0e0f0113/review",
		mustJSON(t, map[string]any{
			"verdict": "ALLOW", "reviewer_id": "act_sentinel-reference-01",
			"rationale": "x", "latency_ms": 1, "self_approved": true,
		}), serviceHeaders("idk_review-push-0003"))
	if reply.StatusCode != http.StatusBadRequest || problem["code"] != "review_schema" {
		t.Fatalf("unknown field: %d %+v", reply.StatusCode, problem)
	}
	reply, problem = doJSON(t, "POST", server.URL+"/v1/effects/eff_"+"0a0b0c0d0e0f0113/review",
		mustJSON(t, map[string]any{
			"verdict": "FINE", "reviewer_id": "act_sentinel-reference-01",
			"rationale": "x", "latency_ms": 1,
		}), serviceHeaders("idk_review-push-0004"))
	if reply.StatusCode != http.StatusUnprocessableEntity || problem["code"] != "review_schema" {
		t.Fatalf("bad verdict: %d %+v", reply.StatusCode, problem)
	}
	_ = broker
}

// testServerWithSink mirrors testServer with a custom sink.
func testServerWithSink(t *testing.T, sink Sink) (*httptest.Server, *Broker) {
	t.Helper()
	broker := testBroker(t, sink)
	server := httptest.NewServer((&Server{Broker: broker}).Handler())
	t.Cleanup(server.Close)
	return server, broker
}
