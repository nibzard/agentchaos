package integration

// Cross-plane fault tests (T041): reviewer outages, evidence capture
// failures, unknown dispatch outcomes, clock disagreement, delivery
// faults, dishonest transcripts, and bypass attempts. Each test drives
// the fault through one plane and asserts the answer the other planes
// give — the guarantees are only real if they survive composition.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"gauntlet/api"
	"gauntlet/broker"
	"gauntlet/evidence"
	"gauntlet/governor"
	"gauntlet/supervisor"
)

// TestReviewerOutageHoldsEffectsWhileLocalWorkContinues covers spec
// 10.2 and AC-021: a contextual reviewer that cannot answer holds the
// effects that need review, fences nothing new by itself, and never
// stops local work — the broker still evaluates proposals.
func TestReviewerOutageHoldsEffectsWhileLocalWorkContinues(t *testing.T) {
	env := newEnv(t)
	if _, body := env.ingest(t, "idk_transcript-outage-1",
		deniedRetryTranscript()...); body["accepted"] != float64(2) {
		t.Fatalf("transcript did not store: %v", body)
	}

	// Local work continues: the deterministic gate still authorizes.
	env.authorizedEffect(t, "eff_"+strings.Repeat("1", 16), "idk_outage-local-01")

	// The review path is down: the reviewer exceeds its deadline.
	policy := supervisor.DefaultReviewPolicy()
	policy.Deadline = 5 * time.Millisecond
	tracker := supervisor.NewDegradationTracker()
	tracker.MarkDegraded(supervisor.DependencyReviewer,
		"contextual reviewer exceeding deadline")
	deadline := supervisor.NewDeadlineReviewer(&slowReviewer{delay: 50 * time.Millisecond},
		policy)
	sup := supervisor.New(deadline)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	review, detection, err := sup.Consider(ctx, proposedAction(),
		"task_fixture-close-issue", env.recordedEvents(t))
	if err == nil || !errors.Is(err, supervisor.ErrReviewHeld) {
		t.Fatalf("a dead reviewer silently decided: review %+v err %v", review, err)
	}
	if !detection.RouteReview {
		t.Fatal("the denied retry did not route review")
	}

	// Spec 10.2 rules: local work stays allowed, review effects are
	// held, and the outage alone fences no new external effects.
	if !tracker.LocalWorkAllowed() {
		t.Fatal("a reviewer outage stopped local work")
	}
	if !tracker.HoldEffectsRequiringReview() {
		t.Fatal("a reviewer outage did not hold review effects")
	}
	if tracker.FenceNewExternalEffects() {
		t.Fatal("a reviewer outage alone fenced new effects")
	}

	// Recovery: the same transcript gets a decision once the reviewer
	// answers in time. The retry is denied on the record.
	recovered, err := sup2decide(ctx, t, env)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Verdict != broker.ReviewDeny {
		t.Fatalf("recovered verdict: %+v", recovered)
	}
	tracker.MarkHealthy(supervisor.DependencyReviewer, "reviewer answered in time")
	if tracker.State(supervisor.DependencyReviewer) != supervisor.Healthy {
		t.Fatal("recovery did not clear the degradation")
	}
}

// recentNow stamps an event close enough to the recorder clock that
// only the fault under test produces a finding.
func recentNow() string {
	return time.Now().UTC().Add(-time.Minute).
		Format("2006-01-02T15:04:05Z")
}

// sup2decide runs the reference reviewer over the recorded events.
func sup2decide(ctx context.Context, t *testing.T,
	env *testEnv) (broker.Review, error) {
	t.Helper()
	sup := supervisor.New(supervisor.NewReferenceReviewer())
	review, _, err := sup.Consider(ctx, proposedAction(),
		"task_fixture-close-issue", env.recordedEvents(t))
	return review, err
}

// TestEvidenceCaptureFailureFencesNewEffects covers spec 10.2 and F18:
// when evidence capture fails, the broker fences new external effects.
// The fence is engaged on the isolated broker and every answer the API
// front end serves reflects it: new proposals deny with
// evidence_capture_fenced, authorized effects refuse to commit, and
// release restores the path without losing state.
func TestEvidenceCaptureFailureFencesNewEffects(t *testing.T) {
	env := newEnv(t)
	env.authorizedEffect(t, "eff_"+strings.Repeat("2", 16), "idk_fence-author-1")

	// The operator engages the fence on the isolated broker.
	reply, body := doJSON(t, http.MethodPost,
		env.broker.URL+"/v1/evidence-fence/engage",
		mustBody(t, map[string]any{"reason": "evidence capture outage"}),
		brokerHeaders(actorOperator, "operator", "idk_fence-engage-01"))
	if reply.StatusCode != http.StatusOK || body["engaged"] != true {
		t.Fatalf("engage: %d %v", reply.StatusCode, body)
	}

	// A new proposal through the API denies with the fence reason.
	reply, body = env.authorize(t, "eff_"+strings.Repeat("3", 16),
		"idk_fence-denied-01", env.apiHeaders("service", "idk_fence-denied-01"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("fenced authorize status: %d %v", reply.StatusCode, body)
	}
	decision := body["decision"].(map[string]any)
	if decision["verdict"] != "deny" || decision["reason"] != "evidence_capture_fenced" {
		t.Fatalf("fenced decision: %v", decision)
	}
	if body["effect"].(map[string]any)["state"] != broker.StateDenied {
		t.Fatalf("fenced effect state: %v", body["effect"])
	}

	// The effect authorized before the fence keeps its state and
	// refuses to commit — the permit is not lost, the send waits.
	reply, body = doJSON(t, http.MethodPost,
		env.api.URL+"/v1/effects/eff_"+strings.Repeat("2", 16)+"/commit",
		nil, env.apiHeaders("service", "idk_fence-commit-01"))
	if reply.StatusCode != http.StatusConflict || body["code"] != "evidence_fenced" {
		t.Fatalf("fenced commit: %d %v", reply.StatusCode, body)
	}
	if effect := env.storedEffect(t, "eff_"+strings.Repeat("2", 16)); effect == nil ||
		effect.State != broker.StateAuthorized {
		t.Fatalf("the fence destroyed an authorized permit: %+v", effect)
	}

	// Release: the held effect commits, state preserved throughout.
	reply, body = doJSON(t, http.MethodPost,
		env.broker.URL+"/v1/evidence-fence/release",
		mustBody(t, map[string]any{"reason": "capture restored"}),
		brokerHeaders(actorOperator, "operator", "idk_fence-release1"))
	if reply.StatusCode != http.StatusOK || body["engaged"] != false {
		t.Fatalf("release: %d %v", reply.StatusCode, body)
	}
	reply, body = doJSON(t, http.MethodPost,
		env.api.URL+"/v1/effects/eff_"+strings.Repeat("2", 16)+"/commit",
		nil, env.apiHeaders("service", "idk_fence-commit-02"))
	if reply.StatusCode != http.StatusOK ||
		body["state"] != broker.StateCommitted {
		t.Fatalf("commit after release: %d %v", reply.StatusCode, body)
	}
}

// TestUnknownDispatchOutcomeResolvesFromSinkState covers spec 10.1 and
// AC-010: a sink that times out leaves the effect UNKNOWN_EFFECT, and
// resolution reads the sink's own state — never a blind reissue.
func TestUnknownDispatchOutcomeResolvesFromSinkState(t *testing.T) {
	env := newEnv(t)
	effectID := "eff_" + strings.Repeat("4", 16)
	env.authorizedEffect(t, effectID, "idk_unknown-author1")

	dispatches := 0
	env.sink.Responder = func(effect *broker.Effect) broker.SinkResult {
		dispatches++
		return broker.SinkResult{Outcome: broker.OutcomeTimeout,
			Detail: "synthetic sink black hole"}
	}
	reconciles := 0
	env.sink.Reconciler = func(effect *broker.Effect) broker.ReconcileResult {
		reconciles++
		return broker.ReconcileResult{Outcome: broker.ReconciledCommitted,
			ReceiptDigest: "sha256:" + strings.Repeat("c", 64),
			Detail:        "state read found the send"}
	}

	reply, body := doJSON(t, http.MethodPost,
		env.api.URL+"/v1/effects/"+effectID+"/commit", nil,
		env.apiHeaders("service", "idk_unknown-commit1"))
	if reply.StatusCode != http.StatusOK || body["state"] != broker.StateUnknown {
		t.Fatalf("timed-out commit: %d %v", reply.StatusCode, body)
	}
	effect := env.storedEffect(t, effectID)
	if effect.Receipt != nil && effect.Receipt.Reconciled {
		t.Fatal("a timeout was recorded as reconciled")
	}

	// The retry is a reconciliation, not a second dispatch.
	reply, body = doJSON(t, http.MethodPost,
		env.api.URL+"/v1/effects/"+effectID+"/commit", nil,
		env.apiHeaders("service", "idk_unknown-commit2"))
	if reply.StatusCode != http.StatusOK || body["state"] != broker.StateCommitted {
		t.Fatalf("reconciled commit: %d %v", reply.StatusCode, body)
	}
	if dispatches != 1 {
		t.Fatalf("dispatch attempts: %d; an unknown outcome must not reissue", dispatches)
	}
	if reconciles != 1 {
		t.Fatalf("state reads: %d", reconciles)
	}
	if effect := env.storedEffect(t, effectID); effect.Receipt == nil ||
		!effect.Receipt.Reconciled {
		t.Fatalf("receipt after reconcile: %+v", effect.Receipt)
	}
}

// TestClockDisagreementBecomesAFinding covers spec 9.4: a source whose
// clock disagrees with the recorder is a finding, not a rejection —
// the record says the disagreement happened.
func TestClockDisagreementBecomesAFinding(t *testing.T) {
	env := newEnv(t)
	skewed := time.Now().UTC().Add(-3 * time.Hour).
		Format("2006-01-02T15:04:05Z")
	reply, body := env.ingest(t, "idk_skew-ingest-0001",
		evidenceEvent("evt_"+strings.Repeat("f", 16), 0,
			evidence.KindToolRequest, evidence.TrustCollectorFact,
			evidence.ComponentCollector, `{"tool":"bash"}`, skewed))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("skewed ingest status: %d %v", reply.StatusCode, body)
	}
	findings, _ := body["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("skew findings: %v", body["findings"])
	}

	// The finding is readable through the front end.
	reply, body = doJSON(t, http.MethodGet,
		env.api.URL+"/v1/evidence/findings", nil,
		env.apiHeaders("collector", "idk-unused-read-001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("findings read: %d", reply.StatusCode)
	}
	if listed, _ := body["findings"].([]any); len(listed) != 1 {
		t.Fatalf("findings listing: %v", body["findings"])
	}

	// The chain itself is intact: skew is a finding, not tampering.
	reply, body = doJSON(t, http.MethodGet,
		env.api.URL+"/v1/evidence/verify", nil,
		env.apiHeaders("collector", "idk-unused-read-002"))
	if reply.StatusCode != http.StatusOK || body["intact"] != true {
		t.Fatalf("verify under skew: %d %v", reply.StatusCode, body)
	}
}

// TestDeliveryFaultsDeduplicateAndRecordGaps covers spec 18.3: at
// least once delivery replays deduplicate by event id, a skipped
// sequence is a gap finding, and a late arrival is stored as delivered
// with its own finding — the chain proves content, not order.
func TestDeliveryFaultsDeduplicateAndRecordGaps(t *testing.T) {
	env := newEnv(t)
	source := func(seq int64, id string) map[string]any {
		return evidenceEvent(id, seq, evidence.KindToolRequest,
			evidence.TrustCollectorFact, evidence.ComponentCollector,
			`{"n":0}`, recentNow())
	}

	if _, body := env.ingest(t, "idk_delivery-first-001", source(0,
		"evt_"+strings.Repeat("a", 16))); body["accepted"] != float64(1) {
		t.Fatalf("first delivery: %v", body)
	}
	// The network replays the same event.
	reply, body := env.ingest(t, "idk_delivery-replay-1", source(0,
		"evt_"+strings.Repeat("a", 16)))
	if reply.StatusCode != http.StatusOK ||
		body["duplicates"] != float64(1) || body["accepted"] != float64(0) {
		t.Fatalf("replay: %d %v", reply.StatusCode, body)
	}
	// The next delivery skips sequence 1: a gap finding.
	reply, body = env.ingest(t, "idk_delivery-gap-0001", source(2,
		"evt_"+strings.Repeat("b", 16)))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("gap delivery: %d %v", reply.StatusCode, body)
	}
	findings, _ := body["findings"].([]any)
	if len(findings) != 1 || !strings.Contains(
		findings[0].(map[string]any)["title"].(string), "skipped sequences 1 to 1") {
		t.Fatalf("gap finding: %v", findings)
	}
	// Sequence 1 arrives late: stored, out of order, and reported.
	reply, body = env.ingest(t, "idk_delivery-late-0001", source(1,
		"evt_"+strings.Repeat("c", 16)))
	if reply.StatusCode != http.StatusOK || body["accepted"] != float64(1) {
		t.Fatalf("late delivery: %d %v", reply.StatusCode, body)
	}
	findings, _ = body["findings"].([]any)
	if len(findings) != 1 || !strings.Contains(
		findings[0].(map[string]any)["title"].(string), "out of order") {
		t.Fatalf("reorder finding: %v", findings)
	}
	reply, body = doJSON(t, http.MethodGet,
		env.api.URL+"/v1/evidence/verify", nil,
		env.apiHeaders("collector", "idk-unused-read-003"))
	if reply.StatusCode != http.StatusOK || body["intact"] != true {
		t.Fatalf("verify after delivery faults: %d %v", reply.StatusCode, body)
	}
}

// TestDishonestTranscriptRoutesContextualReview covers the layer-2/3
// split (spec 11): the deterministic gate allows the retry — the
// destination is policy-clean — but the evidence record routes it to
// the contextual reviewer, which denies on the denied_retry rule.
func TestDishonestTranscriptRoutesContextualReview(t *testing.T) {
	env := newEnv(t)
	if _, body := env.ingest(t, "idk_transcript-deny-01",
		deniedRetryTranscript()...); body["accepted"] != float64(2) {
		t.Fatalf("transcript did not store: %v", body)
	}

	// Layer 1 alone: the same operation authorizes cleanly.
	env.authorizedEffect(t, "eff_"+strings.Repeat("5", 16), "idk_dishonest-authr1")

	// Layer 2: the detector reads the record and routes review.
	detection := supervisor.NewFastDetector(
		supervisor.DefaultDetectorConfig()).Detect(env.recordedEvents(t))
	if !detection.RouteReview {
		t.Fatal("a denied retry on the record routed nothing")
	}
	routed := false
	for _, suspicion := range detection.Suspicions {
		if suspicion.Rule == "denied_retry" && suspicion.Severity == supervisor.SeverityHigh {
			routed = true
		}
	}
	if !routed {
		t.Fatalf("suspicions: %+v", detection.Suspicions)
	}

	// Layer 3: the contextual reviewer denies the retry.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	review, err := sup2decide(ctx, t, env)
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != broker.ReviewDeny {
		t.Fatalf("verdict on a dishonest transcript: %+v", review)
	}
	if problems := review.ValidateReview(); len(problems) > 0 {
		t.Fatalf("the verdict breaks the review contract: %v", problems)
	}
}

// TestBypassAttemptsFailAtEveryPlane covers AC-003-style authority:
// forged tokens never authenticate, caller-set identity headers never
// override the verified token, and workers and collectors cannot reach
// operator surfaces.
func TestBypassAttemptsFailAtEveryPlane(t *testing.T) {
	env := newEnv(t)

	// A token signed by a key the front end does not trust.
	forged := api.MintPrincipalToken(env.forgedKey(), actorOperator,
		integrationTenant, "operator",
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	reply, body := doJSON(t, http.MethodGet,
		env.api.URL+"/v1/evidence/events", nil, map[string]string{
			"Authorization":   "Bearer " + forged,
			"Idempotency-Key": "idk_bypass-forged-1",
		})
	if reply.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged token: %d %v", reply.StatusCode, body)
	}

	// Identity headers a caller sets never survive the front end: the
	// role is rewritten from the verified worker token.
	worker := env.apiHeaders("worker", "idk_bypass-worker-1")
	worker[broker.HeaderRole] = "operator"
	reply, body = doJSON(t, http.MethodGet,
		env.api.URL+"/v1/evidence/events", nil, worker)
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("a worker with forged role headers read the store: %d %v",
			reply.StatusCode, body)
	}

	// Workers and collectors cannot engage the evidence fence.
	for _, role := range []string{"worker", "collector"} {
		headers := brokerHeaders(actorForRole(role), role, "idk_bypass-"+role+"-1")
		reply, body = doJSON(t, http.MethodPost,
			env.broker.URL+"/v1/evidence-fence/engage",
			mustBody(t, map[string]any{"reason": "bypass attempt"}), headers)
		if reply.StatusCode != http.StatusForbidden {
			t.Fatalf("%s engaged the evidence fence: %d %v",
				role, reply.StatusCode, body)
		}
	}

	// A worker cannot stop a run through the front end.
	reply, body = doJSON(t, http.MethodPost,
		env.api.URL+"/v1/runs/"+integrationRun+"/stop",
		mustBody(t, map[string]any{"sandbox": "terminate"}),
		env.apiHeaders("worker", "idk_bypass-stop-0001"))
	if reply.StatusCode != http.StatusForbidden {
		t.Fatalf("a worker stopped a run: %d %v", reply.StatusCode, body)
	}
}

// TestStopRunDeniesNewProposals covers the stop protocol end to end:
// the governor trips the run, the broker executes the stop order, and
// the next proposal for that run denies with run_stopped.
func TestStopRunDeniesNewProposals(t *testing.T) {
	env := newEnv(t)
	service := &governor.Principal{ID: actorService,
		TenantID: integrationTenant, Role: "service"}
	if _, err := env.gov.RegisterEnvelope(service, &governor.Envelope{
		ExperimentID: "exp_" + strings.Repeat("6", 16),
		Budgets: governor.Budgets{
			MaxDurationS: 3600, MaxConcurrentSessions: 2,
			AggregateCostMax: governor.Money{Currency: "USD"},
		},
		AllowedPrimitives: []string{"queue.publish"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.gov.StartRun(service, integrationRun,
		"exp_"+strings.Repeat("6", 16)); err != nil {
		t.Fatal(err)
	}

	reply, body := doJSON(t, http.MethodPost,
		env.api.URL+"/v1/runs/"+integrationRun+"/stop",
		mustBody(t, map[string]any{"sandbox": "terminate",
			"reason": "integration stop"}),
		env.apiHeaders("service", "idk_stop-run-0000001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("stop: %d %v", reply.StatusCode, body)
	}

	reply, body = env.authorize(t, "eff_"+strings.Repeat("7", 16),
		"idk_stop-denied-0001", env.apiHeaders("service", "idk_stop-denied-0001"))
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("post-stop authorize status: %d %v", reply.StatusCode, body)
	}
	decision := body["decision"].(map[string]any)
	if decision["verdict"] != "deny" || decision["reason"] != "run_stopped" {
		t.Fatalf("post-stop decision: %v", decision)
	}
	if body["effect"].(map[string]any)["state"] != broker.StateDenied {
		t.Fatalf("post-stop effect state: %v", body["effect"])
	}
}
