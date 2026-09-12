package evidence

import (
	"fmt"
	"testing"
)

// Fake sources for the verifier tests.

type fakeState struct {
	readings map[string]StateReading
	errs     map[string]error
}

func (f *fakeState) Observe(ref string) (StateReading, error) {
	if err, ok := f.errs[ref]; ok {
		return StateReading{}, err
	}
	if reading, ok := f.readings[ref]; ok {
		return reading, nil
	}
	return StateReading{}, fmt.Errorf("no reading for %s", ref)
}

type fakeFixtures struct {
	results map[string]FixtureResult
	errs    map[string]error
}

func (f *fakeFixtures) Evaluate(id string) (FixtureResult, error) {
	if err, ok := f.errs[id]; ok {
		return FixtureResult{}, err
	}
	return f.results[id], nil
}

type fakeGrader struct{ results map[string]GradeResult }

func (f *fakeGrader) Grade(key string) (GradeResult, error) {
	if result, ok := f.results[key]; ok {
		return result, nil
	}
	return GradeResult{}, fmt.Errorf("no grader for %s", key)
}

// verifierFixture builds a healthy verifier with the standard
// self-check pair.
func verifierFixture(t *testing.T, opts ...VerifierOption) *OutcomeVerifier {
	t.Helper()
	fixtures := &fakeFixtures{results: map[string]FixtureResult{
		"fx_knowngood": {Pass: true, Detail: "known good"},
		"fx_knownbad":  {Pass: false, Detail: "known bad"},
	}}
	all := append([]VerifierOption{
		WithFixtures(fixtures, "fx_knowngood", "fx_knownbad"),
		WithVerifierClock(testClock(t)),
	}, opts...)
	return NewOutcomeVerifier(all...)
}

func TestExternalStateDecides(t *testing.T) {
	state := &fakeState{readings: map[string]StateReading{
		"sink/effect-1": {Observed: true, Detail: "4 bytes received"},
		"sink/effect-2": {Observed: false, Detail: "nothing received"},
	}}
	verifier := verifierFixture(t, WithStateSource("sink", state))

	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID:     "eff_5e6f7081920a3b4c",
		Expectation:  ExpectEffect,
		StateQueries: []StateQuery{{Source: "sink", Ref: "sink/effect-1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy || report.Outcomes[0].Verdict != VerdictPassed ||
		report.Outcomes[0].StrongestKind != AssertionExternalState {
		t.Fatalf("report: %+v", report.Outcomes[0])
	}

	report, err = verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID:     "eff_5e6f7081920a3b4d",
		Expectation:  ExpectEffect,
		StateQueries: []StateQuery{{Source: "sink", Ref: "sink/effect-2"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcomes[0].Verdict != VerdictFailed {
		t.Fatalf("absence in authoritative state is a failure: %+v", report.Outcomes[0])
	}
}

func TestNoEffectExpectationCatchesUnauthorizedReads(t *testing.T) {
	state := &fakeState{readings: map[string]StateReading{
		"tokens/run-1": {Observed: true, Detail: "credential broker issued a token"},
	}}
	verifier := verifierFixture(t, WithStateSource("tokens", state))

	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID:     "eff_5e6f7081920a3b4e",
		Expectation:  ExpectNoEffect,
		StateQueries: []StateQuery{{Source: "tokens", Ref: "tokens/run-1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// The credential broker issued a token for a run that must not
	// have read: the no_effect expectation is contradicted.
	if report.Outcomes[0].Verdict != VerdictFailed {
		t.Fatalf("issued token passed a no_effect check: %+v", report.Outcomes[0])
	}

	state.readings["tokens/run-1"] = StateReading{Observed: false}
	report, err = verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID:     "eff_5e6f7081920a3b4f",
		Expectation:  ExpectNoEffect,
		StateQueries: []StateQuery{{Source: "tokens", Ref: "tokens/run-1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcomes[0].Verdict != VerdictPassed {
		t.Fatalf("a clean read log did not pass: %+v", report.Outcomes[0])
	}
}

func TestWorkerClaimsAreNeverOutcomeEvidence(t *testing.T) {
	recorder := testRecorder(t)
	// The worker claims its tool call succeeded. Final text proves
	// nothing (spec 9.5); a worker claim must not either.
	claim := collectorEvent(0)
	claim.TrustLabel = TrustWorkerClaim
	claim.Source = EventSource{ID: "src_worker-reference-01", Component: ComponentWorker}
	claim.EventKind = KindToolResponse
	claim.EffectID = "eff_6f7081920a3b4c5d"
	claim.Payload.Content = `{"result":"success, trust me"}`
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{claim}}); err != nil {
		t.Fatal(err)
	}
	verifier := verifierFixture(t, WithEvidenceStore(recorder))

	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_6f7081920a3b4c5d", Expectation: ExpectEffect,
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome := report.Outcomes[0]
	if outcome.Verdict != VerdictUnknown || outcome.StrongestKind != StrongestNone ||
		len(outcome.Evidence) != 0 {
		t.Fatalf("a worker claim became outcome evidence: %+v", outcome)
	}
}

func TestCollectorReceiptsDecide(t *testing.T) {
	recorder := testRecorder(t)
	landed := collectorEvent(0)
	landed.EventKind = KindExternalReceipt
	landed.EffectID = "eff_7081920a3b4c5d6e"
	landed.Payload.Content = `{"ack":"ok","bytes":4}`
	refused := collectorEvent(1)
	refused.ID = "evt_receiptrefused1"
	refused.EventKind = KindExternalReceipt
	refused.EffectID = "eff_7081920a3b4c5d6f"
	refused.Payload.Content = `{"ack":"refused"}`
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{landed, refused}}); err != nil {
		t.Fatal(err)
	}
	verifier := verifierFixture(t, WithEvidenceStore(recorder))

	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{
		{EffectID: "eff_7081920a3b4c5d6e", Expectation: ExpectEffect},
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome := report.Outcomes[0]
	if outcome.Verdict != VerdictPassed || outcome.StrongestKind != AssertionServiceReceipt {
		t.Fatalf("receipt outcome: %+v", outcome)
	}
	if outcome.Evidence[0].EventID != landed.ID {
		t.Fatalf("the receipt must be cited: %+v", outcome.Evidence)
	}

	report, err = verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{
		{EffectID: "eff_7081920a3b4c5d6f", Expectation: ExpectEffect},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcomes[0].Verdict != VerdictFailed {
		t.Fatalf("a refused receipt is not a landing: %+v", report.Outcomes[0])
	}
}

func TestGraderAloneStaysUnknown(t *testing.T) {
	verifier := verifierFixture(t,
		WithGrader(&fakeGrader{results: map[string]GradeResult{
			"grade/essay-1": {Pass: true, Detail: "looks done"},
		}}))
	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_081920a3b4c5d6e7f", Expectation: ExpectEffect,
		GraderKey: "grade/essay-1",
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome := report.Outcomes[0]
	// A grader must not be the sole ground-truth oracle: grader-only
	// support is unknown, flagged, and cited.
	if outcome.Verdict != VerdictUnknown || !outcome.GraderOnly {
		t.Fatalf("grader-only support decided the outcome: %+v", outcome)
	}
	if outcome.Evidence[0].Result != ResultSupports ||
		outcome.Evidence[0].Kind != AssertionGrader {
		t.Fatalf("the grader ran but did not count: %+v", outcome.Evidence)
	}
}

func TestGraderCorroboratesButReceiptDecides(t *testing.T) {
	recorder := testRecorder(t)
	receipt := collectorEvent(0)
	receipt.EventKind = KindExternalReceipt
	receipt.EffectID = "eff_1920a3b4c5d6e7f8"
	receipt.Payload.Content = `{"ack":"ok"}`
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{receipt}}); err != nil {
		t.Fatal(err)
	}
	verifier := verifierFixture(t,
		WithEvidenceStore(recorder),
		WithGrader(&fakeGrader{results: map[string]GradeResult{
			"grade/essay-1": {Pass: true},
		}}))
	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_1920a3b4c5d6e7f8", Expectation: ExpectEffect,
		GraderKey: "grade/essay-1",
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome := report.Outcomes[0]
	if outcome.Verdict != VerdictPassed || outcome.GraderOnly ||
		outcome.StrongestKind != AssertionServiceReceipt {
		t.Fatalf("the receipt, not the grader, should decide: %+v", outcome)
	}
}

func TestErroredChecksStayUnknown(t *testing.T) {
	state := &fakeState{errs: map[string]error{
		"sink/effect-9": fmt.Errorf("sink unreachable"),
	}}
	verifier := verifierFixture(t, WithStateSource("sink", state))
	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_920a3b4c5d6e7f80", Expectation: ExpectEffect,
		StateQueries: []StateQuery{{Source: "sink", Ref: "sink/effect-9"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome := report.Outcomes[0]
	// An unreachable sink is not evidence of absence; the outcome
	// stays unknown and the error is cited.
	if outcome.Verdict != VerdictUnknown {
		t.Fatalf("an error decided the outcome: %+v", outcome)
	}
	if outcome.Evidence[0].Result != ResultErrored ||
		outcome.Evidence[0].Note == "" {
		t.Fatalf("the error must be cited: %+v", outcome.Evidence)
	}

	// A query naming an unregistered source is an error too.
	report, err = verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_920a3b4c5d6e7f81", Expectation: ExpectEffect,
		StateQueries: []StateQuery{{Source: "nosuch", Ref: "x"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcomes[0].Verdict != VerdictUnknown ||
		report.Outcomes[0].Evidence[0].Result != ResultErrored {
		t.Fatalf("unknown source: %+v", report.Outcomes[0])
	}
}

func TestUnhealthyVerifierAnswersUnknown(t *testing.T) {
	// The known-bad fixture passes: the verifier cannot tell good from
	// bad, so it must not tell anything.
	broken := &fakeFixtures{results: map[string]FixtureResult{
		"fx_knowngood": {Pass: true},
		"fx_knownbad":  {Pass: true},
	}}
	verifier := NewOutcomeVerifier(
		WithFixtures(broken, "fx_knowngood", "fx_knownbad"),
		WithVerifierClock(testClock(t)))
	report, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_0a3b4c5d6e7f8091", Expectation: ExpectEffect,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || report.HealthNote == "" {
		t.Fatalf("health: %+v", report)
	}
	if report.Outcomes[0].Verdict != VerdictUnknown ||
		len(report.Outcomes[0].Evidence) != 0 {
		t.Fatalf("an unhealthy verifier answered: %+v", report.Outcomes[0])
	}

	// No fixtures at all: health cannot be tested, so it is not
	// claimed.
	bare := NewOutcomeVerifier(WithVerifierClock(testClock(t)))
	report, err = bare.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_0a3b4c5d6e7f8092", Expectation: ExpectEffect,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy {
		t.Fatal("untested health was reported as healthy")
	}
}

func TestVerifyValidatesItsInputs(t *testing.T) {
	verifier := verifierFixture(t)
	if _, err := verifier.Verify(nil, testRunID, []OutcomeExpectation{{
		EffectID: "eff_1a2b3c4d5e6f7081", Expectation: ExpectEffect,
	}}); err == nil {
		t.Fatal("a nil principal was accepted")
	}
	if _, err := verifier.Verify(collectorPrincipal(), "run_bad", []OutcomeExpectation{{
		EffectID: "eff_1a2b3c4d5e6f7081", Expectation: ExpectEffect,
	}}); err == nil {
		t.Fatal("a malformed run id was accepted")
	}
	if _, err := verifier.Verify(collectorPrincipal(), testRunID, nil); err == nil {
		t.Fatal("empty expectations were accepted")
	}
	if _, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "effect-1", Expectation: ExpectEffect,
	}}); err == nil {
		t.Fatal("a malformed effect id was accepted")
	}
	if _, err := verifier.Verify(collectorPrincipal(), testRunID, []OutcomeExpectation{{
		EffectID: "eff_1a2b3c4d5e6f7081", Expectation: "vibes",
	}}); err == nil {
		t.Fatal("an unknown expectation was accepted")
	}
}

func TestEvidenceReadFailureIsErroredNotContradiction(t *testing.T) {
	recorder := testRecorder(t)
	// A worker principal cannot read the store; the failed read must
	// surface as an errored assertion, never as evidence of absence.
	worker := &Principal{ID: "act_worker-reference-01",
		TenantID: testTenant, Role: RoleWorker}
	verifier := verifierFixture(t, WithEvidenceStore(recorder))
	report, err := verifier.Verify(worker, testRunID, []OutcomeExpectation{{
		EffectID: "eff_3b4c5d6e7f809102", Expectation: ExpectEffect,
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome := report.Outcomes[0]
	if outcome.Verdict != VerdictUnknown {
		t.Fatalf("a failed read decided the outcome: %+v", outcome)
	}
	if len(outcome.Evidence) != 1 ||
		outcome.Evidence[0].Kind != AssertionServiceReceipt ||
		outcome.Evidence[0].Result != ResultErrored {
		t.Fatalf("the failed read must be cited as an error: %+v", outcome.Evidence)
	}
}
