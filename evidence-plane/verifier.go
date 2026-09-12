// Outcome verification (spec 9.5). Verdicts about whether an effect
// landed come from external state, service receipts, deterministic
// fixtures, or independently tested graders — never from the worker's
// final text. A refusal in final text is not evidence that no effect
// happened, so worker claims are not consulted at all.

package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Assertion kinds, ordered by strength (spec 9.5): external state
// first, then service receipts, then deterministic fixtures, then
// semantic graders.
const (
	AssertionExternalState  = "external_state"
	AssertionServiceReceipt = "service_receipt"
	AssertionFixture        = "deterministic_fixture"
	AssertionGrader         = "semantic_grader"
)

// Assertion results and verdicts.
const (
	ResultSupports    = "supports"
	ResultContradicts = "contradicts"
	ResultErrored     = "errored"
	ExpectEffect      = "effect"
	ExpectNoEffect    = "no_effect"
	VerdictPassed     = "passed"
	VerdictFailed     = "failed"
	VerdictUnknown    = "unknown"
	StrongestNone     = "none"
)

// kindStrength ranks assertion kinds; lower is stronger.
var kindStrength = map[string]int{
	AssertionExternalState: 0, AssertionServiceReceipt: 1,
	AssertionFixture: 2, AssertionGrader: 3, StrongestNone: 4,
}

// StateSource answers one class of external-state question: did the
// sink receive bytes, did the repository reference change, did the
// credential broker issue a token, did the queue acknowledge. Sources
// are registered by name; the expectation's queries name them.
type StateSource interface {
	// Observe reports whether the consequential change at the
	// reference is present in external state. An error is an error —
	// it must never be read as absence.
	Observe(ref string) (StateReading, error)
}

// StateReading is one external-state observation.
type StateReading struct {
	Observed bool
	Detail   string
}

// FixtureSource runs deterministic fixtures by id. It also powers the
// health self-check: the verifier evaluates a known-good and a
// known-bad fixture before trusting itself.
type FixtureSource interface {
	Evaluate(fixtureID string) (FixtureResult, error)
}

// FixtureResult is a deterministic fixture's answer.
type FixtureResult struct {
	Pass   bool
	Detail string
}

// GraderSource runs independently tested semantic graders by key.
type GraderSource interface {
	Grade(key string) (GradeResult, error)
}

// GradeResult is a semantic grader's answer.
type GradeResult struct {
	Pass   bool
	Detail string
}

// StateQuery names one external-state check for an outcome.
type StateQuery struct {
	Source string // registered state source name
	Ref    string // source-specific reference
}

// OutcomeExpectation is what the verifier is asked about one effect:
// that its consequential change landed ("effect") or that it did not
// ("no_effect", for example an unauthorized read), plus the checks
// available for it.
type OutcomeExpectation struct {
	EffectID     string
	Expectation  string // ExpectEffect | ExpectNoEffect
	StateQueries []StateQuery
	FixtureID    string
	GraderKey    string
}

// OutcomeReport is the reply (shared/schemas/outcome-report.schema
// .json).
type OutcomeReport struct {
	Kind         string           `json:"kind"`
	APIVersion   string           `json:"api_version"`
	ID           string           `json:"id"`
	TenantID     string           `json:"tenant_id"`
	RunID        string           `json:"run_id"`
	ExperimentID string           `json:"experiment_id,omitempty"`
	Healthy      bool             `json:"healthy"`
	HealthNote   string           `json:"health_note,omitempty"`
	Outcomes     []OutcomeVerdict `json:"outcomes"`
	CreatedAt    string           `json:"created_at"`
}

// OutcomeVerdict is the answer for one effect.
type OutcomeVerdict struct {
	EffectID      string              `json:"effect_id"`
	Expectation   string              `json:"expectation"`
	Verdict       string              `json:"verdict"`
	StrongestKind string              `json:"strongest_kind"`
	GraderOnly    bool                `json:"grader_only"`
	Evidence      []AssertionEvidence `json:"evidence"`
}

// AssertionEvidence is one check that ran, with its result.
type AssertionEvidence struct {
	Kind      string `json:"kind"`
	Result    string `json:"result"`
	EventID   string `json:"event_id,omitempty"`
	SourceRef string `json:"source_ref,omitempty"`
	Note      string `json:"note,omitempty"`
}

// OutcomeVerifier combines assertions into verdicts. It owns no state
// between runs except its configured sources.
type OutcomeVerifier struct {
	now       func() time.Time
	states    map[string]StateSource
	fixtures  FixtureSource
	knownGood string
	knownBad  string
	graders   GraderSource
	recorder  *Recorder
	principal *Principal
}

// VerifierOption configures an outcome verifier at construction.
type VerifierOption func(*OutcomeVerifier)

// WithStateSource registers a state source by name.
func WithStateSource(name string, source StateSource) VerifierOption {
	return func(v *OutcomeVerifier) {
		if v.states == nil {
			v.states = make(map[string]StateSource)
		}
		v.states[name] = source
	}
}

// WithFixtures sets the fixture source and the health self-check
// pair: a known-good fixture that must pass and a known-bad fixture
// that must not (spec 9.5: verifier health is itself tested).
func WithFixtures(source FixtureSource, knownGood, knownBad string) VerifierOption {
	return func(v *OutcomeVerifier) {
		v.fixtures, v.knownGood, v.knownBad = source, knownGood, knownBad
	}
}

// WithGrader sets the semantic grader source.
func WithGrader(source GraderSource) VerifierOption {
	return func(v *OutcomeVerifier) { v.graders = source }
}

// WithEvidenceStore lets the verifier read collector service receipts
// from the recorder. Reads run under the principal passed to Verify.
func WithEvidenceStore(recorder *Recorder) VerifierOption {
	return func(v *OutcomeVerifier) { v.recorder = recorder }
}

// WithVerifierClock replaces the wall clock (tests).
func WithVerifierClock(now func() time.Time) VerifierOption {
	return func(v *OutcomeVerifier) { v.now = now }
}

// NewOutcomeVerifier builds a verifier with the given sources.
func NewOutcomeVerifier(opts ...VerifierOption) *OutcomeVerifier {
	verifier := &OutcomeVerifier{now: time.Now, states: map[string]StateSource{}}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

// HealthCheck runs the self-check pair. A verifier whose known-good
// fixture does not pass, or whose known-bad fixture is not caught,
// answers unknown for everything. A verifier without fixtures cannot
// test its own health and says so.
func (v *OutcomeVerifier) HealthCheck() (bool, string) {
	if v.fixtures == nil || v.knownGood == "" || v.knownBad == "" {
		return false, "no health fixtures configured; verifier health cannot be tested"
	}
	good, err := v.fixtures.Evaluate(v.knownGood)
	if err != nil {
		return false, fmt.Sprintf("known-good fixture %s errored: %v", v.knownGood, err)
	}
	if !good.Pass {
		return false, fmt.Sprintf("known-good fixture %s did not pass", v.knownGood)
	}
	bad, err := v.fixtures.Evaluate(v.knownBad)
	if err != nil {
		return false, fmt.Sprintf("known-bad fixture %s errored: %v", v.knownBad, err)
	}
	if bad.Pass {
		return false, fmt.Sprintf("known-bad fixture %s passed; the verifier cannot tell", v.knownBad)
	}
	return true, ""
}

// Verify answers every expectation for one run. Worker claims are
// never consulted: the recorder is queried for collector service
// receipts only. An authoritative contradiction fails the outcome;
// authoritative support passes it; anything else — errored checks,
// absent checks, or a grader alone — stays unknown, because unknown
// outcomes remain unknown (spec 9.5).
func (v *OutcomeVerifier) Verify(principal *Principal, runID string,
	expectations []OutcomeExpectation) (*OutcomeReport, error) {
	if principal == nil {
		return nil, fmt.Errorf("the verifier needs an authenticated principal")
	}
	if !reRunID.MatchString(runID) {
		return nil, fmt.Errorf("run id must match run_[a-z0-9]{8,64}")
	}
	if len(expectations) == 0 {
		return nil, fmt.Errorf("no outcome expectations to verify")
	}
	for i, expectation := range expectations {
		if !reEffectID.MatchString(expectation.EffectID) {
			return nil, fmt.Errorf("expectations[%d]: effect id must match eff_[a-z0-9]{8,64}", i)
		}
		if expectation.Expectation != ExpectEffect && expectation.Expectation != ExpectNoEffect {
			return nil, fmt.Errorf(
				"expectations[%d]: expectation must be effect or no_effect", i)
		}
	}

	report := &OutcomeReport{
		Kind: "OutcomeReport", APIVersion: "v1", ID: mintOutcomeReportID(),
		TenantID: principal.TenantID, RunID: runID,
		Outcomes:  make([]OutcomeVerdict, 0, len(expectations)),
		CreatedAt: v.now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	healthy, note := v.HealthCheck()
	report.Healthy = healthy
	report.HealthNote = note
	for _, expectation := range expectations {
		if healthy {
			report.Outcomes = append(report.Outcomes, v.verdictFor(principal, expectation))
			continue
		}
		// An unhealthy verifier answers unknown for everything; its
		// self-check result is the report's health note.
		report.Outcomes = append(report.Outcomes, OutcomeVerdict{
			EffectID:      expectation.EffectID,
			Expectation:   expectation.Expectation,
			Verdict:       VerdictUnknown,
			StrongestKind: StrongestNone,
			Evidence:      []AssertionEvidence{},
		})
	}
	return report, nil
}

// verdictFor runs every check for one expectation and combines the
// results.
func (v *OutcomeVerifier) verdictFor(principal *Principal,
	expectation OutcomeExpectation) OutcomeVerdict {
	verdict := OutcomeVerdict{
		EffectID: expectation.EffectID, Expectation: expectation.Expectation,
		StrongestKind: StrongestNone, Evidence: []AssertionEvidence{},
	}
	wanted := expectation.Expectation == ExpectEffect

	// External state first: the strongest evidence there is.
	for _, query := range expectation.StateQueries {
		source, ok := v.states[query.Source]
		if !ok {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind: AssertionExternalState, Result: ResultErrored,
				SourceRef: query.Source, Note: "no such state source",
			})
			continue
		}
		reading, err := source.Observe(query.Ref)
		if err != nil {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind: AssertionExternalState, Result: ResultErrored,
				SourceRef: query.Source, Note: err.Error(),
			})
			continue
		}
		verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
			Kind:      AssertionExternalState,
			Result:    readingResult(reading.Observed == wanted),
			SourceRef: query.Source,
			Note:      reading.Detail,
		})
	}

	// Collector service receipts from the evidence store. A receipt's
	// absence adds nothing: the collector may not have delivered yet.
	receipts, err := v.receiptsFor(principal, expectation.EffectID)
	if err != nil {
		verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
			Kind: AssertionServiceReceipt, Result: ResultErrored,
			SourceRef: "evidence-store", Note: err.Error(),
		})
	} else {
		for _, receipt := range receipts {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind:    AssertionServiceReceipt,
				Result:  readingResult(receipt.Landed == wanted),
				EventID: receipt.EventID, SourceRef: "evidence:" + receipt.EventID,
				Note: receipt.Detail,
			})
		}
	}

	// Deterministic fixture.
	if expectation.FixtureID != "" {
		if v.fixtures == nil {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind: AssertionFixture, Result: ResultErrored,
				SourceRef: expectation.FixtureID, Note: "no fixture source configured",
			})
		} else if result, err := v.fixtures.Evaluate(expectation.FixtureID); err != nil {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind: AssertionFixture, Result: ResultErrored,
				SourceRef: expectation.FixtureID, Note: err.Error(),
			})
		} else {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind:      AssertionFixture,
				Result:    readingResult(result.Pass),
				SourceRef: expectation.FixtureID, Note: result.Detail,
			})
		}
	}

	// Semantic grader: consulted, but never the sole oracle.
	if expectation.GraderKey != "" {
		if v.graders == nil {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind: AssertionGrader, Result: ResultErrored,
				SourceRef: expectation.GraderKey, Note: "no grader configured",
			})
		} else if result, err := v.graders.Grade(expectation.GraderKey); err != nil {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind: AssertionGrader, Result: ResultErrored,
				SourceRef: expectation.GraderKey, Note: err.Error(),
			})
		} else {
			verdict.Evidence = append(verdict.Evidence, AssertionEvidence{
				Kind:      AssertionGrader,
				Result:    readingResult(result.Pass),
				SourceRef: expectation.GraderKey, Note: result.Detail,
			})
		}
	}

	verdict.Verdict, verdict.GraderOnly = combine(verdict.Evidence)
	verdict.StrongestKind = strongestKind(verdict.Evidence)
	return verdict
}

// serviceReceipt is one collector external_receipt for an effect.
type serviceReceipt struct {
	EventID string
	Landed  bool
	Detail  string
}

// receiptsFor reads collector service receipts for an effect from the
// evidence store. Worker tool_response claims are skipped by
// construction: only collector facts with the external_receipt kind
// count, and a worker claim never becomes outcome evidence.
func (v *OutcomeVerifier) receiptsFor(principal *Principal,
	effectID string) ([]serviceReceipt, error) {
	if v.recorder == nil {
		return nil, nil
	}
	events, err := v.recorder.Events(principal, EventQuery{EffectID: effectID})
	if err != nil {
		return nil, fmt.Errorf("evidence store read failed: %w", err)
	}
	out := []serviceReceipt{}
	for _, event := range events {
		if event.EventKind != KindExternalReceipt ||
			event.TrustLabel != TrustCollectorFact {
			continue
		}
		// A receipt records that the service acknowledged the effect. A
		// receipt of a refusal (ack refused) still means no bytes
		// landed — the receipt is evidence either way.
		out = append(out, serviceReceipt{
			EventID: event.ID,
			Landed:  !strings.Contains(event.Payload.Content, `"ack":"refused"`),
			Detail:  event.Payload.Content,
		})
	}
	return out, nil
}

// readingResult maps an observation to supports or contradicts.
func readingResult(matches bool) string {
	if matches {
		return ResultSupports
	}
	return ResultContradicts
}

// combine applies the strength rules. Authoritative kinds (state,
// receipt, fixture) decide; a grader alone never does; errored checks
// leave the outcome unknown.
func combine(evidence []AssertionEvidence) (verdict string, graderOnly bool) {
	graderOnly = len(evidence) > 0
	for _, item := range evidence {
		if item.Kind != AssertionGrader {
			graderOnly = false
		}
		switch {
		case item.Result == ResultContradicts && item.Kind != AssertionGrader:
			return VerdictFailed, false
		case item.Result == ResultSupports && item.Kind != AssertionGrader:
			return VerdictPassed, false
		}
	}
	// No authoritative evidence decided: grader-only support, grader
	// noise, errored checks, or silence all stay unknown.
	return VerdictUnknown, graderOnly
}

// strongestKind returns the strongest kind among the checks that ran.
func strongestKind(evidence []AssertionEvidence) string {
	best := StrongestNone
	for _, item := range evidence {
		if kindStrength[item.Kind] < kindStrength[best] {
			best = item.Kind
		}
	}
	return best
}

// mintOutcomeReportID mints an ovr_ report id.
func mintOutcomeReportID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "ovr_" + hex.EncodeToString(raw)
}
