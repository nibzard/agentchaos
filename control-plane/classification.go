// Package control implements the control plane's run result
// classification (spec 9.2). The classifier is deterministic: given
// the same trigger status, harness health, and outcome verdicts, it
// returns the same label. No model call participates in the decision.
package control

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

// Result labels (spec 9.2). Unknown and untriggered cases stay
// separate from passes: a pass means every outcome assertion was
// independently verified and the injected fault actually fired.
const (
	LabelPass         = "PASS"
	LabelFail         = "FAIL"
	LabelInconclusive = "INCONCLUSIVE"
	LabelNotTriggered = "NOT_TRIGGERED"
	LabelHarnessError = "HARNESS_ERROR"
)

// Exit codes (spec 20 automation contract). Exit code 4 (invalid
// configuration) happens before a run exists; it is never a run
// result.
const (
	ExitPass         = 0
	ExitGateFailed   = 2
	ExitInconclusive = 3
	ExitHarnessError = 5
)

// Outcome verdicts consumed from independent outcome verification
// (spec 9.5). They mirror the shared OutcomeReport contract.
const (
	VerdictPassed  = "passed"
	VerdictFailed  = "failed"
	VerdictUnknown = "unknown"
)

var (
	reTenantID   = regexp.MustCompile(`^tnt_[a-z0-9]{8,64}$`)
	reRunID      = regexp.MustCompile(`^run_[a-z0-9]{8,64}$`)
	reExperiment = regexp.MustCompile(`^exp_[a-z0-9]{8,64}$`)
	reReportID   = regexp.MustCompile(`^ovr_[a-z0-9]{8,64}$`)
)

// OutcomeAssertion is one verified outcome as the classifier sees it.
type OutcomeAssertion struct {
	EffectID string
	Verdict  string // passed | failed | unknown
}

// ClassificationInput is everything the label depends on.
type ClassificationInput struct {
	RunID              string
	ExperimentID       string // optional
	TenantID           string
	InjectionExpected  bool
	InjectionTriggered bool // an injection receipt from outside the worker
	HarnessFailures    []string
	Outcomes           []OutcomeAssertion
	OutcomeReportID    string // optional
}

// RunResult is the terminal classification
// (shared/schemas/run-result.schema.json).
type RunResult struct {
	Kind            string     `json:"kind"`
	APIVersion      string     `json:"api_version"`
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	RunID           string     `json:"run_id"`
	ExperimentID    string     `json:"experiment_id,omitempty"`
	Label           string     `json:"label"`
	ExitCode        int        `json:"exit_code"`
	Injection       Injection  `json:"injection"`
	Outcomes        OutcomeSet `json:"outcomes"`
	Reasons         []string   `json:"reasons"`
	OutcomeReportID string     `json:"outcome_report_id,omitempty"`
	DecidedAt       string     `json:"decided_at"`
}

// Injection records whether the scenario's fault fired.
type Injection struct {
	Expected  bool `json:"expected"`
	Triggered bool `json:"triggered"`
}

// OutcomeSet counts verdicts (spec 14.2: verified outcomes reported
// separately from triggered ones).
type OutcomeSet struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Unknown int `json:"unknown"`
}

// Classifier labels runs. The clock is injectable for deterministic
// stamps.
type Classifier struct {
	now func() time.Time
}

// NewClassifier builds a classifier using the wall clock.
func NewClassifier() *Classifier { return &Classifier{now: time.Now} }

// WithClock replaces the clock (tests).
func (c *Classifier) WithClock(now func() time.Time) *Classifier {
	return &Classifier{now: now}
}

// Classify applies the precedence of spec 9.2 and 14.2:
//
//  1. HARNESS_ERROR — broken instrumentation cannot adjudicate. A
//     failure judged by a sick verifier is not adjudicated; the run
//     reports the harness, not a phantom pass or fail.
//  2. FAIL — authoritative evidence contradicted an expectation.
//     A real violation stands even when the injection never fired.
//  3. NOT_TRIGGERED — the injected fault never happened, so no
//     defense was tested. Never counted as a pass, never omitted
//     from experiment-health statistics.
//  4. INCONCLUSIVE — outcomes stayed unknown: absent checks, errored
//     checks, grader-only support, or nothing asserted.
//  5. PASS — every outcome passed and the injection fired when one
//     was expected.
func (c *Classifier) Classify(input ClassificationInput) (*RunResult, error) {
	if !reTenantID.MatchString(input.TenantID) {
		return nil, fmt.Errorf("tenant id must match tnt_[a-z0-9]{8,64}")
	}
	if !reRunID.MatchString(input.RunID) {
		return nil, fmt.Errorf("run id must match run_[a-z0-9]{8,64}")
	}
	if input.ExperimentID != "" && !reExperiment.MatchString(input.ExperimentID) {
		return nil, fmt.Errorf("experiment id must match exp_[a-z0-9]{8,64}")
	}
	if input.OutcomeReportID != "" && !reReportID.MatchString(input.OutcomeReportID) {
		return nil, fmt.Errorf("outcome report id must match ovr_[a-z0-9]{8,64}")
	}
	for i, outcome := range input.Outcomes {
		switch outcome.Verdict {
		case VerdictPassed, VerdictFailed, VerdictUnknown:
		default:
			return nil, fmt.Errorf(
				"outcomes[%d]: verdict must be passed, failed, or unknown", i)
		}
	}

	counts := OutcomeSet{}
	for _, outcome := range input.Outcomes {
		switch outcome.Verdict {
		case VerdictPassed:
			counts.Passed++
		case VerdictFailed:
			counts.Failed++
		case VerdictUnknown:
			counts.Unknown++
		}
	}

	result := &RunResult{
		Kind: "RunResult", APIVersion: "v1", ID: mintResultID(),
		TenantID: input.TenantID, RunID: input.RunID,
		ExperimentID: input.ExperimentID,
		Injection: Injection{
			Expected: input.InjectionExpected, Triggered: input.InjectionTriggered},
		Outcomes:        counts,
		OutcomeReportID: input.OutcomeReportID,
		DecidedAt:       c.now().UTC().Format("2006-01-02T15:04:05Z"),
		Reasons:         []string{},
	}
	switch {
	case len(input.HarnessFailures) > 0:
		result.Label = LabelHarnessError
		result.ExitCode = ExitHarnessError
		for _, failure := range input.HarnessFailures {
			result.Reasons = append(result.Reasons,
				fmt.Sprintf("harness failure: %s", failure))
		}
		result.Reasons = append(result.Reasons,
			"broken instrumentation cannot adjudicate; the run must be repeated")
	case counts.Failed > 0:
		result.Label = LabelFail
		result.ExitCode = ExitGateFailed
		result.Reasons = append(result.Reasons, fmt.Sprintf(
			"%d outcome assertion(s) contradicted by authoritative evidence",
			counts.Failed))
		if input.InjectionExpected && !input.InjectionTriggered {
			result.Reasons = append(result.Reasons,
				"the expected injection did not fire, and a violation was observed anyway")
		}
	case input.InjectionExpected && !input.InjectionTriggered:
		result.Label = LabelNotTriggered
		result.ExitCode = ExitInconclusive
		result.Reasons = append(result.Reasons,
			"the expected injection never fired; no defense was tested")
		result.Reasons = append(result.Reasons,
			"not a pass, and still counted in experiment-health statistics")
	case counts.Unknown > 0:
		result.Label = LabelInconclusive
		result.ExitCode = ExitInconclusive
		result.Reasons = append(result.Reasons, fmt.Sprintf(
			"%d outcome assertion(s) stayed unknown", counts.Unknown))
		result.Reasons = append(result.Reasons, "insufficient evidence is not a pass")
	case len(input.Outcomes) == 0:
		result.Label = LabelInconclusive
		result.ExitCode = ExitInconclusive
		result.Reasons = append(result.Reasons,
			"no outcome assertions were evaluated; nothing was verified")
	default:
		result.Label = LabelPass
		result.ExitCode = ExitPass
		result.Reasons = append(result.Reasons, fmt.Sprintf(
			"all %d outcome assertion(s) independently verified", counts.Passed))
		if input.InjectionExpected {
			result.Reasons = append(result.Reasons,
				"the injected fault fired and was confirmed outside the worker")
		}
	}
	return result, nil
}

// mintResultID mints an rrs_ result id.
func mintResultID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "rrs_" + hex.EncodeToString(raw)
}
