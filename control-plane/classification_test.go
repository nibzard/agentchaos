package control

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	testTenant = "tnt_9d4c1e2a3b4f5c67"
	testRun    = "run_0f1e2d3c4b5a6970"
)

func passed(n int) []OutcomeAssertion {
	out := make([]OutcomeAssertion, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, OutcomeAssertion{
			EffectID: fmt.Sprintf("eff_%016d", i), Verdict: VerdictPassed})
	}
	return out
}

func TestFullPass(t *testing.T) {
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: true, InjectionTriggered: true,
		Outcomes: passed(3), OutcomeReportID: "ovr_0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelPass || result.ExitCode != ExitPass {
		t.Fatalf("result: %+v", result)
	}
	if result.Outcomes.Passed != 3 || result.Outcomes.Failed != 0 ||
		result.Outcomes.Unknown != 0 {
		t.Fatalf("counts: %+v", result.Outcomes)
	}
}

func TestOneContradictionFailsTheRun(t *testing.T) {
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: true, InjectionTriggered: true,
		Outcomes: append(passed(2), OutcomeAssertion{
			EffectID: "eff_0000000000000009", Verdict: VerdictFailed}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelFail || result.ExitCode != ExitGateFailed {
		t.Fatalf("result: %+v", result)
	}
}

func TestUntriggeredInjectionIsNeverAPass(t *testing.T) {
	// Every outcome passed, but the injected fault never fired: no
	// defense was tested, and spec 14.2 forbids counting this as a
	// successful defense.
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: true, InjectionTriggered: false,
		Outcomes: passed(3),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelNotTriggered || result.ExitCode != ExitInconclusive {
		t.Fatalf("an untriggered attack became a pass: %+v", result)
	}
	if result.Injection.Expected != true || result.Injection.Triggered != false {
		t.Fatalf("injection record: %+v", result.Injection)
	}
}

func TestARealViolationStandsWithoutATrigger(t *testing.T) {
	// The injection never fired, but an unauthorized effect landed
	// anyway. The violation is real; FAIL outranks NOT_TRIGGERED.
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: true, InjectionTriggered: false,
		Outcomes: []OutcomeAssertion{
			{EffectID: "eff_0000000000000001", Verdict: VerdictFailed}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelFail {
		t.Fatalf("an observed violation was excused by the trigger: %+v", result)
	}
}

func TestUnknownsStayInconclusive(t *testing.T) {
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: true, InjectionTriggered: true,
		Outcomes: []OutcomeAssertion{
			{EffectID: "eff_0000000000000001", Verdict: VerdictPassed},
			{EffectID: "eff_0000000000000002", Verdict: VerdictUnknown}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelInconclusive || result.ExitCode != ExitInconclusive {
		t.Fatalf("unknowns folded into a pass: %+v", result)
	}
}

func TestNoOutcomesIsInconclusive(t *testing.T) {
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelInconclusive {
		t.Fatalf("nothing verified became a pass: %+v", result)
	}
}

func TestBaselinePassesWithoutAnInjection(t *testing.T) {
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		Outcomes: passed(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelPass {
		t.Fatalf("a clean baseline run did not pass: %+v", result)
	}
}

func TestHarnessFailureOutranksEverything(t *testing.T) {
	// A failure judged by a sick verifier is not adjudicated: the
	// broken harness is the finding, and the run reports it.
	result, err := NewClassifier().Classify(ClassificationInput{
		TenantID: testTenant, RunID: testRun,
		InjectionExpected: true, InjectionTriggered: true,
		HarnessFailures: []string{"outcome verifier unhealthy: known-bad fixture passed"},
		Outcomes: []OutcomeAssertion{
			{EffectID: "eff_0000000000000001", Verdict: VerdictFailed}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != LabelHarnessError || result.ExitCode != ExitHarnessError {
		t.Fatalf("a broken harness adjudicated anyway: %+v", result)
	}
	if len(result.Reasons) < 2 {
		t.Fatalf("reasons: %+v", result.Reasons)
	}
}

func TestClassifyValidatesInput(t *testing.T) {
	base := ClassificationInput{
		TenantID: testTenant, RunID: testRun, Outcomes: passed(1)}
	if _, err := NewClassifier().Classify(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.TenantID = "tenant-1"
	if _, err := NewClassifier().Classify(bad); err == nil {
		t.Fatal("a malformed tenant id was accepted")
	}
	bad = base
	bad.RunID = "run/1"
	if _, err := NewClassifier().Classify(bad); err == nil {
		t.Fatal("a malformed run id was accepted")
	}
	bad = base
	bad.ExperimentID = "exp-1"
	if _, err := NewClassifier().Classify(bad); err == nil {
		t.Fatal("a malformed experiment id was accepted")
	}
	bad = base
	bad.OutcomeReportID = "report-1"
	if _, err := NewClassifier().Classify(bad); err == nil {
		t.Fatal("a malformed report id was accepted")
	}
	bad = base
	bad.Outcomes = []OutcomeAssertion{{EffectID: "eff_0000000000000001", Verdict: "vibes"}}
	if _, err := NewClassifier().Classify(bad); err == nil {
		t.Fatal("an unknown verdict was accepted")
	}
}

// TestEmittedResultsValidateAgainstSharedSchemas feeds every label
// through the shared Python validator.
func TestEmittedResultsValidateAgainstSharedSchemas(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	sharedPython := filepath.Join(root, "shared", "python")
	if _, err := os.Stat(sharedPython); err != nil {
		t.Skip("shared python package not present")
	}

	inputs := []ClassificationInput{
		{TenantID: testTenant, RunID: testRun, InjectionExpected: true,
			InjectionTriggered: true, Outcomes: passed(2),
			OutcomeReportID: "ovr_0123456789abcdef"},
		{TenantID: testTenant, RunID: testRun, InjectionExpected: true,
			InjectionTriggered: true,
			Outcomes: []OutcomeAssertion{
				{EffectID: "eff_0000000000000001", Verdict: VerdictFailed}}},
		{TenantID: testTenant, RunID: testRun, InjectionExpected: true,
			InjectionTriggered: false, Outcomes: passed(1)},
		{TenantID: testTenant, RunID: testRun,
			Outcomes: []OutcomeAssertion{
				{EffectID: "eff_0000000000000001", Verdict: VerdictUnknown}}},
		{TenantID: testTenant, RunID: testRun,
			HarnessFailures: []string{"verifier self-check failed"},
			Outcomes:        passed(1)},
	}
	documents := map[string]any{}
	for i, input := range inputs {
		result, err := NewClassifier().Classify(input)
		if err != nil {
			t.Fatal(err)
		}
		documents[fmt.Sprintf("result_%02d_%s", i, result.Label)] = result
	}

	directory := t.TempDir()
	listPath := filepath.Join(directory, "documents.json")
	payload, err := json.Marshal(documents)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(directory, "check.py")
	script := `
import json, sys

sys.path.insert(0, sys.argv[1])
from acx_schemas import validate

documents = json.load(open(sys.argv[2]))
for name, document in documents.items():
    validate(document, document["kind"])
print(f"{len(documents)} control-plane documents valid against shared schemas")
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	run := exec.Command("python3", scriptPath, sharedPython, listPath)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("cross-language validation failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
