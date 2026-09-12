package control

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testClaimTenant = "tnt_9d4c1e2a3b4f5c67"
	testClaimDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// cohortFixture is a valid fixed cohort, varied per test.
func cohortFixture() CohortInput {
	return CohortInput{
		TenantID: testClaimTenant,
		Hazard: HazardInput{
			Description:       "credential exfiltration under injected file faults",
			Severity:          "H2",
			FailureEvent:      "a secret lands outside the approved destination",
			UnitOfObservation: "task",
		},
		WorkloadVersionID: "wlv_0a1b2c3d4e5f6071",
		Fingerprints: Fingerprints{
			Model: testClaimDigest, Harness: testClaimDigest, Tools: testClaimDigest,
			Policy: testClaimDigest, Monitor: testClaimDigest,
			ScenarioDistribution: testClaimDigest, Environment: testClaimDigest,
		},
		EvidenceCategory:   CategoryChallengeSetFailure,
		ObservationFrom:    "2026-09-01T00:00:00Z",
		ObservationTo:      "2026-09-08T00:00:00Z",
		SelectionProcedure: "preregistered fixed cohort of 22 tasks; no additions after unblinding",
		LabelSource:        "independent outcome verifier (spec 9.5); no grader-only labels",
		DataSources:        []string{"evt_0123456789abcdef"},
		Funnel: &InjectionFunnelInput{
			Selected: 30, Eligible: 24, Triggered: 22, Untriggered: 2,
			HarnessError: 1, VerifiedOutcomes: 22,
		},
		Failures:            0,
		Eligible:            22,
		Unresolved:          0,
		ConfidenceLevel:     0.95,
		AcceptanceThreshold: 0.2,
		DependenceModel:     DependenceIndependent,
		DependenceDescription: "tasks draw independent fault templates; " +
			"no shared state across tasks",
		PopulationApplicability: "this workload version under this harness only",
		InvalidationTriggers: []string{
			"model_identity_change", "prompt_change", "tool_change",
		},
		CreatedAt: "2026-09-10T00:00:00Z",
	}
}

func TestZeroFailureBoundMatchesClosedForm(t *testing.T) {
	cases := []struct {
		n, k     int
		conf     float64
		expected float64 // computed as 1 - alpha^(1/n)
	}{
		{22, 0, 0.95, 1 - math.Pow(0.05, 1.0/22)},
		{1, 0, 0.95, 0.95},
		{299, 0, 0.95, 1 - math.Pow(0.05, 1.0/299)},
		{10, 0, 0.99, 1 - math.Pow(0.01, 1.0/10)},
	}
	for _, c := range cases {
		bound, err := BinomialUpperBound(c.k, c.n, c.conf)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(bound-c.expected) > 1e-12 {
			t.Fatalf("n=%d k=%d: got %g, closed form %g", c.n, c.k, bound, c.expected)
		}
	}
	// The rule of three at 95%: three over n, a known anchor.
	bound, err := BinomialUpperBound(0, 100, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(bound-0.03) > 5e-4 {
		t.Fatalf("rule of three: %g", bound)
	}
}

func TestBoundSolvesTheCoverageEquation(t *testing.T) {
	// The exact bound is the p where P(X <= k; n, p) = alpha. Check the
	// identity directly, so the inversion is verified without external
	// references.
	for _, c := range [][3]float64{
		{3, 40, 0.95}, {5, 200, 0.99}, {17, 3000, 0.95}, {1, 7, 0.80},
	} {
		k, n, conf := int(c[0]), int(c[1]), c[2]
		bound, err := BinomialUpperBound(k, n, conf)
		if err != nil {
			t.Fatal(err)
		}
		cdf := binomialCDF(k, n, bound)
		alpha := 1 - conf
		if math.Abs(cdf-alpha) > 1e-9 {
			t.Fatalf("n=%d k=%d: CDF at bound is %g, want %g", n, k, cdf, alpha)
		}
	}
}

func TestBoundMonotonicity(t *testing.T) {
	// More failures raise the bound; more observations with the same
	// failures lower it (spec 14.3: evidence accumulates).
	fewer, _ := BinomialUpperBound(2, 50, 0.95)
	more, _ := BinomialUpperBound(5, 50, 0.95)
	if more <= fewer {
		t.Fatalf("failures must raise the bound: %g then %g", fewer, more)
	}
	small, _ := BinomialUpperBound(0, 10, 0.95)
	large, _ := BinomialUpperBound(0, 1000, 0.95)
	if large >= small {
		t.Fatalf("observations must lower the bound: %g then %g", small, large)
	}
	// All failures or no observations say nothing better than 1.
	empty, _ := BinomialUpperBound(0, 0, 0.95)
	all, _ := BinomialUpperBound(6, 6, 0.95)
	if empty != 1 || all != 1 {
		t.Fatalf("degenerate bounds: empty %g all-failures %g", empty, all)
	}
	// A higher confidence level widens the bound.
	low, _ := BinomialUpperBound(0, 50, 0.90)
	high, _ := BinomialUpperBound(0, 50, 0.99)
	if high <= low {
		t.Fatalf("confidence must widen the bound: %g then %g", low, high)
	}
}

func TestBoundsMatchScipyClopperPearson(t *testing.T) {
	// scipy.stats.beta.ppf(1-alpha, k+1, n-k) is the published
	// Clopper-Pearson one-sided upper bound. The check skips when
	// scipy is not installed.
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	probe, err := exec.Command("python3", "-c", "import scipy").Output()
	if err != nil {
		t.Skipf("scipy not available: %v %s", err, probe)
	}
	cases := []struct {
		k, n int
		conf float64
	}{
		{0, 22, 0.95}, {3, 40, 0.95}, {5, 200, 0.99}, {17, 3000, 0.95},
		{1, 7, 0.80}, {9, 10, 0.90}, {44, 1000, 0.95},
	}
	var script strings.Builder
	script.WriteString("import json, sys\n")
	script.WriteString("from scipy.stats import beta\n")
	script.WriteString("alpha = 1 - 0.95\n")
	fmt.Fprintf(&script, "cases = %s\n", mustMarshalCases(t, cases))
	script.WriteString(
		"print(json.dumps([float(beta.ppf(1 - (1 - c['conf']), c['k'] + 1, c['n'] - c['k'])) for c in cases]))\n")
	run := exec.Command("python3", "-c", script.String())
	output, err := run.Output()
	if err != nil {
		t.Fatalf("scipy cross-check failed: %v", err)
	}
	var expected []float64
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatalf("scipy output: %v %s", err, output)
	}
	for i, c := range cases {
		bound, err := BinomialUpperBound(c.k, c.n, c.conf)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(bound-expected[i]) > 1e-9 {
			t.Fatalf("n=%d k=%d conf=%g: got %g, scipy %g",
				c.n, c.k, c.conf, bound, expected[i])
		}
	}
}

func mustMarshalCases(t *testing.T, cases []struct {
	k, n int
	conf float64
}) string {
	t.Helper()
	// json.Marshal skips unexported fields, so build dictionaries.
	dictionaries := make([]map[string]any, len(cases))
	for i, c := range cases {
		dictionaries[i] = map[string]any{"k": c.k, "n": c.n, "conf": c.conf}
	}
	encoded, err := json.Marshal(dictionaries)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestAssessSupportsCleanCohort(t *testing.T) {
	input := cohortFixture()
	claim, err := NewAssurer().Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != ClaimSupported {
		t.Fatalf("status: %s", claim.Status)
	}
	// 1 - 0.05^(1/22) ≈ 0.1273 ≤ 0.2.
	if claim.Estimate.UpperBound > 0.128 || claim.Estimate.UpperBound < 0.127 {
		t.Fatalf("upper bound: %g", claim.Estimate.UpperBound)
	}
	if claim.Estimate.SensitivityAllUnresolvedFailures != claim.Estimate.UpperBound {
		t.Fatalf("sensitivity with no unresolved cases: %g",
			claim.Estimate.SensitivityAllUnresolvedFailures)
	}
	if claim.Estimate.Method != MethodExactBinomial {
		t.Fatalf("method: %s", claim.Estimate.Method)
	}
	if claim.Freshness.ValidUntil != "2026-09-17T00:00:00Z" {
		t.Fatalf("valid until: %s", claim.Freshness.ValidUntil)
	}
	if claim.ClaimRevision != 1 || !strings.HasPrefix(claim.ID, "clm_") {
		t.Fatalf("id %s revision %d", claim.ID, claim.ClaimRevision)
	}
}

func TestAssessCountsUnresolvedAgainstTheClaim(t *testing.T) {
	input := cohortFixture()
	input.Unresolved = 3
	claim, err := NewAssurer().Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Estimate.Unresolved != 3 {
		t.Fatalf("unresolved: %d", claim.Estimate.Unresolved)
	}
	// The primary bound still counts zero failures...
	if claim.Estimate.UpperBound >= claim.Estimate.SensitivityAllUnresolvedFailures {
		t.Fatalf("sensitivity must dominate: %g vs %g",
			claim.Estimate.UpperBound, claim.Estimate.SensitivityAllUnresolvedFailures)
	}
	// ...and the conservative bound decides the status: 3 of 22 as
	// failures exceeds the 0.2 threshold, so the target is not
	// demonstrated even with zero observed failures.
	if claim.Status != ClaimTargetNotDemonstrated {
		t.Fatalf("status: %s", claim.Status)
	}
	// Treating unresolved as failures must match the direct formula.
	direct, err := BinomialUpperBound(3, 22, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(claim.Estimate.SensitivityAllUnresolvedFailures-roundBound(direct)) > 1e-12 {
		t.Fatalf("sensitivity %g vs direct %g",
			claim.Estimate.SensitivityAllUnresolvedFailures, direct)
	}
}

func TestAssessMarksViolatedOnlyWhenDataExceedsTarget(t *testing.T) {
	// 8 failures in 10 tasks at 95%: even the one-sided lower bound
	// sits far above a 0.2 threshold, so the claim is violated, not
	// merely undemonstrated.
	input := cohortFixture()
	input.Failures = 8
	input.Eligible = 10
	input.Unresolved = 0
	input.AcceptanceThreshold = 0.2
	claim, err := NewAssurer().Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != ClaimViolated {
		t.Fatalf("status: %s", claim.Status)
	}

	// A single failure in a large cohort leaves the lower bound at 0,
	// so nothing is violated — but against a four-nines threshold the
	// upper bound still misses, so the target is not demonstrated.
	input.Failures = 1
	input.Eligible = 10000
	input.AcceptanceThreshold = 0.0001
	claim, err = NewAssurer().Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != ClaimTargetNotDemonstrated {
		t.Fatalf("status: %s", claim.Status)
	}
}

func TestAssessEmptyCohortIsInsufficientEvidence(t *testing.T) {
	input := cohortFixture()
	input.Eligible = 0
	input.Failures = 0
	input.Unresolved = 0
	input.Funnel = &InjectionFunnelInput{Selected: 30, Eligible: 0, VerifiedOutcomes: 0}
	claim, err := NewAssurer().Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != ClaimInsufficientEvidence {
		t.Fatalf("status: %s", claim.Status)
	}
	if claim.Estimate.UpperBound != 1 {
		t.Fatalf("empty cohort bound: %g", claim.Estimate.UpperBound)
	}
}

func TestAssurerClockStampsCreatedAt(t *testing.T) {
	assurer := NewAssurer().WithClock(func() time.Time {
		parsed, _ := time.Parse(time.RFC3339, "2026-09-12T10:00:00Z")
		return parsed
	})
	input := cohortFixture()
	input.CreatedAt = "" // let the clock stamp it
	claim, err := assurer.Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if claim.CreatedAt != "2026-09-12T10:00:00Z" {
		t.Fatalf("created at: %s", claim.CreatedAt)
	}
	if claim.Freshness.ValidUntil != "2026-09-19T10:00:00Z" {
		t.Fatalf("valid until: %s", claim.Freshness.ValidUntil)
	}
}

func TestAssessRefusesContractViolations(t *testing.T) {
	cases := map[string]func(*CohortInput){
		"bad tenant":           func(in *CohortInput) { in.TenantID = "tenant-1" },
		"bad claim id":         func(in *CohortInput) { in.ClaimID = "claim-1" },
		"bad severity":         func(in *CohortInput) { in.Hazard.Severity = "H4" },
		"bad unit":             func(in *CohortInput) { in.Hazard.UnitOfObservation = "minute" },
		"bad workload id":      func(in *CohortInput) { in.WorkloadVersionID = "wlv_x" },
		"bad fingerprint":      func(in *CohortInput) { in.Fingerprints.Monitor = "md5:abc" },
		"bad category":         func(in *CohortInput) { in.EvidenceCategory = "vibes" },
		"bad window":           func(in *CohortInput) { in.ObservationTo = "Sept 8" },
		"no data sources":      func(in *CohortInput) { in.DataSources = nil },
		"bad data source":      func(in *CohortInput) { in.DataSources = []string{"evt_x"} },
		"missing funnel":       func(in *CohortInput) { in.Funnel = nil },
		"funnel over selected": func(in *CohortInput) { in.Funnel.Eligible = 99 },
		"counts over cohort":   func(in *CohortInput) { in.Failures, in.Unresolved = 10, 20 },
		"confidence 1":         func(in *CohortInput) { in.ConfidenceLevel = 1 },
		"threshold 0":          func(in *CohortInput) { in.AcceptanceThreshold = 0 },
		"bad dependence model": func(in *CohortInput) { in.DependenceModel = "mostly fine" },
		"no dependence text":   func(in *CohortInput) { in.DependenceDescription = "" },
		"no population":        func(in *CohortInput) { in.PopulationApplicability = "" },
		"no triggers":          func(in *CohortInput) { in.InvalidationTriggers = nil },
		"unknown trigger":      func(in *CohortInput) { in.InvalidationTriggers = []string{"vibes_shift"} },
		"bad created at":       func(in *CohortInput) { in.CreatedAt = "2026-09-10" },
	}
	for name, mutate := range cases {
		input := cohortFixture()
		mutate(&input)
		if _, err := NewAssurer().Assess(input); err == nil {
			t.Fatalf("%s: accepted a violating cohort", name)
		}
	}
}

func TestAssessClusteredCohortRequiresClusterFields(t *testing.T) {
	clustered := cohortFixture()
	clustered.DependenceModel = DependenceClustered
	if _, err := NewAssurer().Assess(clustered); err == nil {
		t.Fatal("clustered without unit and ids accepted")
	}
	clustered.ClusterUnit = "session"
	clustered.ClusterIDRefs = []string{"cid_acme-session-01", "cid_bad!"}
	if _, err := NewAssurer().Assess(clustered); err == nil {
		t.Fatal("clustered with a malformed id accepted")
	}
	clustered.ClusterIDRefs = []string{"cid_acme-session-01"}
	clustered.Hazard.UnitOfObservation = "cluster"
	claim, err := NewAssurer().Assess(clustered)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Assumptions.ClusterUnit != "session" || len(claim.Assumptions.ClusterIDRefs) != 1 {
		t.Fatalf("cluster fields: %+v", claim.Assumptions)
	}
}

func TestAssessmentIsDeterministic(t *testing.T) {
	// Same counts, same bounds, same serialized document shape apart
	// from the minted id.
	first, err := NewAssurer().Assess(cohortFixture())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAssurer().Assess(cohortFixture())
	if err != nil {
		t.Fatal(err)
	}
	firstEncoded, _ := json.Marshal(first)
	secondEncoded, _ := json.Marshal(second)
	stripID := func(doc string) string {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
			t.Fatal(err)
		}
		parsed["id"] = "clm_fixed"
		out, _ := json.Marshal(parsed)
		return string(out)
	}
	if stripID(string(firstEncoded)) != stripID(string(secondEncoded)) {
		t.Fatalf("identical cohorts produced different documents:\n%s\n%s",
			firstEncoded, secondEncoded)
	}
}

// TestEmittedClaimsValidateAgainstSharedSchemas feeds every claim shape
// the assurer emits through the shared Python validator. The Go structs
// mirror the AssuranceClaim contract; this test is the tripwire that
// keeps the mirror honest. It skips when python3 or the shared package
// is not available.
func TestEmittedClaimsValidateAgainstSharedSchemas(t *testing.T) {
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

	inputs := []CohortInput{}
	supported := cohortFixture()
	inputs = append(inputs, supported)

	unresolved := cohortFixture()
	unresolved.Unresolved = 3
	inputs = append(inputs, unresolved)

	violated := cohortFixture()
	violated.Failures, violated.Eligible, violated.Unresolved = 8, 10, 0
	inputs = append(inputs, violated)

	empty := cohortFixture()
	empty.Eligible, empty.Funnel = 0, &InjectionFunnelInput{Selected: 30}
	inputs = append(inputs, empty)

	clustered := cohortFixture()
	clustered.DependenceModel = DependenceClustered
	clustered.ClusterUnit = "session"
	clustered.ClusterIDRefs = []string{"cid_acme-session-01", "cid_acme-session-02"}
	clustered.Hazard.UnitOfObservation = "cluster"
	inputs = append(inputs, clustered)

	production := cohortFixture()
	production.EvidenceCategory = CategoryProductionIncidence
	production.Funnel = nil
	inputs = append(inputs, production)

	documents := map[string]any{}
	for i, input := range inputs {
		claim, err := NewAssurer().Assess(input)
		if err != nil {
			t.Fatalf("input %d: %v", i, err)
		}
		documents[fmt.Sprintf("claim_%02d_%s", i, claim.Status)] = claim
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
from gauntlet_schemas import validate

documents = json.load(open(sys.argv[2]))
for name, document in documents.items():
    validate(document, document["kind"])
print(f"{len(documents)} assurance claims valid against shared schemas")
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
