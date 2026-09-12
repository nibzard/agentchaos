package control

// Advanced sampling and statistics tests (T053, spec 14.4 and 15.1,
// AC-034).
//
// Planted outcomes with known arithmetic prove each piece: cluster
// bounds count clusters, sequential looks only happen where they were
// preregistered, weighted strata never pool into the exact formula,
// multiple comparisons adjust by Holm and Bonferroni, and a sampling
// plan without the uniform sentinel is refused.

import (
	"strings"
	"testing"
)

func clusterObservations() []ClusterObservation {
	// Three clusters. cid_a fails (two failing observations inside
	// it — one cluster failure), cid_b is clean with three
	// observations, cid_c has no failures but one unresolved
	// observation.
	return []ClusterObservation{
		{ClusterID: "cid_cluster-a0001", Failed: true},
		{ClusterID: "cid_cluster-a0001", Failed: true},
		{ClusterID: "cid_cluster-b0002"},
		{ClusterID: "cid_cluster-b0002"},
		{ClusterID: "cid_cluster-b0002"},
		{ClusterID: "cid_cluster-c0003", Unresolved: true},
	}
}

// TestClusteredOutcomesReportAtTheClusterLevel proves the unit rule:
// the claim counts clusters, not the observations inside them, and
// the session-level bound is labeled unjustified.
func TestClusteredOutcomesReportAtTheClusterLevel(t *testing.T) {
	report, err := AnalyzeClusters(clusterObservations(), 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if report.Clusters != 3 || report.Observations != 6 {
		t.Fatalf("scope: %d clusters, %d observations",
			report.Clusters, report.Observations)
	}
	if report.ClusterLevel.Failures != 1 ||
		report.ClusterLevel.Observations != 3 {
		t.Fatalf("cluster level: %+v", report.ClusterLevel)
	}
	if report.SessionLevel.Failures != 2 ||
		report.SessionLevel.Observations != 6 {
		t.Fatalf("session level: %+v", report.SessionLevel)
	}
	if report.SessionClaimJustified {
		t.Fatal("a session-level claim was justified with multi-observation " +
			"clusters")
	}
	joined := strings.Join(report.Limitations, " ")
	if !strings.Contains(joined, "not justified") {
		t.Fatalf("limitations: %v", report.Limitations)
	}
	// The sensitivity bound treats the unresolved cluster as failed.
	if report.Sensitivity.Failures != 2 ||
		report.Sensitivity.Observations != 3 {
		t.Fatalf("sensitivity: %+v", report.Sensitivity)
	}
}

// TestSingletonClustersJustifyTheSessionLevel is the one case where
// the observation-level claim is honest: every cluster holds exactly
// one observation.
func TestSingletonClustersJustifyTheSessionLevel(t *testing.T) {
	report, err := AnalyzeClusters([]ClusterObservation{
		{ClusterID: "cid_cluster-a0001", Failed: true},
		{ClusterID: "cid_cluster-b0002"},
		{ClusterID: "cid_cluster-c0003"},
	}, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if !report.SessionClaimJustified {
		t.Fatal("singleton clusters did not justify the session level")
	}
	if report.ClusterLevel.Observations !=
		report.SessionLevel.Observations {
		t.Fatalf("units diverge on singletons: %+v vs %+v",
			report.ClusterLevel, report.SessionLevel)
	}
}

// TestClusterAnalysisRefusesBadInput fails closed: no observations, a
// bad confidence, and a malformed cluster id.
func TestClusterAnalysisRefusesBadInput(t *testing.T) {
	if _, err := AnalyzeClusters(nil, 0.95); err == nil {
		t.Fatal("empty input accepted")
	}
	if _, err := AnalyzeClusters(clusterObservations(), 1.0); err == nil {
		t.Fatal("confidence 1.0 accepted")
	}
	broken := []ClusterObservation{{ClusterID: "cluster-nope"}}
	if _, err := AnalyzeClusters(broken, 0.95); err == nil {
		t.Fatal("a malformed cluster id was accepted")
	}
}

// TestSequentialLooksReleaseOnlyAtThePreregisteredSchedule proves the
// union-bound boundary: release needs the per-look upper bound under
// the threshold, and the final look without release is inconclusive.
func TestSequentialLooksReleaseOnlyAtThePreregisteredSchedule(t *testing.T) {
	boundary, err := NewSequentialBoundary(0.05, []int{500, 2000, 8000})
	if err != nil {
		t.Fatal(err)
	}
	// Look 1: 0 failures in 500 — continue or release depending on the
	// threshold; with a 1% threshold the first look already releases.
	first, err := boundary.Evaluate(1, 0, 500, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if first.Verdict != VerdictRelease {
		t.Fatalf("look 1: %s (bound %v)", first.Verdict, first.UpperBound)
	}
	if first.PerLookAlpha > 0.05/3+1e-12 || first.PerLookAlpha <= 0 {
		t.Fatalf("per-look alpha: %v", first.PerLookAlpha)
	}
	// Two failures at look 1 against a tight threshold continues.
	continues, err := boundary.Evaluate(1, 2, 500, 0.0001)
	if err != nil {
		t.Fatal(err)
	}
	if continues.Verdict != VerdictContinue {
		t.Fatalf("look 1 with failures: %s", continues.Verdict)
	}
	// The final look without release is inconclusive, never a pass.
	final, err := boundary.Evaluate(3, 2, 8000, 0.000001)
	if err != nil {
		t.Fatal(err)
	}
	if final.Verdict != VerdictInconclusive {
		t.Fatalf("final look: %s", final.Verdict)
	}
	if !strings.Contains(strings.Join(final.Limitations, " "),
		"union bound") {
		t.Fatalf("limitations: %v", final.Limitations)
	}
}

// TestSequentialEvaluationOutsideTheScheduleIsRefused is the
// anti-gaming rule: a look at an unregistered cohort size, a look
// past the schedule, and a malformed schedule all fail closed.
func TestSequentialEvaluationOutsideTheScheduleIsRefused(t *testing.T) {
	if _, err := NewSequentialBoundary(0.05, nil); err == nil {
		t.Fatal("an empty schedule was accepted")
	}
	if _, err := NewSequentialBoundary(0.05, []int{100, 50}); err == nil {
		t.Fatal("a shrinking schedule was accepted")
	}
	if _, err := NewSequentialBoundary(1.5, []int{100}); err == nil {
		t.Fatal("alpha 1.5 was accepted")
	}
	boundary, err := NewSequentialBoundary(0.05, []int{500, 2000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.Evaluate(1, 0, 501, 0.01); err == nil {
		t.Fatal("an off-schedule cohort size was accepted")
	} else if !strings.Contains(err.Error(), "not a sequential test") {
		t.Fatalf("error: %v", err)
	}
	if _, err := boundary.Evaluate(3, 0, 8000, 0.01); err == nil {
		t.Fatal("a look past the schedule was accepted")
	}
	if _, err := boundary.Evaluate(1, 0, 500, 1.5); err == nil {
		t.Fatal("a threshold outside (0, 1) was accepted")
	}
}

// TestWeightedStrataReportSeparately proves the pooling rule: sampled
// strata report their own exact bounds plus point estimates, and the
// pooled exact bound exists only for a full census.
func TestWeightedStrataReportSeparately(t *testing.T) {
	report, err := AnalyzeStrata([]SampleStratum{
		{ID: "str_core-tasks", Population: 10000, Selected: 1000,
			Failures: 0, InclusionProbability: 0.1},
		{ID: "str_long-tasks", Population: 500, Selected: 50,
			Failures: 1, InclusionProbability: 0.1},
	}, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if report.Census {
		t.Fatal("sampled strata read as a census")
	}
	if report.PooledBound != nil {
		t.Fatal("a pooled exact bound appeared for sampled strata")
	}
	if !strings.Contains(report.PooledRefusal, "exact formula") {
		t.Fatalf("pooled refusal: %q", report.PooledRefusal)
	}
	if len(report.Strata) != 2 {
		t.Fatalf("strata: %d", len(report.Strata))
	}
	long := report.Strata[1]
	if long.Stratum.ID != "str_long-tasks" {
		t.Fatalf("strata not sorted: %+v", report.Strata)
	}
	// Horvitz-Thompson point estimates only: 1 failure at a 10%
	// inclusion rate estimates 10 failures in a population of 500.
	if long.EstimatedFailures != 10 || long.EstimatedRate != 0.02 {
		t.Fatalf("estimates: %+v", long)
	}
	joined := strings.Join(report.Limitations, " ")
	if !strings.Contains(joined, "point estimates only") {
		t.Fatalf("limitations: %v", report.Limitations)
	}
	// A census pools: exact arithmetic needs no weights.
	census, err := AnalyzeStrata([]SampleStratum{
		{ID: "str_small-full", Population: 40, Selected: 40,
			Failures: 1, InclusionProbability: 1},
	}, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if !census.Census || census.PooledBound == nil {
		t.Fatalf("census report: %+v", census)
	}
	if census.PooledBound.Observations != 40 ||
		census.PooledBound.Failures != 1 {
		t.Fatalf("pooled bound: %+v", census.PooledBound)
	}
}

// TestStratumValidationRefusesBadShapes fails closed on every
// nonsense stratum.
func TestStratumValidationRefusesBadShapes(t *testing.T) {
	cases := []struct {
		name   string
		strata []SampleStratum
	}{
		{"empty", nil},
		{"no id", []SampleStratum{{ID: "", Population: 10,
			Selected: 1, InclusionProbability: 0.1}}},
		{"duplicate", []SampleStratum{
			{ID: "str_dup", Population: 10, Selected: 1,
				InclusionProbability: 0.1},
			{ID: "str_dup", Population: 10, Selected: 1,
				InclusionProbability: 0.1}}},
		{"zero population", []SampleStratum{{ID: "str_zero",
			Population: 0, InclusionProbability: 1}}},
		{"probability above one", []SampleStratum{{ID: "str_over",
			Population: 10, Selected: 5, InclusionProbability: 1.5}}},
		{"probability zero", []SampleStratum{{ID: "str_never",
			Population: 10, Selected: 5, InclusionProbability: 0}}},
		{"selected over population", []SampleStratum{{ID: "str_greedy",
			Population: 10, Selected: 11, InclusionProbability: 1}}},
		{"failures over selected", []SampleStratum{{ID: "str_wrong",
			Population: 10, Selected: 2, Failures: 3,
			InclusionProbability: 1}}},
	}
	for _, testCase := range cases {
		if _, err := AnalyzeStrata(testCase.strata, 0.95); err == nil {
			t.Fatalf("%s: accepted", testCase.name)
		}
	}
	if _, err := AnalyzeStrata([]SampleStratum{
		{ID: "str_ok", Population: 10, Selected: 2,
			InclusionProbability: 0.5},
	}, 0); err == nil {
		t.Fatal("confidence 0 accepted")
	}
}

// TestHolmAndBonferroniAdjustTheFamily plants four p-values with a
// known Holm ordering and checks both methods' arithmetic and
// rejections.
func TestHolmAndBonferroniAdjustTheFamily(t *testing.T) {
	comparisons := []RawComparison{
		{Name: "contextual_vs_baseline", PValue: 0.001},
		{Name: "classifier_vs_baseline", PValue: 0.008},
		{Name: "session_vs_baseline", PValue: 0.030},
		{Name: "fullcall_vs_baseline", PValue: 0.120},
	}
	holm, err := AdjustForMultipleComparisons(
		comparisons, MethodHolm, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]AdjustedComparison{}
	for _, comparison := range holm.Comparisons {
		byName[comparison.Name] = comparison
	}
	// Holm multiplies the sorted p-values by m, m-1, ...: 0.008*3 is
	// 0.024, and the running maximum carries it.
	if got := byName["classifier_vs_baseline"].Adjusted; got != 0.024 {
		t.Fatalf("holm classifier adjusted: %v, want 0.024", got)
	}
	// 0.001*4 = 0.004; 0.008*3 = 0.024; 0.030*2 = 0.06 — the third
	// comparison stops rejecting (0.030 > 0.05/2).
	for name, reject := range map[string]bool{
		"contextual_vs_baseline": true,
		"classifier_vs_baseline": true,
		"session_vs_baseline":    false,
		"fullcall_vs_baseline":   false,
	} {
		if byName[name].Reject != reject {
			t.Fatalf("holm %s reject: %v, want %v", name,
				byName[name].Reject, reject)
		}
	}
	bonf, err := AdjustForMultipleComparisons(
		comparisons, MethodBonferroni, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	for _, comparison := range bonf.Comparisons {
		if comparison.Name == "classifier_vs_baseline" {
			if comparison.Adjusted != 0.032 {
				t.Fatalf("bonferroni classifier: %v", comparison.Adjusted)
			}
			if !comparison.Reject {
				t.Fatal("bonferroni should reject 0.008 at m=4, alpha 0.05")
			}
		}
	}
	// Holm is never more conservative than Bonferroni.
	for _, comparison := range holm.Comparisons {
		if comparison.Adjusted >
			bonf.Comparisons[indexOf(bonf.Comparisons, comparison.Name)].Adjusted {
			t.Fatalf("holm more conservative than bonferroni at %s",
				comparison.Name)
		}
	}
}

func indexOf(comparisons []AdjustedComparison, name string) int {
	for i, comparison := range comparisons {
		if comparison.Name == name {
			return i
		}
	}
	return -1
}

// TestComparisonAdjustmentRefusesBadInput fails closed: no
// comparisons, p-values outside [0, 1], an unknown method.
func TestComparisonAdjustmentRefusesBadInput(t *testing.T) {
	if _, err := AdjustForMultipleComparisons(nil, MethodHolm, 0.05); err == nil {
		t.Fatal("an empty family was accepted")
	}
	bad := []RawComparison{{Name: "a", PValue: 1.5}}
	if _, err := AdjustForMultipleComparisons(bad, MethodHolm, 0.05); err == nil {
		t.Fatal("a p-value above 1 was accepted")
	}
	unnamed := []RawComparison{{Name: "", PValue: 0.5}}
	if _, err := AdjustForMultipleComparisons(unnamed, MethodHolm, 0.05); err == nil {
		t.Fatal("an unnamed comparison was accepted")
	}
	ok := []RawComparison{{Name: "a", PValue: 0.5}}
	if _, err := AdjustForMultipleComparisons(ok, "benjamini", 0.05); err == nil {
		t.Fatal("an unknown method was accepted")
	}
	if _, err := AdjustForMultipleComparisons(ok, MethodHolm, 0); err == nil {
		t.Fatal("alpha 0 was accepted")
	}
}

// TestASamplingPlanNeedsTheUniformSentinel proves the allocation rule
// of spec 15.1: the uniform sample is mandatory and nonzero, and
// risk-routed strata are additional.
func TestASamplingPlanNeedsTheUniformSentinel(t *testing.T) {
	if err := (AuditSamplingPlan{}).Validate(); err == nil {
		t.Fatal("an empty plan was accepted")
	}
	if err := (AuditSamplingPlan{Strata: []SamplingStratumPlan{
		{Kind: StratumRiskTriggered, Rule: "detector_high", Rate: 1},
	}}).Validate(); err == nil {
		t.Fatal("a risk-only plan was accepted: risk is additional, " +
			"never a substitute")
	} else if !strings.Contains(err.Error(), "never a substitute") {
		t.Fatalf("error: %v", err)
	}
	if err := (AuditSamplingPlan{Strata: []SamplingStratumPlan{
		{Kind: StratumUniformSentinel, Rate: 0},
	}}).Validate(); err == nil {
		t.Fatal("a zero-rate sentinel was accepted")
	}
	if err := (AuditSamplingPlan{Strata: []SamplingStratumPlan{
		{Kind: StratumUniformSentinel, Rate: 0.01},
		{Kind: StratumRiskTriggered},
	}}).Validate(); err == nil {
		t.Fatal("a rule-less trigger stratum was accepted")
	}
	if err := (AuditSamplingPlan{Strata: []SamplingStratumPlan{
		{Kind: "vibes", Rate: 0.5},
	}}).Validate(); err == nil {
		t.Fatal("an unknown stratum kind was accepted")
	}
	if err := (AuditSamplingPlan{Strata: []SamplingStratumPlan{
		{Kind: StratumUniformSentinel, Rate: 0.01},
		{Kind: StratumUniformSentinel, Rate: 0.02},
	}}).Validate(); err == nil {
		t.Fatal("two sentinel strata were accepted")
	}
	valid := AuditSamplingPlan{Strata: []SamplingStratumPlan{
		{Kind: StratumUniformSentinel, Rate: 0.01},
		{Kind: StratumRiskTriggered, Rule: "detector_high", Rate: 1},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid plan was refused: %v", err)
	}
}

// TestKeyedInclusionIsDeterministicAndRateBound proves the keyed draw:
// the same key and unit always decide the same way, the rate bounds
// the realized fraction, and the key id is a fingerprint, not the key.
func TestKeyedInclusionIsDeterministicAndRateBound(t *testing.T) {
	key := []byte("sampling-key-fixture-2026q3")
	first := KeyedInclusion(key, StratumUniformSentinel, "evt_unit0001", 0.5)
	for i := 0; i < 5; i++ {
		if got := KeyedInclusion(key, StratumUniformSentinel,
			"evt_unit0001", 0.5); got != first {
			t.Fatal("the keyed draw is not deterministic")
		}
	}
	// A different stratum label is a different draw space.
	other := KeyedInclusion(key, StratumRiskTriggered, "evt_unit0001", 0.5)
	// Not asserted unequal (they may collide); the check is that both
	// spaces exist. The rate bound is what must hold.
	_ = other
	drawn, total := 0, 10000
	for i := 0; i < total; i++ {
		unit := "evt_" + strings.Repeat("0", 12) +
			strings.Repeat("a", 2) + string(rune('a'+i%26)) +
			string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
		if KeyedInclusion(key, StratumUniformSentinel, unit, 0.1) {
			drawn++
		}
	}
	// A 10% keyed draw of 10,000 units lands near 10%: keyed hashing
	// spreads uniformly. Generous bounds keep the test deterministic
	// in principle — the HMAC output is fixed for these exact inputs.
	if drawn < 800 || drawn > 1200 {
		t.Fatalf("keyed 10%% draw selected %d of %d", drawn, total)
	}
	// Rate 1 draws everything; rate 0 draws nothing.
	allDrawn := true
	for i := 0; i < 100; i++ {
		unit := "evt_" + strings.Repeat("1", 12) + string(rune('a'+i%26))
		if !KeyedInclusion(key, StratumUniformSentinel, unit, 1) {
			allDrawn = false
		}
		if KeyedInclusion(key, StratumUniformSentinel, unit, 0) {
			t.Fatal("rate 0 drew a unit")
		}
	}
	if !allDrawn {
		t.Fatal("rate 1 missed a unit")
	}
	if id := InclusionKeyID(key); !strings.HasPrefix(id, "hmk_") ||
		strings.Contains(id, string(key)) {
		t.Fatalf("key id: %q", id)
	}
}

// TestPopulationRatesComeFromTheUniformStratumOnly proves the
// disclosure rule: the population bound draws on the uniform stratum
// alone, and an empty uniform stratum produces no population rate.
func TestPopulationRatesComeFromTheUniformStratumOnly(t *testing.T) {
	bound, err := PopulationRateFromUniform(1000, 1, 0.95)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Unit != "population_rate_from_uniform_sentinel" ||
		bound.Observations != 1000 {
		t.Fatalf("bound: %+v", bound)
	}
	if bound.UpperBound <= 0.001 {
		t.Fatalf("one failure in 1000 should bound above 0.1%%: %v",
			bound.UpperBound)
	}
	if _, err := PopulationRateFromUniform(0, 0, 0.95); err == nil {
		t.Fatal("an empty uniform stratum produced a population rate")
	}
}
