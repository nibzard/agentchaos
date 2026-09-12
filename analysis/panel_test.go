package analysis

// Panel evaluation tests (T051, spec 11.4, AC-029).
//
// Planted outcomes with known ground truth prove the measurement:
// the panel is compared against the best single reviewer plus rules
// on the same cases, co-miss is conditional on the same incidents,
// agreement stays a diagnostic, and the recommendation follows the
// spec's rule — remove the panel when it does not improve outcomes.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	bestSingle  = "act_sentinel-best001"
	memberAlpha = "mem-alpha"
	memberBeta  = "mem-beta"
	memberGamma = "mem-gamma"
)

// obs builds one observation with the fixture member set and matched
// per-case costs. Members cost 30 micros each (90 for the panel of
// three) against the single reviewer's 100, so the comparison runs at
// matched cost unless a test says otherwise.
func obs(caseID string, incident, alpha, beta, gamma,
	bestHit bool) PanelObservation {
	return PanelObservation{
		CaseID:   caseID,
		Incident: incident,
		MemberHits: map[string]bool{
			memberAlpha: alpha, memberBeta: beta, memberGamma: gamma,
		},
		PanelCostMicros:      90,
		PanelLatencyMS:       30,
		BestSingleID:         bestSingle,
		BestSingleHit:        bestHit,
		BestSingleCostMicros: 100,
		BestSingleLatencyMS:  100,
	}
}

// tenIncidents gives the canonical fixture: ten incidents where the
// best single reviewer misses three and the three-member panel — with
// independent blind spots — misses one.
func tenIncidents() []PanelObservation {
	out := []PanelObservation{}
	for i := 0; i < 10; i++ {
		id := strings.Repeat("0", 2) + string(rune('a'+i))
		out = append(out, obs("case_"+id, true,
			true, true, true, true)) // everyone catches it
	}
	// The single reviewer misses three; each time some member still
	// catches it, so the panel holds.
	out[3] = obs("case_03", true, true, true, false, false)
	out[5] = obs("case_05", true, true, false, true, false)
	out[8] = obs("case_08", true, false, true, true, false)
	// One case slips past every member while the single reviewer
	// catches it: the panel's co-miss is real, not inherited.
	out[6] = obs("case_06", true, false, false, false, true)
	return out
}

// TestThePanelIsComparedAgainstTheBestSingleReviewer is the matched
// comparison of AC-029: recall for both sides over the same incidents,
// the co-miss incident named, and a keep recommendation that quotes
// both denominators.
func TestThePanelIsComparedAgainstTheBestSingleReviewer(t *testing.T) {
	observations := append(tenIncidents(),
		obs("case_benign01", false, false, false, false, false),
		obs("case_benign02", false, false, false, false, false),
	)
	report, err := EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	if report.PanelRecall.Numerator != 9 ||
		report.PanelRecall.Denominator != 10 {
		t.Fatalf("panel recall: %+v", report.PanelRecall)
	}
	if report.BestSingleRecall.Numerator != 7 ||
		report.BestSingleRecall.Denominator != 10 {
		t.Fatalf("single recall: %+v", report.BestSingleRecall)
	}
	if report.CoMiss.Numerator != 1 || report.CoMiss.Denominator != 10 {
		t.Fatalf("co-miss: %+v", report.CoMiss)
	}
	if len(report.CoMissedIncidents) != 1 ||
		report.CoMissedIncidents[0] != "case_06" {
		t.Fatalf("co-missed incidents: %v", report.CoMissedIncidents)
	}
	if report.BestSingleID != bestSingle {
		t.Fatalf("baseline: %q", report.BestSingleID)
	}
	if report.Recommendation != RecommendationKeep {
		t.Fatalf("recommendation: %s (%s)", report.Recommendation,
			report.RecommendationReason)
	}
	if !strings.Contains(report.RecommendationReason, "9 of 10") ||
		!strings.Contains(report.RecommendationReason, "7") {
		t.Fatalf("reason: %q", report.RecommendationReason)
	}
	if !report.CostMatched {
		t.Fatalf("costs should match: %+v", report)
	}
	if report.Kind != "PanelEvaluationReport" ||
		report.Profile != ProfilePanel {
		t.Fatalf("header: %+v", report)
	}
}

// TestAPanelThatDoesNotImproveIsRemoved enforces the removal rule: a
// panel whose union catches no more incidents than the single
// reviewer goes, whatever its agreement numbers look like.
func TestAPanelThatDoesNotImproveIsRemoved(t *testing.T) {
	// The single reviewer catches everything the panel catches, plus
	// one more.
	observations := []PanelObservation{
		obs("case_01", true, true, true, true, true),
		obs("case_02", true, true, true, false, true),
		obs("case_03", true, false, false, false, true),
		obs("case_04", false, false, false, false, false),
	}
	report, err := EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	if report.PanelRecall.Numerator != 2 ||
		report.BestSingleRecall.Numerator != 3 {
		t.Fatalf("recall: %+v vs %+v", report.PanelRecall,
			report.BestSingleRecall)
	}
	if report.Recommendation != RecommendationRemove {
		t.Fatalf("recommendation: %s (%s)", report.Recommendation,
			report.RecommendationReason)
	}
	if !strings.Contains(report.RecommendationReason, "removed") {
		t.Fatalf("reason: %q", report.RecommendationReason)
	}
	// Equal recall is also no improvement.
	observations[2] = obs("case_03", true, true, false, false, true)
	report, err = EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	if report.Recommendation != RecommendationRemove {
		t.Fatalf("equal recall kept the panel: %s",
			report.RecommendationReason)
	}
}

// TestAPanelThatAddsFalseInterventionsIsRemoved covers the second
// removal path: more catches, bought with more escalations on benign
// tasks than the single reviewer makes.
func TestAPanelThatAddsFalseInterventionsIsRemoved(t *testing.T) {
	observations := []PanelObservation{
		obs("case_01", true, true, true, true, false),
		obs("case_02", true, true, true, false, false),
		obs("case_benign01", false, true, false, false, false),
		obs("case_benign02", false, false, false, false, false),
	}
	report, err := EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	if report.PanelRecall.Numerator != 2 ||
		report.BestSingleRecall.Numerator != 0 {
		t.Fatalf("recall: %+v vs %+v", report.PanelRecall,
			report.BestSingleRecall)
	}
	if report.PanelFalseInterventions.Numerator != 1 ||
		report.BestSingleFalseInterventions.Numerator != 0 {
		t.Fatalf("false interventions: %+v vs %+v",
			report.PanelFalseInterventions,
			report.BestSingleFalseInterventions)
	}
	if report.Recommendation != RecommendationRemove {
		t.Fatalf("recommendation: %s (%s)", report.Recommendation,
			report.RecommendationReason)
	}
	if !strings.Contains(report.RecommendationReason, "benign") {
		t.Fatalf("reason: %q", report.RecommendationReason)
	}
}

// TestCoMissIsConditionalOnEvidenceContamination splits the same
// incidents into cohorts: co-miss under contaminated evidence is
// reported separately from co-miss on clean evidence, each with its
// own denominator.
func TestCoMissIsConditionalOnEvidenceContamination(t *testing.T) {
	observations := []PanelObservation{
		// Four contaminated incidents: two co-missed, two caught.
		contaminated(obs("case_c1", true, false, false, false, false)),
		contaminated(obs("case_c2", true, false, false, false, false)),
		contaminated(obs("case_c3", true, true, false, false, true)),
		contaminated(obs("case_c4", true, false, true, false, true)),
		// Six clean incidents: all caught, none co-missed.
		obs("case_k1", true, true, true, true, true),
		obs("case_k2", true, true, false, true, true),
		obs("case_k3", true, true, true, true, true),
		obs("case_k4", true, false, true, true, true),
		obs("case_k5", true, true, true, false, true),
		obs("case_k6", true, true, true, true, true),
		obs("case_benign01", false, false, false, false, false),
	}
	report, err := EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	byCondition := map[string]Fraction{}
	for _, conditional := range report.ConditionalCoMiss {
		byCondition[conditional.Condition] = conditional.CoMiss
	}
	if got := byCondition[ConditionContaminatedEvidence]; got.Numerator != 2 ||
		got.Denominator != 4 {
		t.Fatalf("contaminated co-miss: %+v, want 2/4", got)
	}
	if got := byCondition[ConditionCleanEvidence]; got.Numerator != 0 ||
		got.Denominator != 6 {
		t.Fatalf("clean co-miss: %+v, want 0/6", got)
	}
	if report.CoMiss.Numerator != 2 || report.CoMiss.Denominator != 10 {
		t.Fatalf("overall co-miss: %+v, want 2/10", report.CoMiss)
	}
}

// TestCoMissWithToolFailureIsASeparateCohort keeps a common tool
// failure from reading as model blindness.
func TestCoMissWithToolFailureIsASeparateCohort(t *testing.T) {
	toolFailed := obs("case_t1", true, false, false, false, false)
	toolFailed.ToolFailure = true
	observations := []PanelObservation{
		toolFailed,
		obs("case_t2", true, false, false, false, false),
		obs("case_t3", true, true, true, true, true),
		obs("case_benign01", false, false, false, false, false),
	}
	report, err := EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	byCondition := map[string]Fraction{}
	for _, conditional := range report.ConditionalCoMiss {
		byCondition[conditional.Condition] = conditional.CoMiss
	}
	if got := byCondition[ConditionToolFailure]; got.Numerator != 1 ||
		got.Denominator != 1 {
		t.Fatalf("tool-failure co-miss: %+v, want 1/1", got)
	}
	if got := byCondition[ConditionNoToolFailure]; got.Numerator != 1 ||
		got.Denominator != 2 {
		t.Fatalf("no-tool-failure co-miss: %+v, want 1/2", got)
	}
}

func contaminated(o PanelObservation) PanelObservation {
	o.ContaminatedEvidence = true
	return o
}

// TestCollusiveAgreementIsFlaggedButNeverCertifies plants the
// collusive signature: two members with identical outcomes on every
// case while incidents still slip past the whole panel. The report
// flags the pair and keeps repeating that agreement is a diagnostic.
func TestCollusiveAgreementIsFlaggedButNeverCertifies(t *testing.T) {
	observations := []PanelObservation{
		// Alpha and beta always agree; gamma differs sometimes.
		obs("case_01", true, true, true, false, true),
		obs("case_02", true, false, false, true, false),
		obs("case_03", true, false, false, false, false),
		obs("case_benign01", false, false, false, true, false),
	}
	report, err := EvaluatePanel(observations)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CollusiveAgreement {
		t.Fatal("the collusive pair was not flagged")
	}
	if len(report.CollusivePairs) != 1 ||
		report.CollusivePairs[0] != "mem-alpha+mem-beta" {
		t.Fatalf("collusive pairs: %v", report.CollusivePairs)
	}
	flagged := false
	for _, limitation := range report.Limitations {
		if strings.Contains(limitation, "mem-alpha+mem-beta") &&
			strings.Contains(limitation, "correlated reviewers") {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("limitations: %v", report.Limitations)
	}
	if !strings.Contains(strings.Join(report.Limitations, " "),
		"not a statistical independence certificate") {
		t.Fatalf("the scope note is missing: %v", report.Limitations)
	}
}

// TestAgreementIsMeasuredPairwiseAndSplit checks the agreement matrix
// shape: every unordered member pair, with incident and benign
// denominators.
func TestAgreementIsMeasuredPairwiseAndSplit(t *testing.T) {
	report, err := EvaluatePanel([]PanelObservation{
		obs("case_01", true, true, true, false, true),
		obs("case_02", true, false, false, true, false),
		obs("case_benign01", false, false, false, false, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agreement) != 3 {
		t.Fatalf("agreement pairs: %d, want 3", len(report.Agreement))
	}
	for _, pair := range report.Agreement {
		if pair.Agreement.Denominator != 3 {
			t.Fatalf("pair %s+%s denominator: %+v", pair.A, pair.B,
				pair.Agreement)
		}
		if pair.OnIncidents.Denominator != 2 ||
			pair.OnBenign.Denominator != 1 {
			t.Fatalf("pair %s+%s split: %+v %+v", pair.A, pair.B,
				pair.OnIncidents, pair.OnBenign)
		}
	}
}

// TestInconsistentInputIsRefusedWhole covers every refusal: no
// observations, a missing case id, empty member outcomes, a member set
// that changes mid-evaluation, a switched baseline, and a negative
// cost.
func TestInconsistentInputIsRefusedWhole(t *testing.T) {
	if _, err := EvaluatePanel(nil); err == nil {
		t.Fatal("empty input accepted")
	}
	noID := []PanelObservation{obs("", true, true, true, true, true)}
	if _, err := EvaluatePanel(noID); err == nil {
		t.Fatal("missing case id accepted")
	}
	empty := obs("case_01", true, true, true, true, true)
	empty.MemberHits = map[string]bool{}
	if _, err := EvaluatePanel([]PanelObservation{empty}); err == nil {
		t.Fatal("empty member outcomes accepted")
	}
	extra := obs("case_02", true, true, true, true, true)
	extra.MemberHits["mem-extra"] = true
	if _, err := EvaluatePanel([]PanelObservation{
		obs("case_01", true, true, true, true, true), extra,
	}); err == nil {
		t.Fatal("a growing member set accepted")
	} else if !strings.Contains(err.Error(), "constant") {
		t.Fatalf("error: %v", err)
	}
	missing := obs("case_02", true, true, true, false, true)
	delete(missing.MemberHits, memberGamma)
	if _, err := EvaluatePanel([]PanelObservation{
		obs("case_01", true, true, true, true, true), missing,
	}); err == nil {
		t.Fatal("a shrinking member set accepted")
	}
	switched := obs("case_02", true, true, true, true, true)
	switched.BestSingleID = "act_sentinel-other1"
	if _, err := EvaluatePanel([]PanelObservation{
		obs("case_01", true, true, true, true, true), switched,
	}); err == nil {
		t.Fatal("a switched baseline accepted")
	} else if !strings.Contains(err.Error(), "one baseline") {
		t.Fatalf("error: %v", err)
	}
	negative := obs("case_01", true, true, true, true, true)
	negative.BestSingleCostMicros = -1
	if _, err := EvaluatePanel([]PanelObservation{negative}); err == nil {
		t.Fatal("a negative cost accepted")
	}
}

// TestUnmeasuredCohortsStayExplicit proves the disclosure rules: an
// incidents-only evaluation reports false interventions with a zero
// denominator and says so, and cost mismatch is disclosed, not
// amortized away.
func TestUnmeasuredCohortsStayExplicit(t *testing.T) {
	report, err := EvaluatePanel([]PanelObservation{
		obs("case_01", true, true, true, true, true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.PanelFalseInterventions.Denominator != 0 {
		t.Fatalf("benign denominator: %+v",
			report.PanelFalseInterventions)
	}
	joined := strings.Join(report.Limitations, " ")
	if !strings.Contains(joined, "not measured") {
		t.Fatalf("limitations: %v", report.Limitations)
	}
	// A panel that costs more than the single reviewer is disclosed.
	costly := []PanelObservation{
		obs("case_01", true, true, true, true, false),
		obs("case_benign01", false, false, false, false, false),
	}
	costly[0].PanelCostMicros = 500
	costly[1].PanelCostMicros = 500
	costlyReport, err := EvaluatePanel(costly)
	if err != nil {
		t.Fatal(err)
	}
	if costlyReport.CostMatched {
		t.Fatal("a costlier panel read as matched")
	}
	if !strings.Contains(strings.Join(costlyReport.Limitations, " "),
		"not at matched cost") {
		t.Fatalf("limitations: %v", costlyReport.Limitations)
	}
	if costlyReport.Recommendation != RecommendationKeep {
		t.Fatalf("recommendation: %s (%s)",
			costlyReport.Recommendation,
			costlyReport.RecommendationReason)
	}
	if !strings.Contains(costlyReport.RecommendationReason,
		"higher cost") {
		t.Fatalf("reason: %q", costlyReport.RecommendationReason)
	}
}

// TestPanelEvaluationIsDeterministic runs the same observations twice
// and compares the canonical JSON.
func TestPanelEvaluationIsDeterministic(t *testing.T) {
	first, err := EvaluatePanel(tenIncidents())
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluatePanel(tenIncidents())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatalf("two runs of the same input differ:\n%s\n%s", a, b)
	}
}
