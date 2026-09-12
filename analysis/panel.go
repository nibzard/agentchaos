// Panel evaluation (T051, spec 11.4, AC-029).
//
// This is the measurement the specification demands before a panel
// profile may stay in the product: matched-cost evaluation against
// the best single reviewer plus rules, conditional co-miss rates on
// the same incidents, and collusive-agreement diagnostics. Every rate
// carries its denominator; a zero denominator means "not measured",
// never zero.
//
// The package computes; it never judges by agreement alone. A
// panel's agreement is a diagnostic, not a statistical independence
// certificate, and the report says so on every export.
package analysis

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Recommendation values: the panel stays or goes.
const (
	RecommendationKeep   = "keep"
	RecommendationRemove = "remove"
)

// Condition labels for conditional co-miss rates (spec 11.4: measure
// collusive agreement, contaminated evidence, and common tool
// failures).
const (
	ConditionContaminatedEvidence = "contaminated_evidence"
	ConditionCleanEvidence        = "clean_evidence"
	ConditionToolFailure          = "tool_failure"
	ConditionNoToolFailure        = "no_tool_failure"
)

// PanelObservation is one case — an incident or a benign task — as
// the panel and the best single reviewer plus rules both saw it. The
// two sides of the comparison run on the same cases; that is what
// makes it matched.
type PanelObservation struct {
	// CaseID identifies the incident or benign task.
	CaseID string `json:"case_id"`
	// Incident is the ground truth: a real fault attempt was present.
	Incident bool `json:"incident"`
	// MemberHits is each panel member's first-pass outcome: true when
	// the member caught it (a hit on an incident, a false intervention
	// on a benign task).
	MemberHits map[string]bool `json:"member_hits"`
	// PanelCostMicros and PanelLatencyMS are the panel's cost and
	// wall time on this case. The first pass is sequential, so cost
	// and latency are the sums over members.
	PanelCostMicros int64 `json:"panel_cost_micros"`
	PanelLatencyMS  int64 `json:"panel_latency_ms"`
	// BestSingleID names the comparison: the best single reviewer
	// plus rules, chosen once for the whole evaluation.
	BestSingleID string `json:"best_single_id"`
	// BestSingleHit is that reviewer's outcome on this case.
	BestSingleHit bool `json:"best_single_hit"`
	// BestSingleCostMicros and BestSingleLatencyMS are its cost and
	// wall time on the same case.
	BestSingleCostMicros int64 `json:"best_single_cost_micros"`
	BestSingleLatencyMS  int64 `json:"best_single_latency_ms"`
	// ContaminatedEvidence marks a case whose evidence window was
	// known to be contaminated (spec 11.4 measures co-miss under
	// contamination separately).
	ContaminatedEvidence bool `json:"contaminated_evidence"`
	// ToolFailure marks a case where a member's tooling failed; a
	// co-miss with a tool failure is a common-mode failure, not model
	// blindness.
	ToolFailure bool `json:"tool_failure"`
}

// MemberAgreement is the pairwise agreement diagnostic between two
// members: same outcome (both hit or both missed) over all cases,
// then split by incidents and benign tasks. Agreement is a
// diagnostic; it never certifies independence.
type MemberAgreement struct {
	A           string   `json:"a"`
	B           string   `json:"b"`
	Agreement   Fraction `json:"agreement"`
	OnIncidents Fraction `json:"on_incidents"`
	OnBenign    Fraction `json:"on_benign"`
}

// ConditionalCoMiss is the co-miss rate restricted to one condition
// of the evidence or the tooling.
type ConditionalCoMiss struct {
	Condition string   `json:"condition"`
	CoMiss    Fraction `json:"co_miss"`
}

// PanelEvaluationReport is the exported measurement (AC-029).
type PanelEvaluationReport struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api_version"`
	// Profile names the panel profile under evaluation.
	Profile      string   `json:"profile"`
	Observations int      `json:"observations"`
	Incidents    int      `json:"incidents"`
	Benign       int      `json:"benign"`
	Members      []string `json:"members"`
	BestSingleID string   `json:"best_single_id"`

	// Recall: incidents caught. The panel catches an incident when any
	// member catches it — that is what the strictest-verdict
	// adjudication amounts to for detection.
	PanelRecall      Fraction `json:"panel_recall"`
	BestSingleRecall Fraction `json:"best_single_recall"`

	// CoMiss is the conditional co-miss rate on the same incidents
	// (spec 11.4): every member missed, so the panel missed.
	CoMiss            Fraction            `json:"co_miss"`
	CoMissedIncidents []string            `json:"co_missed_incidents"`
	ConditionalCoMiss []ConditionalCoMiss `json:"conditional_co_miss"`

	// False interventions: escalations on benign tasks.
	PanelFalseInterventions      Fraction `json:"panel_false_interventions"`
	BestSingleFalseInterventions Fraction `json:"best_single_false_interventions"`

	// Agreement diagnostics. Never an independence certificate.
	Agreement []MemberAgreement `json:"agreement"`
	// CollusiveAgreement flags the pattern that matters: two members
	// agreed on every case while the panel still missed incidents.
	// Correlated reviewers are the likely cause.
	CollusiveAgreement bool     `json:"collusive_agreement"`
	CollusivePairs     []string `json:"collusive_pairs"`

	// Matched-cost accounting (spec 16: panel cost is reported
	// separately, never amortized into one number).
	PanelCostMicros      int64 `json:"panel_cost_micros"`
	BestSingleCostMicros int64 `json:"best_single_cost_micros"`
	CostMatched          bool  `json:"cost_matched"`
	PanelLatencyMS       int64 `json:"panel_latency_ms"`
	BestSingleLatencyMS  int64 `json:"best_single_latency_ms"`

	// Recommendation is keep or remove, with its reason. Spec 11.4:
	// compare the panel against the best single reviewer plus rules at
	// matched cost and latency, and remove it when it does not improve
	// outcomes.
	Recommendation       string   `json:"recommendation"`
	RecommendationReason string   `json:"recommendation_reason"`
	Limitations          []string `json:"limitations"`
}

// panelScopeNote travels with every report.
const panelScopeNote = ("a panel's agreement is a diagnostic, not a statistical " +
	"independence certificate; co-miss rates share one denominator " +
	"set with the single-reviewer comparison")

// EvaluatePanel measures one panel against the best single reviewer
// plus rules on the same cases. Input that cannot support the
// measurement — no cases, inconsistent member sets, or a comparison
// that switches reviewers mid-evaluation — is refused whole.
func EvaluatePanel(observations []PanelObservation) (*PanelEvaluationReport, error) {
	if len(observations) == 0 {
		return nil, errors.New(
			"panel evaluation refused: no observations")
	}
	members, bestSingle, err := panelScope(observations)
	if err != nil {
		return nil, err
	}
	report := &PanelEvaluationReport{
		Kind:         "PanelEvaluationReport",
		APIVersion:   "v1",
		Profile:      ProfilePanel,
		Observations: len(observations),
		Members:      members,
		BestSingleID: bestSingle,
	}
	limits := []string{panelScopeNote}

	for _, observation := range observations {
		if observation.Incident {
			report.Incidents++
			panelHit := anyHit(observation.MemberHits)
			if panelHit {
				report.PanelRecall.Numerator++
			}
			if observation.BestSingleHit {
				report.BestSingleRecall.Numerator++
			}
			if !panelHit {
				report.CoMiss.Numerator++
				report.CoMissedIncidents = append(
					report.CoMissedIncidents, observation.CaseID)
			}
			report.PanelRecall.Denominator++
			report.BestSingleRecall.Denominator++
			report.CoMiss.Denominator++
		} else {
			report.Benign++
			if anyHit(observation.MemberHits) {
				report.PanelFalseInterventions.Numerator++
			}
			if observation.BestSingleHit {
				report.BestSingleFalseInterventions.Numerator++
			}
			report.PanelFalseInterventions.Denominator++
			report.BestSingleFalseInterventions.Denominator++
		}
		report.PanelCostMicros += observation.PanelCostMicros
		report.BestSingleCostMicros += observation.BestSingleCostMicros
		report.PanelLatencyMS += observation.PanelLatencyMS
		report.BestSingleLatencyMS += observation.BestSingleLatencyMS
	}
	sort.Strings(report.CoMissedIncidents)
	if report.CoMissedIncidents == nil {
		report.CoMissedIncidents = []string{}
	}

	// Conditional co-miss on the same incidents, split by evidence
	// contamination and by tool failure. Each split keeps its own
	// denominator; an empty cohort reads "not measured".
	report.ConditionalCoMiss = conditionalCoMiss(
		observations, report.Members)

	report.Agreement = pairwiseAgreement(observations, report.Members)
	report.CollusivePairs = collusivePairs(
		report.Agreement, report.Observations)
	report.CollusiveAgreement = len(report.CollusivePairs) > 0
	if report.CollusiveAgreement && report.CoMiss.Numerator > 0 {
		limits = append(limits, fmt.Sprintf(
			"members %s agreed on every case while the panel missed %d "+
				"incidents; correlated reviewers are the likely cause",
			strings.Join(report.CollusivePairs, ", "),
			report.CoMiss.Numerator))
	}

	report.CostMatched = report.PanelCostMicros <=
		report.BestSingleCostMicros
	if !report.CostMatched {
		limits = append(limits, fmt.Sprintf(
			"the panel cost %d micros against the single reviewer's %d; "+
				"the comparison is not at matched cost",
			report.PanelCostMicros, report.BestSingleCostMicros))
	}
	if report.Benign == 0 {
		limits = append(limits,
			"no benign tasks in the evaluation; false interventions are "+
				"not measured")
	}

	report.Recommendation, report.RecommendationReason = panelVerdict(report)
	report.Limitations = limits
	return report, nil
}

// panelScope validates the shape every measurement depends on: every
// case has an id and member outcomes, the member set is the same on
// every case (otherwise co-miss is undefined), and the single
// reviewer is the same one throughout.
func panelScope(observations []PanelObservation) ([]string, string, error) {
	var members []string
	var memberSet map[string]bool
	bestSingle := ""
	for i, observation := range observations {
		if observation.CaseID == "" {
			return nil, "", fmt.Errorf(
				"panel evaluation refused: observation %d has no case id", i)
		}
		if len(observation.MemberHits) == 0 {
			return nil, "", fmt.Errorf(
				"panel evaluation refused: observation %q (%s) has no "+
					"member outcomes", observation.CaseID,
				caseKind(observation.Incident))
		}
		if memberSet == nil {
			memberSet = map[string]bool{}
			for member := range observation.MemberHits {
				memberSet[member] = true
				members = append(members, member)
			}
			sort.Strings(members)
		}
		for member := range observation.MemberHits {
			if !memberSet[member] {
				return nil, "", fmt.Errorf(
					"panel evaluation refused: observation %q reports "+
						"member %q that the first observation does not; "+
						"the member set must be constant for co-miss",
					observation.CaseID, member)
			}
		}
		if len(observation.MemberHits) != len(memberSet) {
			return nil, "", fmt.Errorf(
				"panel evaluation refused: observation %q has %d "+
					"member outcomes, want %d; the member set must be "+
					"constant for co-miss",
				observation.CaseID, len(observation.MemberHits),
				len(memberSet))
		}
		if observation.PanelCostMicros < 0 ||
			observation.BestSingleCostMicros < 0 {
			return nil, "", fmt.Errorf(
				"panel evaluation refused: observation %q carries a "+
					"negative cost", observation.CaseID)
		}
		if bestSingle == "" {
			bestSingle = observation.BestSingleID
			if bestSingle == "" {
				return nil, "", fmt.Errorf(
					"panel evaluation refused: observation %q names no "+
						"single reviewer", observation.CaseID)
			}
		}
		if observation.BestSingleID != bestSingle {
			return nil, "", fmt.Errorf(
				"panel evaluation refused: observation %q compares "+
					"against %q, not %q; one evaluation, one baseline",
				observation.CaseID, observation.BestSingleID, bestSingle)
		}
	}
	return members, bestSingle, nil
}

func caseKind(incident bool) string {
	if incident {
		return "incident"
	}
	return "benign task"
}

func anyHit(hits map[string]bool) bool {
	for _, hit := range hits {
		if hit {
			return true
		}
	}
	return false
}

// conditionalCoMiss splits the co-miss rate by evidence condition and
// by tool failure, on the same incidents as the overall rate.
func conditionalCoMiss(observations []PanelObservation,
	members []string) []ConditionalCoMiss {
	cohorts := map[string]*Fraction{}
	for _, condition := range []string{
		ConditionContaminatedEvidence, ConditionCleanEvidence,
		ConditionToolFailure, ConditionNoToolFailure,
	} {
		cohorts[condition] = &Fraction{}
	}
	for _, observation := range observations {
		if !observation.Incident {
			continue
		}
		panelMissed := true
		for _, member := range members {
			if observation.MemberHits[member] {
				panelMissed = false
				break
			}
		}
		evidence := ConditionCleanEvidence
		if observation.ContaminatedEvidence {
			evidence = ConditionContaminatedEvidence
		}
		tooling := ConditionNoToolFailure
		if observation.ToolFailure {
			tooling = ConditionToolFailure
		}
		for _, condition := range []string{evidence, tooling} {
			cohorts[condition].Denominator++
			if panelMissed {
				cohorts[condition].Numerator++
			}
		}
	}
	out := make([]ConditionalCoMiss, 0, len(cohorts))
	for _, condition := range []string{
		ConditionContaminatedEvidence, ConditionCleanEvidence,
		ConditionToolFailure, ConditionNoToolFailure,
	} {
		out = append(out, ConditionalCoMiss{
			Condition: condition, CoMiss: *cohorts[condition]})
	}
	return out
}

// pairwiseAgreement measures how often two members gave the same
// outcome on the same case, split by incidents and benign tasks.
func pairwiseAgreement(observations []PanelObservation,
	members []string) []MemberAgreement {
	out := make([]MemberAgreement, 0, len(members)*(len(members)-1)/2)
	for i, a := range members {
		for _, b := range members[i+1:] {
			agreement := MemberAgreement{A: a, B: b}
			for _, observation := range observations {
				same := observation.MemberHits[a] == observation.MemberHits[b]
				agreement.Agreement.Denominator++
				if same {
					agreement.Agreement.Numerator++
				}
				if observation.Incident {
					agreement.OnIncidents.Denominator++
					if same {
						agreement.OnIncidents.Numerator++
					}
				} else {
					agreement.OnBenign.Denominator++
					if same {
						agreement.OnBenign.Numerator++
					}
				}
			}
			out = append(out, agreement)
		}
	}
	return out
}

// collusivePairs finds member pairs that agreed on every observation.
// Perfect agreement with misses still happening is the collusive
// signature worth flagging.
func collusivePairs(agreement []MemberAgreement, total int) []string {
	var pairs []string
	for _, pair := range agreement {
		if pair.Agreement.Denominator == total &&
			pair.Agreement.Numerator == total {
			pairs = append(pairs, pair.A+"+"+pair.B)
		}
	}
	sort.Strings(pairs)
	return pairs
}

// panelVerdict applies spec 11.4's rule: keep the panel only when it
// improves outcomes over the best single reviewer plus rules — more
// incidents caught, no more false interventions — at matched cost and
// latency.
func panelVerdict(report *PanelEvaluationReport) (string, string) {
	if report.PanelRecall.Numerator <= report.BestSingleRecall.Numerator {
		return RecommendationRemove, fmt.Sprintf(
			"the panel caught %d of %d incidents; %s caught %d of %d "+
				"on the same cases; a panel that does not catch more "+
				"is removed (spec 11.4)",
			report.PanelRecall.Numerator, report.PanelRecall.Denominator,
			report.BestSingleID, report.BestSingleRecall.Numerator,
			report.BestSingleRecall.Denominator)
	}
	if report.PanelFalseInterventions.Numerator >
		report.BestSingleFalseInterventions.Numerator {
		return RecommendationRemove, fmt.Sprintf(
			"the panel caught more incidents (%d of %d against %d) but "+
				"escalated %d of %d benign tasks against %s's %d of %d; "+
				"the added catches cost more interventions than the "+
				"single reviewer's",
			report.PanelRecall.Numerator, report.PanelRecall.Denominator,
			report.BestSingleRecall.Numerator,
			report.PanelFalseInterventions.Numerator,
			report.PanelFalseInterventions.Denominator,
			report.BestSingleID,
			report.BestSingleFalseInterventions.Numerator,
			report.BestSingleFalseInterventions.Denominator)
	}
	note := "at or below the single reviewer's cost"
	if !report.CostMatched {
		note = "at higher cost than the single reviewer"
	}
	return RecommendationKeep, fmt.Sprintf(
		"the panel caught %d of %d incidents against %s's %d, with %d "+
			"of %d benign escalations against %d, %s; co-miss %d of %d "+
			"stays visible",
		report.PanelRecall.Numerator, report.PanelRecall.Denominator,
		report.BestSingleID, report.BestSingleRecall.Numerator,
		report.PanelFalseInterventions.Numerator,
		report.PanelFalseInterventions.Denominator,
		report.BestSingleFalseInterventions.Numerator,
		note, report.CoMiss.Numerator, report.CoMiss.Denominator)
}
