package control

// Advanced sampling and statistics (T053, spec 14.4, 14.5, 15.1,
// AC-034).
//
// The fixed-cohort statistics of assurance.go are exact because they
// refuse every input they cannot honestly handle. This file extends
// that refusal discipline to the cases the spec calls P1: clustered
// outcomes, sequential looks, weighted samples, multiple comparisons,
// and adaptive sampling.
//
// The rules come straight from spec 14.4: repeated variants from the
// same task or incident are not independent, so outcomes are reported
// at the cluster level and an unsupported session-rate claim is named
// as unsupported. A fixed interval recomputed until it passes is not
// a sequential test, so looks are preregistered and spent by union
// bound. Weighted counts never feed the exact binomial formula, so
// strata report separately. Risk-routed review is additional to the
// uniform sentinel sample, never a substitute for it.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
)

// Bound methods exported on reports. MethodExactBinomial comes from
// assurance.go, the fixed-cohort statistics this file extends.
const (
	MethodUnionSequential  = "preregistered_exact_union_bound_sequential"
	MethodHolm             = "holm_step_down"
	MethodBonferroni       = "bonferroni"
	StratumUniformSentinel = "uniform_sentinel"
	StratumRiskTriggered   = "risk_triggered"
)

// RateBound is one rate with its exact one-sided upper bound. Unit
// names what the denominator counts; the spec forbids switching units
// for more impressive numbers.
type RateBound struct {
	Unit         string  `json:"unit"`
	Failures     int     `json:"failures"`
	Observations int     `json:"observations"`
	UpperBound   float64 `json:"upper_bound"`
	Method       string  `json:"method"`
}

// ClusterObservation is one observation carrying the cluster it
// belongs to (spec 14.4: record cluster ids).
type ClusterObservation struct {
	ClusterID  string `json:"cluster_id"`
	Failed     bool   `json:"failed"`
	Unresolved bool   `json:"unresolved"`
}

// ClusterReport is the clustered-outcome analysis: the cluster-level
// bound is the claim; the observation-level bound is shown for
// contrast and labeled with whether a session-level claim is
// justified at all.
type ClusterReport struct {
	Kind                  string    `json:"kind"`
	ConfidenceLevel       float64   `json:"confidence_level"`
	Clusters              int       `json:"clusters"`
	Observations          int       `json:"observations"`
	ClusterLevel          RateBound `json:"cluster_level"`
	SessionLevel          RateBound `json:"session_level"`
	SessionClaimJustified bool      `json:"session_claim_justified"`
	// Sensitivity treats every unresolved cluster as failed (spec
	// 14.4: conservative release gating).
	Sensitivity RateBound `json:"sensitivity"`
	Limitations []string  `json:"limitations"`
}

// AnalyzeClusters computes the cluster-level exact bound. A cluster
// fails when any observation in it failed; a cluster with no failures
// but an unresolved observation is unresolved and counts as failed in
// the sensitivity bound only.
func AnalyzeClusters(observations []ClusterObservation,
	confidence float64) (*ClusterReport, error) {
	if len(observations) == 0 {
		return nil, fmt.Errorf("cluster analysis refused: no observations")
	}
	if confidence <= 0 || confidence >= 1 {
		return nil, fmt.Errorf(
			"confidence level must be strictly between 0 and 1")
	}
	failedClusters := map[string]bool{}
	unresolvedClusters := map[string]bool{}
	sizes := map[string]int{}
	observationFailures := 0
	observationUnresolved := 0
	for _, observation := range observations {
		if !reClusterRef.MatchString(observation.ClusterID) {
			return nil, fmt.Errorf(
				"cluster analysis refused: cluster id %q must match "+
					"cid_[A-Za-z0-9_-]{4,128}", observation.ClusterID)
		}
		sizes[observation.ClusterID]++
		if observation.Failed {
			failedClusters[observation.ClusterID] = true
			observationFailures++
		}
		if observation.Unresolved {
			unresolvedClusters[observation.ClusterID] = true
			observationUnresolved++
		}
	}
	clusters := len(sizes)
	clusterFailures := len(failedClusters)
	clusterUnresolved := 0
	for cluster := range unresolvedClusters {
		if !failedClusters[cluster] {
			clusterUnresolved++
		}
	}
	clusterBound, err := BinomialUpperBound(
		clusterFailures, clusters, confidence)
	if err != nil {
		return nil, err
	}
	sessionBound, err := BinomialUpperBound(
		observationFailures, len(observations), confidence)
	if err != nil {
		return nil, err
	}
	sensitivityBound, err := BinomialUpperBound(
		clusterFailures+clusterUnresolved, clusters, confidence)
	if err != nil {
		return nil, err
	}

	// A session-level claim is justified only when every cluster is a
	// single observation: otherwise the observations share whatever
	// dependence made clustering necessary, and the session-level
	// denominator overstates the evidence (spec 14.4).
	justified := true
	for _, size := range sizes {
		if size != 1 {
			justified = false
			break
		}
	}
	report := &ClusterReport{
		Kind:            "ClusterReport",
		ConfidenceLevel: confidence,
		Clusters:        clusters,
		Observations:    len(observations),
		ClusterLevel: RateBound{
			Unit: "cluster", Failures: clusterFailures,
			Observations: clusters, UpperBound: clusterBound,
			Method: MethodExactBinomial,
		},
		SessionLevel: RateBound{
			Unit: "observation", Failures: observationFailures,
			Observations: len(observations), UpperBound: sessionBound,
			Method: MethodExactBinomial,
		},
		SessionClaimJustified: justified,
		Sensitivity: RateBound{
			Unit: "cluster", Failures: clusterFailures + clusterUnresolved,
			Observations: clusters, UpperBound: sensitivityBound,
			Method: MethodExactBinomial,
		},
	}
	report.Limitations = []string{
		"cluster-level outcomes are the valid unit; within-cluster " +
			"observations are not independent (spec 14.4)",
	}
	if !justified {
		report.Limitations = append(report.Limitations,
			"an exact session-rate bound is not justified at these "+
				"cluster sizes; the session-level bound above is shown "+
				"for contrast only and is not a claim")
	}
	if clusterUnresolved > 0 {
		report.Limitations = append(report.Limitations, fmt.Sprintf(
			"%d unresolved clusters; the sensitivity bound treats every "+
				"unresolved cluster as failed", clusterUnresolved))
	}
	if observationUnresolved > 0 {
		report.Limitations = append(report.Limitations, fmt.Sprintf(
			"%d unresolved observations sit inside otherwise-clean "+
				"clusters; zero detected failures with unresolved "+
				"outcomes is weaker evidence (spec 14.4)",
			observationUnresolved))
	}
	return report, nil
}

// SequentialBoundary is a preregistered look schedule for release
// testing. Each look is an exact one-sided binomial test at level
// alpha/K; the union bound over the K preregistered keeps the overall
// error at or under alpha. Evaluating anywhere else, or adding looks
// after seeing data, is refused: a fixed interval recomputed until it
// passes is not a valid sequential test (spec 14.4).
type SequentialBoundary struct {
	Alpha float64
	Looks []int
}

// NewSequentialBoundary preregisters the schedule: strictly
// increasing eligible counts, at least one look, alpha in (0, 1).
func NewSequentialBoundary(alpha float64, looks []int) (
	*SequentialBoundary, error) {
	if alpha <= 0 || alpha >= 1 {
		return nil, fmt.Errorf("alpha must be strictly between 0 and 1")
	}
	if len(looks) == 0 {
		return nil, fmt.Errorf(
			"a sequential boundary preregisters at least one look")
	}
	for i, eligible := range looks {
		if eligible <= 0 {
			return nil, fmt.Errorf("look %d has %d eligible", i+1, eligible)
		}
		if i > 0 && eligible <= looks[i-1] {
			return nil, fmt.Errorf(
				"look %d (%d eligible) does not grow past look %d (%d)",
				i+1, eligible, i, looks[i-1])
		}
	}
	return &SequentialBoundary{Alpha: alpha, Looks: looks}, nil
}

// Sequential verdicts.
const (
	VerdictContinue     = "continue"
	VerdictRelease      = "release"
	VerdictInconclusive = "inconclusive"
)

// SequentialResult is one look's outcome under the boundary.
type SequentialResult struct {
	Look         int      `json:"look"`
	Eligible     int      `json:"eligible"`
	Failures     int      `json:"failures"`
	PerLookAlpha float64  `json:"per_look_alpha"`
	UpperBound   float64  `json:"upper_bound"`
	Threshold    float64  `json:"threshold"`
	Verdict      string   `json:"verdict"`
	TotalSpent   float64  `json:"total_alpha_spent"`
	Method       string   `json:"method"`
	Limitations  []string `json:"limitations"`
}

// Evaluate tests one preregistered look. Release needs the exact
// upper bound at this look's level below the threshold; the final
// look without release is inconclusive, never a pass.
func (b *SequentialBoundary) Evaluate(look, failures, eligible int,
	threshold float64) (*SequentialResult, error) {
	if look < 1 || look > len(b.Looks) {
		return nil, fmt.Errorf(
			"look %d is outside the preregistered schedule of %d looks; "+
				"adding looks after seeing data invalidates the boundary "+
				"(spec 14.4)", look, len(b.Looks))
	}
	if eligible != b.Looks[look-1] {
		return nil, fmt.Errorf(
			"look %d was preregistered at %d eligible, evaluated at %d; "+
				"recomputing the interval at another cohort until it "+
				"passes is not a sequential test",
			look, b.Looks[look-1], eligible)
	}
	if threshold <= 0 || threshold >= 1 {
		return nil, fmt.Errorf("threshold must be strictly between 0 and 1")
	}
	perLook := b.Alpha / float64(len(b.Looks))
	upper, err := BinomialUpperBound(failures, eligible, 1-perLook)
	if err != nil {
		return nil, err
	}
	verdict := VerdictContinue
	if upper < threshold {
		verdict = VerdictRelease
	} else if look == len(b.Looks) {
		verdict = VerdictInconclusive
	}
	return &SequentialResult{
		Look:         look,
		Eligible:     eligible,
		Failures:     failures,
		PerLookAlpha: perLook,
		UpperBound:   upper,
		Threshold:    threshold,
		Verdict:      verdict,
		TotalSpent:   perLook * float64(look),
		Method:       MethodUnionSequential,
		Limitations: []string{
			"exact at each preregistered look; overall error controlled " +
				"by the union bound over the schedule, not a confidence " +
				"sequence for continuous monitoring",
		},
	}, nil
}

// SampleStratum is one stratum of a sampled population with its known
// inclusion probability.
type SampleStratum struct {
	ID                   string  `json:"id"`
	Population           int     `json:"population"`
	Selected             int     `json:"selected"`
	Failures             int     `json:"failures"`
	InclusionProbability float64 `json:"inclusion_probability"`
}

// StratumResult is one stratum's separate report.
type StratumResult struct {
	Stratum           SampleStratum `json:"stratum"`
	UpperBound        float64       `json:"upper_bound"`
	EstimatedFailures float64       `json:"estimated_failures"`
	EstimatedRate     float64       `json:"estimated_rate"`
}

// StratifiedReport reports each stratum separately. Weighted counts
// never enter the exact binomial formula (spec 14.4); the Horvitz-
// Thompson point estimates carry no interval because no validated
// interval estimator ships yet.
type StratifiedReport struct {
	Kind            string          `json:"kind"`
	ConfidenceLevel float64         `json:"confidence_level"`
	Strata          []StratumResult `json:"strata"`
	Census          bool            `json:"census"`
	PooledBound     *RateBound      `json:"pooled_bound,omitempty"`
	PooledRefusal   string          `json:"pooled_refusal,omitempty"`
	Limitations     []string        `json:"limitations"`
}

// AnalyzeStrata validates the strata, computes each stratum's exact
// bound over its selected units, and refuses to pool anything but a
// full census.
func AnalyzeStrata(strata []SampleStratum,
	confidence float64) (*StratifiedReport, error) {
	if len(strata) == 0 {
		return nil, fmt.Errorf("stratified analysis refused: no strata")
	}
	if confidence <= 0 || confidence >= 1 {
		return nil, fmt.Errorf(
			"confidence level must be strictly between 0 and 1")
	}
	seen := map[string]bool{}
	census := true
	for i, stratum := range strata {
		if stratum.ID == "" {
			return nil, fmt.Errorf("stratum %d has no id", i)
		}
		if seen[stratum.ID] {
			return nil, fmt.Errorf("stratum %q appears twice", stratum.ID)
		}
		seen[stratum.ID] = true
		if stratum.Population < 1 {
			return nil, fmt.Errorf(
				"stratum %q has population %d", stratum.ID, stratum.Population)
		}
		if stratum.InclusionProbability <= 0 ||
			stratum.InclusionProbability > 1 {
			return nil, fmt.Errorf(
				"stratum %q inclusion probability %v is not in (0, 1]",
				stratum.ID, stratum.InclusionProbability)
		}
		if stratum.Selected > stratum.Population {
			return nil, fmt.Errorf(
				"stratum %q selected %d of a population of %d",
				stratum.ID, stratum.Selected, stratum.Population)
		}
		if stratum.Failures > stratum.Selected {
			return nil, fmt.Errorf(
				"stratum %q reports %d failures among %d selected",
				stratum.ID, stratum.Failures, stratum.Selected)
		}
		if stratum.Selected != stratum.Population {
			census = false
		}
	}
	report := &StratifiedReport{
		Kind:            "StratifiedReport",
		ConfidenceLevel: confidence,
		Census:          census,
		Limitations: []string{
			"strata report separately; weighted counts never feed the " +
				"exact binomial formula (spec 14.4)",
			"Horvitz-Thompson estimates are point estimates only; no " +
				"validated interval estimator ships in this version",
		},
	}
	for _, stratum := range strata {
		bound, err := BinomialUpperBound(
			stratum.Failures, stratum.Selected, confidence)
		if err != nil {
			return nil, err
		}
		report.Strata = append(report.Strata, StratumResult{
			Stratum:    stratum,
			UpperBound: bound,
			EstimatedFailures: float64(stratum.Failures) /
				stratum.InclusionProbability,
			EstimatedRate: float64(stratum.Failures) /
				stratum.InclusionProbability /
				float64(stratum.Population),
		})
	}
	sort.Slice(report.Strata, func(i, j int) bool {
		return report.Strata[i].Stratum.ID < report.Strata[j].Stratum.ID
	})
	if census {
		// A census needs no weights: pooling is the exact arithmetic.
		var failures, population int
		for _, stratum := range strata {
			failures += stratum.Failures
			population += stratum.Population
		}
		bound, err := BinomialUpperBound(failures, population, confidence)
		if err != nil {
			return nil, err
		}
		report.PooledBound = &RateBound{
			Unit: "population", Failures: failures,
			Observations: population, UpperBound: bound,
			Method: MethodExactBinomial,
		}
	} else {
		report.PooledRefusal = "pooled exact bound refused: at least one " +
			"stratum is sampled below its population, and weighted " +
			"counts do not enter the exact formula (spec 14.4)"
	}
	return report, nil
}

// RawComparison is one hypothesis test's p-value before adjustment.
type RawComparison struct {
	Name   string  `json:"name"`
	PValue float64 `json:"p_value"`
}

// AdjustedComparison is one comparison after multiple-comparison
// control.
type AdjustedComparison struct {
	Name     string  `json:"name"`
	PValue   float64 `json:"p_value"`
	Adjusted float64 `json:"adjusted_p"`
	Reject   bool    `json:"reject"`
}

// ComparisonReport carries the adjusted family with its method.
type ComparisonReport struct {
	Kind        string               `json:"kind"`
	Method      string               `json:"method"`
	Alpha       float64              `json:"alpha"`
	Comparisons []AdjustedComparison `json:"comparisons"`
	Limitations []string             `json:"limitations"`
}

// AdjustForMultipleComparisons applies Bonferroni or Holm step-down.
// Both control the family-wise error rate at alpha; Holm is uniformly
// less conservative and is the default recommendation.
func AdjustForMultipleComparisons(comparisons []RawComparison,
	method string, alpha float64) (*ComparisonReport, error) {
	if len(comparisons) == 0 {
		return nil, fmt.Errorf("no comparisons to adjust")
	}
	if alpha <= 0 || alpha >= 1 {
		return nil, fmt.Errorf("alpha must be strictly between 0 and 1")
	}
	for i, comparison := range comparisons {
		if comparison.Name == "" {
			return nil, fmt.Errorf("comparison %d has no name", i)
		}
		if comparison.PValue < 0 || comparison.PValue > 1 {
			return nil, fmt.Errorf(
				"comparison %q p-value %v is not in [0, 1]",
				comparison.Name, comparison.PValue)
		}
	}
	order := append([]RawComparison{}, comparisons...)
	sort.Slice(order, func(i, j int) bool {
		if order[i].PValue != order[j].PValue {
			return order[i].PValue < order[j].PValue
		}
		return order[i].Name < order[j].Name
	})
	m := len(order)
	adjusted := map[string]float64{}
	reject := map[string]bool{}
	report := &ComparisonReport{Kind: "ComparisonReport", Alpha: alpha}
	switch method {
	case MethodBonferroni:
		report.Method = MethodBonferroni
		for _, comparison := range order {
			adjusted[comparison.Name] = math.Min(1,
				comparison.PValue*float64(m))
			reject[comparison.Name] = comparison.PValue <=
				alpha/float64(m)
		}
	case MethodHolm:
		report.Method = MethodHolm
		running := 0.0
		stillRejecting := true
		for i, comparison := range order {
			scale := float64(m - i)
			value := math.Min(1, comparison.PValue*scale)
			if value > running {
				running = value
			}
			adjusted[comparison.Name] = running
			if stillRejecting && comparison.PValue <= alpha/scale {
				reject[comparison.Name] = true
			} else {
				stillRejecting = false
			}
		}
	default:
		return nil, fmt.Errorf(
			"multiple-comparison method %q is not %q or %q",
			method, MethodBonferroni, MethodHolm)
	}
	for _, comparison := range comparisons {
		report.Comparisons = append(report.Comparisons, AdjustedComparison{
			Name:     comparison.Name,
			PValue:   comparison.PValue,
			Adjusted: adjusted[comparison.Name],
			Reject:   reject[comparison.Name],
		})
	}
	report.Limitations = []string{
		"family-wise error control over the declared comparison family; " +
			"comparisons added after seeing results are a new family",
	}
	return report, nil
}

// AuditSamplingPlan is the sentinel-plus-triggered review allocation
// of spec 15.1. The uniform sentinel stratum is mandatory and nonzero;
// risk-routed strata are additional, never a substitute.
type AuditSamplingPlan struct {
	Strata []SamplingStratumPlan `json:"strata"`
}

// SamplingStratumPlan declares one stratum's kind and parameters.
type SamplingStratumPlan struct {
	Kind string  `json:"kind"` // uniform_sentinel | risk_triggered
	Rate float64 `json:"rate"` // inclusion probability for the uniform stratum
	Rule string  `json:"rule"` // deterministic trigger rule id
}

// Validate applies spec 15.1's allocation rules: exactly one uniform
// sentinel stratum with a nonzero rate, every risk-triggered stratum
// bound to a declared rule, and no unknown kinds.
func (p AuditSamplingPlan) Validate() error {
	if len(p.Strata) == 0 {
		return fmt.Errorf("a sampling plan has no strata")
	}
	uniform := 0
	for i, stratum := range p.Strata {
		switch stratum.Kind {
		case StratumUniformSentinel:
			uniform++
			if stratum.Rate <= 0 || stratum.Rate > 1 {
				return fmt.Errorf(
					"the uniform sentinel stratum %d has rate %v; the "+
						"uniform sample is nonzero by design (spec 15.1)",
					i, stratum.Rate)
			}
		case StratumRiskTriggered:
			if stratum.Rule == "" {
				return fmt.Errorf(
					"risk-triggered stratum %d declares no deterministic "+
						"rule; trigger criteria must be declared, not "+
						"improvised", i)
			}
			if stratum.Rate < 0 || stratum.Rate > 1 {
				return fmt.Errorf(
					"risk-triggered stratum %d expected rate %v is not "+
						"in [0, 1]", i, stratum.Rate)
			}
		default:
			return fmt.Errorf(
				"stratum %d has unknown kind %q", i, stratum.Kind)
		}
	}
	if uniform == 0 {
		return fmt.Errorf(
			"no uniform sentinel stratum; risk-routed review is " +
				"additional to the random sample, never a substitute " +
				"(spec 15.1)")
	}
	if uniform > 1 {
		return fmt.Errorf(
			"%d uniform sentinel strata; the uniform sample is one "+
				"declared stratum", uniform)
	}
	return nil
}

// KeyedInclusion is the deterministic keyed draw for one unit in one
// stratum: HMAC-SHA256 over the stratum and unit id, compared against
// the rate. The same key and unit always decide the same way, and an
// auditor with the key reproduces every inclusion decision without
// worker access to the key itself.
func KeyedInclusion(key []byte, stratum, unitID string, rate float64) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stratum))
	mac.Write([]byte{0})
	mac.Write([]byte(unitID))
	digest := mac.Sum(nil)
	sample := uint32(digest[0]) |
		uint32(digest[1])<<8 |
		uint32(digest[2])<<16 |
		uint32(digest[3])<<24
	// Map to [0, 1) over the low 32 bits.
	return float64(sample)/4294967296.0 < rate
}

// InclusionKeyID names a sampling key by fingerprint, so a report can
// say which key drew the sample without publishing the key.
func InclusionKeyID(key []byte) string {
	digest := sha256.Sum256([]byte("gauntlet-sampling-key\x00" + string(key)))
	return "hmk_" + hex.EncodeToString(digest[:8])
}

// PopulationRateFromUniform reports the population failure-rate bound
// from the uniform sentinel stratum alone. Triggered reviews never
// enter: their inclusion depends on the outcome-bearing triggers, so
// their rates are conditional on selection, not population rates.
func PopulationRateFromUniform(selected, failures int,
	confidence float64) (*RateBound, error) {
	if selected <= 0 {
		return nil, fmt.Errorf(
			"the uniform stratum selected nothing; no population rate")
	}
	bound, err := BinomialUpperBound(failures, selected, confidence)
	if err != nil {
		return nil, err
	}
	return &RateBound{
		Unit:         "population_rate_from_uniform_sentinel",
		Failures:     failures,
		Observations: selected,
		UpperBound:   bound,
		Method:       MethodExactBinomial,
	}, nil
}
