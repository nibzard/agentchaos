// Package control also computes fixed-cohort assurance estimates
// (spec 14.3, 14.4). The statistics are exact and deterministic: the
// same cohort counts always produce the same bounds, and no model call
// participates anywhere in the calculation.
package control

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// The estimate method the AssuranceClaim contract allows (spec 14.4):
// weighted counts must not feed the exact formula, so it is the only
// representable method.
const MethodExactBinomial = "exact_one_sided_binomial_upper_bound"

// DefaultFreshnessDays is the seven-day expiration default (spec 14.7):
// a review cadence, not evidence the distribution still holds.
const DefaultFreshnessDays = 7

// Assurance statuses (spec 14.1).
const (
	ClaimSupported             = "SUPPORTED_WITHIN_SCOPE"
	ClaimTargetNotDemonstrated = "TARGET_NOT_DEMONSTRATED"
	ClaimViolated              = "VIOLATED"
	ClaimInsufficientEvidence  = "INSUFFICIENT_EVIDENCE"
)

// Evidence categories (spec 14.2). The four stay separate; a
// challenge-set rate is not a production prevalence estimate.
const (
	CategoryProductionIncidence = "production_incidence"
	CategoryChallengeSetFailure = "challenge_set_failure"
	CategoryBoundaryConformance = "boundary_conformance"
	CategoryDetectorPerformance = "detector_performance"
)

// Dependence models (spec 14.4).
const (
	DependenceIndependent = "independent_bernoulli"
	DependenceClustered   = "clustered_reported_at_cluster_level"
)

// Units of observation (spec 14.1). A per-action bound must not be
// displayed as a per-session or per-task bound (spec 14.3).
var unitsOfObservation = map[string]bool{
	"action": true, "session": true, "task": true, "cluster": true, "experiment": true,
}

// Severity classes (spec 14.6).
var severityClasses = map[string]bool{"H0": true, "H1": true, "H2": true, "H3": true}

// Invalidation triggers (spec 14.7).
var invalidationTriggers = map[string]bool{
	"model_identity_change": true, "prompt_change": true, "policy_change": true,
	"tool_change": true, "topology_change": true, "isolation_test_failure": true,
	"distribution_drift": true, "telemetry_gap": true,
}

var (
	reClaimID    = regexp.MustCompile(`^clm_[a-z0-9]{8,64}$`)
	reWorkloadID = regexp.MustCompile(`^wlv_[a-z0-9]{8,64}$`)
	reProfileID  = regexp.MustCompile(`^aup_[a-z0-9]{8,64}$`)
	reEventID    = regexp.MustCompile(`^evt_[a-z0-9]{8,64}$`)
	reDigest     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reClusterRef = regexp.MustCompile(`^cid_[A-Za-z0-9_-]{4,128}$`)
	reTimestampZ = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
)

// Fingerprints bind the claim to a versioned system (spec 14.1). Any
// change invalidates the affected scope.
type Fingerprints struct {
	Model                string `json:"model"`
	Harness              string `json:"harness"`
	Tools                string `json:"tools"`
	Policy               string `json:"policy"`
	Monitor              string `json:"monitor"`
	ScenarioDistribution string `json:"scenario_distribution"`
	Environment          string `json:"environment"`
}

// HazardInput is the defined hazard the claim reasons about.
type HazardInput struct {
	Description       string
	Severity          string // H0..H3
	FailureEvent      string
	UnitOfObservation string // action | session | task | cluster | experiment
}

// InjectionFunnelInput is the selection-to-verification funnel a
// challenge-set claim must report (spec 14.2, AC-018).
type InjectionFunnelInput struct {
	Selected         int
	Eligible         int
	Triggered        int
	Untriggered      int
	HarnessError     int
	VerifiedOutcomes int
}

// CohortInput is everything a fixed-cohort estimate depends on. The
// cohort must be preregistered and fixed; the selection procedure says
// so, and the calculation never sees a growing denominator.
type CohortInput struct {
	TenantID string
	ClaimID  string // optional; minted when empty
	Revision int    // optional; 1 by default

	Hazard            HazardInput
	WorkloadVersionID string
	AutonomyProfileID string // optional
	Fingerprints      Fingerprints

	EvidenceCategory   string
	ObservationFrom    string
	ObservationTo      string
	CoverageGaps       []string
	SelectionProcedure string
	LabelSource        string
	DataSources        []string // evt_ evidence event ids
	Funnel             *InjectionFunnelInput

	Failures            int
	Eligible            int
	Unresolved          int
	ConfidenceLevel     float64 // for example 0.95
	AcceptanceThreshold float64 // for example 0.0001 for four nines

	DependenceModel         string
	ClusterUnit             string   // clustered claims only
	ClusterIDRefs           []string // clustered claims only
	DependenceDescription   string
	PopulationApplicability string
	Exclusions              []string

	ValidDays            int // optional; seven by default
	InvalidationTriggers []string
	CreatedAt            string // optional; the clock stamps it
}

// AssuranceClaim is the emitted document. Field names match the shared
// contract exactly (shared/schemas/assurance-claim.schema.json).
type AssuranceClaim struct {
	Kind              string           `json:"kind"`
	APIVersion        string           `json:"api_version"`
	ID                string           `json:"id"`
	TenantID          string           `json:"tenant_id"`
	ClaimRevision     int              `json:"claim_revision"`
	SupersedesClaimID string           `json:"supersedes_claim_id,omitempty"`
	Status            string           `json:"status"`
	Hazard            claimHazard      `json:"hazard"`
	Scope             claimScope       `json:"scope"`
	Provenance        claimProvenance  `json:"provenance"`
	Estimate          claimEstimate    `json:"estimate"`
	Assumptions       claimAssumptions `json:"assumptions"`
	Freshness         claimFreshness   `json:"freshness"`
	CreatedAt         string           `json:"created_at"`
}

type claimHazard struct {
	Description       string `json:"description"`
	Severity          string `json:"severity"`
	FailureEvent      string `json:"failure_event"`
	UnitOfObservation string `json:"unit_of_observation"`
}

type claimScope struct {
	WorkloadVersionID string       `json:"workload_version_id"`
	AutonomyProfileID string       `json:"autonomy_profile_id,omitempty"`
	Fingerprints      Fingerprints `json:"fingerprints"`
}

type claimProvenance struct {
	EvidenceCategory   string                `json:"evidence_category"`
	ObservationWindow  observationWindow     `json:"observation_window"`
	CoverageGaps       []string              `json:"coverage_gaps"`
	SelectionProcedure string                `json:"selection_procedure"`
	LabelSource        string                `json:"label_source"`
	DataSources        []string              `json:"data_sources"`
	InjectionFunnel    *claimInjectionFunnel `json:"injection_funnel,omitempty"`
}

type observationWindow struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type claimInjectionFunnel struct {
	Selected         int `json:"selected"`
	Eligible         int `json:"eligible"`
	Triggered        int `json:"triggered"`
	Untriggered      int `json:"untriggered"`
	HarnessError     int `json:"harness_error"`
	VerifiedOutcomes int `json:"verified_outcomes"`
}

type claimEstimate struct {
	Method                           string  `json:"method"`
	Failures                         int     `json:"failures"`
	EligibleObservations             int     `json:"eligible_observations"`
	Unresolved                       int     `json:"unresolved"`
	ConfidenceLevel                  float64 `json:"confidence_level"`
	UpperBound                       float64 `json:"upper_bound"`
	SensitivityAllUnresolvedFailures float64 `json:"sensitivity_all_unresolved_failures"`
	AcceptanceThreshold              float64 `json:"acceptance_threshold"`
}

type claimAssumptions struct {
	DependenceModel         string   `json:"dependence_model"`
	ClusterUnit             string   `json:"cluster_unit,omitempty"`
	ClusterIDRefs           []string `json:"cluster_id_refs,omitempty"`
	DependenceDescription   string   `json:"dependence_description"`
	PopulationApplicability string   `json:"population_applicability"`
	Exclusions              []string `json:"exclusions"`
}

type claimFreshness struct {
	ValidUntil           string   `json:"valid_until"`
	InvalidationTriggers []string `json:"invalidation_triggers"`
}

// Assurer computes claims. The clock is injectable for deterministic
// stamps.
type Assurer struct {
	now func() time.Time
}

// NewAssurer builds an assurer using the wall clock.
func NewAssurer() *Assurer { return &Assurer{now: time.Now} }

// WithClock replaces the clock (tests).
func (a *Assurer) WithClock(now func() time.Time) *Assurer {
	return &Assurer{now: now}
}

// Assess validates the cohort input, computes the exact one-sided
// binomial bounds, and emits an AssuranceClaim document (spec 14.3,
// 14.4):
//
//   - upper_bound counts observed failures against eligible
//     observations. Unresolved outcomes stay in the denominator and out
//     of the numerator — which is exactly why they are reported
//     separately and never folded into passes;
//   - sensitivity_all_unresolved_failures recomputes the bound with
//     every unresolved outcome treated as a failure: the conservative
//     floor of what the cohort supports;
//   - the status is fail-closed. SUPPORTED_WITHIN_SCOPE requires the
//     conservative bound to meet the threshold, VIOLATED requires the
//     exact one-sided lower bound to exceed it (the data itself places
//     the hazard above target), and everything else is
//     TARGET_NOT_DEMONSTRATED. An empty cohort is
//     INSUFFICIENT_EVIDENCE.
func (a *Assurer) Assess(input CohortInput) (*AssuranceClaim, error) {
	if err := validateCohortInput(&input); err != nil {
		return nil, err
	}

	upper, err := BinomialUpperBound(input.Failures, input.Eligible, input.ConfidenceLevel)
	if err != nil {
		return nil, err
	}
	sensitivity, err := BinomialUpperBound(
		input.Failures+input.Unresolved, input.Eligible, input.ConfidenceLevel)
	if err != nil {
		return nil, err
	}

	createdAt := input.CreatedAt
	if createdAt == "" {
		createdAt = a.now().UTC().Format("2006-01-02T15:04:05Z")
	}
	validDays := input.ValidDays
	if validDays == 0 {
		validDays = DefaultFreshnessDays
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, fmt.Errorf("created_at must be an RFC 3339 UTC timestamp with Z")
	}
	validUntil := created.AddDate(0, 0, validDays).UTC().Format("2006-01-02T15:04:05Z")

	status := ClaimTargetNotDemonstrated
	switch {
	case input.Eligible == 0:
		status = ClaimInsufficientEvidence
	default:
		lower, err := binomialLowerBound(input.Failures, input.Eligible, input.ConfidenceLevel)
		if err != nil {
			return nil, err
		}
		switch {
		case lower > input.AcceptanceThreshold:
			status = ClaimViolated
		case sensitivity <= input.AcceptanceThreshold:
			status = ClaimSupported
		}
	}

	revision := input.Revision
	if revision == 0 {
		revision = 1
	}
	claimID := input.ClaimID
	if claimID == "" {
		claimID = mintClaimID()
	}

	claim := &AssuranceClaim{
		Kind:          "AssuranceClaim",
		APIVersion:    "v1",
		ID:            claimID,
		TenantID:      input.TenantID,
		ClaimRevision: revision,
		Status:        status,
		Hazard: claimHazard{
			Description:       input.Hazard.Description,
			Severity:          input.Hazard.Severity,
			FailureEvent:      input.Hazard.FailureEvent,
			UnitOfObservation: input.Hazard.UnitOfObservation,
		},
		Scope: claimScope{
			WorkloadVersionID: input.WorkloadVersionID,
			AutonomyProfileID: input.AutonomyProfileID,
			Fingerprints:      input.Fingerprints,
		},
		Provenance: claimProvenance{
			EvidenceCategory:   input.EvidenceCategory,
			ObservationWindow:  observationWindow{From: input.ObservationFrom, To: input.ObservationTo},
			CoverageGaps:       nonEmpty(input.CoverageGaps),
			SelectionProcedure: input.SelectionProcedure,
			LabelSource:        input.LabelSource,
			DataSources:        input.DataSources,
		},
		Estimate: claimEstimate{
			Method:                           MethodExactBinomial,
			Failures:                         input.Failures,
			EligibleObservations:             input.Eligible,
			Unresolved:                       input.Unresolved,
			ConfidenceLevel:                  input.ConfidenceLevel,
			UpperBound:                       roundBound(upper),
			SensitivityAllUnresolvedFailures: roundBound(sensitivity),
			AcceptanceThreshold:              input.AcceptanceThreshold,
		},
		Assumptions: claimAssumptions{
			DependenceModel:         input.DependenceModel,
			ClusterUnit:             input.ClusterUnit,
			ClusterIDRefs:           nonEmpty(input.ClusterIDRefs),
			DependenceDescription:   input.DependenceDescription,
			PopulationApplicability: input.PopulationApplicability,
			Exclusions:              nonEmpty(input.Exclusions),
		},
		Freshness: claimFreshness{
			ValidUntil:           validUntil,
			InvalidationTriggers: input.InvalidationTriggers,
		},
		CreatedAt: createdAt,
	}
	if input.Funnel != nil {
		claim.Provenance.InjectionFunnel = &claimInjectionFunnel{
			Selected:         input.Funnel.Selected,
			Eligible:         input.Funnel.Eligible,
			Triggered:        input.Funnel.Triggered,
			Untriggered:      input.Funnel.Untriggered,
			HarnessError:     input.Funnel.HarnessError,
			VerifiedOutcomes: input.Funnel.VerifiedOutcomes,
		}
	}
	return claim, nil
}

// BinomialUpperBound is the exact one-sided (1-alpha) upper bound on a
// Bernoulli failure probability: the p for which P(X <= failures;
// observations, p) = alpha, with alpha = 1 - confidence. With zero
// failures it collapses to the closed form 1 - alpha^(1/n) (spec 14.3).
// An empty cohort returns 1: absence of observations is no evidence.
func BinomialUpperBound(failures, observations int, confidence float64) (float64, error) {
	if observations < 0 || failures < 0 || failures > observations {
		return 0, fmt.Errorf("counts must satisfy 0 <= failures <= observations")
	}
	if confidence <= 0 || confidence >= 1 {
		return 0, fmt.Errorf("confidence level must be strictly between 0 and 1")
	}
	if observations == 0 || failures == observations {
		return 1, nil
	}
	alpha := 1 - confidence
	if failures == 0 {
		return 1 - math.Pow(alpha, 1/float64(observations)), nil
	}
	// P(X <= k; p) falls as p rises, so bisect upward until the CDF
	// drops to alpha. The returned end stays at or above the exact
	// quantile: the bound errs on the conservative side.
	low, high := 0.0, 1.0
	for i := 0; i < 200 && high-low > 1e-15; i++ {
		mid := (low + high) / 2
		if binomialCDF(failures, observations, mid) > alpha {
			low = mid
		} else {
			high = mid
		}
	}
	return high, nil
}

// binomialLowerBound is the matching one-sided lower bound: the p for
// which P(X >= failures; observations, p) = alpha. It decides VIOLATED:
// a lower bound above the threshold means the data itself places the
// hazard above target.
func binomialLowerBound(failures, observations int, confidence float64) (float64, error) {
	if observations < 0 || failures < 0 || failures > observations {
		return 0, fmt.Errorf("counts must satisfy 0 <= failures <= observations")
	}
	if observations == 0 || failures == 0 {
		return 0, nil
	}
	// P(X >= k; p) = P(X <= k-1; p) mirrored: solve P(X <= failures-1;
	// p) = confidence. That CDF falls as p rises; bisect to where it
	// equals confidence.
	low, high := 0.0, 1.0
	for i := 0; i < 200 && high-low > 1e-15; i++ {
		mid := (low + high) / 2
		if binomialCDF(failures-1, observations, mid) > confidence {
			low = mid
		} else {
			high = mid
		}
	}
	return low, nil
}

// binomialCDF is P(X <= k) for X ~ Binomial(n, p), through the
// regularized incomplete beta function: I_{1-p}(n-k, k+1).
func binomialCDF(k, n int, p float64) float64 {
	return regularizedIncompleteBeta(float64(n-k), float64(k+1), 1-p)
}

// regularizedIncompleteBeta is I_x(a, b), the symmetric continued
// fraction form with the reflection identity for the far side. It is
// the standard Numerical Recipes construction; math.Lgamma keeps the
// prefactor in a safe range for large cohorts.
func regularizedIncompleteBeta(a, b, x float64) float64 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 1
	}
	lnAb, _ := math.Lgamma(a + b)
	lnA, _ := math.Lgamma(a)
	lnB, _ := math.Lgamma(b)
	lnFront := lnAb - lnA - lnB + a*math.Log(x) + b*math.Log(1-x)
	front := math.Exp(lnFront)
	if x < (a+1)/(a+b+2) {
		return front * betaContinuedFraction(a, b, x) / a
	}
	return 1 - math.Exp(lnFront+
		math.Log(betaContinuedFraction(b, a, 1-x)))/b
}

// betaContinuedFraction evaluates the continued fraction for the
// incomplete beta function (Lentz's method).
func betaContinuedFraction(a, b, x float64) float64 {
	const maxIterations = 300
	const epsilon = 3e-14
	const tiny = 1e-300
	qab, qap, qam := a+b, a+1, a-1
	c := 1.0
	d := 1 - qab*x/qap
	if math.Abs(d) < tiny {
		d = tiny
	}
	d = 1 / d
	h := d
	for m := 1; m <= maxIterations; m++ {
		m2 := 2 * float64(m)
		aa := float64(m) * (b - float64(m)) * x / ((qam + m2) * (a + m2))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		h *= d * c
		aa = -(a + float64(m)) * (qab + float64(m)) * x / ((a + m2) * (qap + m2))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		change := d * c
		h *= change
		if math.Abs(change-1) < epsilon {
			break
		}
	}
	return h
}

// roundBound trims float noise to 12 decimal places so the same counts
// always serialize to the same document, on every platform.
func roundBound(value float64) float64 {
	return math.Round(value*1e12) / 1e12
}

// validateCohortInput fails closed on every contract violation before
// any statistics run. Bad input never produces a claim.
func validateCohortInput(input *CohortInput) error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	if !reTenantID.MatchString(input.TenantID) {
		add("tenant id must match tnt_[a-z0-9]{8,64}")
	}
	if input.ClaimID != "" && !reClaimID.MatchString(input.ClaimID) {
		add("claim id must match clm_[a-z0-9]{8,64}")
	}
	if input.Revision < 0 {
		add("claim revision cannot be negative")
	}
	if input.Hazard.Description == "" {
		add("hazard description is required")
	}
	if !severityClasses[input.Hazard.Severity] {
		add("hazard severity must be H0, H1, H2, or H3")
	}
	if input.Hazard.FailureEvent == "" {
		add("hazard failure event is required")
	}
	if !unitsOfObservation[input.Hazard.UnitOfObservation] {
		add("unit of observation must be action, session, task, cluster, or experiment")
	}
	if !reWorkloadID.MatchString(input.WorkloadVersionID) {
		add("workload version id must match wlv_[a-z0-9]{8,64}")
	}
	if input.AutonomyProfileID != "" && !reProfileID.MatchString(input.AutonomyProfileID) {
		add("autonomy profile id must match aup_[a-z0-9]{8,64}")
	}
	fingerprints := []struct {
		name, value string
	}{
		{"model", input.Fingerprints.Model},
		{"harness", input.Fingerprints.Harness},
		{"tools", input.Fingerprints.Tools},
		{"policy", input.Fingerprints.Policy},
		{"monitor", input.Fingerprints.Monitor},
		{"scenario_distribution", input.Fingerprints.ScenarioDistribution},
		{"environment", input.Fingerprints.Environment},
	}
	for _, fingerprint := range fingerprints {
		if !reDigest.MatchString(fingerprint.value) {
			add("fingerprint %s must be a sha256 digest", fingerprint.name)
		}
	}
	switch input.EvidenceCategory {
	case CategoryProductionIncidence, CategoryChallengeSetFailure,
		CategoryBoundaryConformance, CategoryDetectorPerformance:
	default:
		add("evidence category must be one of the four separated categories (spec 14.2)")
	}
	if !reTimestampZ.MatchString(input.ObservationFrom) ||
		!reTimestampZ.MatchString(input.ObservationTo) {
		add("observation window needs RFC 3339 UTC timestamps with Z")
	}
	if input.SelectionProcedure == "" {
		add("selection procedure is required; state whether the cohort was preregistered and fixed")
	}
	if input.LabelSource == "" {
		add("label source is required")
	}
	if len(input.DataSources) < 1 {
		add("at least one data source evidence event is required")
	}
	for i, source := range input.DataSources {
		if !reEventID.MatchString(source) {
			add("data source %d must match evt_[a-z0-9]{8,64}", i)
		}
	}
	if len(input.DataSources) > 256 {
		add("data sources are capped at 256")
	}
	// A challenge-set failure rate without its funnel reads silent
	// non-triggers as defense success (spec 14.2, AC-018).
	if input.EvidenceCategory == CategoryChallengeSetFailure && input.Funnel == nil {
		add("a challenge-set failure rate must report its injection funnel (AC-018)")
	}
	if input.Funnel != nil {
		funnel := input.Funnel
		if funnel.Selected < 0 || funnel.Eligible < 0 || funnel.Triggered < 0 ||
			funnel.Untriggered < 0 || funnel.HarnessError < 0 || funnel.VerifiedOutcomes < 0 {
			add("funnel counts cannot be negative")
		}
		if funnel.Eligible > funnel.Selected {
			add("funnel eligible cannot exceed selected")
		}
		if funnel.Triggered+funnel.Untriggered > funnel.Eligible {
			add("funnel triggered plus untriggered cannot exceed eligible")
		}
	}
	if input.Failures < 0 || input.Eligible < 0 || input.Unresolved < 0 {
		add("cohort counts cannot be negative")
	}
	if input.Failures+input.Unresolved > input.Eligible {
		add("failures plus unresolved cannot exceed eligible observations")
	}
	if input.ConfidenceLevel <= 0 || input.ConfidenceLevel >= 1 {
		add("confidence level must be strictly between 0 and 1")
	}
	if input.AcceptanceThreshold <= 0 || input.AcceptanceThreshold >= 1 {
		add("acceptance threshold must be strictly between 0 and 1")
	}
	switch input.DependenceModel {
	case DependenceIndependent, DependenceClustered:
	default:
		add("dependence model must be independent_bernoulli or clustered_reported_at_cluster_level")
	}
	if input.DependenceDescription == "" {
		add("dependence description is required")
	}
	if input.PopulationApplicability == "" {
		add("population applicability is required")
	}
	if input.DependenceModel == DependenceClustered {
		if input.ClusterUnit == "" {
			add("clustered outcomes must name their cluster unit (spec 14.4)")
		}
		if len(input.ClusterIDRefs) < 1 {
			add("clustered outcomes must list their cluster ids (spec 14.4)")
		}
		for i, ref := range input.ClusterIDRefs {
			if !reClusterRef.MatchString(ref) {
				add("cluster id %d must match cid_[A-Za-z0-9_-]{4,128}", i)
			}
		}
		if input.Hazard.UnitOfObservation != "cluster" &&
			input.Hazard.UnitOfObservation != "task" {
			add("clustered outcomes are reported at the cluster or task unit (spec 14.3)")
		}
	}
	if len(input.InvalidationTriggers) < 1 || len(input.InvalidationTriggers) > 16 {
		add("1 to 16 invalidation triggers are required")
	}
	for i, trigger := range input.InvalidationTriggers {
		if !invalidationTriggers[trigger] {
			add("invalidation trigger %d is not a contract trigger", i)
		}
	}
	if input.ValidDays < 0 {
		add("valid days cannot be negative")
	}
	if input.CreatedAt != "" && !reTimestampZ.MatchString(input.CreatedAt) {
		add("created_at must be an RFC 3339 UTC timestamp with Z")
	}
	if len(problems) > 0 {
		return fmt.Errorf("cohort input violates the claim contract: %s",
			strings.Join(problems, "; "))
	}
	return nil
}

// nonEmpty returns an empty slice for empty input so required arrays
// serialize as [] — the contract requires arrays, and null is not an
// array. Optional arrays (cluster ids) omit the field instead.
func nonEmpty(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return values
}

// mintClaimID mints a clm_ claim id.
func mintClaimID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "clm_" + hex.EncodeToString(raw)
}
