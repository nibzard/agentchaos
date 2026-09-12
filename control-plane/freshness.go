package control

// Claim freshness invalidation (spec 14.7 / T023). A claim binds to a
// system fingerprint; when the system changes — model identity, prompt,
// policy, tools, topology, isolation tests, drift, or telemetry gaps —
// the affected scope goes stale and the relevant suite is scheduled.
//
// Staleness is a status change, not an edit of the claim's evidence:
// the shared contract allows no freshness fields beyond valid_until and
// invalidation_triggers, so every reason lives in the invalidation
// records the registry keeps. Expiry is symmetric: a claim whose
// valid_until has elapsed is stale on first read, and a claim whose
// valid_until cannot be parsed never stays fresh.

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// timeFormat is the shared RFC 3339 UTC stamp.
const timeFormat = "2006-01-02T15:04:05Z"

// ClaimStale is the status of a claim whose scope no longer matches
// the running system, or whose freshness window has elapsed.
const ClaimStale = "STALE"

// ChangeKindExpiry is the audit kind of an automatic valid-until
// expiry. It is not one of the claim-declared triggers; it applies to
// every claim unconditionally.
const ChangeKindExpiry = "valid_until_elapsed"

// FreshnessComponents are the fingerprint components a change can name.
// "*" addresses every claim that declared the trigger.
var freshnessComponents = map[string]bool{
	"model": true, "harness": true, "tools": true, "policy": true,
	"monitor": true, "scenario_distribution": true, "environment": true,
	"*": true,
}

// defaultComponent maps each declared trigger to the fingerprint it
// touches. Isolation test failure implicates the whole deployment, so
// it defaults to every scope.
var defaultComponent = map[string]string{
	"model_identity_change":  "model",
	"prompt_change":          "harness",
	"policy_change":          "policy",
	"tool_change":            "tools",
	"topology_change":        "environment",
	"distribution_drift":     "scenario_distribution",
	"isolation_test_failure": "*",
	"telemetry_gap":          "monitor",
}

// SystemChange is a declared change to the versioned system a claim
// binds to. Component names the fingerprint that changed; the empty
// string takes the trigger's default component. PreviousValue scopes
// the change to claims that still bind the old value; the empty string
// fails closed and matches every claim in scope.
type SystemChange struct {
	Kind          string `json:"kind"`
	Component     string `json:"component"`
	PreviousValue string `json:"previous_value"`
	Detail        string `json:"detail"`
	OccurredAt    string `json:"occurred_at"`
}

// AffectedClaim is one claim an invalidation marked stale.
type AffectedClaim struct {
	ClaimID      string `json:"claim_id"`
	StatusBefore string `json:"status_before"`
	StatusAfter  string `json:"status_after"`
	Reason       string `json:"reason"`
}

// InvalidationResult is the audit record of one invalidation: what
// changed, which claims it touched, and why each went stale.
type InvalidationResult struct {
	Kind            string          `json:"kind"`
	APIVersion      string          `json:"api_version"`
	TenantID        string          `json:"tenant_id"`
	Change          SystemChange    `json:"change"`
	AffectedClaims  []AffectedClaim `json:"affected_claims"`
	UntouchedClaims []string        `json:"untouched_claims"`
	ReviewedAt      string          `json:"reviewed_at"`
}

// SuiteSchedule is the re-evaluation a stale claim owes: one per
// affected workload and autonomy profile (spec 14.7: mark stale and
// schedule the relevant suite).
type SuiteSchedule struct {
	SuiteID           string   `json:"suite_id"`
	TenantID          string   `json:"tenant_id"`
	WorkloadVersionID string   `json:"workload_version_id"`
	AutonomyProfileID string   `json:"autonomy_profile_id"`
	Reason            string   `json:"reason"`
	ClaimIDs          []string `json:"claim_ids"`
	DueBy             string   `json:"due_by"`
}

// FreshnessRegistry stores claims tenant-scoped and applies freshness
// rules to them. The clock is injectable for deterministic expiry.
type FreshnessRegistry struct {
	mu      sync.Mutex
	claims  map[string]*AssuranceClaim // tenant + "\x00" + id
	records map[string][]InvalidationResult
	suites  map[string][]SuiteSchedule
	now     func() time.Time
}

// NewFreshnessRegistry builds a registry on the wall clock.
func NewFreshnessRegistry() *FreshnessRegistry {
	return &FreshnessRegistry{
		claims:  map[string]*AssuranceClaim{},
		records: map[string][]InvalidationResult{},
		suites:  map[string][]SuiteSchedule{},
		now:     time.Now,
	}
}

// WithClock replaces the clock (tests).
func (r *FreshnessRegistry) WithClock(now func() time.Time) *FreshnessRegistry {
	return &FreshnessRegistry{
		claims: r.claims, records: r.records, suites: r.suites, now: now,
	}
}

// Put stores a private copy of the claim for the tenant.
func (r *FreshnessRegistry) Put(tenantID string, claim *AssuranceClaim) {
	stored := *claim
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claims[tenantID+"\x00"+claim.ID] = &stored
}

// Claim returns the claim, expiring it first when its freshness window
// has elapsed. Expiry is lazy and tenant-scoped: a read after
// valid_until observes STALE, and the expiry is audited like any other
// invalidation.
func (r *FreshnessRegistry) Claim(tenantID, id string) *AssuranceClaim {
	key := tenantID + "\x00" + id
	r.mu.Lock()
	claim := r.claims[key]
	if claim == nil {
		r.mu.Unlock()
		return nil
	}
	if expired, at := r.elapsed(claim); expired {
		r.expireLocked(tenantID, claim, at)
	}
	stored := *claim
	r.mu.Unlock()
	return &stored
}

// elapsed reports whether the claim's freshness window has passed, and
// the moment it did. A window that cannot be parsed has already
// passed: freshness is proven, never assumed.
func (r *FreshnessRegistry) elapsed(claim *AssuranceClaim) (bool, time.Time) {
	validUntil, err := time.Parse(time.RFC3339Nano, claim.Freshness.ValidUntil)
	if err != nil {
		return true, r.now()
	}
	now := r.now()
	return now.After(validUntil), validUntil
}

// expireLocked marks one claim stale from expiry and records the audit
// trail. Caller holds the lock.
func (r *FreshnessRegistry) expireLocked(tenantID string,
	claim *AssuranceClaim, at time.Time) {
	if claim.Status == ClaimStale {
		return
	}
	before := claim.Status
	claim.Status = ClaimStale
	now := r.now().UTC().Format(timeFormat)
	r.records[tenantID] = append(r.records[tenantID], InvalidationResult{
		Kind:       "ClaimInvalidation",
		APIVersion: "v1",
		TenantID:   tenantID,
		Change: SystemChange{
			Kind:      ChangeKindExpiry,
			Component: "*",
			Detail: fmt.Sprintf("freshness window elapsed; valid_until %s",
				claim.Freshness.ValidUntil),
			OccurredAt: at.UTC().Format(timeFormat),
		},
		AffectedClaims: []AffectedClaim{{
			ClaimID:      claim.ID,
			StatusBefore: before,
			StatusAfter:  ClaimStale,
			Reason: fmt.Sprintf("valid_until %s elapsed at %s",
				claim.Freshness.ValidUntil, now),
		}},
		ReviewedAt: now,
	})
	r.scheduleSuiteLocked(tenantID, claim, claim.ID,
		"claim expired; fresh evidence required")
}

// Invalidate applies a declared system change to the tenant's claims.
// A claim is affected when it declared the change kind as an
// invalidation trigger and the change touches its scope. Every other
// claim is listed untouched — silence about scope is not an outcome.
func (r *FreshnessRegistry) Invalidate(tenantID string,
	change SystemChange) (*InvalidationResult, error) {
	if err := validateSystemChange(&change); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	result := InvalidationResult{
		Kind:       "ClaimInvalidation",
		APIVersion: "v1",
		TenantID:   tenantID,
		Change:     change,
		ReviewedAt: r.now().UTC().Format(timeFormat),
	}
	for _, key := range sortedClaimKeys(r.claims) {
		if !strings.HasPrefix(key, tenantID+"\x00") {
			continue
		}
		claim := r.claims[key]
		if !scopeAffected(claim, change) {
			result.UntouchedClaims = append(result.UntouchedClaims, claim.ID)
			continue
		}
		if claim.Status != ClaimStale {
			result.AffectedClaims = append(result.AffectedClaims, AffectedClaim{
				ClaimID:      claim.ID,
				StatusBefore: claim.Status,
				StatusAfter:  ClaimStale,
				Reason:       changeReason(change),
			})
			claim.Status = ClaimStale
		} else {
			// Already stale: still affected, already at the terminal state.
			result.AffectedClaims = append(result.AffectedClaims, AffectedClaim{
				ClaimID:      claim.ID,
				StatusBefore: ClaimStale,
				StatusAfter:  ClaimStale,
				Reason:       changeReason(change) + "; already stale",
			})
		}
	}
	r.records[tenantID] = append(r.records[tenantID], result)
	for _, affected := range result.AffectedClaims {
		r.scheduleSuiteLocked(tenantID, r.claims[tenantID+"\x00"+affected.ClaimID],
			affected.ClaimID, changeReason(change))
	}
	return &result, nil
}

// Records returns the tenant's invalidation audit trail, oldest first.
func (r *FreshnessRegistry) Records(tenantID string) []InvalidationResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]InvalidationResult, len(r.records[tenantID]))
	copy(out, r.records[tenantID])
	return out
}

// Suites returns the tenant's scheduled re-evaluation suites.
func (r *FreshnessRegistry) Suites(tenantID string) []SuiteSchedule {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SuiteSchedule, len(r.suites[tenantID]))
	copy(out, r.suites[tenantID])
	return out
}

// scheduleSuiteLocked adds one suite per affected workload and
// autonomy profile, keeping the claim ids that owe re-evaluation.
// Caller holds the lock.
func (r *FreshnessRegistry) scheduleSuiteLocked(tenantID string,
	claim *AssuranceClaim, claimID, reason string) {
	profile := claim.Scope.AutonomyProfileID
	if profile == "" {
		profile = "any"
	}
	suiteID := "suite_" + claim.Scope.WorkloadVersionID + "-" + profile
	for i := range r.suites[tenantID] {
		if r.suites[tenantID][i].SuiteID == suiteID {
			for _, id := range r.suites[tenantID][i].ClaimIDs {
				if id == claimID {
					return
				}
			}
			r.suites[tenantID][i].ClaimIDs = append(
				r.suites[tenantID][i].ClaimIDs, claimID)
			return
		}
	}
	r.suites[tenantID] = append(r.suites[tenantID], SuiteSchedule{
		SuiteID:           suiteID,
		TenantID:          tenantID,
		WorkloadVersionID: claim.Scope.WorkloadVersionID,
		AutonomyProfileID: claim.Scope.AutonomyProfileID,
		Reason:            reason,
		ClaimIDs:          []string{claimID},
		DueBy:             r.now().UTC().Format(timeFormat),
	})
}

// scopeAffected decides whether a change touches one claim. The claim's
// own declared triggers decide eligibility (spec 14.7); the component
// and previous value decide scope. An unknown component or an unstated
// previous value fails closed: a claim that cannot be proven outside
// the change is inside it.
func scopeAffected(claim *AssuranceClaim, change SystemChange) bool {
	declared := false
	for _, trigger := range claim.Freshness.InvalidationTriggers {
		if trigger == change.Kind {
			declared = true
			break
		}
	}
	if !declared {
		return false
	}
	if change.Component == "*" {
		return true
	}
	previous, known := fingerprintValue(claim.Scope.Fingerprints, change.Component)
	if !known {
		return true
	}
	return change.PreviousValue == "" || previous == change.PreviousValue
}

// fingerprintValue reads one component of a claim's fingerprint.
func fingerprintValue(prints Fingerprints, component string) (string, bool) {
	switch component {
	case "model":
		return prints.Model, true
	case "harness":
		return prints.Harness, true
	case "tools":
		return prints.Tools, true
	case "policy":
		return prints.Policy, true
	case "monitor":
		return prints.Monitor, true
	case "scenario_distribution":
		return prints.ScenarioDistribution, true
	case "environment":
		return prints.Environment, true
	}
	return "", false
}

// changeReason is the human-readable cause an affected claim carries.
func changeReason(change SystemChange) string {
	component := change.Component
	if change.Kind == ChangeKindExpiry {
		return change.Detail
	}
	if change.PreviousValue != "" {
		return fmt.Sprintf("%s on %s (was %s)", change.Kind, component,
			change.PreviousValue)
	}
	return fmt.Sprintf("%s on %s (previous value unstated; scope assumed)",
		change.Kind, component)
}

// validateSystemChange checks a declared change against the trigger
// vocabulary and stamps its defaults.
func validateSystemChange(change *SystemChange) error {
	if !invalidationTriggers[change.Kind] {
		return fmt.Errorf("unknown invalidation trigger %q", change.Kind)
	}
	switch {
	case change.Component == "":
		change.Component = defaultComponent[change.Kind]
	case freshnessComponents[change.Component]:
		// An explicit component, including the global "*".
	default:
		return fmt.Errorf("unknown component %q", change.Component)
	}
	if change.OccurredAt == "" {
		change.OccurredAt = time.Now().UTC().Format(timeFormat)
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, change.OccurredAt); err != nil {
		return fmt.Errorf("occurred_at must be an RFC 3339 UTC timestamp with Z")
	}
	return nil
}

// sortedClaimKeys iterates claims deterministically.
func sortedClaimKeys(claims map[string]*AssuranceClaim) []string {
	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
