package control

// Spec 14.7 / T023: declared system changes mark the affected claim
// scope stale and schedule the suite; undeclared triggers and
// out-of-scope fingerprints leave claims alone; valid_until expiry is
// lazy, audited, and fails closed when unreadable.

import (
	"strings"
	"testing"
	"time"
)

// staleClock pins the registry between the claim's window and after it.
var staleNow = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

// assessedClaim builds and stores one claim that declares the given
// triggers and binds the fixture fingerprints.
func assessedClaim(t *testing.T, registry *FreshnessRegistry,
	id string, triggers []string) *AssuranceClaim {
	t.Helper()
	input := cohortFixture()
	input.ClaimID = id
	input.InvalidationTriggers = triggers
	input.CreatedAt = "2026-09-10T00:00:00Z"
	claim, err := NewAssurer().WithClock(func() time.Time { return staleNow }).
		Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	registry.Put(testClaimTenant, claim)
	return claim
}

func freshRegistry() *FreshnessRegistry {
	return NewFreshnessRegistry().WithClock(func() time.Time { return staleNow })
}

func TestADeclaredChangeMarksTheMatchingScopeStale(t *testing.T) {
	registry := freshRegistry()
	declarer := assessedClaim(t, registry, "clm_declares001",
		[]string{"model_identity_change"})
	silent := assessedClaim(t, registry, "clm_silent00001",
		[]string{"telemetry_gap"})

	result, err := registry.Invalidate(testClaimTenant, SystemChange{
		Kind:          "model_identity_change",
		PreviousValue: testClaimDigest,
		Detail:        "serving weights replaced",
		OccurredAt:    "2026-09-12T10:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedClaims) != 1 ||
		result.AffectedClaims[0].ClaimID != declarer.ID {
		t.Fatalf("affected: %+v", result.AffectedClaims)
	}
	if result.AffectedClaims[0].StatusBefore != ClaimSupported ||
		result.AffectedClaims[0].StatusAfter != ClaimStale {
		t.Fatalf("transition: %+v", result.AffectedClaims[0])
	}
	// The claim that never declared the trigger is listed untouched.
	if len(result.UntouchedClaims) != 1 ||
		result.UntouchedClaims[0] != silent.ID {
		t.Fatalf("untouched: %v", result.UntouchedClaims)
	}
	if registry.Claim(testClaimTenant, declarer.ID).Status != ClaimStale {
		t.Fatal("the declarer did not go stale")
	}
	if registry.Claim(testClaimTenant, silent.ID).Status != ClaimSupported {
		t.Fatal("the silent claim changed")
	}
}

func TestTheReasonNamesTheChangeAndItsScope(t *testing.T) {
	registry := freshRegistry()
	assessedClaim(t, registry, "clm_reason00001",
		[]string{"policy_change"})
	result, err := registry.Invalidate(testClaimTenant, SystemChange{
		Kind:          "policy_change",
		PreviousValue: testClaimDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	reason := result.AffectedClaims[0].Reason
	if !strings.Contains(reason, "policy_change") ||
		!strings.Contains(reason, "policy") ||
		!strings.Contains(reason, testClaimDigest) {
		t.Fatalf("reason: %s", reason)
	}
	// The declared component defaults from the kind.
	if result.Change.Component != "policy" {
		t.Fatalf("default component: %s", result.Change.Component)
	}
}

func TestAFingerprintTheClaimAlreadyLeftStaysFresh(t *testing.T) {
	registry := freshRegistry()
	claim := assessedClaim(t, registry, "clm_movedon0001",
		[]string{"tool_change"})

	// The claim binds tools digest "aaa..."; the change replaced a
	// tools digest the claim never had.
	other := "sha256:" + strings.Repeat("b", 64)
	result, err := registry.Invalidate(testClaimTenant, SystemChange{
		Kind: "tool_change", PreviousValue: other,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedClaims) != 0 {
		t.Fatalf("a mismatched scope went stale: %+v", result.AffectedClaims)
	}
	if registry.Claim(testClaimTenant, claim.ID).Status != ClaimSupported {
		t.Fatal("the claim on the new value went stale")
	}

	// An unstated previous value cannot prove the claim out of scope:
	// it fails closed.
	result, err = registry.Invalidate(testClaimTenant, SystemChange{
		Kind: "tool_change", Detail: "tool set changed, old digest unrecorded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedClaims) != 1 {
		t.Fatalf("fail-closed scope: %+v", result.AffectedClaims)
	}
}

func TestIsolationFailureReachesEveryScope(t *testing.T) {
	registry := freshRegistry()
	first := assessedClaim(t, registry, "clm_isofail001",
		[]string{"isolation_test_failure"})
	// A claim binding entirely different fingerprints still falls.
	second := assessedClaim(t, registry, "clm_isofail002",
		[]string{"isolation_test_failure"})
	second.Scope.Fingerprints = Fingerprints{
		Model:                "sha256:" + strings.Repeat("c", 64),
		Harness:              "sha256:" + strings.Repeat("c", 64),
		Tools:                "sha256:" + strings.Repeat("c", 64),
		Policy:               "sha256:" + strings.Repeat("c", 64),
		Monitor:              "sha256:" + strings.Repeat("c", 64),
		ScenarioDistribution: "sha256:" + strings.Repeat("c", 64),
		Environment:          "sha256:" + strings.Repeat("c", 64),
	}
	registry.Put(testClaimTenant, second)

	result, err := registry.Invalidate(testClaimTenant, SystemChange{
		Kind:   "isolation_test_failure",
		Detail: "egress isolation test 7 failed under load",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedClaims) != 2 {
		t.Fatalf("an isolation failure missed scope: %+v", result.AffectedClaims)
	}
	if result.Change.Component != "*" {
		t.Fatalf("isolation default: %s", result.Change.Component)
	}
	if first.Status != ClaimStale && registry.Claim(testClaimTenant,
		first.ID).Status != ClaimStale {
		t.Fatal("first claim fresh after isolation failure")
	}
}

func TestExpiryIsLazyAndAudited(t *testing.T) {
	// The registry starts inside the claim's window.
	within := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	registry := NewFreshnessRegistry().WithClock(func() time.Time {
		return within
	})
	input := cohortFixture()
	input.ClaimID = "clm_expiring001"
	input.ValidDays = 1 // created 2026-09-10, valid until 2026-09-11
	claim, err := NewAssurer().WithClock(func() time.Time {
		return staleNow
	}).Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	registry.Put(testClaimTenant, claim)

	// Before the window closes the claim stays fresh.
	if registry.Claim(testClaimTenant, claim.ID).Status != ClaimSupported {
		t.Fatal("expired before valid_until")
	}

	after := staleNow.AddDate(0, 0, 3) // 2026-09-15
	registry = registry.WithClock(func() time.Time { return after })
	if registry.Claim(testClaimTenant, claim.ID).Status != ClaimStale {
		t.Fatal("a claim outlived its valid_until")
	}
	records := registry.Records(testClaimTenant)
	if len(records) != 1 || records[0].Change.Kind != ChangeKindExpiry {
		t.Fatalf("expiry audit: %+v", records)
	}
	if !strings.Contains(records[0].AffectedClaims[0].Reason,
		claim.Freshness.ValidUntil) {
		t.Fatalf("expiry reason: %s",
			records[0].AffectedClaims[0].Reason)
	}
	// The expiry owes a suite like any invalidation.
	suites := registry.Suites(testClaimTenant)
	if len(suites) != 1 || suites[0].ClaimIDs[0] != claim.ID {
		t.Fatalf("expiry suite: %+v", suites)
	}
}

func TestAnUnreadableWindowNeverStaysFresh(t *testing.T) {
	registry := freshRegistry()
	claim := assessedClaim(t, registry, "clm_badwindow01",
		[]string{"telemetry_gap"})
	claim.Freshness.ValidUntil = "not-a-timestamp"
	registry.Put(testClaimTenant, claim)
	if registry.Claim(testClaimTenant, claim.ID).Status != ClaimStale {
		t.Fatal("an unreadable freshness window stayed fresh")
	}
}

func TestSuitesGroupByScopeAndCarryTheirClaims(t *testing.T) {
	registry := freshRegistry()
	assessedClaim(t, registry, "clm_suitea0001",
		[]string{"prompt_change"})
	assessedClaim(t, registry, "clm_suitea0002",
		[]string{"prompt_change"})
	other := assessedClaim(t, registry, "clm_suiteb0001",
		[]string{"prompt_change"})
	other.Scope.WorkloadVersionID = "wlv_9999c3d4e5f6071"
	registry.Put(testClaimTenant, other)

	if _, err := registry.Invalidate(testClaimTenant, SystemChange{
		Kind: "prompt_change"}); err != nil {
		t.Fatal(err)
	}
	suites := registry.Suites(testClaimTenant)
	if len(suites) != 2 {
		t.Fatalf("suites: %+v", suites)
	}
	for _, suite := range suites {
		if suite.SuiteID == "suite_wlv_0a1b2c3d4e5f6071-any" &&
			len(suite.ClaimIDs) != 2 {
			t.Fatalf("grouped claims: %+v", suite)
		}
		if suite.DueBy == "" || suite.Reason == "" {
			t.Fatalf("suite fields: %+v", suite)
		}
	}
}

func TestInvalidationValidatesItsInputs(t *testing.T) {
	registry := freshRegistry()
	if _, err := registry.Invalidate(testClaimTenant,
		SystemChange{Kind: "vibe_shift"}); err == nil {
		t.Fatal("an unknown trigger was accepted")
	}
	if _, err := registry.Invalidate(testClaimTenant,
		SystemChange{Kind: "tool_change", Component: "vibes"}); err == nil {
		t.Fatal("an unknown component was accepted")
	}
	if _, err := registry.Invalidate(testClaimTenant,
		SystemChange{Kind: "tool_change", OccurredAt: "yesterday"}); err == nil {
		t.Fatal("an unparseable timestamp was accepted")
	}
	// Every trigger kind and component pair resolves its default.
	for kind := range invalidationTriggers {
		change := SystemChange{Kind: kind}
		if err := validateSystemChange(&change); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !freshnessComponents[change.Component] {
			t.Fatalf("%s defaulted to %s", kind, change.Component)
		}
	}
}

func TestFreshnessNeverCrossesTenants(t *testing.T) {
	registry := freshRegistry()
	mine := assessedClaim(t, registry, "clm_mine000001",
		[]string{"model_identity_change"})

	if _, err := registry.Invalidate("tnt_other0000000001", SystemChange{
		Kind: "model_identity_change"}); err != nil {
		t.Fatal(err)
	}
	if registry.Claim(testClaimTenant, mine.ID).Status != ClaimSupported {
		t.Fatal("another tenant's change staled this claim")
	}
	if len(registry.Records(testClaimTenant)) != 0 ||
		len(registry.Suites(testClaimTenant)) != 0 {
		t.Fatal("audit crossed tenants")
	}
	if registry.Claim("tnt_other0000000001", mine.ID) != nil {
		t.Fatal("a claim leaked across tenants")
	}
}

func TestAStaleClaimStillValidatesAgainstTheContract(t *testing.T) {
	registry := freshRegistry()
	claim := assessedClaim(t, registry, "clm_schemacheck",
		[]string{"model_identity_change"})
	if _, err := registry.Invalidate(testClaimTenant, SystemChange{
		Kind: "model_identity_change"}); err != nil {
		t.Fatal(err)
	}
	stored := registry.Claim(testClaimTenant, claim.ID)
	if stored.Status != ClaimStale {
		t.Fatal("not stale")
	}
	if stored.Freshness.ValidUntil == "" ||
		len(stored.Freshness.InvalidationTriggers) != 1 {
		// The freshness block itself must stay exactly as assessed:
		// the contract allows no extra fields for stale reasons.
		t.Fatalf("freshness block changed: %+v", stored.Freshness)
	}
}
