package control

// Automated profile promotion tests (T052, spec 15.4, AC-033).
//
// Planted authorities and gate evidence prove the promotion rule end
// to end: only preapproved profiles promote, all three gates must
// pass bound to the candidate's own digest, the hard boundary never
// leaves, rollback is rehearsed first and works after, and every
// promotion is bounded and signed.

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

const (
	promotionTenant = "tnt_5f4a3b2c1d0e6f77"
	promotionRoot   = "pol_1.1.0/root.authority"
	promotionAttest = "ops-release-lead"
)

var promotionClock = time.Date(
	2026, 9, 12, 0, 0, 0, 0, time.UTC)

func floorProfile() ProfileDefinition {
	return ProfileDefinition{
		ID:         "prf_hard-controls-only",
		Version:    "v1.0.0",
		RootPolicy: promotionRoot,
		Layers:     []string{LayerHardControls},
	}
}

func contextualCandidate() ProfileDefinition {
	return ProfileDefinition{
		ID:         "prf_contextual-review",
		Version:    "v2.1.0",
		RootPolicy: promotionRoot,
		Layers:     []string{LayerHardControls, LayerContextual},
	}
}

func promotionAuthority(t *testing.T, profiles ...ProfileDefinition,
) *PromotionAuthority {
	t.Helper()
	all := append([]ProfileDefinition{floorProfile()}, profiles...)
	preapproval, err := NewPreapproval(all...)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = public
	authority, err := NewPromotionAuthority(
		preapproval, promotionRoot, private, "key_profiles-2026q3",
		[]string{promotionAttest})
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return promotionClock }
	return authority
}

func gatesFor(candidate ProfileDefinition,
	edits ...func(*GateResult)) []GateResult {
	digest := candidate.Digest()
	gates := []GateResult{
		{Gate: GateDevelopment, CandidateDigest: digest,
			SuiteDigest: "sha256:" + strings.Repeat("a", 64), Passed: true},
		{Gate: GateHeldOut, CandidateDigest: digest,
			SuiteDigest: "sha256:" + strings.Repeat("b", 64), Passed: true},
		{Gate: GateShadow, CandidateDigest: digest,
			SuiteDigest: "sha256:" + strings.Repeat("c", 64), Passed: true,
			Observations: 500, BenignTasks: 100},
	}
	for _, edit := range edits {
		edit(&gates[2])
	}
	return gates
}

func validRequest(candidate ProfileDefinition,
	restores string) PromotionRequest {
	return PromotionRequest{
		TenantID:   promotionTenant,
		Candidate:  candidate,
		AttestedBy: promotionAttest,
		Gates:      gatesFor(candidate),
		Rollback: RollbackDrill{
			Candidate: candidate.key(), Restores: restores, Passed: true},
		ExpiresAt: promotionClock.Add(time.Hour),
	}
}

func refusalProblems(t *testing.T, err error) []string {
	t.Helper()
	refusal, ok := err.(*PromotionRefusal)
	if !ok {
		t.Fatalf("error is not a refusal: %v", err)
	}
	return refusal.Problems
}

func problemsMention(problems []string, needle string) bool {
	joined := strings.Join(problems, "; ")
	return strings.Contains(joined, needle)
}

// TestAPreapprovedProfilePromotesAfterAllGates is the happy path:
// every gate passes bound to the candidate digest, the drill restored
// the floor, the record is signed, and the tenant runs the candidate.
func TestAPreapprovedProfilePromotesAfterAllGates(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	candidate := contextualCandidate()
	request := validRequest(candidate, floorProfile().key())
	record, err := authority.Promote(request)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if !strings.HasPrefix(record.ID, "prm_") {
		t.Fatalf("promotion id: %q", record.ID)
	}
	if record.Previous != floorProfile().key() {
		t.Fatalf("previous: %q", record.Previous)
	}
	if err := authority.VerifyPromotion(record); err != nil {
		t.Fatalf("verify: %v", err)
	}
	active, err := authority.Active(promotionTenant)
	if err != nil {
		t.Fatal(err)
	}
	if active.key() != candidate.key() {
		t.Fatalf("active: %s, want %s", active.key(), candidate.key())
	}
	events := authority.Events()
	if len(events) != 1 || events[0].Kind != EventPromoted {
		t.Fatalf("events: %+v", events)
	}
}

// TestOnlyPreapprovedProfilesPromote refuses a candidate outside the
// set, and a candidate whose bytes drifted from the preapproved
// definition under the same id and version.
func TestOnlyPreapprovedProfilesPromotes(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	outside := ProfileDefinition{
		ID: "prf_full-call-review", Version: "v1.0.0",
		RootPolicy: promotionRoot,
		Layers:     []string{LayerHardControls, LayerFullCall},
	}
	_, err := authority.Promote(validRequest(outside, floorProfile().key()))
	problems := refusalProblems(t, err)
	if !problemsMention(problems, "preapproval") {
		t.Fatalf("problems: %v", problems)
	}
	// Same id and version as the preapproved candidate, but an extra
	// layer: the digest no longer matches, so it does not promote.
	drifted := contextualCandidate()
	drifted.Layers = append(drifted.Layers, LayerSession)
	_, err = authority.Promote(validRequest(drifted, floorProfile().key()))
	problems = refusalProblems(t, err)
	if !problemsMention(problems, "preapproval") {
		t.Fatalf("problems: %v", problems)
	}
}

// TestEveryRefusalIsCollected proves the whole problem list comes
// back at once: a request with six defects reports six problems,
// and nothing activates.
func TestEveryRefusalIsCollected(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	broken := validRequest(contextualCandidate(), floorProfile().key())
	broken.TenantID = "tenant-wrong"
	broken.AttestedBy = "ops-nobody"
	broken.Gates = broken.Gates[:2] // held-out stays, shadow drops
	broken.Gates[1].Passed = false
	broken.Rollback.Passed = false
	broken.ExpiresAt = time.Time{}
	_, err := authority.Promote(broken)
	problems := refusalProblems(t, err)
	if len(problems) != 6 {
		t.Fatalf("problems: %d, want 6: %v", len(problems), problems)
	}
	for _, needle := range []string{
		"tenant id", "attester", "shadow", "held-out", "did not pass",
		"rollback drill", "expiry",
	} {
		if !problemsMention(problems, needle) {
			t.Fatalf("missing %q in %v", needle, problems)
		}
	}
	if _, err := authority.Active(promotionTenant); err == nil {
		t.Fatal("a refused promotion still activated")
	}
}

// TestGateEvidenceIsBoundToTheCandidate keeps gate results from an
// older profile version from promoting a newer one.
func TestGateEvidenceIsBoundToTheCandidate(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	candidate := contextualCandidate()
	request := validRequest(candidate, floorProfile().key())
	request.Gates = gatesFor(candidate, func(g *GateResult) {
		g.CandidateDigest = "sha256:" + strings.Repeat("9", 64)
	})
	_, err := authority.Promote(request)
	problems := refusalProblems(t, err)
	if !problemsMention(problems, "does not carry across") {
		t.Fatalf("problems: %v", problems)
	}
}

// TestDroppingTheHardBoundaryIsRefused is the silent-weakening rule:
// no promotion removes the hard controls, and no profile changes the
// root policy it enforces.
func TestDroppingTheHardBoundaryIsRefused(t *testing.T) {
	fast := ProfileDefinition{
		ID: "prf_fast-no-boundary", Version: "v1.0.0",
		RootPolicy: promotionRoot,
		Layers:     []string{LayerClassifier},
	}
	authority, err := func() (*PromotionAuthority, error) {
		all := []ProfileDefinition{floorProfile(), fast}
		preapproval, err := NewPreapproval(all...)
		if err != nil {
			return nil, err
		}
		_, private, _ := ed25519.GenerateKey(rand.Reader)
		return NewPromotionAuthority(preapproval, promotionRoot, private,
			"key_profiles-2026q3", []string{promotionAttest})
	}()
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	authority.now = func() time.Time { return promotionClock }
	_, err = authority.Promote(validRequest(fast, floorProfile().key()))
	problems := refusalProblems(t, err)
	if !problemsMention(problems, "silent weakening") {
		t.Fatalf("problems: %v", problems)
	}

	// A profile under a different root policy never enters the
	// preapproval of this authority at all.
	other := contextualCandidate()
	other.RootPolicy = "pol_2.0.0/root.authority"
	if _, err := NewPreapproval(floorProfile(), other); err != nil {
		t.Fatalf("preapproval should accept the profile itself: %v", err)
	}
	preapproval, err := NewPreapproval(floorProfile(), other)
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewPromotionAuthority(preapproval, promotionRoot, private,
		"key_profiles-2026q3", []string{promotionAttest}); err == nil {
		t.Fatal("an authority accepted a profile under another root policy")
	}

	// No floor, no authority: rollback needs somewhere to land.
	onlyCandidate := contextualCandidate()
	noFloor, err := NewPreapproval(onlyCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPromotionAuthority(noFloor, promotionRoot, private,
		"key_profiles-2026q3", []string{promotionAttest}); err == nil {
		t.Fatal("an authority without a floor profile was accepted")
	}
}

// TestTheShadowGateCarriesSafetyCounters refuses a candidate whose
// shadow run showed the harm it supervises, or bought speed with
// interventions on benign tasks.
func TestTheShadowGateCarriesSafetyCounters(t *testing.T) {
	candidate := contextualCandidate()
	cases := []struct {
		name   string
		edit   func(*GateResult)
		needle string
	}{
		{"unauthorized effects", func(g *GateResult) {
			g.UnauthorizedEffects = 1
		}, "unauthorized effects"},
		{"no benign tasks", func(g *GateResult) {
			g.BenignTasks = 0
		}, "unmeasured, not zero"},
		{"too many interventions", func(g *GateResult) {
			g.BenignTasks = 100
			g.FalseInterventions = 1
		}, "benign tasks"},
		{"too few observations", func(g *GateResult) {
			g.Observations = 0
		}, "at least"},
	}
	for _, testCase := range cases {
		authority := promotionAuthority(t, candidate)
		request := validRequest(candidate, floorProfile().key())
		request.Gates = gatesFor(candidate, testCase.edit)
		_, err := authority.Promote(request)
		problems := refusalProblems(t, err)
		if !problemsMention(problems, testCase.needle) {
			t.Fatalf("%s: problems %v", testCase.name, problems)
		}
	}
}

// TestPromotionsAreBounded refuses promotions without an expiry, in
// the past, or beyond the authority's cap.
func TestPromotionsAreBounded(t *testing.T) {
	candidate := contextualCandidate()
	cases := []struct {
		name   string
		expiry time.Time
	}{
		{"no expiry", time.Time{}},
		{"in the past", promotionClock.Add(-time.Minute)},
		{"beyond the cap", promotionClock.Add(72 * time.Hour)},
	}
	for _, testCase := range cases {
		authority := promotionAuthority(t, candidate)
		request := validRequest(candidate, floorProfile().key())
		request.ExpiresAt = testCase.expiry
		_, err := authority.Promote(request)
		problems := refusalProblems(t, err)
		if !problemsMention(problems, "expir") &&
			!problemsMention(problems, "outlive") {
			t.Fatalf("%s: problems %v", testCase.name, problems)
		}
	}
}

// TestRollbackIsRehearsedBeforeAndWorksAfter covers both halves of
// AC-033: the drill must pass for promotion to happen, and the real
// rollback then restores the floor with an audit event and a reason.
func TestRollbackIsRehearsedBeforeAndWorksAfter(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	candidate := contextualCandidate()

	// A drill for a different candidate does not count.
	request := validRequest(candidate, floorProfile().key())
	request.Rollback.Candidate = "prf_other@v1.0.0"
	if _, err := authority.Promote(request); err == nil {
		t.Fatal("a drill for another candidate promoted")
	}
	// A drill restoring something other than what promotion replaces.
	request = validRequest(candidate, floorProfile().key())
	request.Rollback.Restores = "prf_hard-controls-only@v9.9.9"
	if _, err := authority.Promote(request); err == nil {
		t.Fatal("a drill restoring a ghost promoted")
	}

	// Real promotion, then rollback.
	request = validRequest(candidate, floorProfile().key())
	if _, err := authority.Promote(request); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := authority.Rollback(promotionTenant, ""); err == nil {
		t.Fatal("a rollback without a reason was accepted")
	}
	event, err := authority.Rollback(
		promotionTenant, "shadow regression on issue triage")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if event.Kind != EventRolledBack ||
		!strings.Contains(event.Detail, "issue triage") {
		t.Fatalf("event: %+v", event)
	}
	active, err := authority.Active(promotionTenant)
	if err != nil {
		t.Fatal(err)
	}
	if active.key() != floorProfile().key() {
		t.Fatalf("after rollback: %s", active.key())
	}

	// Promoting again needs a drill that restores the floor — which
	// is what the tenant runs now.
	again := validRequest(candidate, floorProfile().key())
	if _, err := authority.Promote(again); err != nil {
		t.Fatalf("promote after rollback: %v", err)
	}
}

// TestPromotionsExpireOnTheirOwn proves bounded means bounded: past
// the expiry the tenant is back on the replaced profile, with one
// lapse event, not one per read.
func TestPromotionsExpireOnTheirOwn(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	candidate := contextualCandidate()
	request := validRequest(candidate, floorProfile().key())
	if _, err := authority.Promote(request); err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time {
		return promotionClock.Add(2 * time.Hour)
	}
	active, err := authority.Active(promotionTenant)
	if err != nil {
		t.Fatal(err)
	}
	if active.key() != floorProfile().key() {
		t.Fatalf("after expiry: %s", active.key())
	}
	lapses := 0
	for _, event := range authority.Events() {
		if event.Kind == EventLapsed {
			lapses++
		}
	}
	if lapses != 1 {
		t.Fatalf("lapse events: %d, want 1", lapses)
	}
	// Reading again does not log another lapse.
	if _, err := authority.Active(promotionTenant); err != nil {
		t.Fatal(err)
	}
	after := 0
	for _, event := range authority.Events() {
		if event.Kind == EventLapsed {
			after++
		}
	}
	if after != 1 {
		t.Fatalf("lapse events after second read: %d, want 1", after)
	}
	// After a lapse, a new promotion replaces the profile the tenant
	// actually runs: the floor. The clock keeps moving forward; a
	// promotion granted now expires an hour from now.
	again := validRequest(candidate, floorProfile().key())
	again.ExpiresAt = promotionClock.Add(3 * time.Hour)
	if _, err := authority.Promote(again); err != nil {
		t.Fatalf("promote after lapse: %v", err)
	}
	active, err = authority.Active(promotionTenant)
	if err != nil {
		t.Fatal(err)
	}
	if active.key() != candidate.key() {
		t.Fatalf("after re-promotion: %s", active.key())
	}
}

// TestPromotionRecordsVerifyAndTamperFails signs honestly and breaks
// loudly: any edit after signing fails verification.
func TestPromotionRecordsVerifyAndTamperFails(t *testing.T) {
	authority := promotionAuthority(t, contextualCandidate())
	record, err := authority.Promote(
		validRequest(contextualCandidate(), floorProfile().key()))
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.VerifyPromotion(record); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tampered := PromotionRecord(*record)
	tampered.ExpiresAt = record.ExpiresAt.Add(time.Hour)
	if err := authority.VerifyPromotion(&tampered); err == nil {
		t.Fatal("a tampered promotion verified")
	}
	claimant := PromotionRecord(*record)
	claimant.KeyID = "key_other-2026q4"
	if err := authority.VerifyPromotion(&claimant); err == nil {
		t.Fatal("a record under another key verified")
	}
	unsigned := PromotionRecord(*record)
	unsigned.Signature = nil
	if err := authority.VerifyPromotion(&unsigned); err == nil {
		t.Fatal("an unsigned promotion verified")
	}
}

// TestPreapprovalValidatesItsOwnShape keeps the closed set closed.
func TestPreapprovalValidatesItsOwnShape(t *testing.T) {
	bad := ProfileDefinition{
		ID: "not-a-profile-id", Version: "1.0", RootPolicy: "nope",
		Layers: []string{"magic"},
	}
	if _, err := NewPreapproval(bad); err == nil {
		t.Fatal("an invalid profile entered the preapproval")
	}
	duplicate := contextualCandidate()
	if _, err := NewPreapproval(floorProfile(), duplicate,
		duplicate); err == nil {
		t.Fatal("a duplicate entered the preapproval")
	}
	// Layer order is the profile's own: both orders are the same
	// definition by digest.
	reordered := contextualCandidate()
	reordered.Layers = []string{LayerContextual, LayerHardControls}
	set, err := NewPreapproval(floorProfile(), contextualCandidate())
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(reordered) {
		t.Fatal("layer order changed the digest")
	}
}
