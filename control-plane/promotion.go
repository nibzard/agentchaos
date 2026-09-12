package control

// Automated profile promotion (T052, spec 15.4 and the optimizer rule
// of section 9.3, AC-033).
//
// The improvement loop ends in a promotion, and the spec is explicit
// about what that takes: evaluate a candidate control change on
// development and held-out suites, run it in shadow, then promote a
// signed profile within existing authority. A profile optimizer MAY
// choose among preapproved profiles; it MUST NOT silently weaken root
// policy to increase throughput, and it MUST NOT use untested
// production observations to rewrite its own safeguards.
//
// This file is that rule as code. Promotion is evidence-gated, not
// time-gated: every refusal is collected, nothing promotes with one
// gate missing, the rollback drill runs before the promotion is
// granted, and every promotion is bounded — it expires, and expiry
// lapses the binding back without anyone asking.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Supervision layers a profile may run (spec 11.1). The order of a
// profile's Layers field is its own; membership is what the checks
// read.
const (
	LayerHardControls = "hard-controls"
	LayerClassifier   = "classifier"
	LayerContextual   = "contextual-review"
	LayerFullCall     = "full-call-review"
	LayerSession      = "session-review"
)

// RequiredLayers is the floor no promotion may drop. Removing the
// hard boundary is the "silent weakening of root policy" the
// specification forbids: every faster profile still runs it.
var RequiredLayers = []string{LayerHardControls}

var knownLayers = map[string]bool{
	LayerHardControls: true, LayerClassifier: true,
	LayerContextual: true, LayerFullCall: true, LayerSession: true,
}

// Gates every candidate passes, in order (spec 15.4).
const (
	GateDevelopment = "development"
	GateHeldOut     = "held-out"
	GateShadow      = "shadow"
)

// RequiredGates is the promotion gate set. All of them, passed, bound
// to the candidate's own digest — no gate from an older version
// counts.
var RequiredGates = []string{GateDevelopment, GateHeldOut, GateShadow}

// Audit event kinds.
const (
	EventPromoted   = "promotion_granted"
	EventRolledBack = "promotion_rolled_back"
	EventLapsed     = "promotion_lapsed"
)

var (
	reSupervisionProfileID = regexp.MustCompile(
		`^prf_[a-z0-9][a-z0-9-]{3,63}$`)
	reProfileSemver = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	reRootPolicyRef = regexp.MustCompile(
		`^pol_[a-z0-9][a-z0-9.-]*/[a-z][a-z0-9._:/-]{1,60}$`)
	rePromotionID = regexp.MustCompile(`^prm_[a-z0-9]{16}$`)
)

// ProfileDefinition is one preapproved supervision profile: the
// layers it runs under a root policy it enforces but never replaces.
type ProfileDefinition struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	RootPolicy  string   `json:"root_policy"`
	Layers      []string `json:"layers"`
	Description string   `json:"description,omitempty"`
}

// Digest is the candidate binding: promotion evidence must cite it
// exactly, so gates from a different version of the same profile id
// never carry over.
func (p ProfileDefinition) Digest() string {
	layers := append([]string{}, p.Layers...)
	sort.Strings(layers)
	payload, err := json.Marshal(struct {
		ID         string   `json:"id"`
		Version    string   `json:"version"`
		RootPolicy string   `json:"root_policy"`
		Layers     []string `json:"layers"`
	}{p.ID, p.Version, p.RootPolicy, layers})
	if err != nil {
		// Marshal over plain strings cannot fail; panic loudly if the
		// shape ever grows something that can.
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (p ProfileDefinition) key() string { return p.ID + "@" + p.Version }

// Validate checks the closed shape: id, version, root policy, known
// layers, no duplicates.
func (p ProfileDefinition) Validate() error {
	if !reSupervisionProfileID.MatchString(p.ID) {
		return fmt.Errorf(
			"profile id %q must match prf_[a-z0-9][a-z0-9-]{3,63}", p.ID)
	}
	if !reProfileSemver.MatchString(p.Version) {
		return fmt.Errorf("profile version %q must be vN.N.N", p.Version)
	}
	if !reRootPolicyRef.MatchString(p.RootPolicy) {
		return fmt.Errorf("root policy %q is not a policy id", p.RootPolicy)
	}
	if len(p.Layers) == 0 {
		return fmt.Errorf("profile %s runs no supervision layers", p.key())
	}
	seen := map[string]bool{}
	for _, layer := range p.Layers {
		if !knownLayers[layer] {
			return fmt.Errorf(
				"profile %s names unknown layer %q", p.key(), layer)
		}
		if seen[layer] {
			return fmt.Errorf("profile %s lists layer %q twice", p.key(), layer)
		}
		seen[layer] = true
	}
	return nil
}

// RunsRequiredLayers reports whether every required layer is present.
// This is the silent-weakening check: the hard boundary never leaves.
func (p ProfileDefinition) RunsRequiredLayers() bool {
	have := map[string]bool{}
	for _, layer := range p.Layers {
		have[layer] = true
	}
	for _, layer := range RequiredLayers {
		if !have[layer] {
			return false
		}
	}
	return true
}

// Preapproval is the operator's closed set of promotable profiles. A
// candidate outside it never promotes, whatever its scores.
type Preapproval struct {
	profiles map[string]ProfileDefinition
}

// NewPreapproval validates every definition and refuses duplicates.
func NewPreapproval(profiles ...ProfileDefinition) (*Preapproval, error) {
	set := &Preapproval{profiles: map[string]ProfileDefinition{}}
	for _, profile := range profiles {
		if err := profile.Validate(); err != nil {
			return nil, err
		}
		if _, dup := set.profiles[profile.key()]; dup {
			return nil, fmt.Errorf(
				"preapproval lists %s twice", profile.key())
		}
		set.profiles[profile.key()] = profile
	}
	return set, nil
}

// Contains matches the exact definition by digest, not just the id:
// version drift inside a preapproved id does not promote.
func (p *Preapproval) Contains(candidate ProfileDefinition) bool {
	known, ok := p.profiles[candidate.key()]
	return ok && known.Digest() == candidate.Digest()
}

// GateResult is one gate's evidence. CandidateDigest binds it to one
// exact profile version; a result bound elsewhere is stale evidence
// and never counts.
type GateResult struct {
	Gate            string `json:"gate"`
	CandidateDigest string `json:"candidate_digest"`
	SuiteDigest     string `json:"suite_digest"`
	Passed          bool   `json:"passed"`
	// Shadow observations. Live production outcomes are not promotion
	// evidence; the shadow gate runs on predeclared observation sets.
	Observations        int `json:"observations,omitempty"`
	BenignTasks         int `json:"benign_tasks,omitempty"`
	FalseInterventions  int `json:"false_interventions,omitempty"`
	UnauthorizedEffects int `json:"unauthorized_effects,omitempty"`
}

// RollbackDrill is the rehearsed rollback, run before the promotion
// is granted (AC-033: "rollback before bounded promotion").
type RollbackDrill struct {
	Candidate string `json:"candidate"` // prf id@version drilled
	Restores  string `json:"restores"`  // the target the drill restored
	Passed    bool   `json:"passed"`
}

// PromotionRecord is the signed, bounded promotion.
type PromotionRecord struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	Candidate  ProfileDefinition `json:"candidate"`
	Previous   string            `json:"previous"`
	AttestedBy string            `json:"attested_by"`
	Gates      []GateResult      `json:"gates"`
	Rollback   RollbackDrill     `json:"rollback"`
	GrantedAt  time.Time         `json:"granted_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	KeyID      string            `json:"key_id"`
	Signature  []byte            `json:"signature,omitempty"`
}

// signedBytes is the canonical payload the authority signs and
// verifies. The signature itself is not part of it.
func (r *PromotionRecord) signedBytes() []byte {
	stripped := PromotionRecord(*r)
	stripped.Signature = nil
	data, err := json.Marshal(stripped)
	if err != nil {
		panic(err)
	}
	return data
}

// PromotionEvent is one audit line: granted, rolled back, or lapsed.
type PromotionEvent struct {
	Kind      string    `json:"kind"`
	TenantID  string    `json:"tenant_id"`
	Promotion string    `json:"promotion_id"`
	Detail    string    `json:"detail"`
	At        time.Time `json:"at"`
}

// PromotionRefusal carries every problem, not the first. A promotion
// with two broken gates reports both.
type PromotionRefusal struct{ Problems []string }

func (e *PromotionRefusal) Error() string {
	return fmt.Sprintf("promotion refused: %d problems: %s",
		len(e.Problems), joinProblems(e.Problems))
}

func joinProblems(problems []string) string {
	out := ""
	for i, problem := range problems {
		if i > 0 {
			out += "; "
		}
		out += problem
	}
	return out
}

// binding is what a tenant currently runs. A binding with an empty
// promotion is a rollback landing: the restored profile is not itself
// a promotion and carries no expiry.
type binding struct {
	profile    ProfileDefinition
	promotion  string
	previous   string
	expiresAt  time.Time
	lapseNoted bool
}

// PromotionAuthority promotes preapproved profiles within one root
// policy. It signs every record, keeps the active binding per tenant,
// and restores the previous profile on rollback or expiry.
type PromotionAuthority struct {
	mu sync.Mutex

	preapproval *Preapproval
	rootPolicy  string
	private     ed25519.PrivateKey
	keyID       string
	attesters   map[string]bool

	// MaxExpiry caps every promotion's lifetime. Bounded promotion
	// means bounded: no request extends past it.
	MaxExpiry time.Duration
	// MaxFalseInterventions caps the shadow gate's benign
	// escalations. A candidate that buys speed with interventions
	// does not promote.
	MaxFalseInterventions int
	// MinShadowObservations is the smallest shadow set that counts as
	// evidence at all.
	MinShadowObservations int

	active     map[string]*binding
	promotions map[string]*PromotionRecord
	events     []PromotionEvent

	now func() time.Time
}

// NewPromotionAuthority builds the authority. The preapproval must
// contain a floor profile — exactly the required layers under this
// root policy — so rollback always has somewhere safe to land. Every
// preapproved profile must run under this authority's root policy: a
// profile cannot change the root policy it enforces.
func NewPromotionAuthority(preapproval *Preapproval,
	rootPolicy string, private ed25519.PrivateKey, keyID string,
	attesters []string) (*PromotionAuthority, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"the authority key is not an ed25519 private key")
	}
	if keyID == "" {
		return nil, fmt.Errorf("the authority key needs an id")
	}
	if !reRootPolicyRef.MatchString(rootPolicy) {
		return nil, fmt.Errorf("root policy %q is not a policy id", rootPolicy)
	}
	floor := false
	for _, profile := range preapproval.profiles {
		if profile.RootPolicy != rootPolicy {
			return nil, fmt.Errorf(
				"preapproval carries %s under root policy %q; this "+
					"authority operates under %q and a profile cannot "+
					"change its root policy",
				profile.key(), profile.RootPolicy, rootPolicy)
		}
		if onlyRequiredLayers(profile) {
			floor = true
		}
	}
	if !floor {
		return nil, fmt.Errorf(
			"preapproval has no floor profile: exactly %v under %q, "+
				"so rollback has nowhere safe to land",
			RequiredLayers, rootPolicy)
	}
	attesterSet := map[string]bool{}
	for _, attester := range attesters {
		if attester == "" {
			return nil, fmt.Errorf("an attester id is empty")
		}
		attesterSet[attester] = true
	}
	if len(attesterSet) == 0 {
		return nil, fmt.Errorf(
			"the authority needs at least one allowed attester")
	}
	return &PromotionAuthority{
		preapproval:           preapproval,
		rootPolicy:            rootPolicy,
		private:               private,
		keyID:                 keyID,
		attesters:             attesterSet,
		MaxExpiry:             24 * time.Hour,
		MaxFalseInterventions: 0,
		MinShadowObservations: 1,
		active:                map[string]*binding{},
		promotions:            map[string]*PromotionRecord{},
		now:                   time.Now,
	}, nil
}

func onlyRequiredLayers(profile ProfileDefinition) bool {
	if len(profile.Layers) != len(RequiredLayers) {
		return false
	}
	return profile.RunsRequiredLayers()
}

// PromotionRequest is everything Promote needs.
type PromotionRequest struct {
	TenantID   string
	Candidate  ProfileDefinition
	AttestedBy string
	Gates      []GateResult
	Rollback   RollbackDrill
	ExpiresAt  time.Time
}

// Promote runs the gate checks and, when everything passes, signs and
// records a bounded promotion. Every failed check is collected: the
// caller sees the whole problem list, not a race to the first.
func (a *PromotionAuthority) Promote(request PromotionRequest) (
	*PromotionRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	problems := []string{}
	now := a.now()

	if !reTenantID.MatchString(request.TenantID) {
		problems = append(problems, fmt.Sprintf(
			"tenant id %q must match tnt_[a-z0-9]{8,64}", request.TenantID))
	}
	if !a.attesters[request.AttestedBy] {
		problems = append(problems, fmt.Sprintf(
			"attester %q is not allowed to attest gates for this authority",
			request.AttestedBy))
	}
	if err := request.Candidate.Validate(); err != nil {
		problems = append(problems, err.Error())
	}
	if request.Candidate.ID != "" && !a.preapproval.Contains(request.Candidate) {
		problems = append(problems, fmt.Sprintf(
			"candidate %s is not in the preapproval set by digest; only "+
				"preapproved profiles promote (spec 15.4)",
			request.Candidate.key()))
	}
	if request.Candidate.RootPolicy != "" &&
		request.Candidate.RootPolicy != a.rootPolicy {
		problems = append(problems, fmt.Sprintf(
			"candidate %s runs under root policy %q, not %q; automated "+
				"promotion cannot change the root policy",
			request.Candidate.key(), request.Candidate.RootPolicy,
			a.rootPolicy))
	}
	if request.Candidate.ID != "" && !request.Candidate.RunsRequiredLayers() {
		problems = append(problems, fmt.Sprintf(
			"candidate %s drops required layers %v; removing the hard "+
				"boundary is the silent weakening of root policy the "+
				"specification forbids",
			request.Candidate.key(), RequiredLayers))
	}

	// Gates: all present, passed, and bound to this candidate's
	// digest. Gate evidence from any other version is stale.
	byGate := map[string]GateResult{}
	for _, gate := range request.Gates {
		if gate.Gate == "" {
			problems = append(problems, "a gate result carries no gate name")
			continue
		}
		if _, dup := byGate[gate.Gate]; dup {
			problems = append(problems, fmt.Sprintf(
				"gate %q appears twice", gate.Gate))
			continue
		}
		byGate[gate.Gate] = gate
	}
	candidateDigest := request.Candidate.Digest()
	for _, gate := range RequiredGates {
		result, ok := byGate[gate]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"gate %q is missing; development, held-out, and shadow "+
					"all run before promotion (spec 15.4)", gate))
			continue
		}
		if result.CandidateDigest != candidateDigest {
			problems = append(problems, fmt.Sprintf(
				"gate %q is bound to candidate digest %q, not %q; gate "+
					"evidence does not carry across profile versions", gate,
				result.CandidateDigest, candidateDigest))
		}
		if result.SuiteDigest == "" {
			problems = append(problems, fmt.Sprintf(
				"gate %q cites no suite digest; unevaluable evidence "+
					"never promotes", gate))
		}
		if !result.Passed {
			problems = append(problems, fmt.Sprintf(
				"gate %q did not pass", gate))
		}
	}
	// The shadow gate carries the safety counters.
	if shadow, ok := byGate[GateShadow]; ok &&
		shadow.CandidateDigest == candidateDigest {
		if shadow.UnauthorizedEffects != 0 {
			problems = append(problems, fmt.Sprintf(
				"the shadow gate observed %d unauthorized effects; a "+
					"candidate that causes the harm it supervises never "+
					"promotes", shadow.UnauthorizedEffects))
		}
		if shadow.Observations < a.MinShadowObservations {
			problems = append(problems, fmt.Sprintf(
				"the shadow gate ran %d observations; this authority "+
					"requires at least %d before its evidence counts",
				shadow.Observations, a.MinShadowObservations))
		}
		if shadow.BenignTasks == 0 {
			problems = append(problems,
				"the shadow gate observed no benign tasks; false "+
					"interventions are unmeasured, not zero")
		} else if shadow.FalseInterventions > a.MaxFalseInterventions {
			problems = append(problems, fmt.Sprintf(
				"the shadow gate escalated %d of %d benign tasks; this "+
					"authority allows at most %d",
				shadow.FalseInterventions, shadow.BenignTasks,
				a.MaxFalseInterventions))
		}
	}

	// Rollback before bounded promotion: the drill must exist, pass,
	// and restore from this candidate to what promotion replaces.
	previous := a.previousKey(request.TenantID)
	if !request.Rollback.Passed {
		problems = append(problems,
			"no rollback drill passed; rollback is rehearsed before "+
				"promotion, not improvised after (AC-033)")
	} else if request.Rollback.Candidate != request.Candidate.key() {
		problems = append(problems, fmt.Sprintf(
			"the rollback drill exercised %q, not candidate %q",
			request.Rollback.Candidate, request.Candidate.key()))
	} else if request.Rollback.Restores != previous {
		problems = append(problems, fmt.Sprintf(
			"the rollback drill restores %q, but promotion would replace "+
				"%q", request.Rollback.Restores, previous))
	}

	// Bounded lifetime.
	if request.ExpiresAt.IsZero() {
		problems = append(problems,
			"the promotion carries no expiry; bounded promotion means "+
				"it ends")
	} else if !request.ExpiresAt.After(now) {
		problems = append(problems, fmt.Sprintf(
			"the promotion expires at %s, which is not in the future",
			request.ExpiresAt.Format(timeFormat)))
	} else if request.ExpiresAt.After(now.Add(a.MaxExpiry)) {
		problems = append(problems, fmt.Sprintf(
			"the promotion would outlive this authority's cap of %s",
			a.MaxExpiry))
	}

	if len(problems) > 0 {
		return nil, &PromotionRefusal{Problems: problems}
	}

	record := &PromotionRecord{
		ID:         "prm_" + hex.EncodeToString(shortDigest(request, now)),
		TenantID:   request.TenantID,
		Candidate:  request.Candidate,
		Previous:   previous,
		AttestedBy: request.AttestedBy,
		Gates:      append([]GateResult{}, request.Gates...),
		Rollback:   request.Rollback,
		GrantedAt:  now,
		ExpiresAt:  request.ExpiresAt,
		KeyID:      a.keyID,
	}
	record.Signature = ed25519.Sign(a.private, record.signedBytes())
	a.promotions[record.ID] = record
	a.active[request.TenantID] = &binding{
		profile:   request.Candidate,
		promotion: record.ID,
		previous:  previous,
		expiresAt: request.ExpiresAt,
	}
	a.events = append(a.events, PromotionEvent{
		Kind:      EventPromoted,
		TenantID:  request.TenantID,
		Promotion: record.ID,
		Detail: fmt.Sprintf("%s promoted over %s, expires %s",
			request.Candidate.key(), previous,
			request.ExpiresAt.Format(timeFormat)),
		At: now,
	})
	return record, nil
}

// previousKey names what a promotion replaces: what the tenant
// actually runs now — the active profile, the restored landing after
// a rollback, the previous profile after a lapse, or the floor for a
// tenant's first promotion.
func (a *PromotionAuthority) previousKey(tenantID string) string {
	current, ok := a.active[tenantID]
	if !ok {
		return a.floorKey()
	}
	if current.promotion == "" || !a.expired(current) {
		return current.profile.key()
	}
	if current.previous != "" {
		if _, still := a.preapproval.profiles[current.previous]; still {
			return current.previous
		}
	}
	return a.floorKey()
}

func (a *PromotionAuthority) expired(b *binding) bool {
	return !b.expiresAt.After(a.now())
}

// Active returns the tenant's current profile. An expired promotion
// lapses here: the binding falls back to the profile it replaced, and
// the lapse is audited once.
func (a *PromotionAuthority) Active(tenantID string) (
	ProfileDefinition, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.active[tenantID]
	if !ok {
		return ProfileDefinition{}, fmt.Errorf(
			"tenant %s has no promoted profile", tenantID)
	}
	if current.promotion == "" {
		// A rollback landing: the restored profile runs without being
		// a promotion of its own.
		return current.profile, nil
	}
	if a.expired(current) {
		if !current.lapseNoted {
			a.events = append(a.events, PromotionEvent{
				Kind:      EventLapsed,
				TenantID:  tenantID,
				Promotion: current.promotion,
				Detail: fmt.Sprintf("promotion %s expired; back on %s",
					current.promotion, current.previous),
				At: a.now(),
			})
			current.lapseNoted = true
		}
		return a.resolveKey(current.previous)
	}
	return current.profile, nil
}

// Rollback restores what the tenant ran before the active promotion.
// The operator drives it; the authority records why. A rollback with
// no reason is refused: a silent rollback is a silent weakening.
func (a *PromotionAuthority) Rollback(tenantID, reason string) (
	*PromotionEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.active[tenantID]
	if !ok {
		return nil, fmt.Errorf(
			"tenant %s has no promotion to roll back", tenantID)
	}
	if reason == "" {
		return nil, fmt.Errorf(
			"a rollback records its reason; a silent rollback is a " +
				"silent weakening")
	}
	target := current.previous
	if target == "" {
		target = a.floorKey()
	}
	restored, err := a.resolveKey(target)
	if err != nil {
		return nil, err
	}
	event := PromotionEvent{
		Kind:      EventRolledBack,
		TenantID:  tenantID,
		Promotion: current.promotion,
		Detail:    fmt.Sprintf("back on %s: %s", restored.key(), reason),
		At:        a.now(),
	}
	a.events = append(a.events, event)
	a.active[tenantID] = &binding{
		profile:   restored,
		promotion: "",
		previous:  a.floorKey(),
	}
	return &event, nil
}

// resolveKey finds a preapproved profile by id@version key, landing
// on the floor when the key left the preapproval set.
func (a *PromotionAuthority) resolveKey(key string) (
	ProfileDefinition, error) {
	if profile, ok := a.preapproval.profiles[key]; ok {
		return profile, nil
	}
	floor := a.floorKey()
	if profile, ok := a.preapproval.profiles[floor]; ok {
		return profile, nil
	}
	return ProfileDefinition{}, fmt.Errorf(
		"profile %q left the preapproval set and no floor profile exists",
		key)
}

func (a *PromotionAuthority) floorKey() string {
	for key, profile := range a.preapproval.profiles {
		if profile.RootPolicy == a.rootPolicy && onlyRequiredLayers(profile) {
			return key
		}
	}
	return ""
}

// VerifyPromotion checks a record's signature against the authority
// key. A promotion record that cannot be verified is not evidence of
// anything.
func (a *PromotionAuthority) VerifyPromotion(record *PromotionRecord) error {
	if !rePromotionID.MatchString(record.ID) {
		return fmt.Errorf("promotion id %q is malformed", record.ID)
	}
	if record.KeyID != a.keyID {
		return fmt.Errorf(
			"promotion %s claims key %q; this authority signs with %q",
			record.ID, record.KeyID, a.keyID)
	}
	if len(record.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("promotion %s carries no valid signature", record.ID)
	}
	public := a.private.Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, record.signedBytes(), record.Signature) {
		return fmt.Errorf(
			"promotion %s fails signature verification", record.ID)
	}
	return nil
}

// Records returns every promotion this authority granted, oldest
// first.
func (a *PromotionAuthority) Records() []*PromotionRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*PromotionRecord, 0, len(a.promotions))
	for _, record := range a.promotions {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].GrantedAt.Before(out[j].GrantedAt)
	})
	return out
}

// Events returns the audit trail.
func (a *PromotionAuthority) Events() []PromotionEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]PromotionEvent{}, a.events...)
}

// shortDigest hashes the request's signed-shape bytes for the
// promotion id: the same request at the same instant is the same
// promotion; anything that differs gets its own id.
func shortDigest(request PromotionRequest, now time.Time) []byte {
	shape := &PromotionRecord{
		TenantID:  request.TenantID,
		Candidate: request.Candidate,
		Previous:  request.Rollback.Restores,
		Gates:     request.Gates,
		Rollback:  request.Rollback,
		GrantedAt: now,
		ExpiresAt: request.ExpiresAt,
	}
	sum := sha256.Sum256(shape.signedBytes())
	return sum[:8]
}
