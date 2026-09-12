package broker

import (
	"fmt"
	"net/url"
	"strings"
)

// Delegation states (Delegation contract).
const (
	DelegationActive  = "active"
	DelegationRevoked = "revoked"
)

// MaxDelegationDepth bounds the delegation tree (spec 12, F13:
// excessive delegation and recursion are bounded).
const MaxDelegationDepth = 8

// Delegation mirrors the Delegation contract
// (shared/schemas/delegation.schema.json). Children can only narrow
// capabilities and share the parent's cumulative budget; widening is
// not representable (spec 10, 18.1, AC-008).
type Delegation struct {
	Kind               string       `json:"kind"`
	APIVersion         string       `json:"api_version"`
	ID                 string       `json:"id"`
	TenantID           string       `json:"tenant_id"`
	RunID              string       `json:"run_id"`
	ParentActor        string       `json:"parent_actor"`
	ChildActor         string       `json:"child_actor"`
	ParentDelegationID string       `json:"parent_delegation_id,omitempty"`
	Depth              int          `json:"depth"`
	Capabilities       Capabilities `json:"capabilities"`
	CumulativeBudget   Budget       `json:"cumulative_budget"`
	State              string       `json:"state"`
	RevokedAt          string       `json:"revoked_at,omitempty"`
	CreatedAt          string       `json:"created_at"`
}

// Capabilities is the narrowed capability set.
type Capabilities struct {
	AllowedActionClasses []string `json:"allowed_action_classes"`
	AllowedDestinations  []string `json:"allowed_destinations"`
	AllowedResources     []string `json:"allowed_resources"`
}

// Budget is the cumulative ceiling shared by a delegation group.
type Budget struct {
	MaxTotalCost   Money `json:"max_total_cost"`
	MaxTotalTokens int64 `json:"max_total_tokens"`
	MaxEffects     int64 `json:"max_effects"`
}

// DelegationRequest is a parent's proposal to mint a child
// delegation. The tenant never appears here: it comes from the
// authenticated principal (spec 18.3).
type DelegationRequest struct {
	ID                 string       `json:"id"`
	RunID              string       `json:"run_id"`
	ParentActor        string       `json:"parent_actor"`
	ChildActor         string       `json:"child_actor"`
	ParentDelegationID string       `json:"parent_delegation_id,omitempty"`
	Capabilities       Capabilities `json:"capabilities"`
	CumulativeBudget   Budget       `json:"cumulative_budget"`
}

// DelegationRefusal reports narrowing violations as contract errors
// for the problem body.
type DelegationRefusal struct {
	Errors []ContractError
}

func (r *DelegationRefusal) Error() string {
	if len(r.Errors) == 0 {
		return "delegation refused"
	}
	return fmt.Sprintf("delegation refused: %s: %s", r.Errors[0].Check, r.Errors[0].Detail)
}

// Delegate mints a child delegation after checking the narrowing
// rules (spec 10, AC-008): the child's capabilities must be a subset
// of the parent's, the child's budget cannot exceed the parent's,
// and the tree depth stays bounded. The parent of a root delegation
// is the run grant itself.
func (b *Broker) Delegate(principal *Principal, request *DelegationRequest) (*Delegation, error) {
	if principal == nil {
		return nil, fmt.Errorf("unauthenticated caller cannot delegate")
	}
	switch principal.Role {
	case RoleService, RoleOperator:
	default:
		return nil, fmt.Errorf("role %s cannot delegate", principal.Role)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.delegateLocked(principal, request)
}

// delegateLocked mints the delegation. The caller holds b.mu.
func (b *Broker) delegateLocked(principal *Principal, request *DelegationRequest) (*Delegation, error) {
	run := b.runs[request.RunID]
	if run == nil || run.TenantID != principal.TenantID {
		return nil, &DelegationRefusal{Errors: []ContractError{{
			Check: "run_unknown", Path: "$.run_id",
			Detail: "the run does not exist in the caller's tenant",
		}}}
	}
	scoped := effectKey(principal.TenantID, request.ID)
	if _, exists := b.delegations[scoped]; exists {
		return nil, errDelegationExists
	}

	parent, err := b.resolveParentLocked(principal.TenantID, request)
	if err != nil {
		return nil, err
	}

	refusal := &DelegationRefusal{}
	// Normalized before every check: omitted and empty arrays are the
	// same fail-closed narrowing to nothing, never "unrestricted".
	caps := normalizeCapabilities(request.Capabilities)
	budget := request.CumulativeBudget
	if !subsetOf(caps.AllowedActionClasses, parent.classes) {
		refusal.Errors = append(refusal.Errors, ContractError{
			Check: "classes_widened", Path: "$.capabilities.allowed_action_classes",
			Detail: "a child can only narrow action classes",
		})
	}
	if parent.destinations != nil && !subsetOf(caps.AllowedDestinations, parent.destinations) {
		refusal.Errors = append(refusal.Errors, ContractError{
			Check: "destinations_widened", Path: "$.capabilities.allowed_destinations",
			Detail: "every child destination must appear in the parent set",
		})
	}
	if parent.resources != nil && !subsetOf(caps.AllowedResources, parent.resources) {
		refusal.Errors = append(refusal.Errors, ContractError{
			Check: "resources_widened", Path: "$.capabilities.allowed_resources",
			Detail: "every child resource must appear in the parent set",
		})
	}
	if parent.budget != nil {
		if budget.MaxTotalCost.Micros > parent.budget.MaxTotalCost.Micros ||
			budget.MaxTotalCost.Currency != parent.budget.MaxTotalCost.Currency {
			refusal.Errors = append(refusal.Errors, ContractError{
				Check: "budget_raised", Path: "$.cumulative_budget.max_total_cost",
				Detail: "a child cannot raise the shared cumulative cost budget",
			})
		}
		if budget.MaxTotalTokens > parent.budget.MaxTotalTokens {
			refusal.Errors = append(refusal.Errors, ContractError{
				Check: "budget_raised", Path: "$.cumulative_budget.max_total_tokens",
				Detail: "a child cannot raise the shared cumulative token budget",
			})
		}
		if budget.MaxEffects > parent.budget.MaxEffects {
			refusal.Errors = append(refusal.Errors, ContractError{
				Check: "budget_raised", Path: "$.cumulative_budget.max_effects",
				Detail: "a child cannot raise the shared cumulative effect budget",
			})
		}
	}
	if parent.depth+1 > MaxDelegationDepth {
		refusal.Errors = append(refusal.Errors, ContractError{
			Check: "depth_exceeded", Path: "$.depth",
			Detail: fmt.Sprintf("delegation trees are bounded at depth %d (spec F13)", MaxDelegationDepth),
		})
	}
	if len(refusal.Errors) > 0 {
		return nil, refusal
	}

	delegation := &Delegation{
		Kind:               "Delegation",
		APIVersion:         "v1",
		ID:                 request.ID,
		TenantID:           principal.TenantID,
		RunID:              request.RunID,
		ParentActor:        request.ParentActor,
		ChildActor:         request.ChildActor,
		ParentDelegationID: request.ParentDelegationID,
		Depth:              parent.depth + 1,
		Capabilities:       cloneCapabilities(caps),
		CumulativeBudget:   budget,
		State:              DelegationActive,
		CreatedAt:          b.ClockUTC(),
	}
	b.delegations[scoped] = delegation
	b.appendEvent(delegationEvent(delegation, "mint", b.ClockUTC(), map[string]any{
		"depth":  delegation.Depth,
		"budget": budgetSummary(delegation.CumulativeBudget),
	}))
	return cloneDelegation(delegation), nil
}

// parentScope is what a child narrows from. A nil destinations or
// resources slice means the RUN ROOT is unrestricted: only
// resolveParentLocked's run-root branch produces nil, because stored
// delegations normalize their arrays to non-nil. For a delegation
// parent, an empty (non-nil) array means "nothing permitted", and a
// child of it can only stay empty.
type parentScope struct {
	classes      []string
	destinations []string // nil only for an unrestricted run root
	resources    []string // nil only for an unrestricted run root
	budget       *Budget  // nil means the run root declared no budget
	depth        int
}

// resolveParentLocked resolves the parent scope for a mint: a parent
// delegation, or the run grant for a tree root. The caller holds b.mu.
func (b *Broker) resolveParentLocked(tenantID string, request *DelegationRequest) (*parentScope, error) {
	run := b.runs[request.RunID]
	if request.ParentDelegationID == "" {
		scope := &parentScope{classes: run.AllowedClasses, depth: 0}
		if run.RootCapabilities != nil {
			scope.destinations = run.RootCapabilities.AllowedDestinations
			scope.resources = run.RootCapabilities.AllowedResources
			if !subsetOf(run.RootCapabilities.AllowedActionClasses, run.AllowedClasses) {
				return nil, &DelegationRefusal{Errors: []ContractError{{
					Check: "run_root_invalid", Path: "$.run_id",
					Detail: "the run's root capabilities exceed its permitted classes",
				}}}
			}
			scope.classes = run.RootCapabilities.AllowedActionClasses
		}
		scope.budget = run.RootBudget
		return scope, nil
	}

	scoped := effectKey(tenantID, request.ParentDelegationID)
	parent, ok := b.delegations[scoped]
	if !ok || parent.RunID != request.RunID {
		return nil, &DelegationRefusal{Errors: []ContractError{{
			Check: "parent_unknown", Path: "$.parent_delegation_id",
			Detail: "the parent delegation does not exist in this run",
		}}}
	}
	if err := b.chainActiveLocked(tenantID, parent); err != nil {
		return nil, err
	}
	if parent.ChildActor != request.ParentActor {
		return nil, &DelegationRefusal{Errors: []ContractError{{
			Check: "parent_actor_mismatch", Path: "$.parent_actor",
			Detail: "only the delegation holder can delegate further",
		}}}
	}
	return &parentScope{
		classes:      parent.Capabilities.AllowedActionClasses,
		destinations: parent.Capabilities.AllowedDestinations,
		resources:    parent.Capabilities.AllowedResources,
		budget:       &parent.CumulativeBudget,
		depth:        parent.Depth,
	}, nil
}

// chainActiveLocked walks the ancestor chain and fails when any node
// is revoked: a revoked delegation fences its whole group (spec 13,
// stop behavior). The caller holds b.mu.
func (b *Broker) chainActiveLocked(tenantID string, delegation *Delegation) error {
	for node := delegation; node != nil; {
		if node.State != DelegationActive {
			return &DelegationRefusal{Errors: []ContractError{{
				Check: "delegation_revoked", Path: "$.parent_delegation_id",
				Detail: fmt.Sprintf("delegation %s is revoked; its group is fenced", node.ID),
			}}}
		}
		if node.ParentDelegationID == "" {
			return nil
		}
		parent, ok := b.delegations[effectKey(tenantID, node.ParentDelegationID)]
		if !ok {
			return &DelegationRefusal{Errors: []ContractError{{
				Check: "parent_unknown", Path: "$.parent_delegation_id",
				Detail: "the ancestor chain is broken",
			}}}
		}
		node = parent
	}
	return nil
}

// RevokeDelegation marks a delegation revoked. Revocation is the only
// mutation after minting: attenuate or revoke, never widen
// (spec 18.1). Revoking fences the whole delegation group.
func (b *Broker) RevokeDelegation(principal *Principal, delegationID, reason string) (*Delegation, error) {
	if principal == nil {
		return nil, fmt.Errorf("unauthenticated caller cannot revoke")
	}
	switch principal.Role {
	case RoleService, RoleOperator:
	default:
		return nil, fmt.Errorf("role %s cannot revoke", principal.Role)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	scoped := effectKey(principal.TenantID, delegationID)
	delegation, ok := b.delegations[scoped]
	if !ok {
		return nil, errDelegationNotFound
	}
	if delegation.TenantID != principal.TenantID {
		return nil, fmt.Errorf("tenant %s cannot act on tenant %s records",
			principal.TenantID, delegation.TenantID)
	}
	if delegation.State == DelegationActive {
		delegation.State = DelegationRevoked
		delegation.RevokedAt = b.ClockUTC()
		// The reason is advisory; long input is truncated, never
		// amplified into the evidence journal (spec 19).
		if len(reason) > MaxRevocationReason {
			reason = reason[:MaxRevocationReason]
		}
		b.appendEvent(delegationEvent(delegation, "revoke", b.ClockUTC(), map[string]any{
			"reason": reason,
		}))
	}
	return cloneDelegation(delegation), nil
}

// delegationReason applies the delegation scope to an allowed
// proposal: the child identity is bound, every capability narrows,
// and the shared cumulative budget holds tree-wide (AC-008). It
// returns the deny reason, or "" when the delegation permits the
// proposal. The caller holds b.mu.
func (b *Broker) delegationReason(tenantID string, proposal *Effect, rule *OperationRule) string {
	scoped := effectKey(tenantID, proposal.DelegationID)
	delegation, ok := b.delegations[scoped]
	if !ok {
		return "delegation_unknown"
	}
	if delegation.RunID != proposal.RunID {
		return "delegation_run_mismatch"
	}
	if delegation.ChildActor != proposal.Actor {
		return "delegation_actor_mismatch"
	}
	if err := b.chainActiveLocked(tenantID, delegation); err != nil {
		return "delegation_revoked"
	}
	caps := delegation.Capabilities
	if !contains(caps.AllowedActionClasses, proposal.ActionClass) {
		return "class_not_permitted_for_delegation"
	}
	if !destinationAllowed(caps.AllowedDestinations, proposal.ProposedAction.Destination) {
		return "destination_not_permitted_for_delegation"
	}
	if !contains(caps.AllowedResources, proposal.ProposedAction.Resource) {
		return "resource_not_permitted_for_delegation"
	}
	if reason := b.budgetReasonLocked(tenantID, delegation, rule); reason != "" {
		return reason
	}
	return ""
}

// budgetReasonLocked enforces the shared cumulative budget (spec 10,
// F13). The tightest ceiling along the ancestor chain governs,
// because a child can only lower it; a run root budget governs every
// delegated effect of the run, because the run grant is the parent of
// a tree root. Effects count when they carry a permit (a deny consumes
// nothing); cost is the authorized money ceiling, a fail-closed upper
// bound known before dispatch. Tokens are observed in the execution
// plane, not by the broker; the runner enforces that field. The
// caller holds b.mu.
func (b *Broker) budgetReasonLocked(tenantID string, delegation *Delegation, rule *OperationRule) string {
	chain := b.delegationChainLocked(tenantID, delegation)
	maxEffects := delegation.CumulativeBudget.MaxEffects
	maxCostMicros := delegation.CumulativeBudget.MaxTotalCost.Micros
	for _, node := range chain {
		if node.CumulativeBudget.MaxEffects < maxEffects {
			maxEffects = node.CumulativeBudget.MaxEffects
		}
		if node.CumulativeBudget.MaxTotalCost.Micros < maxCostMicros {
			maxCostMicros = node.CumulativeBudget.MaxTotalCost.Micros
		}
	}
	runWide := false
	if run := b.runs[delegation.RunID]; run != nil && run.RootBudget != nil {
		runWide = true
		if run.RootBudget.MaxEffects < maxEffects {
			maxEffects = run.RootBudget.MaxEffects
		}
		if run.RootBudget.MaxTotalCost.Micros < maxCostMicros {
			maxCostMicros = run.RootBudget.MaxTotalCost.Micros
		}
	}
	tree := b.delegationTreeLocked(tenantID, chain[0])

	effects := int64(0)
	var costMicros int64
	for _, effect := range b.effects {
		if effect.RunID != delegation.RunID || effect.Authorization == nil {
			continue // denied and unpermitted effects consume nothing
		}
		if effect.DelegationID == "" {
			continue
		}
		// A run-wide root budget counts every delegated effect of the
		// run; a tree budget counts only this tree.
		if runWide || tree[effect.DelegationID] {
			effects++
			if limit := effect.Authorization.AmountLimit; limit != nil {
				// Saturate at the ceiling instead of wrapping: money
				// micros carry no upper bound in the contract, and a
				// negative sum would disarm the check.
				costMicros = addSaturating(costMicros, limit.Money.Micros, maxCostMicros)
			}
		}
	}
	if effects+1 > maxEffects {
		return "effect_budget_exhausted"
	}
	pendingMicros, pendingCurrency := int64(0), ""
	if rule != nil && rule.AmountLimit != nil {
		pendingMicros = rule.AmountLimit.Micros
		pendingCurrency = rule.AmountLimit.Currency
	}
	if pendingCurrency != "" && pendingCurrency != delegation.CumulativeBudget.MaxTotalCost.Currency {
		// Money the budget cannot denominate fails closed: an
		// incomparable ceiling is an exceeded one.
		return "cost_currency_mismatch"
	}
	// The subtraction form cannot overflow: both addends are
	// non-negative, and each is compared against the ceiling first.
	if pendingMicros > maxCostMicros || costMicros > maxCostMicros ||
		costMicros > maxCostMicros-pendingMicros {
		return "cost_budget_exhausted"
	}
	return ""
}

// addSaturating adds two non-negative int64 values and clamps the
// result at ceiling. Wrapped sums would read as negative and disarm
// every later comparison (AC-008).
func addSaturating(a, b, ceiling int64) int64 {
	if a >= ceiling || b >= ceiling || a > ceiling-b {
		return ceiling
	}
	return a + b
}

// delegationChainLocked returns the chain from the tree root down to
// the given delegation, root first. The caller holds b.mu.
func (b *Broker) delegationChainLocked(tenantID string, delegation *Delegation) []*Delegation {
	var chain []*Delegation
	for node := delegation; node != nil; {
		chain = append(chain, node)
		if node.ParentDelegationID == "" {
			break
		}
		parent, ok := b.delegations[effectKey(tenantID, node.ParentDelegationID)]
		if !ok {
			break
		}
		node = parent
	}
	// Reverse: root first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// delegationTreeLocked collects every delegation id in the tree
// rooted at the given root, the root included. The caller holds b.mu.
func (b *Broker) delegationTreeLocked(tenantID string, root *Delegation) map[string]bool {
	tree := map[string]bool{root.ID: true}
	// Breadth-first over child links; depth is bounded at mint, so
	// this walk terminates.
	frontier := []*Delegation{root}
	for len(frontier) > 0 {
		node := frontier[0]
		frontier = frontier[1:]
		for _, candidate := range b.delegations {
			if candidate.ParentDelegationID == node.ID &&
				candidate.TenantID == tenantID && !tree[candidate.ID] {
				tree[candidate.ID] = true
				frontier = append(frontier, candidate)
			}
		}
	}
	return tree
}

// delegationEvent journals a mint or revoke as a delegation evidence
// event (spec 9.4: delegations are recorded).
func delegationEvent(delegation *Delegation, action, at string, extra map[string]any) EvidenceEvent {
	payload := map[string]any{
		"action":       action,
		"child_actor":  delegation.ChildActor,
		"parent_actor": delegation.ParentActor,
		"state":        delegation.State,
	}
	for key, value := range extra {
		payload[key] = value
	}
	return EvidenceEvent{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         mintEventIDSoon(),
		TenantID:   delegation.TenantID,
		RunID:      delegation.RunID,
		EventKind:  "delegation",
		TrustLabel: "collector_fact",
		Source:     EventSource{ID: brokerSourceID, Component: "broker"},
		ObservedAt: at,
		Payload:    inlinePayload(payload),
	}
}

func budgetSummary(budget Budget) string {
	return fmt.Sprintf("%s %d micros, %d tokens, %d effects",
		budget.MaxTotalCost.Currency, budget.MaxTotalCost.Micros,
		budget.MaxTotalTokens, budget.MaxEffects)
}

// subsetOf reports whether every element of want appears in have. An
// empty want is a valid narrowing to nothing.
func subsetOf(want, have []string) bool {
	for _, element := range want {
		if !contains(have, element) {
			return false
		}
	}
	return true
}

// normalizeCapabilities makes every capability array non-nil. An
// omitted or empty array means "nothing permitted" — the fail-closed
// reading — and it must stay distinguishable from the run root's
// nil-means-unrestricted convention, which applies only to
// RunContext.RootCapabilities. Storing non-nil empty slices also keeps
// the emitted document schema-valid: null is not an array.
func normalizeCapabilities(caps Capabilities) Capabilities {
	return Capabilities{
		AllowedActionClasses: append([]string{}, caps.AllowedActionClasses...),
		AllowedDestinations:  append([]string{}, caps.AllowedDestinations...),
		AllowedResources:     append([]string{}, caps.AllowedResources...),
	}
}

func cloneCapabilities(caps Capabilities) Capabilities {
	return normalizeCapabilities(caps)
}

func cloneDelegation(delegation *Delegation) *Delegation {
	duplicate := *delegation
	duplicate.Capabilities = cloneCapabilities(delegation.Capabilities)
	return &duplicate
}

// errDelegationExists refuses a duplicate delegation id; the registry
// is append-only like the effect ledger.
var errDelegationExists = fmt.Errorf("delegation id already exists")

// errDelegationNotFound is the tenant-safe miss.
var errDelegationNotFound = fmt.Errorf("delegation not found")

// ValidateDelegationRequest checks the request shape against the
// Delegation contract's patterns. Every violation becomes a contract
// error for the problem body.
func (r *DelegationRequest) ValidateDelegationRequest() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if !matches(`^dlg_[a-z0-9]{8,64}$`, r.ID) {
		add("id", "$.id", "must match dlg_[a-z0-9]{8,64}")
	}
	if !reRunID.MatchString(r.RunID) {
		add("run_id", "$.run_id", "must match run_[a-z0-9]{8,64}")
	}
	if !reActorID.MatchString(r.ParentActor) {
		add("parent_actor", "$.parent_actor", "must match act_[a-z0-9][a-z0-9-]{3,63}")
	}
	if !reActorID.MatchString(r.ChildActor) {
		add("child_actor", "$.child_actor", "must match act_[a-z0-9][a-z0-9-]{3,63}")
	}
	if r.ParentDelegationID != "" && !matches(`^dlg_[a-z0-9]{8,64}$`, r.ParentDelegationID) {
		add("parent_delegation_id", "$.parent_delegation_id", "must match dlg_[a-z0-9]{8,64}")
	}
	caps := r.Capabilities
	if len(caps.AllowedActionClasses) > 3 || !uniqueStrings(caps.AllowedActionClasses) {
		add("allowed_action_classes", "$.capabilities.allowed_action_classes",
			"at most three unique classes")
	}
	for _, class := range caps.AllowedActionClasses {
		if class != ClassA0 && class != ClassA1 && class != ClassA2 {
			add("allowed_action_classes", "$.capabilities.allowed_action_classes",
				"class must be A0, A1, or A2")
			break
		}
	}
	if len(caps.AllowedDestinations) > 256 || !uniqueStrings(caps.AllowedDestinations) {
		add("allowed_destinations", "$.capabilities.allowed_destinations",
			"at most 256 unique destinations")
	}
	for _, destination := range caps.AllowedDestinations {
		if !matches(`^(https?://|sink:)[A-Za-z0-9._:/-]{3,252}$`, destination) ||
			!validDestinationEntry(destination) {
			add("allowed_destinations", "$.capabilities.allowed_destinations",
				fmt.Sprintf("%q must be an http(s) URL with a host and no userinfo, or a sink: destination", destination))
			break
		}
	}
	if len(caps.AllowedResources) > 256 || !uniqueStrings(caps.AllowedResources) {
		add("allowed_resources", "$.capabilities.allowed_resources",
			"at most 256 unique resources")
	}
	for _, resource := range caps.AllowedResources {
		if !reResource.MatchString(resource) {
			add("allowed_resources", "$.capabilities.allowed_resources",
				fmt.Sprintf("%q must match the resource pattern", resource))
			break
		}
	}
	budget := r.CumulativeBudget
	if !matches(`^[A-Z]{3}$`, budget.MaxTotalCost.Currency) {
		add("max_total_cost", "$.cumulative_budget.max_total_cost.currency",
			"must be a three-letter currency code")
	}
	if budget.MaxTotalCost.Micros < 0 {
		add("max_total_cost", "$.cumulative_budget.max_total_cost.micros",
			"must not be negative")
	}
	if budget.MaxTotalTokens < 0 || budget.MaxTotalTokens > 1000000000000 {
		add("max_total_tokens", "$.cumulative_budget.max_total_tokens",
			"must be 0..1000000000000")
	}
	if budget.MaxEffects < 0 || budget.MaxEffects > 100000 {
		add("max_effects", "$.cumulative_budget.max_effects", "must be 0..100000")
	}
	return errs
}

// validDestinationEntry fail-closes http(s) entries at request time:
// the entry must parse to a URL with a host and no userinfo.
func validDestinationEntry(destination string) bool {
	if !strings.HasPrefix(destination, "http://") && !strings.HasPrefix(destination, "https://") {
		return true // opaque sink: destination
	}
	parsed, err := url.Parse(destination)
	return err == nil && parsed.Host != "" && parsed.User == nil
}

func uniqueStrings(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
