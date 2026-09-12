package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Semantics declares what an operation does to the outside world.
// A read is not assumed harmless (spec 6.1): reads stay brokered
// because a query can leak, cost, or trigger server-side actions.
const (
	SemanticsRead   = "read"
	SemanticsMutate = "mutate"
)

// OperationRule is one entry of the broker's operation registry.
// The registry is the boundary of "supported external tool calls":
// an operation without a rule is not brokerable and fails closed.
type OperationRule struct {
	Name         string   `json:"name"`
	ActionClass  string   `json:"action_class"`
	Semantics    string   `json:"semantics"`
	Destinations []string `json:"destinations"` // allowed destination prefixes
	MaxSizeBytes int64    `json:"max_size_bytes"`
	AmountLimit  *Money   `json:"amount_limit,omitempty"` // costed operations

	// HardDeny bans the operation outright. A hard deny is enforced
	// before every other check and no review verdict can lift it
	// (spec 11.2: hard denies cannot be outvoted).
	HardDeny bool `json:"hard_deny,omitempty"`
	// RequiresReview holds the effect PROPOSED until a well-formed
	// ALLOW review arrives (spec 10, 11.1). The deterministic gate
	// still runs in full; the review never widens scope.
	RequiresReview bool `json:"requires_review,omitempty"`
	// RequiresResourceVersion demands the proposal pin the resource
	// version it acted on, so time-of-check/time-of-use drift is
	// detectable (spec 10, F15).
	RequiresResourceVersion bool `json:"requires_resource_version,omitempty"`
}

// Policy is the deterministic gate input. It is a versioned
// supply-chain artifact (spec 19): its digest is bound into every
// permit it issues.
type Policy struct {
	Kind       string          `json:"kind"`
	APIVersion string          `json:"api_version"`
	Version    string          `json:"version"`
	Operations []OperationRule `json:"operations"`

	byName map[string]OperationRule
	digest string
}

// RunContext is what the broker knows about an authorized run. The
// control plane supplies it; the broker never learns downstream
// credentials, only the task binding and the grant window (spec 10).
type RunContext struct {
	RunID          string
	TenantID       string
	TaskID         string
	GrantExpiresAt string
	AllowedClasses []string

	// RootCapabilities narrows the run root for delegation minting:
	// the first delegation in a tree narrows from here. Nil means
	// the run's classes apply and destinations and resources are
	// unrestricted (spec 10).
	RootCapabilities *Capabilities
	// RootBudget is the cumulative budget the run's delegation trees
	// share. Nil means no broker-enforced budget; the grant window
	// still bounds everything (spec 10, F13).
	RootBudget *Budget
}

// LoadPolicy decodes and indexes a policy document, computing its
// canonical digest.
func LoadPolicy(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var policy Policy
	if err := dec.Decode(&policy); err != nil {
		return nil, fmt.Errorf("policy decode: %w", err)
	}
	if policy.Kind != "BrokerPolicy" || policy.APIVersion != "v1" {
		return nil, fmt.Errorf("policy must be a v1 BrokerPolicy document")
	}
	if !reSemVer.MatchString(policy.Version) {
		return nil, fmt.Errorf("policy version must be semantic")
	}
	policy.byName = make(map[string]OperationRule, len(policy.Operations))
	for _, rule := range policy.Operations {
		if rule.HardDeny && (rule.RequiresReview || rule.RequiresResourceVersion) {
			return nil, fmt.Errorf(
				"operation %s: a hard deny never reaches review or dispatch; "+
					"it cannot also require either", rule.Name)
		}
		switch rule.ActionClass {
		case ClassA1, ClassA2:
		default:
			return nil, fmt.Errorf("operation %s: class must be A1 or A2", rule.Name)
		}
		switch rule.Semantics {
		case SemanticsRead, SemanticsMutate:
		default:
			return nil, fmt.Errorf("operation %s: semantics must be read or mutate", rule.Name)
		}
		if rule.MaxSizeBytes < 0 {
			return nil, fmt.Errorf("operation %s: negative size ceiling", rule.Name)
		}
		if rule.AmountLimit != nil {
			// Money ceilings feed the delegation budget arithmetic,
			// which assumes non-negative micros (AC-008).
			if rule.AmountLimit.Micros < 0 {
				return nil, fmt.Errorf("operation %s: negative amount limit", rule.Name)
			}
			if !reCurrency.MatchString(rule.AmountLimit.Currency) {
				return nil, fmt.Errorf("operation %s: amount limit currency must be three letters", rule.Name)
			}
		}
		for _, destination := range rule.Destinations {
			if err := validateRuleDestination(rule.Name, destination); err != nil {
				return nil, err
			}
		}
		if _, duplicate := policy.byName[rule.Name]; duplicate {
			return nil, fmt.Errorf("duplicate operation %s", rule.Name)
		}
		policy.byName[rule.Name] = rule
	}
	digest, err := policy.Digest()
	if err != nil {
		return nil, err
	}
	policy.digest = digest
	return &policy, nil
}

// Digest is the sha256 over the canonical policy document. The same
// policy bytes always produce the same digest.
func (p *Policy) Digest() (string, error) {
	ordered := make([]OperationRule, len(p.Operations))
	copy(ordered, p.Operations)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	canonical := struct {
		Kind       string          `json:"kind"`
		APIVersion string          `json:"api_version"`
		Version    string          `json:"version"`
		Operations []OperationRule `json:"operations"`
	}{p.Kind, p.APIVersion, p.Version, ordered}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// GateVerdict is the deterministic gate's decision on one proposal.
type GateVerdict struct {
	Allowed bool
	// NeedsReview marks a proposal that passed every deterministic
	// check but whose rule demands a machine review before a permit
	// exists (spec 10, 11.1). It is not a deny: the effect stays
	// PROPOSED until a well-formed ALLOW review arrives.
	NeedsReview bool
	Reason      string // stable deny code, empty when allowed
	Rule        *OperationRule
	PolicyRefs  []string
}

// Evaluate runs the deterministic gate (spec 11.1 layer 1): scope,
// limits, class, and destination checks. It never consults a model;
// every deny cites the rule that produced it.
func (p *Policy) Evaluate(effect *Effect, run *RunContext, now string) GateVerdict {
	proposal := effect.ProposedAction
	rule, known := p.byName[proposal.Operation]
	if !known {
		return GateVerdict{
			Reason:     "unknown_operation",
			PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
		}
	}
	if rule.HardDeny {
		// Before anything else: a banned operation denies no matter
		// what scope, run, or review would have said (spec 11.2).
		return GateVerdict{
			Reason:     "operation_hard_denied",
			PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
		}
	}
	if run == nil {
		return GateVerdict{
			Reason:     "run_unknown",
			PolicyRefs: []string{p.ref("runs." + effect.RunID)},
		}
	}
	if run.TenantID != effect.TenantID {
		return GateVerdict{
			Reason:     "run_tenant_mismatch",
			PolicyRefs: []string{p.ref("runs." + effect.RunID)},
		}
	}
	if !reTimestamp.MatchString(run.GrantExpiresAt) || momentAtOrBefore(run.GrantExpiresAt, now) {
		return GateVerdict{
			Reason:     "grant_expired",
			PolicyRefs: []string{p.ref("runs." + effect.RunID)},
		}
	}
	if !contains(run.AllowedClasses, effect.ActionClass) {
		return GateVerdict{
			Reason:     "class_not_permitted_for_run",
			PolicyRefs: []string{p.ref("runs." + effect.RunID)},
		}
	}
	if rule.ActionClass != effect.ActionClass {
		return GateVerdict{
			Reason:     "class_mismatch",
			PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
		}
	}
	if !destinationAllowed(rule.Destinations, proposal.Destination) {
		return GateVerdict{
			Reason:     "destination_not_allowed",
			PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
		}
	}
	if proposal.SizeBytes > rule.MaxSizeBytes {
		return GateVerdict{
			Reason:     "size_exceeds_ceiling",
			PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
		}
	}
	if rule.RequiresResourceVersion && proposal.ResourceVersion == "" {
		return GateVerdict{
			Reason:     "resource_version_required",
			PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
		}
	}
	if rule.RequiresReview && effect.Review == nil {
		return GateVerdict{
			NeedsReview: true,
			Reason:      "review_required",
			Rule:        &rule,
			PolicyRefs:  []string{p.ref("operations." + proposal.Operation)},
		}
	}
	return GateVerdict{
		Allowed:    true,
		Rule:       &rule,
		PolicyRefs: []string{p.ref("operations." + proposal.Operation)},
	}
}

func (p *Policy) ref(suffix string) string {
	return "pol_" + p.Version + "/" + suffix
}

// ruleFor looks up an operation's rule for callers that need the rule
// itself, not just a verdict.
func (p *Policy) ruleFor(operation string) (OperationRule, bool) {
	rule, ok := p.byName[operation]
	return rule, ok
}

// destinationAllowed reports whether the destination falls inside a
// rule's allowed destinations. http(s) entries match the exact
// scheme, host, and port plus a path prefix; other entries (sink:
// queue names) match on a string prefix.
func destinationAllowed(prefixes []string, destination string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(prefix, "http://") || strings.HasPrefix(prefix, "https://") {
			if urlWithinPrefix(destination, prefix) {
				return true
			}
			continue
		}
		if strings.HasPrefix(destination, prefix) {
			return true
		}
	}
	return false
}

// urlWithinPrefix is the anchored check for http(s) destinations: the
// destination must share the rule's scheme, host, and port, carry no
// userinfo, and stay under the rule's path. A host that merely
// starts with the rule host ("api.github.evil.com" under
// "api.github.com") is outside the rule.
func urlWithinPrefix(destination, rule string) bool {
	d, err := url.Parse(destination)
	if err != nil || d.User != nil {
		return false
	}
	r, err := url.Parse(rule)
	if err != nil || r.User != nil {
		return false
	}
	if d.Scheme != r.Scheme || d.Hostname() == "" ||
		!strings.EqualFold(d.Hostname(), r.Hostname()) || urlPort(d) != urlPort(r) {
		return false
	}
	rulePath := r.Path
	if rulePath == "" {
		rulePath = "/"
	}
	return strings.HasPrefix(d.Path, rulePath)
}

// urlPort returns the effective port of a parsed URL.
func urlPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// validateRuleDestination fails closed at load time: an http(s)
// entry must parse to a URL with a host and no userinfo.
func validateRuleDestination(operation, destination string) error {
	if !strings.HasPrefix(destination, "http://") && !strings.HasPrefix(destination, "https://") {
		return nil // opaque destination (sink: queue names)
	}
	parsed, err := url.Parse(destination)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("operation %s: destination %q must be an http(s) URL with a host and no userinfo",
			operation, destination)
	}
	return nil
}

// momentAtOrBefore compares two contract timestamps as instants.
// Unparseable input fails closed: it counts as already past.
func momentAtOrBefore(a, b string) bool {
	momentA, errA := time.Parse(time.RFC3339Nano, a)
	momentB, errB := time.Parse(time.RFC3339Nano, b)
	if errA != nil || errB != nil {
		return true
	}
	return !momentA.After(momentB)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
