package broker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testNow = "2026-09-12T10:00:00Z"

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	policy, err := LoadPolicy(DefaultPolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testRun() *RunContext {
	return &RunContext{
		RunID:    "run_" + "0f1e2d3c4b5a6970",
		TenantID: "tnt_9d4c1e2a3b4f5c67",
		TaskID:   "task_fixture-close-issue",
		// Derived from the clock, not a fixed date: a fixed future
		// timestamp rots into an expired grant and fails the suite.
		GrantExpiresAt: time.Now().UTC().Add(24 * time.Hour).
			Format("2006-01-02T15:04:05Z"),
		AllowedClasses: []string{ClassA1, ClassA2},
	}
}

func testEffect() *Effect {
	encoded, err := json.Marshal(validProposalJSON())
	if err != nil {
		panic(err)
	}
	effect, err := DecodeProposal(encoded)
	if err != nil {
		panic(err)
	}
	return effect
}

func TestPolicyDigestIsOrderIndependent(t *testing.T) {
	base := testPolicy(t)
	reversed := testPolicy(t)
	// Reverse the operations; the digest must not move.
	for i, j := 0, len(reversed.Operations)-1; i < j; i, j = i+1, j-1 {
		reversed.Operations[i], reversed.Operations[j] =
			reversed.Operations[j], reversed.Operations[i]
	}
	first, second := mustDigest(t, base), mustDigest(t, reversed)
	if first != second {
		t.Fatalf("digest depends on operation order: %s vs %s", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("digest shape: %s", first)
	}
}

func mustDigest(t *testing.T, p *Policy) string {
	t.Helper()
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestPolicyLoadFailsClosed(t *testing.T) {
	raw := map[string]any{
		"kind":        "BrokerPolicy",
		"api_version": "v1",
		"version":     "1.0.0",
	}
	cases := map[string]map[string]any{
		"unknown class": {"name": "x", "action_class": "A0", "semantics": "read", "destinations": []string{"sink:"}, "max_size_bytes": 1},
		"a3 class":      {"name": "x", "action_class": "A3", "semantics": "mutate", "destinations": []string{"sink:"}, "max_size_bytes": 1},
		"bad semantics": {"name": "x", "action_class": "A1", "semantics": "maybe", "destinations": []string{"sink:"}, "max_size_bytes": 1},
		"negative size": {"name": "x", "action_class": "A1", "semantics": "read", "destinations": []string{"sink:"}, "max_size_bytes": -1},
	}
	for name, rule := range cases {
		document := map[string]any{}
		for key, value := range raw {
			document[key] = value
		}
		document["operations"] = []map[string]any{rule}
		encoded, _ := json.Marshal(document)
		if _, err := LoadPolicy(encoded); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestPolicyRejectsDuplicateOperations(t *testing.T) {
	document := map[string]any{
		"kind":        "BrokerPolicy",
		"api_version": "v1",
		"version":     "1.0.0",
		"operations": []map[string]any{
			{"name": "x", "action_class": "A1", "semantics": "read", "destinations": []string{"sink:"}, "max_size_bytes": 1},
			{"name": "x", "action_class": "A1", "semantics": "read", "destinations": []string{"sink:"}, "max_size_bytes": 2},
		},
	}
	encoded, _ := json.Marshal(document)
	if _, err := LoadPolicy(encoded); err == nil {
		t.Fatal("duplicate operation accepted")
	}
}

func TestGateDeniesWithoutRun(t *testing.T) {
	policy := testPolicy(t)
	effect := testEffect()
	verdict := policy.Evaluate(effect, nil, testNow)
	if verdict.Allowed || verdict.Reason != "run_unknown" {
		t.Fatalf("unknown run must fail closed, got %+v", verdict)
	}
}

func TestGateDeniesTenantMismatch(t *testing.T) {
	policy := testPolicy(t)
	run := testRun()
	effect := testEffect()
	effect.TenantID = "tnt_0000000000000000"
	verdict := policy.Evaluate(effect, run, testNow)
	if verdict.Allowed || verdict.Reason != "run_tenant_mismatch" {
		t.Fatalf("tenant mismatch must fail closed, got %+v", verdict)
	}
}

func TestGateDeniesExpiredGrant(t *testing.T) {
	policy := testPolicy(t)
	run := testRun()
	run.GrantExpiresAt = testNow // expiry equal to now authorizes nothing
	effect := testEffect()
	verdict := policy.Evaluate(effect, run, testNow)
	if verdict.Allowed || verdict.Reason != "grant_expired" {
		t.Fatalf("expired grant must fail closed, got %+v", verdict)
	}
}

func TestGateDeniesClassNotPermittedForRun(t *testing.T) {
	policy := testPolicy(t)
	run := testRun()
	run.AllowedClasses = []string{ClassA1}
	effect := testEffect() // A2 proposal
	verdict := policy.Evaluate(effect, run, testNow)
	if verdict.Allowed || verdict.Reason != "class_not_permitted_for_run" {
		t.Fatalf("unpermitted class must fail closed, got %+v", verdict)
	}
}

func TestGateDeniesClassMismatch(t *testing.T) {
	policy := testPolicy(t)
	effect := testEffect()
	effect.ActionClass = ClassA1 // queue.publish is A2; a read label must not downgrade it
	verdict := policy.Evaluate(effect, testRun(), testNow)
	if verdict.Allowed || verdict.Reason != "class_mismatch" {
		t.Fatalf("self-downgraded class accepted: %+v", verdict)
	}
}

func TestGateDeniesDestinationOutsideRule(t *testing.T) {
	policy := testPolicy(t)
	effect := testEffect()
	effect.ProposedAction.Destination = "https://evil.example.com/exfil"
	verdict := policy.Evaluate(effect, testRun(), testNow)
	if verdict.Allowed || verdict.Reason != "destination_not_allowed" {
		t.Fatalf("destination escape accepted: %+v", verdict)
	}
}

func TestGateDeniesOversizedContent(t *testing.T) {
	policy := testPolicy(t)
	effect := testEffect()
	effect.ProposedAction.SizeBytes = 10 << 20 // queue.publish ceiling is 256 KiB
	verdict := policy.Evaluate(effect, testRun(), testNow)
	if verdict.Allowed || verdict.Reason != "size_exceeds_ceiling" {
		t.Fatalf("oversized content accepted: %+v", verdict)
	}
}

func TestGateAllowsInScopeProposal(t *testing.T) {
	policy := testPolicy(t)
	verdict := policy.Evaluate(testEffect(), testRun(), testNow)
	if !verdict.Allowed {
		t.Fatalf("in-scope proposal denied: %+v", verdict)
	}
	if verdict.Rule.ActionClass != ClassA2 || verdict.Rule.Semantics != SemanticsMutate {
		t.Fatalf("wrong rule bound: %+v", verdict.Rule)
	}
}

func TestGrantExpiryComparisonHandlesFractionalSeconds(t *testing.T) {
	// The contract's timestamp pattern admits fractional seconds, and
	// '.' sorts before 'Z', so string comparison would call a grant
	// with 500 ms left expired. Comparisons must parse instants.
	run := testRun()
	run.GrantExpiresAt = "2026-09-12T10:00:00.500000000Z"
	verdict := testPolicy(t).Evaluate(testEffect(), run, testNow)
	if !verdict.Allowed {
		t.Fatalf("fractional grant with time left denied: %+v", verdict)
	}
	run.GrantExpiresAt = "2026-09-12T10:00:00.500000000Z"
	expired := testPolicy(t).Evaluate(testEffect(), run, "2026-09-12T10:00:00.600000000Z")
	if expired.Allowed || expired.Reason != "grant_expired" {
		t.Fatalf("fractional grant past its moment allowed: %+v", expired)
	}
}

func TestGateDeniesHostPrefixConfusion(t *testing.T) {
	// The rule destination is https://api.github.com/. A host that
	// merely starts with the rule text is a different host.
	escape := []string{
		"https://api.github.evil.com/exfil",
		"https://api.github.com.evil.io/x",
		"https://api.github.com:8443/x",
		"https://api.api.github.com/x",
		"https://api.github.",
		"https://user@api.github.com/x",
		"http://api.github.com/x",
	}
	for _, destination := range escape {
		effect := testEffect()
		effect.ProposedAction.Operation = "http.request"
		effect.ActionClass = ClassA1
		effect.ProposedAction.Resource = "repos/fixture/hello"
		effect.ProposedAction.Destination = destination
		verdict := testPolicy(t).Evaluate(effect, testRun(), testNow)
		if verdict.Allowed || verdict.Reason != "destination_not_allowed" {
			t.Fatalf("host confusion via %q: %+v", destination, verdict)
		}
	}
}

func TestGateAllowsAnchoredHostAndPath(t *testing.T) {
	for _, destination := range []string{
		"https://api.github.com/",
		"https://api.github.com/repos/fixture/hello",
	} {
		effect := testEffect()
		effect.ProposedAction.Operation = "http.request"
		effect.ActionClass = ClassA1
		effect.ProposedAction.Resource = "repos/fixture/hello"
		effect.ProposedAction.Destination = destination
		verdict := testPolicy(t).Evaluate(effect, testRun(), testNow)
		if !verdict.Allowed {
			t.Fatalf("anchored destination %q denied: %+v", destination, verdict)
		}
	}
}

func TestPolicyLoadRejectsBadDestinations(t *testing.T) {
	for _, destination := range []string{"https://", "https://user@api.github.com/"} {
		document := map[string]any{
			"kind":        "BrokerPolicy",
			"api_version": "v1",
			"version":     "1.0.0",
			"operations": []map[string]any{
				{"name": "x", "action_class": "A1", "semantics": "read",
					"destinations": []string{destination}, "max_size_bytes": 1},
			},
		}
		encoded, _ := json.Marshal(document)
		if _, err := LoadPolicy(encoded); err == nil {
			t.Fatalf("destination %q accepted at load time", destination)
		}
	}
}

func TestGateDeniesUnknownOperation(t *testing.T) {
	effect := testEffect()
	effect.ProposedAction.Operation = "shell.exec"
	policy := testPolicy(t)
	verdict := policy.Evaluate(effect, testRun(), testNow)
	if verdict.Allowed || verdict.Reason != "unknown_operation" {
		t.Fatalf("unregistered operation allowed: %+v", verdict)
	}
	want := "pol_1.1.0/operations.shell.exec"
	if len(verdict.PolicyRefs) != 1 || verdict.PolicyRefs[0] != want {
		t.Fatalf("policy refs: %+v", verdict.PolicyRefs)
	}
	// Precedence: the registry boundary is checked before the run.
	effect.RunID = "run_1111111111111111"
	verdict = policy.Evaluate(effect, nil, testNow)
	if verdict.Reason != "unknown_operation" {
		t.Fatalf("precedence moved: %+v", verdict)
	}
}
