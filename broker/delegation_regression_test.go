package broker

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
)

// TestEmptyCapabilitiesNarrowToNothing pins the AC-008 widening hole:
// a delegation minted with empty (or omitted) destination and resource
// arrays used to coerce them to nil, and nil skipped the subset checks
// for its children — a deny-all parent produced unrestricted children.
func TestEmptyCapabilitiesNarrowToNothing(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})

	denyAll := rootRequest()
	denyAll.Capabilities.AllowedDestinations = nil // omitted: same as empty
	denyAll.Capabilities.AllowedResources = []string{}
	parent, err := broker.Delegate(servicePrincipal(), denyAll)
	if err != nil {
		t.Fatal(err)
	}
	// The parent itself can dispatch nothing.
	_, decision, err := broker.Authorize(servicePrincipal(),
		delegatedEffect(1, parent.ID, parent.ChildActor))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Reason != "destination_not_permitted_for_delegation" {
		t.Fatalf("parent dispatch: %+v", decision)
	}

	// A child cannot name anything the parent did not hold: empty
	// means nothing permitted, not everything.
	widened := childRequest(parent)
	widened.Capabilities.AllowedDestinations = []string{"https://evil.example.com/", "sink:any-queue-here"}
	widened.Capabilities.AllowedResources = []string{"any-resource-you-like"}
	_, err = broker.Delegate(servicePrincipal(), widened)
	if violation := refusalCheck(t, err); violation.Check != "destinations_widened" {
		t.Fatalf("widening child: %s at %s", violation.Check, violation.Path)
	}

	// The stored parent serializes arrays, not null: the emitted
	// document must stay schema-valid.
	encoded, err := json.Marshal(parent.Capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "null") {
		t.Fatalf("capabilities serialized null: %s", encoded)
	}
	var caps map[string][]string
	if err := json.Unmarshal(encoded, &caps); err != nil {
		t.Fatal(err)
	}
	if caps["allowed_destinations"] == nil || caps["allowed_resources"] == nil {
		t.Fatalf("arrays decoded as null: %s", encoded)
	}

	// A narrowed-to-empty child mints: empty is a valid narrowing.
	empty := childRequest(parent)
	empty.Capabilities.AllowedDestinations = []string{}
	empty.Capabilities.AllowedResources = nil
	if child, err := broker.Delegate(servicePrincipal(), empty); err != nil {
		t.Fatalf("empty child: %v", err)
	} else if child.Capabilities.AllowedDestinations == nil ||
		child.Capabilities.AllowedResources == nil {
		t.Fatalf("stored child arrays nil: %+v", child.Capabilities)
	}
}

// TestCostBudgetSaturatesInsteadOfWrapping pins the overflow hole: two
// authorized ceilings near the int64 limit used to sum negative and
// disarm the budget for every later effect.
func TestCostBudgetSaturatesInsteadOfWrapping(t *testing.T) {
	policy := testPolicy(t)
	// One operation whose per-effect ceiling is three quarters of the
	// int64 range: two of them sum past the range and used to wrap.
	huge := int64(math.MaxInt64 / 4 * 3)
	policy.Operations = append(policy.Operations, OperationRule{
		Name:         "costly.transfer",
		ActionClass:  ClassA2,
		Semantics:    SemanticsMutate,
		Destinations: []string{"sink:patch-export-beta"},
		MaxSizeBytes: 1024,
		AmountLimit:  &Money{Currency: "USD", Micros: huge},
	})
	policy.byName["costly.transfer"] = policy.Operations[len(policy.Operations)-1]
	broker := New(policy, []*RunContext{testRun()}, []Sink{&SyntheticSink{}})

	request := rootRequest()
	request.CumulativeBudget.MaxTotalCost = Money{Currency: "USD", Micros: math.MaxInt64}
	root, err := broker.Delegate(servicePrincipal(), request)
	if err != nil {
		t.Fatal(err)
	}

	transfer := func(n int) *Effect {
		effect := delegatedEffect(n, root.ID, root.ChildActor)
		effect.ProposedAction.Operation = "costly.transfer"
		effect.ProposedAction.Resource = "patch-export-beta"
		effect.ProposedAction.Destination = "sink:patch-export-beta"
		effect.ProposedAction.SizeBytes = 16
		return effect
	}
	if _, decision, err := broker.Authorize(servicePrincipal(), transfer(1)); err != nil ||
		decision.Verdict != "allow" {
		t.Fatalf("first transfer: %v %+v", err, decision)
	}
	// The second transfer must hit the ceiling; the wrapped sum used
	// to read negative and admit it.
	if _, decision, err := broker.Authorize(servicePrincipal(), transfer(2)); err != nil ||
		decision.Reason != "cost_budget_exhausted" {
		t.Fatalf("second transfer: %v %+v", err, decision)
	}
}

// TestRevokeFencesAPendingCommit pins the dispatch-time fence: a
// revocation between authorize and commit used to leave the permit
// dispatchable.
func TestRevokeFencesAPendingCommit(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	root := mintRoot(t, broker)
	effect, decision, err := broker.Authorize(servicePrincipal(),
		delegatedEffect(1, root.ID, root.ChildActor))
	if err != nil || decision.Verdict != "allow" {
		t.Fatalf("authorize: %v %+v", err, decision)
	}

	if _, err := broker.RevokeDelegation(servicePrincipal(), root.ID, "stop"); err != nil {
		t.Fatal(err)
	}

	committed, err := broker.Commit(servicePrincipal(), effect.ID, "idk_fence-000000001")
	if err == nil {
		t.Fatalf("dispatched a fenced effect: %+v", committed)
	}
	stored := broker.Effects()[0]
	if stored.State != StateCancelled {
		t.Fatalf("state after fence: %s", stored.State)
	}
	if stored.Dispatch != nil {
		t.Fatalf("fence fabricated a dispatch record: %+v", stored.Dispatch)
	}
	// The fence lands in the journal as a delegation event.
	var fences int
	for _, event := range broker.Events() {
		if event.EventKind != "delegation" {
			continue
		}
		var payload struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal([]byte(event.Payload.Content), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Action == "fence" {
			fences++
		}
	}
	if fences != 1 {
		t.Fatalf("fence events: %d", fences)
	}
}

// TestRevocationDigestSeparatesDelegations pins the idempotency digest
// collision: a bare id+body concatenation let one delegation's revoke
// reply replay for a different delegation.
func TestRevocationDigestSeparatesDelegations(t *testing.T) {
	server, _ := testServer(t)
	for _, id := range []string{"dlg_aa00000000001", "dlg_aaa0000000001"} {
		if reply, _ := doJSON(t, "POST", server.URL+"/v1/delegations",
			mustJSON(t, delegationBody(id)), serviceHeaders("idk_mint-"+id)); reply.StatusCode != http.StatusOK {
			t.Fatalf("mint %s failed", id)
		}
	}

	// Same key, colliding concatenations under the old scheme: the
	// first request carries the valid body; the collision carries the
	// id's last character as a leading body byte (invalid JSON, but
	// the replay path used to skip validation entirely).
	first := fmt.Sprintf("%s/v1/delegations/%s/revocation", server.URL, "dlg_aa00000000001")
	collide := fmt.Sprintf("%s/v1/delegations/%s/revocation", server.URL, "dlg_aa0000000000")
	if reply, body := doJSON(t, "POST", first,
		[]byte(`{"reason":"x"}`), serviceHeaders("idk_collide-00001")); reply.StatusCode != http.StatusOK {
		t.Fatalf("first revoke: %d %+v", reply.StatusCode, body)
	}
	// The colliding pair must conflict, not replay the stored reply.
	if reply, problem := doJSON(t, "POST", collide,
		[]byte(`1{"reason":"x"}`), serviceHeaders("idk_collide-00001")); reply.StatusCode != http.StatusConflict ||
		problem["code"] != "idempotency_conflict" {
		t.Fatalf("collision: %d %+v", reply.StatusCode, problem)
	}
}

// TestRevocationReasonIsBounded pins the payload-minimization rule.
func TestRevocationReasonIsBounded(t *testing.T) {
	server, _ := testServer(t)
	doJSON(t, "POST", server.URL+"/v1/delegations",
		mustJSON(t, delegationBody("dlg_long000000001")), serviceHeaders("idk_long-rsn-0001"))

	long := map[string]any{"reason": strings.Repeat("x", MaxRevocationReason+1)}
	if reply, problem := doJSON(t, "POST", server.URL+"/v1/delegations/dlg_long000000001/revocation",
		mustJSON(t, long), serviceHeaders("idk_long-rsn-0002")); reply.StatusCode != http.StatusBadRequest ||
		problem["code"] != "delegation_schema" {
		t.Fatalf("long reason: %d %+v", reply.StatusCode, problem)
	}
}

// TestPolicyFailsClosedOnBadMoneyLimits pins the load-time check that
// keeps negative or malformed money out of the budget arithmetic.
func TestPolicyFailsClosedOnBadMoneyLimits(t *testing.T) {
	base := `{"kind":"BrokerPolicy","api_version":"v1","version":"1.0.0","operations":[{"name":"x.y","action_class":"A2","semantics":"mutate","destinations":["sink:q"],"max_size_bytes":1,%s}]}`
	for name, limit := range map[string]string{
		"negative micros": `"amount_limit":{"currency":"USD","micros":-1}`,
		"bad currency":    `"amount_limit":{"currency":"usd","micros":1}`,
	} {
		if _, err := LoadPolicy([]byte(fmt.Sprintf(base, limit))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
