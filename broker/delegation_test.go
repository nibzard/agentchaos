package broker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// rootRequest is a valid mint request under the plain test run: the
// run root is unrestricted (no RootCapabilities, no RootBudget).
func rootRequest() *DelegationRequest {
	return &DelegationRequest{
		ID:          "dlg_root00000001",
		RunID:       testRun().RunID,
		ParentActor: "act_orchestrator-01",
		ChildActor:  "act_planner-000001",
		Capabilities: Capabilities{
			AllowedActionClasses: []string{ClassA2},
			AllowedDestinations:  []string{"sink:patch-export-beta", "https://api.github.com/"},
			AllowedResources:     []string{"patch-export-beta"},
		},
		CumulativeBudget: Budget{
			MaxTotalCost:   Money{Currency: "USD", Micros: 50000},
			MaxTotalTokens: 1000000,
			MaxEffects:     5,
		},
	}
}

// childRequest narrows rootRequest's delegation further.
func childRequest(parent *Delegation) *DelegationRequest {
	return &DelegationRequest{
		ID:                 "dlg_child00000001",
		RunID:              parent.RunID,
		ParentActor:        parent.ChildActor,
		ChildActor:         "act_worker-narrowed-1",
		ParentDelegationID: parent.ID,
		Capabilities: Capabilities{
			AllowedActionClasses: []string{ClassA2},
			AllowedDestinations:  []string{"sink:patch-export-beta"},
			AllowedResources:     []string{"patch-export-beta"},
		},
		CumulativeBudget: Budget{
			MaxTotalCost:   Money{Currency: "USD", Micros: 30000},
			MaxTotalTokens: 500000,
			MaxEffects:     3,
		},
	}
}

// delegatedEffect clones the fixture proposal under a fresh id and
// binds it to a delegation holder.
func delegatedEffect(n int, delegationID, actor string) *Effect {
	effect := testEffect()
	effect.ID = sprintfEffectID(n)
	effect.DelegationID = delegationID
	effect.Actor = actor
	return effect
}

func sprintfEffectID(n int) string {
	digits := "0123456789abcdef"
	out := []byte("eff_0000000000000000")
	for i := 15; i >= 4 && n > 0; i-- {
		out[i] = digits[n&0xf]
		n >>= 4
	}
	return string(out)
}

func mintRoot(t *testing.T, broker *Broker) *Delegation {
	t.Helper()
	delegation, err := broker.Delegate(servicePrincipal(), rootRequest())
	if err != nil {
		t.Fatal(err)
	}
	return delegation
}

func refusalCheck(t *testing.T, err error) ContractError {
	t.Helper()
	var refusal *DelegationRefusal
	if !errors.As(err, &refusal) || len(refusal.Errors) == 0 {
		t.Fatalf("expected a refusal with errors, got %v", err)
	}
	return refusal.Errors[0]
}

func TestDelegateMintsRootAndNestedDelegations(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	root := mintRoot(t, broker)
	if root.Kind != "Delegation" || root.State != DelegationActive {
		t.Fatalf("root: %+v", root)
	}
	if root.Depth != 1 {
		t.Fatalf("root depth: %d", root.Depth)
	}
	child, err := broker.Delegate(servicePrincipal(), childRequest(root))
	if err != nil {
		t.Fatal(err)
	}
	if child.Depth != 2 || child.ParentDelegationID != root.ID {
		t.Fatalf("child: %+v", child)
	}
	if child.ParentActor != root.ChildActor {
		t.Fatalf("child parent actor: %s", child.ParentActor)
	}

	// Both mints land in the journal as delegation events.
	var mints int
	for _, event := range broker.Events() {
		if event.EventKind == "delegation" {
			mints++
			if event.RunID != root.RunID || event.TenantID != root.TenantID {
				t.Fatalf("event scoping: %+v", event)
			}
		}
	}
	if mints != 2 {
		t.Fatalf("delegation events: %d", mints)
	}
}

func TestDelegateRefusesEveryWidening(t *testing.T) {
	cases := map[string]func(*DelegationRequest){
		"classes_widened": func(r *DelegationRequest) { r.Capabilities.AllowedActionClasses = []string{ClassA1, ClassA2} },
		"destinations_widened": func(r *DelegationRequest) {
			r.Capabilities.AllowedDestinations = []string{"https://evil.example.com/"}
		},
		"resources_widened": func(r *DelegationRequest) {
			r.Capabilities.AllowedResources = []string{"other-resource"}
		},
		"budget_raised_cost":   func(r *DelegationRequest) { r.CumulativeBudget.MaxTotalCost.Micros = 60000 },
		"budget_raised_tokens": func(r *DelegationRequest) { r.CumulativeBudget.MaxTotalTokens = 2000000 },
		"budget_raised_effects": func(r *DelegationRequest) {
			r.CumulativeBudget.MaxEffects = 6
		},
		"parent_actor_mismatch": func(r *DelegationRequest) { r.ParentActor = "act_impostor-000001" },
		"parent_unknown":        func(r *DelegationRequest) { r.ParentDelegationID = "dlg_missing000001" },
	}
	// The three budget raises share one check name and differ by path.
	budgetPaths := map[string]string{
		"budget_raised_cost":    "max_total_cost",
		"budget_raised_tokens":  "max_total_tokens",
		"budget_raised_effects": "max_effects",
	}
	for check, spoil := range cases {
		t.Run(check, func(t *testing.T) {
			broker := testBroker(t, &SyntheticSink{})
			root := mintRoot(t, broker)
			request := childRequest(root)
			spoil(request)
			_, err := broker.Delegate(servicePrincipal(), request)
			violation := refusalCheck(t, err)
			if path, raised := budgetPaths[check]; raised {
				if violation.Check != "budget_raised" || !strings.Contains(violation.Path, path) {
					t.Fatalf("check: %s at %s", violation.Check, violation.Path)
				}
				return
			}
			if violation.Check != check {
				t.Fatalf("check: %s at %s", violation.Check, violation.Path)
			}
		})
	}

	t.Run("run_unknown", func(t *testing.T) {
		broker := testBroker(t, &SyntheticSink{})
		request := rootRequest()
		request.RunID = "run_ffffffffffffffff"
		_, err := broker.Delegate(servicePrincipal(), request)
		if violation := refusalCheck(t, err); violation.Check != "run_unknown" {
			t.Fatalf("check: %s", violation.Check)
		}
	})

	t.Run("depth_exceeded", func(t *testing.T) {
		broker := testBroker(t, &SyntheticSink{})
		request := rootRequest()
		request.ID = "dlg_depth00000001"
		parent, err := broker.Delegate(servicePrincipal(), request)
		if err != nil {
			t.Fatal(err)
		}
		// Chain down to the depth limit, then one node too far.
		for depth := 2; depth <= MaxDelegationDepth; depth++ {
			next := childRequest(parent)
			next.ID = sprintfDelegationID(depth)
			parent, err = broker.Delegate(servicePrincipal(), next)
			if err != nil {
				t.Fatalf("depth %d: %v", depth, err)
			}
			if parent.Depth != depth {
				t.Fatalf("depth %d recorded %d", depth, parent.Depth)
			}
		}
		over := childRequest(parent)
		over.ID = "dlg_over0000000001"
		_, err = broker.Delegate(servicePrincipal(), over)
		if violation := refusalCheck(t, err); violation.Check != "depth_exceeded" {
			t.Fatalf("check: %s", violation.Check)
		}
	})
}

func sprintfDelegationID(n int) string {
	digits := "0123456789abcdef"
	out := []byte("dlg_0000000000000000")
	for i := 15; i >= 4 && n > 0; i-- {
		out[i] = digits[n&0xf]
		n >>= 4
	}
	return string(out)
}

func TestRevokeFencesTheWholeGroup(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	root := mintRoot(t, broker)
	child, err := broker.Delegate(servicePrincipal(), childRequest(root))
	if err != nil {
		t.Fatal(err)
	}

	first, decision, err := broker.Authorize(servicePrincipal(), delegatedEffect(1, child.ID, child.ChildActor))
	if err != nil || decision.Verdict != "allow" {
		t.Fatalf("before revoke: %v %+v", err, decision)
	}
	if first.Authorization == nil {
		t.Fatal("no permit before revoke")
	}

	revoked, err := broker.RevokeDelegation(servicePrincipal(), root.ID, "stop condition met")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != DelegationRevoked || revoked.RevokedAt == "" {
		t.Fatalf("revoked: %+v", revoked)
	}

	// The child itself is unrevoked, but its ancestor fences the group.
	_, decision, err = broker.Authorize(servicePrincipal(), delegatedEffect(2, child.ID, child.ChildActor))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict == "allow" || decision.Reason != "delegation_revoked" {
		t.Fatalf("after revoke: %+v", decision)
	}

	// Minting under the revoked root is refused too.
	grandchild := childRequest(child)
	grandchild.ID = "dlg_grand00000001"
	_, err = broker.Delegate(servicePrincipal(), grandchild)
	if violation := refusalCheck(t, err); violation.Check != "delegation_revoked" {
		t.Fatalf("check: %s", violation.Check)
	}

	// A second revoke is idempotent: same state, one revoke event.
	again, err := broker.RevokeDelegation(servicePrincipal(), root.ID, "duplicate")
	if err != nil {
		t.Fatal(err)
	}
	if again.State != DelegationRevoked {
		t.Fatalf("second revoke: %+v", again)
	}
	var revokes int
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
		if payload.Action == "revoke" {
			revokes++
		}
	}
	if revokes != 1 {
		t.Fatalf("revoke events: %d", revokes)
	}
}

func TestDelegatedEffectEnforcement(t *testing.T) {
	cases := map[string]struct {
		delegationID string
		actor        string
		spoil        func(*Effect)
	}{
		"delegation_unknown": {
			delegationID: "dlg_missing000001",
			actor:        "act_planner-000001",
		},
		"delegation_actor_mismatch": {
			delegationID: "dlg_root00000001",
			actor:        "act_someone-else-01",
		},
		"class_not_permitted_for_delegation": {
			delegationID: "dlg_root00000001",
			actor:        "act_planner-000001",
			spoil: func(e *Effect) {
				e.ActionClass = ClassA1
				e.ProposedAction.Operation = "http.request"
				e.ProposedAction.Destination = "https://api.github.com/repos"
				e.ProposedAction.Resource = "repos"
			},
		},
		"destination_not_permitted_for_delegation": {
			delegationID: "dlg_root00000001",
			actor:        "act_planner-000001",
			spoil: func(e *Effect) {
				e.ProposedAction.Destination = "sink:other-queue-name"
			},
		},
		"resource_not_permitted_for_delegation": {
			delegationID: "dlg_root00000001",
			actor:        "act_planner-000001",
			spoil: func(e *Effect) {
				e.ProposedAction.Resource = "other-resource"
			},
		},
	}
	for reason, spec := range cases {
		t.Run(reason, func(t *testing.T) {
			broker := testBroker(t, &SyntheticSink{})
			mintRoot(t, broker)
			effect := delegatedEffect(1, spec.delegationID, spec.actor)
			if spec.spoil != nil {
				spec.spoil(effect)
			}
			_, decision, err := broker.Authorize(servicePrincipal(), effect)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != "deny" || decision.Reason != reason {
				t.Fatalf("decision: %+v", decision)
			}
		})
	}

	t.Run("permitted effect carries its permit", func(t *testing.T) {
		broker := testBroker(t, &SyntheticSink{})
		root := mintRoot(t, broker)
		effect, decision, err := broker.Authorize(servicePrincipal(),
			delegatedEffect(2, root.ID, root.ChildActor))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Verdict != "allow" || effect.Authorization == nil {
			t.Fatalf("decision: %+v", decision)
		}
		if effect.DelegationID != root.ID {
			t.Fatalf("record lost its delegation: %s", effect.DelegationID)
		}
	})
}

func TestDelegationRunMismatch(t *testing.T) {
	other := &RunContext{
		RunID:          "run_aaaa1111bbbb2222",
		TenantID:       testRun().TenantID,
		TaskID:         "task_other-binding-01",
		GrantExpiresAt: testRun().GrantExpiresAt,
		AllowedClasses: []string{ClassA1, ClassA2},
	}
	broker := New(testPolicy(t), []*RunContext{testRun(), other}, []Sink{&SyntheticSink{}})
	root := mintRoot(t, broker)

	effect := delegatedEffect(1, root.ID, root.ChildActor)
	effect.RunID = other.RunID
	_, decision, err := broker.Authorize(servicePrincipal(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Reason != "delegation_run_mismatch" {
		t.Fatalf("decision: %+v", decision)
	}
}

func TestSharedEffectBudgetAcrossTheTree(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	root := mintRoot(t, broker) // five effects, tree-wide

	// Two sibling children, each with its own three-effect ceiling.
	sibling := childRequest(root)
	sibling.ID = "dlg_sibling0000001"
	sibling.ChildActor = "act_worker-sibling-1"
	first, err := broker.Delegate(servicePrincipal(), sibling)
	if err != nil {
		t.Fatal(err)
	}
	second, err := broker.Delegate(servicePrincipal(), childRequest(root))
	if err != nil {
		t.Fatal(err)
	}

	allow := func(n int, delegation *Delegation) *BrokerDecision {
		t.Helper()
		_, decision, err := broker.Authorize(servicePrincipal(),
			delegatedEffect(n, delegation.ID, delegation.ChildActor))
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}

	// The tree shares one ceiling: the tightest chain bound. Both
	// children lowered it to three, so three permits fill it — even
	// spread across siblings, and the root's five never binds.
	for n := 1; n <= 3; n++ {
		if decision := allow(n, first); decision.Verdict != "allow" {
			t.Fatalf("effect %d denied: %+v", n, decision)
		}
	}
	if decision := allow(4, first); decision.Reason != "effect_budget_exhausted" {
		t.Fatalf("fourth under first: %+v", decision)
	}
	// The sibling spent nothing, but the shared tree ceiling is full:
	// effects under the sibling's own subtree count against it too.
	if decision := allow(5, second); decision.Reason != "effect_budget_exhausted" {
		t.Fatalf("sibling effect: %+v", decision)
	}

	// A proposal the gate itself denies never consumes budget: it
	// carries no permit, so it counts nowhere.
	doomed := delegatedEffect(7, first.ID, first.ChildActor)
	doomed.ProposedAction.Operation = "no.such.operation"
	doomed.ActionClass = ClassA2
	if _, decision, err := broker.Authorize(servicePrincipal(), doomed); err != nil ||
		decision.Reason != "unknown_operation" {
		t.Fatalf("doomed: %v %+v", err, decision)
	}
	// Non-delegated effects never consume the delegation budget.
	plain := testEffect()
	plain.ID = sprintfEffectID(8)
	if _, decision, err := broker.Authorize(servicePrincipal(), plain); err != nil || decision.Verdict != "allow" {
		t.Fatalf("plain effect: %v %+v", err, decision)
	}
}

func TestCostBudgetFailsClosed(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	request := rootRequest()
	request.Capabilities.AllowedActionClasses = []string{ClassA2}
	request.Capabilities.AllowedDestinations = []string{"https://api.github.com/"}
	request.Capabilities.AllowedResources = []string{"issues"}
	request.CumulativeBudget.MaxTotalCost = Money{Currency: "USD", Micros: 15000}
	root, err := broker.Delegate(servicePrincipal(), request)
	if err != nil {
		t.Fatal(err)
	}

	comment := func(n int) *Effect {
		effect := delegatedEffect(n, root.ID, root.ChildActor)
		effect.ActionClass = ClassA2
		effect.ProposedAction.Operation = "repo.comment"
		effect.ProposedAction.Destination = "https://api.github.com/repos/x/y"
		effect.ProposedAction.Resource = "issues"
		effect.ProposedAction.SizeBytes = 100
		return effect
	}

	// repo.comment carries a USD 10000 money ceiling per effect.
	if _, decision, _ := broker.Authorize(servicePrincipal(), comment(1)); decision.Verdict != "allow" {
		t.Fatalf("first comment: %+v", decision)
	}
	_, second, _ := broker.Authorize(servicePrincipal(), comment(2))
	if second.Reason != "cost_budget_exhausted" {
		t.Fatalf("second comment: %+v", second)
	}

	// A budget the rule cannot denominate never authorizes money.
	euro := rootRequest()
	euro.ID = "dlg_euro0000000001"
	euro.Capabilities = request.Capabilities
	euro.CumulativeBudget.MaxTotalCost = Money{Currency: "EUR", Micros: 9000000}
	euro.ChildActor = "act_worker-euro-0001"
	euroDelegation, err := broker.Delegate(servicePrincipal(), euro)
	if err != nil {
		t.Fatal(err)
	}
	_, decision, _ := broker.Authorize(servicePrincipal(), func() *Effect {
		effect := comment(3)
		effect.DelegationID = euroDelegation.ID
		effect.Actor = euroDelegation.ChildActor
		return effect
	}())
	if decision.Reason != "cost_currency_mismatch" {
		t.Fatalf("euro comment: %+v", decision)
	}
}

func TestRunRootBoundsDelegationMinting(t *testing.T) {
	run := testRun()
	run.RootCapabilities = &Capabilities{
		AllowedActionClasses: []string{ClassA2},
		AllowedDestinations:  []string{"sink:patch-export-beta"},
		AllowedResources:     []string{"patch-export-beta"},
	}
	run.RootBudget = &Budget{
		MaxTotalCost:   Money{Currency: "USD", Micros: 40000},
		MaxTotalTokens: 800000,
		MaxEffects:     4,
	}
	broker := New(testPolicy(t), []*RunContext{run}, []Sink{&SyntheticSink{}})

	if _, err := broker.Delegate(servicePrincipal(), rootRequest()); err == nil {
		t.Fatal("root request exceeds the run root scope")
	}

	narrow := rootRequest()
	narrow.Capabilities.AllowedDestinations = []string{"sink:patch-export-beta"}
	narrow.CumulativeBudget = Budget{
		MaxTotalCost:   Money{Currency: "USD", Micros: 40000},
		MaxTotalTokens: 800000,
		MaxEffects:     4,
	}
	if delegation, err := broker.Delegate(servicePrincipal(), narrow); err != nil {
		t.Fatalf("narrow mint: %v", err)
	} else if delegation.Depth != 1 {
		t.Fatalf("depth: %d", delegation.Depth)
	}

	raised := rootRequest()
	raised.ID = "dlg_raised00000001"
	raised.Capabilities.AllowedDestinations = []string{"sink:patch-export-beta"}
	raised.CumulativeBudget.MaxEffects = 5
	if _, err := broker.Delegate(servicePrincipal(), raised); err == nil {
		t.Fatal("budget above the run root minted")
	}
}

func TestRunRootBudgetGovernsRunWide(t *testing.T) {
	run := testRun()
	run.RootBudget = &Budget{
		MaxTotalCost:   Money{Currency: "USD", Micros: 50000},
		MaxTotalTokens: 1000000,
		MaxEffects:     2,
	}
	broker := New(testPolicy(t), []*RunContext{run}, []Sink{&SyntheticSink{}})

	// Two separate trees, each with its own two-effect ceiling; the run
	// root bounds their sum run-wide, not just per tree.
	mint := func(id, actor string) *Delegation {
		request := rootRequest()
		request.ID = id
		request.ChildActor = actor
		request.CumulativeBudget = Budget{
			MaxTotalCost:   Money{Currency: "USD", Micros: 50000},
			MaxTotalTokens: 1000000,
			MaxEffects:     2,
		}
		delegation, err := broker.Delegate(servicePrincipal(), request)
		if err != nil {
			t.Fatal(err)
		}
		return delegation
	}
	treeA := mint("dlg_treea00000001", "act_worker-treea-01")
	treeB := mint("dlg_treeb00000001", "act_worker-treeb-01")

	allow := func(n int, delegation *Delegation) *BrokerDecision {
		_, decision, err := broker.Authorize(servicePrincipal(),
			delegatedEffect(n, delegation.ID, delegation.ChildActor))
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}
	if decision := allow(1, treeA); decision.Verdict != "allow" {
		t.Fatalf("tree A first: %+v", decision)
	}
	if decision := allow(2, treeB); decision.Verdict != "allow" {
		t.Fatalf("tree B first: %+v", decision)
	}
	if decision := allow(3, treeA); decision.Reason != "effect_budget_exhausted" {
		t.Fatalf("run-wide third: %+v", decision)
	}
}

func TestInvalidRunRootCapabilitiesRefuseEveryMint(t *testing.T) {
	run := testRun()
	run.RootCapabilities = &Capabilities{
		AllowedActionClasses: []string{ClassA0, ClassA2}, // A0 exceeds the run
	}
	broker := New(testPolicy(t), []*RunContext{run}, []Sink{&SyntheticSink{}})
	_, err := broker.Delegate(servicePrincipal(), rootRequest())
	if violation := refusalCheck(t, err); violation.Check != "run_root_invalid" {
		t.Fatalf("check: %s", violation.Check)
	}
}

func TestDelegationRegistryIsAppendOnlyAndTenantScoped(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	mintRoot(t, broker)
	if _, err := broker.Delegate(servicePrincipal(), rootRequest()); !errors.Is(err, errDelegationExists) {
		t.Fatalf("duplicate mint: %v", err)
	}

	// Another tenant mints without collision; ids are tenant-scoped.
	other := &RunContext{
		RunID:          "run_cccc3333dddd4444",
		TenantID:       "tnt_1111222233334444",
		TaskID:         "task_other-tenant-01",
		GrantExpiresAt: testRun().GrantExpiresAt,
		AllowedClasses: []string{ClassA1, ClassA2},
	}
	twoTenants := New(testPolicy(t), []*RunContext{testRun(), other}, []Sink{&SyntheticSink{}})
	mintRoot(t, twoTenants) // tenant A holds dlg_root00000001
	foreign := &Principal{ID: "act_service-other-01", TenantID: other.TenantID, Role: RoleService}
	foreignRequest := rootRequest()
	foreignRequest.ID = "dlg_foreign0000001"
	foreignRequest.RunID = other.RunID
	foreignRequest.ParentActor = "act_orchestrator-02"
	if delegation, err := twoTenants.Delegate(foreign, foreignRequest); err != nil {
		t.Fatalf("other tenant mint: %v", err)
	} else if delegation.TenantID != other.TenantID {
		t.Fatalf("foreign delegation tenant: %s", delegation.TenantID)
	}

	// The foreign principal cannot see tenant A's delegation: the
	// tenant-safe miss is indistinguishable from absence.
	if _, err := twoTenants.RevokeDelegation(foreign, "dlg_root00000001", "probe"); !errors.Is(err, errDelegationNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	// A run from another tenant never mints for this principal.
	missed := rootRequest()
	missed.RunID = testRun().RunID
	if _, err := twoTenants.Delegate(foreign, missed); err == nil {
		t.Fatal("foreign principal minted into another tenant's run")
	}
}

func TestDelegateRoleGuards(t *testing.T) {
	broker := testBroker(t, &SyntheticSink{})
	if _, err := broker.Delegate(nil, rootRequest()); err == nil {
		t.Fatal("unauthenticated delegate")
	}
	worker := servicePrincipal()
	worker.Role = RoleWorker
	if _, err := broker.Delegate(worker, rootRequest()); err == nil || !strings.Contains(err.Error(), "cannot delegate") {
		t.Fatalf("worker delegate: %v", err)
	}
	if _, err := broker.RevokeDelegation(nil, "dlg_root00000001", ""); err == nil {
		t.Fatal("unauthenticated revoke")
	}
	if _, err := broker.RevokeDelegation(worker, "dlg_root00000001", ""); err == nil || !strings.Contains(err.Error(), "cannot revoke") {
		t.Fatalf("worker revoke: %v", err)
	}
}
