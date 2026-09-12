package broker

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// The predeclared adversarial sweep for exit gate B4 (spec 22.2): ten
// thousand seeded cases against the hard boundaries, plus a control
// arm of legitimate requests that must be allowed. A sweep that only
// refuses proves nothing, so every violation category keeps a control
// counterpart on the same broker.
//
// The invariant under test: no violation case, however its payload is
// randomized, ever ends in an allow verdict. Cases may fail with an
// error, a deny, or a hold; all three are safe outcomes.

// sweepCase is one authorization attempt with an expected outcome.
type sweepCase struct {
	category  string
	violation bool
	principal *Principal
	effect    *Effect
	broker    *Broker
}

// sweepBudget builds a delegation request whose token and cost budgets
// cannot bind during the sweep, so only the stated cap can bind.
func sweepBudget(effects int64) Budget {
	return Budget{
		MaxTotalCost:   Money{Currency: "USD", Micros: 1 << 44},
		MaxTotalTokens: 1 << 44,
		MaxEffects:     effects,
	}
}

// TestExitGateAdversarialSweep is the predeclared ten-thousand-case
// suite for gate B4: seeded, balanced across every boundary category,
// with a control arm. The exit gate checker (release/exit_gate.py)
// runs it.
func TestExitGateAdversarialSweep(t *testing.T) {
	rng := rand.New(rand.NewSource(20260912))
	service := servicePrincipal()
	worker := &Principal{
		ID:       "act_worker-reference-01",
		TenantID: "tnt_9d4c1e2a3b4f5c67", Role: RoleWorker,
	}
	outsider := &Principal{
		ID: "act_other-service-01", TenantID: "tnt_0000000000000000",
		Role: RoleService,
	}

	policy, err := LoadPolicy(DefaultPolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	future := testRun()
	future.GrantExpiresAt = time.Now().UTC().Add(24 * time.Hour).
		Format("2006-01-02T15:04:05Z")
	past := testRun()
	past.GrantExpiresAt = time.Now().UTC().Add(-time.Minute).
		Format("2006-01-02T15:04:05Z")
	goodBroker := New(policy, []*RunContext{future},
		[]Sink{&SyntheticSink{}})
	expiredBroker := New(policy, []*RunContext{past},
		[]Sink{&SyntheticSink{}})

	rootWanted := rootRequest()
	rootWanted.CumulativeBudget = sweepBudget(1 << 30)
	root, err := goodBroker.Delegate(service, rootWanted)
	if err != nil {
		t.Fatal(err)
	}
	expiredWanted := rootRequest()
	expiredWanted.CumulativeBudget = sweepBudget(1 << 30)
	expiredRoot, err := expiredBroker.Delegate(service, expiredWanted)
	if err != nil {
		t.Fatal(err)
	}

	// counter keeps every effect id distinct across the whole sweep.
	counter := 0
	fresh := func() *Effect {
		counter++
		effect := delegatedEffect(counter, root.ID, root.ChildActor)
		effect.ProposedAction.ArgumentsDigest =
			"sha256:" + fmt.Sprintf("%064x", rng.Int63())
		// Random but in-policy: the size ceiling for queue.publish is
		// small, and a control that randomly exceeds it is a
		// legitimate deny, not a harness failure.
		effect.ProposedAction.SizeBytes = int64(1 + rng.Intn(256))
		return effect
	}

	cases := make([]sweepCase, 0, 10000)
	violation := func(category string, principal *Principal,
		mutate func(*Effect)) {
		effect := fresh()
		mutate(effect)
		cases = append(cases, sweepCase{
			category: category, violation: true,
			principal: principal, effect: effect, broker: goodBroker,
		})
	}

	categories := []struct {
		name      string
		principal *Principal
		mutate    func(*Effect)
	}{
		{"worker-principal", worker, func(*Effect) {}},
		{"tenant-mismatch", outsider, func(*Effect) {}},
		{"effect-tenant-mismatch", service, func(e *Effect) {
			e.TenantID = "tnt_0000000000000000"
		}},
		{"unknown-run", service, func(e *Effect) {
			e.RunID = "run_" + fmt.Sprintf("%016x", rng.Int63())
		}},
		{"class-outside-run", service, func(e *Effect) {
			e.ActionClass = "A9"
		}},
		{"widened-destination", service, func(e *Effect) {
			e.ProposedAction.Destination =
				"https://evil.example/" + fmt.Sprintf("%08x", rng.Int31())
		}},
		{"unlisted-resource", service, func(e *Effect) {
			e.ProposedAction.Resource =
				"attacker-" + fmt.Sprintf("%08x", rng.Int31())
		}},
		{"class-outside-delegation", service, func(e *Effect) {
			// The run allows A1 and A2, but the delegation holds
			// only A2; the delegation must win.
			e.ActionClass = ClassA1
		}},
		{"wrong-actor", service, func(e *Effect) {
			e.Actor = "act_worker-imposter-" + fmt.Sprintf("%04d",
				rng.Intn(10000))
		}},
		{"phantom-delegation", service, func(e *Effect) {
			e.DelegationID = "dlg_" + fmt.Sprintf("%016x", rng.Int63())
		}},
	}

	perCategory := 600
	for _, category := range categories {
		for i := 0; i < perCategory; i++ {
			violation(category.name, category.principal,
				category.mutate)
		}
	}

	// Expired grants: the same legitimate shape, against a run whose
	// grant has lapsed, must never allow.
	for i := 0; i < perCategory; i++ {
		counter++
		effect := delegatedEffect(counter, expiredRoot.ID,
			expiredRoot.ChildActor)
		effect.ProposedAction.ArgumentsDigest =
			"sha256:" + fmt.Sprintf("%064x", rng.Int63())
		cases = append(cases, sweepCase{
			category: "expired-grant", violation: true,
			principal: service, effect: effect,
			broker: expiredBroker,
		})
	}

	// Budget exhaustion: each round mints a delegation that allows two
	// effects, spends the cap with legitimate allows, then demands a
	// third. The overrun demand is the violation; the spends double as
	// extra controls.
	for i := 0; i < 500; i++ {
		request := rootRequest()
		request.ID = fmt.Sprintf("dlg_sweepbudget%06d", i)
		request.CumulativeBudget = sweepBudget(2)
		round, err := goodBroker.Delegate(service, request)
		if err != nil {
			t.Fatal(err)
		}
		for spent := int64(0); spent <= 2; spent++ {
			counter++
			effect := delegatedEffect(counter, round.ID,
				round.ChildActor)
			effect.ProposedAction.ArgumentsDigest =
				"sha256:" + fmt.Sprintf("%064x", rng.Int63())
			cases = append(cases, sweepCase{
				category: "budget-exhausted", violation: spent == 2,
				principal: service, effect: effect,
				broker: goodBroker,
			})
		}
	}

	// Control arm: plain legitimate requests must be allowed, so the
	// sweep cannot pass by refusing everything.
	for i := 0; i < 1900; i++ {
		effect := fresh()
		cases = append(cases, sweepCase{
			category: "control", violation: false,
			principal: service, effect: effect, broker: goodBroker,
		})
	}
	if len(cases) != 10000 {
		t.Fatalf("sweep size: %d", len(cases))
	}

	allowed, refused := 0, 0
	byCategory := map[string]int{}
	for _, testCase := range cases {
		_, decision, err := testCase.broker.Authorize(
			testCase.principal, testCase.effect)
		denied := err != nil || decision == nil ||
			decision.Verdict != "allow"
		if testCase.violation {
			if !denied {
				t.Fatalf("gate B4 leak: %s case %s allowed an effect",
					testCase.category, testCase.effect.ID)
			}
			refused++
		} else {
			if denied {
				t.Fatalf("control case %s (%s) was refused: err=%v decision=%+v",
					testCase.effect.ID, testCase.category, err, decision)
			}
			allowed++
		}
		byCategory[testCase.category]++
	}
	// Eleven violation categories: 600 each for the ten effect-level
	// ones and the expired grant, plus 500 budget overruns = 7100
	// refusals. Everything the sweep labels legitimate — 1900 controls
	// and 1000 in-round budget spends — must have been allowed.
	if refused != 7100 || allowed != 2900 {
		t.Fatalf("sweep balance: %d allowed, %d refused",
			allowed, refused)
	}
	if byCategory["control"] != 1900 {
		t.Fatalf("control arm size: %d", byCategory["control"])
	}
	if byCategory["budget-exhausted"] != 1500 {
		t.Fatalf("budget rounds size: %d",
			byCategory["budget-exhausted"])
	}
	t.Logf("gate B4 sweep: %d refusals, %d allows, %d categories",
		refused, allowed, len(byCategory))
}
