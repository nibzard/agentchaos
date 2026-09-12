package broker

import (
	"fmt"
	"math/rand"
	"testing"
)

// Property tests for the broker core (T040): randomized inputs under
// fixed seeds, with invariants that must hold for every input.
// Attenuation never widens, authorization never exceeds a ceiling,
// and the effect lifecycle is a directed acyclic graph whose sinks
// are the terminal states.

// randomSubset draws a random subset that keeps at least one element.
func randomSubset(rng *rand.Rand, pool []string) []string {
	var picked []string
	for _, item := range pool {
		if rng.Intn(2) == 1 {
			picked = append(picked, item)
		}
	}
	if len(picked) == 0 {
		picked = append(picked, pool[rng.Intn(len(pool))])
	}
	return picked
}

func containsAll(haystack, needles []string) bool {
	for _, needle := range needles {
		found := false
		for _, item := range haystack {
			if item == needle {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestPropertyAttenuationNeverWidens(t *testing.T) {
	rng := rand.New(rand.NewSource(20260912))
	for trial := 0; trial < 200; trial++ {
		broker := testBroker(t, &SyntheticSink{})
		parent := mintRoot(t, broker)

		// A random chain of lawful narrowings.
		depth := 1 + rng.Intn(3)
		for level := 0; level < depth; level++ {
			request := DelegationRequest{
				ID:                 fmt.Sprintf("dlg_chain%07d01", trial*4+level),
				RunID:              parent.RunID,
				ParentActor:        parent.ChildActor,
				ChildActor:         fmt.Sprintf("act_worker-chain%03d", level),
				ParentDelegationID: parent.ID,
				Capabilities: Capabilities{
					AllowedActionClasses: randomSubset(rng,
						parent.Capabilities.AllowedActionClasses),
					AllowedDestinations: randomSubset(rng,
						parent.Capabilities.AllowedDestinations),
					AllowedResources: randomSubset(rng,
						parent.Capabilities.AllowedResources),
				},
				CumulativeBudget: Budget{
					MaxTotalCost: Money{Currency: "USD",
						Micros: 1 + rng.Int63n(parent.CumulativeBudget.MaxTotalCost.Micros)},
					MaxTotalTokens: 1 + rng.Int63n(parent.CumulativeBudget.MaxTotalTokens),
					MaxEffects:     1 + rng.Int63n(parent.CumulativeBudget.MaxEffects),
				},
			}
			child, err := broker.Delegate(servicePrincipal(), &request)
			if err != nil {
				t.Fatalf("trial %d level %d: lawful narrowing refused: %v",
					trial, level, err)
			}
			// The invariant itself: capabilities shrink or hold,
			// budgets never grow, depth advances one level.
			if !containsAll(parent.Capabilities.AllowedActionClasses,
				child.Capabilities.AllowedActionClasses) ||
				!containsAll(parent.Capabilities.AllowedDestinations,
					child.Capabilities.AllowedDestinations) ||
				!containsAll(parent.Capabilities.AllowedResources,
					child.Capabilities.AllowedResources) {
				t.Fatalf("trial %d level %d: capabilities widened",
					trial, level)
			}
			if child.CumulativeBudget.MaxTotalCost.Micros >
				parent.CumulativeBudget.MaxTotalCost.Micros ||
				child.CumulativeBudget.MaxTotalTokens >
					parent.CumulativeBudget.MaxTotalTokens ||
				child.CumulativeBudget.MaxEffects >
					parent.CumulativeBudget.MaxEffects {
				t.Fatalf("trial %d level %d: budget raised", trial, level)
			}
			if child.Depth != parent.Depth+1 {
				t.Fatalf("trial %d level %d: depth jumped", trial, level)
			}
			parent = child
		}

		// One random widening of the deepest node must be refused.
		widening := DelegationRequest{
			ID:                 fmt.Sprintf("dlg_widen%07d01", trial),
			RunID:              parent.RunID,
			ParentActor:        parent.ChildActor,
			ChildActor:         "act_worker-widener",
			ParentDelegationID: parent.ID,
			Capabilities: Capabilities{
				AllowedActionClasses: parent.Capabilities.AllowedActionClasses,
				AllowedDestinations:  parent.Capabilities.AllowedDestinations,
				AllowedResources:     parent.Capabilities.AllowedResources,
			},
			CumulativeBudget: Budget{
				MaxTotalCost:   parent.CumulativeBudget.MaxTotalCost,
				MaxTotalTokens: parent.CumulativeBudget.MaxTotalTokens,
				MaxEffects:     parent.CumulativeBudget.MaxEffects,
			},
		}
		switch rng.Intn(4) {
		case 0:
			widening.Capabilities.AllowedActionClasses = append(
				widening.Capabilities.AllowedActionClasses, ClassA1)
		case 1:
			widening.Capabilities.AllowedDestinations = append(
				widening.Capabilities.AllowedDestinations,
				"https://evil.example.com/")
		case 2:
			widening.Capabilities.AllowedResources = append(
				widening.Capabilities.AllowedResources, "other-resource")
		case 3:
			widening.CumulativeBudget.MaxEffects++
		}
		if _, err := broker.Delegate(servicePrincipal(), &widening); err == nil {
			t.Fatalf("trial %d: a widening was minted", trial)
		}
	}
}

func TestPropertyAuthorizationNeverExceedsTheCeiling(t *testing.T) {
	rng := rand.New(rand.NewSource(20260913))
	for trial := 0; trial < 100; trial++ {
		broker := testBroker(t, &SyntheticSink{})
		root := mintRoot(t, broker)

		// One child with a random effect ceiling; the cost ceiling
		// stays at the root's so effects, not micros, bind first.
		request := childRequest(root)
		request.ID = fmt.Sprintf("dlg_ceiling%06d01", trial)
		request.CumulativeBudget = Budget{
			MaxTotalCost:   root.CumulativeBudget.MaxTotalCost,
			MaxTotalTokens: root.CumulativeBudget.MaxTotalTokens,
			MaxEffects:     1 + int64(rng.Intn(4)),
		}
		child, err := broker.Delegate(servicePrincipal(), request)
		if err != nil {
			t.Fatal(err)
		}

		allowed := 0
		for n := 1; n <= 6; n++ {
			_, decision, err := broker.Authorize(servicePrincipal(),
				delegatedEffect(n, child.ID, child.ChildActor))
			if err != nil {
				t.Fatalf("trial %d effect %d: %v", trial, n, err)
			}
			if decision.Verdict != "allow" {
				if allowed != int(child.CumulativeBudget.MaxEffects) {
					t.Fatalf("trial %d: stopped at %d allowed, ceiling %d",
						trial, allowed, child.CumulativeBudget.MaxEffects)
				}
				if decision.Reason != "effect_budget_exhausted" {
					t.Fatalf("trial %d: refusal reason %q", trial,
						decision.Reason)
				}
				return
			}
			allowed++
		}
		t.Fatalf("trial %d: six effects passed a ceiling of %d", trial,
			child.CumulativeBudget.MaxEffects)
	}
}

func TestPropertyTheLifecycleIsADag(t *testing.T) {
	terminal := map[string]bool{
		StateDenied: true, StateCommitted: true, StateCancelled: true,
		StateExpired: true,
	}
	for from, nexts := range allowedTransitions {
		for _, to := range nexts {
			if from == to {
				t.Fatalf("self edge on %s", from)
			}
			if terminal[from] {
				t.Fatalf("terminal state %s has an outgoing edge", from)
			}
		}
	}
	if !terminal[StateDenied] || !terminal[StateCommitted] {
		t.Fatal("the terminal set lost a member")
	}

	// No cycles: every depth-first walk from any state terminates.
	visiting := map[string]bool{}
	var visit func(state string) bool
	visit = func(state string) bool {
		if visiting[state] {
			return true
		}
		visiting[state] = true
		defer delete(visiting, state)
		for _, next := range allowedTransitions[state] {
			if visit(next) {
				return true
			}
		}
		return false
	}
	for state := range allowedTransitions {
		if visit(state) {
			t.Fatalf("the lifecycle has a cycle through %s", state)
		}
	}

	// canTransition agrees with the graph, and terminal states are
	// sinks for every query.
	states := []string{StateProposed, StateAuthorized, StatePrepared,
		StateCommitting, StateCommitted, StateDenied, StateExpired,
		StateCancelled, StateUnknown, StateCompensating}
	rng := rand.New(rand.NewSource(20260914))
	for trial := 0; trial < 500; trial++ {
		from := states[rng.Intn(len(states))]
		to := states[rng.Intn(len(states))]
		listed := false
		for _, next := range allowedTransitions[from] {
			if next == to {
				listed = true
			}
		}
		if canTransition(from, to) != listed {
			t.Fatalf("canTransition(%s, %s) disagrees with the graph",
				from, to)
		}
		if terminal[from] && listed && from != to {
			t.Fatalf("terminal state %s has an outgoing edge", from)
		}
	}
}
