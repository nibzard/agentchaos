package broker

import (
	"encoding/json"
	"testing"
)

func validProposalJSON() map[string]any {
	return map[string]any{
		"kind":         "Effect",
		"api_version":  "v1",
		"id":           "eff_" + "1a2b3c4d5e6f7081",
		"tenant_id":    "tnt_9d4c1e2a3b4f5c67",
		"run_id":       "run_" + "0f1e2d3c4b5a6970",
		"actor":        "act_worker-reference-01",
		"action_class": "A2",
		"proposed_action": map[string]any{
			"operation":        "queue.publish",
			"resource":         "patch-export-beta",
			"destination":      "sink:patch-export-beta",
			"arguments_digest": "sha256:" + repeat("a", 64),
			"size_bytes":       128,
		},
		"state": "PROPOSED",
		"transitions": []map[string]any{
			{"state": "PROPOSED", "at": "2026-09-12T10:00:00Z"},
		},
		"created_at": "2026-09-12T10:00:00Z",
	}
}

func mustJSON(t *testing.T, value map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeProposalRejectsUnknownFields(t *testing.T) {
	proposal := validProposalJSON()
	proposal["sneaky"] = "field"
	if _, err := DecodeProposal(mustJSON(t, proposal)); err == nil {
		t.Fatal("unknown field accepted; security-sensitive manifests fail closed (AC-001)")
	}
}

func TestDecodeProposalRejectsTrailingContent(t *testing.T) {
	body := append(mustJSON(t, validProposalJSON()), []byte("{\"second\":1}")...)
	if _, err := DecodeProposal(body); err == nil {
		t.Fatal("trailing document accepted")
	}
}

func TestValidProposalPassesValidation(t *testing.T) {
	effect, err := DecodeProposal(mustJSON(t, validProposalJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if errs := effect.ValidateProposal(); len(errs) != 0 {
		t.Fatalf("valid proposal rejected: %+v", errs)
	}
}

func TestProposalClassRestrictions(t *testing.T) {
	for _, class := range []string{"A0", "A3", "B1"} {
		proposal := validProposalJSON()
		proposal["action_class"] = class
		effect, err := DecodeProposal(mustJSON(t, proposal))
		if err != nil {
			t.Fatal(err)
		}
		errs := effect.ValidateProposal()
		if len(errs) == 0 {
			t.Fatalf("class %s accepted", class)
		}
	}
}

func TestProposalMustNotCarryAPermit(t *testing.T) {
	proposal := validProposalJSON()
	proposal["authorization"] = map[string]any{
		"task_id":        "task_reference-fixture",
		"policy_version": "1.0.0",
		"policy_digest":  "sha256:" + repeat("b", 64),
		"expires_at":     "2026-09-12T10:05:00Z",
		"nonce":          repeat("n", 22),
	}
	effect, err := DecodeProposal(mustJSON(t, proposal))
	if err != nil {
		t.Fatal(err)
	}
	errs := effect.ValidateProposal()
	if len(errs) == 0 {
		t.Fatal("pre-authorized proposal accepted; replay would look legitimate (AC-009)")
	}
}

func TestProposalMustArriveProposed(t *testing.T) {
	for _, state := range []string{"AUTHORIZED", "COMMITTED", ""} {
		proposal := validProposalJSON()
		proposal["state"] = state
		effect, err := DecodeProposal(mustJSON(t, proposal))
		if err != nil {
			t.Fatal(err)
		}
		if errs := effect.ValidateProposal(); len(errs) == 0 {
			t.Fatalf("state %q accepted", state)
		}
	}
}

func repeat(char string, n int) string {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, char...)
	}
	return string(out[:n])
}

func TestDecodeProposalRejectsKeyCasingVariants(t *testing.T) {
	// encoding/json matches keys case-insensitively when no exact tag
	// match exists; "Action_Class" would silently bind to
	// action_class. Contract spellings are exact (AC-001).
	proposal := validProposalJSON()
	proposal["Action_Class"] = "A2"
	delete(proposal, "action_class")
	if _, err := DecodeProposal(mustJSON(t, proposal)); err == nil {
		t.Fatal("casing variant accepted")
	}
	action := validProposalJSON()
	action["proposed_action"].(map[string]any)["Destination"] = "sink:x"
	delete(action["proposed_action"].(map[string]any), "destination")
	if _, err := DecodeProposal(mustJSON(t, action)); err == nil {
		t.Fatal("nested casing variant accepted")
	}
	transitions := validProposalJSON()
	transitions["transitions"] = []map[string]any{
		{"State": "PROPOSED", "at": "2026-09-12T10:00:00Z"},
	}
	if _, err := DecodeProposal(mustJSON(t, transitions)); err == nil {
		t.Fatal("transition casing variant accepted")
	}
}

func TestProposalMustNotCarryAReview(t *testing.T) {
	proposal := validProposalJSON()
	proposal["review"] = map[string]any{
		"verdict":     "allow",
		"reviewer_id": "src_broker-effect-broker",
		"rationale":   "self-approved",
	}
	effect, err := DecodeProposal(mustJSON(t, proposal))
	if err != nil {
		t.Fatal(err)
	}
	errs := effect.ValidateProposal()
	if len(errs) == 0 {
		t.Fatal("self-attached review accepted; reviews attach broker-side (spec 11.2)")
	}
}

func TestProposalTransitionsMustBeExactlyProposed(t *testing.T) {
	proposal := validProposalJSON()
	proposal["transitions"] = []map[string]any{
		{"state": "PROPOSED", "at": "2026-09-12T10:00:00Z"},
		{"state": "DENIED", "at": "2026-09-12T09:59:00Z"},
	}
	effect, err := DecodeProposal(mustJSON(t, proposal))
	if err != nil {
		t.Fatal(err)
	}
	if errs := effect.ValidateProposal(); len(errs) == 0 {
		t.Fatal("fabricated transition history accepted; history is append-only broker-side")
	}
}
