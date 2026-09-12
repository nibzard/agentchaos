package governor

import "fmt"

// StopHandoff is the governor's handoff document for the stop
// protocol (spec 13.3). The governor ends experiment authority; the
// stop controller executes the protocol. Every step the spec orders is
// listed as pending, and nothing is marked done because a worker
// exited — the terminal state arrives only from the independent
// cleanup verifier through ReportCleanupState.
//
// The document is a governor-local contract: it is the input the stop
// controller (a later task) works from, not a shared-plane schema.
type StopHandoff struct {
	Kind         string        `json:"kind"` // StopHandoff
	APIVersion   string        `json:"api_version"`
	ID           string        `json:"id"`
	TenantID     string        `json:"tenant_id"`
	RunID        string        `json:"run_id"`
	ExperimentID string        `json:"experiment_id"`
	Cause        Trip          `json:"cause"`
	Steps        []HandoffStep `json:"steps"`
	EmittedAt    string        `json:"emitted_at"`
}

// HandoffStep is one protocol step with its completion status. The
// stop controller reports each step; REQUIRED steps gate the terminal
// state.
type HandoffStep struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Status   string `json:"status"` // pending | done | skipped
}

// Handoff step names, in spec 13.3's order.
const (
	StepRevokePermits    = "revoke_new_effect_permits"
	StepDisableInjectors = "disable_injectors"
	StepFenceDelegations = "fence_delegation_group"
	StepCancelPending    = "cancel_pending_effects"
	StepIdentifyUnknown  = "identify_inflight_and_unknown_effects"
	StepReconcile        = "reconcile_service_receipts"
	StepCompensate       = "execute_preapproved_compensation"
	StepSandbox          = "terminate_or_preserve_sandbox"
	StepCleanupVerifier  = "run_independent_cleanup_verifier"
	StepTerminalState    = "record_terminal_state"
)

// handoffLocked emits a stop handoff for a run whose authority ended
// (spec 13.3). The governor journals it as a recovery action; the run
// record keeps the handoff id so the stop controller can fetch it.
// The caller holds g.mu.
func (g *Governor) handoffLocked(run *GovernedRun, cause Trip) *StopHandoff {
	g.handoffCounter++
	handoff := &StopHandoff{
		Kind:         "StopHandoff",
		APIVersion:   "v1",
		ID:           fmt.Sprintf("sgh_governor%08d", g.handoffCounter),
		TenantID:     run.TenantID,
		RunID:        run.RunID,
		ExperimentID: run.ExperimentID,
		Cause:        cause,
		Steps: []HandoffStep{
			{Name: StepRevokePermits, Required: true, Status: "pending"},
			{Name: StepDisableInjectors, Required: true, Status: "pending"},
			{Name: StepFenceDelegations, Required: true, Status: "pending"},
			{Name: StepCancelPending, Required: false, Status: "pending"},
			{Name: StepIdentifyUnknown, Required: true, Status: "pending"},
			{Name: StepReconcile, Required: true, Status: "pending"},
			{Name: StepCompensate, Required: false, Status: "pending"},
			{Name: StepSandbox, Required: true, Status: "pending"},
			{Name: StepCleanupVerifier, Required: true, Status: "pending"},
			{Name: StepTerminalState, Required: true, Status: "pending"},
		},
		EmittedAt: g.ClockUTC(),
	}
	g.handoffs[handoff.ID] = handoff
	g.appendEvent(recoveryEvent(run, "stop_handoff", cause.Condition, map[string]any{
		"handoff_id":  handoff.ID,
		"trip_action": cause.Action,
		"steps":       len(handoff.Steps),
	}))
	g.logLocked(run.TenantID, run.RunID, "stop_handoff",
		fmt.Sprintf("handoff %s emitted for %s", handoff.ID, cause.Condition))
	return handoff
}

// Handoff returns the run's stop handoff document for the stop
// controller.
func (g *Governor) Handoff(principal *Principal, runID string) (*StopHandoff, error) {
	run, err := g.Run(principal, runID)
	if err != nil {
		return nil, err
	}
	if run.HandoffID == "" {
		return nil, refuse("handoff_unknown", "the run has no stop handoff")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	handoff := g.handoffs[run.HandoffID]
	if handoff == nil {
		return nil, refuse("handoff_unknown", "the handoff record is missing; failing closed")
	}
	return cloneHandoff(handoff), nil
}

// cloneHandoff copies a handoff so callers never share stored state.
func cloneHandoff(handoff *StopHandoff) *StopHandoff {
	duplicate := *handoff
	duplicate.Steps = append([]HandoffStep{}, handoff.Steps...)
	return &duplicate
}
