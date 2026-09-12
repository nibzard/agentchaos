// Package governor implements the independent safety governor
// (spec 13.2): it runs outside the experiment runner and its LLMs,
// issues short-lived experiment grants that survive only through
// heartbeats, enforces selectors and budgets, trips on the spec's
// conditions, fences experiments on emergency stop, and hands the
// stop protocol (spec 13.3) to the stop controller. The governor is
// part of the trusted computing base: its clock is the only clock a
// grant ever trusts (spec 10.2, AC-006).
package governor

import (
	"fmt"
	"regexp"
)

// Roles recognized by the governor. The emergency control adds the
// customer role: revoking experiment authority must not depend on the
// main UI or the model provider (spec 13.2).
const (
	RoleWorker   = "worker"
	RoleService  = "service"
	RoleOperator = "operator"
	RoleCustomer = "customer"
)

// Pattern anchors from shared/schemas/common.schema.json. The schemas
// stay authoritative; these mirror them so the governor can reject
// malformed requests without a schema engine.
var (
	reRunID        = regexp.MustCompile(`^run_[a-z0-9]{8,64}$`)
	reExperimentID = regexp.MustCompile(`^exp_[a-z0-9]{8,64}$`)
	reTenantID     = regexp.MustCompile(`^tnt_[a-z0-9]{8,64}$`)
	reActorID      = regexp.MustCompile(`^act_[a-z0-9][a-z0-9-]{3,63}$`)
	reTargetID     = regexp.MustCompile(`^tgt_[a-z0-9]{8,64}$`)
	reEventID      = regexp.MustCompile(`^evt_[a-z0-9]{8,64}$`)
	reHandoffID    = regexp.MustCompile(`^sgh_[a-z0-9]{8,64}$`)
	reSessionID    = regexp.MustCompile(`^ses_[a-z0-9]{8,64}$`)
	reOperation    = regexp.MustCompile(`^[a-z][a-z0-9_.]{1,127}$`)
	reCurrency     = regexp.MustCompile(`^[A-Z]{3}$`)
	reIdemKey      = regexp.MustCompile(`^idk_[A-Za-z0-9_-]{8,128}$`)
	reReasonWord   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Money in integer micro-units with an ISO-4317-style code, mirroring
// common.schema.json's money def.
type Money struct {
	Currency string `json:"currency"`
	Micros   int64  `json:"micros"`
}

// Trip conditions (spec 13.2). Each names one way experiment authority
// ends early; the experiment's stop rules map a condition to an action.
const (
	TripUnauthorizedEffect  = "unauthorized_effect"
	TripContainmentLoss     = "containment_coverage_loss"
	TripEvidencePersistence = "evidence_persistence_failure"
	TripTargetExpansion     = "unexpected_target_expansion"
	TripGrantExpiry         = "grant_expiry"
	TripBudgetExhaustion    = "budget_exhaustion"
	TripServiceHealth       = "service_health_threshold"
	TripOperatorRequest     = "operator_request"
)

// Trip actions. Stopping injection and fencing effects are separate
// operations: stopping injection does not retract its effects
// (spec 13.2).
const (
	ActionStopInjection = "stop_injection"
	ActionFenceEffects  = "fence_effects"
	ActionTerminate     = "terminate"
)

// Run states under governor authority.
const (
	RunStateActive  = "active"
	RunStateFenced  = "fenced"
	RunStateStopped = "stopped"
)

// Cleanup terminal states (spec 13.3, common.schema.json). Never
// inferred from worker exit.
const (
	TerminalClean            = "CLEAN"
	TerminalDirtyQuarantined = "DIRTY_QUARANTINED"
	TerminalUnknown          = "UNKNOWN"
)

// MaxReason bounds advisory reasons entering the evidence journal
// (spec 19 payload minimization).
const MaxReason = 512

// Principal is the authenticated caller, set by the deployment's
// authentication front end. A tenant in a request body never overrides
// it (spec 18.3).
type Principal struct {
	ID       string
	TenantID string
	Role     string
}

// Selector is a recorded target selection (spec 13.1): an explicit
// enrolled set, the seed that produced it, and the exclusion list.
type Selector struct {
	Kind         string   `json:"kind"`
	TargetIDs    []string `json:"target_ids"`
	RecordedSeed int64    `json:"recorded_seed"`
	Exclusions   []string `json:"exclusions"`
}

// StopRule maps a trip condition to an action (spec 13.2). A threshold
// is required only by threshold-type conditions.
type StopRule struct {
	Condition string  `json:"condition"`
	Action    string  `json:"action"`
	Threshold float64 `json:"threshold,omitempty"`
}

// Budgets is the experiment's declared envelope budgets (spec 13.1).
type Budgets struct {
	MaxDurationS          int64 `json:"max_duration_s"`
	MaxConcurrentSessions int64 `json:"max_concurrent_sessions"`
	PerSessionCostMax     Money `json:"per_session_cost_max"`
	AggregateCostMax      Money `json:"aggregate_cost_max"`
}

// Envelope is the experiment's safety envelope (spec 13.1): eligible
// targets, budgets, allowed primitives, and stop conditions. The
// governor refuses work for an experiment whose envelope it never
// received. A template cannot modify its own envelope — only the
// control plane registers one, and only before runs start.
type Envelope struct {
	Kind              string     `json:"kind"`
	APIVersion        string     `json:"api_version"`
	ExperimentID      string     `json:"experiment_id"`
	TenantID          string     `json:"tenant_id"`
	Selectors         []Selector `json:"selectors"`
	Budgets           Budgets    `json:"budgets"`
	AllowedPrimitives []string   `json:"allowed_primitives"`
	StopRules         []StopRule `json:"stop_rules"`
	MaxSessions       int64      `json:"max_sessions"`
	Fenced            bool       `json:"fenced"`
	RegisteredAt      string     `json:"registered_at"`

	// eligible is the precomputed eligible target set. Never
	// serialized; computed once at registration because envelopes are
	// immutable.
	eligible map[string]bool `json:"-"`
}

// SessionSpend is a runner's claim about one session's cost. Claims are
// lower bounds: the governor never lowers recorded spend because a
// runner reported a smaller number.
type SessionSpend struct {
	SessionID string `json:"session_id"`
	Cost      Money  `json:"cost"`
}

// Heartbeat renews a run's grant lease. It carries the runner's claims
// since the last beat; the governor measures every time bound on its
// own clock.
type Heartbeat struct {
	RunID           string         `json:"run_id"`
	Generation      int64          `json:"generation,omitempty"`
	SessionSpends   []SessionSpend `json:"session_spends"`
	ObservedTargets []string       `json:"observed_targets"`
}

// Incident reports an observed trip condition from outside the
// governor: the broker names unauthorized effects, the collector names
// evidence-persistence failures, monitors name containment and health.
type Incident struct {
	RunID     string `json:"run_id"`
	Condition string `json:"condition"`
	Reason    string `json:"reason,omitempty"`
	// Observed carries the measured value for threshold conditions
	// (for example a service-health ratio) compared against the
	// matching stop rule's threshold.
	Observed float64 `json:"observed,omitempty"`
}

// EmergencyStopScope bounds an emergency stop: one experiment or the
// whole tenant.
type EmergencyStopScope struct {
	Kind         string `json:"kind"` // experiment | tenant
	ExperimentID string `json:"experiment_id,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// Grant is the short-lived experiment grant (spec 13.2). The default
// lease is ten seconds with renewal; a runner reaches an unexpired
// grant only by heartbeating.
type Grant struct {
	RunID        string `json:"run_id"`
	ExperimentID string `json:"experiment_id"`
	Generation   int64  `json:"generation"`
	IssuedAt     string `json:"issued_at"`
	ExpiresAt    string `json:"expires_at"`
	// Deadline is the envelope's duration end; a renewal never extends
	// past it.
	Deadline string `json:"deadline"`
}

// Trip is one raised trip condition and the action applied.
type Trip struct {
	Condition string `json:"condition"`
	Action    string `json:"action"`
	Source    string `json:"source"` // sweep | heartbeat | incident | registration | emergency
	Detail    string `json:"detail,omitempty"`
	At        string `json:"at"`
}

// GovernedRun is the governor's record of one run's authority.
type GovernedRun struct {
	RunID            string           `json:"run_id"`
	ExperimentID     string           `json:"experiment_id"`
	TenantID         string           `json:"tenant_id"`
	State            string           `json:"state"`
	InjectionStopped bool             `json:"injection_stopped"`
	StartedAt        string           `json:"started_at"`
	Grant            Grant            `json:"grant"`
	SessionSpend     map[string]int64 `json:"session_spend"`
	AggregateSpend   int64            `json:"aggregate_spend"`
	SpendCurrency    string           `json:"spend_currency"`
	ObservedTargets  []string         `json:"observed_targets"`
	Trips            []Trip           `json:"trips"`
	TerminalState    string           `json:"terminal_state,omitempty"`
	HandoffID        string           `json:"handoff_id,omitempty"`
}

// Decision is one entry in the governor's own append-only decision
// log. Not every decision is an EvidenceEvent: grant issuance and
// renewal stay here, minimized (spec 19); enforcement facts also land
// in the evidence journal.
type Decision struct {
	At      string `json:"at"`
	Subject string `json:"subject"`
	Action  string `json:"action"`
	Detail  string `json:"detail,omitempty"`
}

// validTripCondition reports whether a condition names a spec 13.2 trip.
func validTripCondition(condition string) bool {
	switch condition {
	case TripUnauthorizedEffect, TripContainmentLoss, TripEvidencePersistence,
		TripTargetExpansion, TripGrantExpiry, TripBudgetExhaustion,
		TripServiceHealth, TripOperatorRequest:
		return true
	}
	return false
}

// validTripAction reports whether an action is one of the three.
func validTripAction(action string) bool {
	return action == ActionStopInjection ||
		action == ActionFenceEffects ||
		action == ActionTerminate
}

// ValidateEnvelopeRequest checks an envelope against the Experiment
// contract's shapes (spec 13.1 mirrors). Every violation becomes a
// contract error for the problem body.
func (e *Envelope) ValidateEnvelopeRequest() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if !reExperimentID.MatchString(e.ExperimentID) {
		add("experiment_id", "$.experiment_id", "must match exp_[a-z0-9]{8,64}")
	}
	if len(e.Selectors) < 1 || len(e.Selectors) > 16 {
		add("selectors", "$.selectors", "one to sixteen selectors are required")
	}
	eligible := 0
	for i, selector := range e.Selectors {
		path := fmt.Sprintf("$.selectors[%d]", i)
		if selector.Kind != "enrolled_targets" {
			add("selector_kind", path+".kind", "selectors must resolve to an enrolled set")
		}
		if len(selector.TargetIDs) < 1 || len(selector.TargetIDs) > 4096 {
			add("target_ids", path+".target_ids", "one to 4096 explicit targets are required")
			continue
		}
		eligible += len(selector.TargetIDs)
		for _, target := range selector.TargetIDs {
			if !reTargetID.MatchString(target) {
				add("target_ids", path+".target_ids",
					fmt.Sprintf("%q must match tgt_[a-z0-9]{8,64}", target))
				break
			}
		}
		if !uniqueStrings(selector.TargetIDs) || !uniqueStrings(selector.Exclusions) {
			add("duplicates", path, "target and exclusion lists must be unique")
		}
	}
	if eligible == 0 {
		add("eligible_targets", "$.selectors", "the envelope must name at least one eligible target")
	}
	budgets := e.Budgets
	if budgets.MaxDurationS < 1 || budgets.MaxDurationS > 86400 {
		add("max_duration_s", "$.budgets.max_duration_s", "must be 1..86400")
	}
	if budgets.MaxConcurrentSessions < 1 || budgets.MaxConcurrentSessions > 64 {
		add("max_concurrent_sessions", "$.budgets.max_concurrent_sessions", "must be 1..64")
	}
	for name, money := range map[string]Money{
		"per_session_cost_max": budgets.PerSessionCostMax,
		"aggregate_cost_max":   budgets.AggregateCostMax,
	} {
		if !reCurrency.MatchString(money.Currency) {
			add(name, "$.budgets."+name+".currency", "must be a three-letter currency code")
		}
		if money.Micros < 0 {
			add(name, "$.budgets."+name+".micros", "must not be negative")
		}
	}
	if reCurrency.MatchString(budgets.PerSessionCostMax.Currency) &&
		budgets.PerSessionCostMax.Currency != budgets.AggregateCostMax.Currency {
		add("currency_mismatch", "$.budgets",
			"per-session and aggregate budgets must share one currency")
	}
	if len(e.AllowedPrimitives) < 1 || len(e.AllowedPrimitives) > 128 {
		add("allowed_primitives", "$.allowed_primitives", "one to 128 primitives are required")
	}
	for _, primitive := range e.AllowedPrimitives {
		if !reOperation.MatchString(primitive) {
			add("allowed_primitives", "$.allowed_primitives",
				fmt.Sprintf("%q must match the operation pattern", primitive))
			break
		}
	}
	if !uniqueStrings(e.AllowedPrimitives) {
		add("allowed_primitives", "$.allowed_primitives", "primitives must be unique")
	}
	if len(e.StopRules) < 1 || len(e.StopRules) > 32 {
		add("stop_rules", "$.stop_rules", "one to thirty-two stop rules are required")
	}
	for i, rule := range e.StopRules {
		path := fmt.Sprintf("$.stop_rules[%d]", i)
		if !validTripCondition(rule.Condition) {
			add("condition", path+".condition", "unknown trip condition")
		}
		if !validTripAction(rule.Action) {
			add("action", path+".action", "action must stop injection, fence effects, or terminate")
		}
	}
	if e.MaxSessions < 1 || e.MaxSessions > 100000 {
		add("max_sessions", "$.max_sessions", "must be 1..100000")
	}
	return errs
}

// ValidateHeartbeat checks a heartbeat's shapes.
func (h *Heartbeat) ValidateHeartbeat() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if !reRunID.MatchString(h.RunID) {
		add("run_id", "$.run_id", "must match run_[a-z0-9]{8,64}")
	}
	if len(h.SessionSpends) > 64 {
		add("session_spends", "$.session_spends", "at most sixty-four sessions per beat")
	}
	for i, spend := range h.SessionSpends {
		path := fmt.Sprintf("$.session_spends[%d]", i)
		if !reSessionID.MatchString(spend.SessionID) {
			add("session_id", path+".session_id", "must match ses_[a-z0-9]{8,64}")
		}
		if !reCurrency.MatchString(spend.Cost.Currency) {
			add("currency", path+".cost.currency", "must be a three-letter currency code")
		}
		if spend.Cost.Micros < 0 {
			add("micros", path+".cost.micros", "must not be negative")
		}
	}
	if len(h.ObservedTargets) > 4096 {
		add("observed_targets", "$.observed_targets", "at most 4096 targets per beat")
	}
	for _, target := range h.ObservedTargets {
		if !reTargetID.MatchString(target) {
			add("observed_targets", "$.observed_targets",
				fmt.Sprintf("%q must match tgt_[a-z0-9]{8,64}", target))
			break
		}
	}
	if !uniqueStrings(h.ObservedTargets) {
		add("observed_targets", "$.observed_targets", "targets must be unique")
	}
	return errs
}

// ValidateIncident checks an incident report's shapes.
func (i *Incident) ValidateIncident() []ContractError {
	var errs []ContractError
	if !reRunID.MatchString(i.RunID) {
		errs = append(errs, ContractError{Check: "run_id", Path: "$.run_id",
			Detail: "must match run_[a-z0-9]{8,64}"})
	}
	if !validTripCondition(i.Condition) {
		errs = append(errs, ContractError{Check: "condition", Path: "$.condition",
			Detail: "unknown trip condition"})
	}
	if len(i.Reason) > MaxReason {
		errs = append(errs, ContractError{Check: "reason", Path: "$.reason",
			Detail: "reason exceeds 512 characters"})
	}
	return errs
}

// ValidateEmergencyStop checks an emergency stop request's shapes.
func (s *EmergencyStopScope) ValidateEmergencyStop() []ContractError {
	var errs []ContractError
	add := func(check, path, detail string) {
		errs = append(errs, ContractError{Check: check, Path: path, Detail: detail})
	}
	if s.Kind != "experiment" && s.Kind != "tenant" {
		add("kind", "$.kind", "scope must be experiment or tenant")
	}
	if s.Kind == "experiment" && !reExperimentID.MatchString(s.ExperimentID) {
		add("experiment_id", "$.experiment_id", "must match exp_[a-z0-9]{8,64}")
	}
	if len(s.Reason) > MaxReason {
		add("reason", "$.reason", "reason exceeds 512 characters")
	}
	return errs
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

// ContractError is one contract violation for a problem body.
type ContractError struct {
	Check  string `json:"check"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}
