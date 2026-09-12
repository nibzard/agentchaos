package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"gauntlet/control"
)

// claimStore holds computed assurance claims, tenant-scoped. A
// cross-tenant claim read is indistinguishable from absence.
type claimStore struct {
	mu     sync.Mutex
	claims map[string]*control.AssuranceClaim // tenant + "\x00" + id
}

func newClaimStore() *claimStore {
	return &claimStore{claims: map[string]*control.AssuranceClaim{}}
}

func (s *claimStore) put(tenantID string, claim *control.AssuranceClaim) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims[tenantID+"\x00"+claim.ID] = claim
}

func (s *claimStore) get(tenantID, id string) *control.AssuranceClaim {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claims[tenantID+"\x00"+id]
}

// claimRequest is the wire shape of a fixed-cohort assessment. The
// tenant never appears here: it comes from the authenticated principal
// (spec 18.3). Field names mirror the AssuranceClaim contract.
type claimRequest struct {
	ClaimID  string `json:"claim_id"`
	Revision int    `json:"claim_revision"`
	Hazard   struct {
		Description       string `json:"description"`
		Severity          string `json:"severity"`
		FailureEvent      string `json:"failure_event"`
		UnitOfObservation string `json:"unit_of_observation"`
	} `json:"hazard"`
	WorkloadVersionID string `json:"workload_version_id"`
	AutonomyProfileID string `json:"autonomy_profile_id"`
	Fingerprints      struct {
		Model                string `json:"model"`
		Harness              string `json:"harness"`
		Tools                string `json:"tools"`
		Policy               string `json:"policy"`
		Monitor              string `json:"monitor"`
		ScenarioDistribution string `json:"scenario_distribution"`
		Environment          string `json:"environment"`
	} `json:"fingerprints"`
	EvidenceCategory  string `json:"evidence_category"`
	ObservationWindow struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"observation_window"`
	CoverageGaps       []string `json:"coverage_gaps"`
	SelectionProcedure string   `json:"selection_procedure"`
	LabelSource        string   `json:"label_source"`
	DataSources        []string `json:"data_sources"`
	Funnel             *struct {
		Selected         int `json:"selected"`
		Eligible         int `json:"eligible"`
		Triggered        int `json:"triggered"`
		Untriggered      int `json:"untriggered"`
		HarnessError     int `json:"harness_error"`
		VerifiedOutcomes int `json:"verified_outcomes"`
	} `json:"injection_funnel"`
	Failures                int      `json:"failures"`
	Eligible                int      `json:"eligible"`
	Unresolved              int      `json:"unresolved"`
	ConfidenceLevel         float64  `json:"confidence_level"`
	AcceptanceThreshold     float64  `json:"acceptance_threshold"`
	DependenceModel         string   `json:"dependence_model"`
	ClusterUnit             string   `json:"cluster_unit"`
	ClusterIDRefs           []string `json:"cluster_id_refs"`
	DependenceDescription   string   `json:"dependence_description"`
	PopulationApplicability string   `json:"population_applicability"`
	Exclusions              []string `json:"exclusions"`
	ValidDays               int      `json:"valid_days"`
	InvalidationTriggers    []string `json:"invalidation_triggers"`
	CreatedAt               string   `json:"created_at"`
}

// claimKeyTree is the exact set of keys the claim request accepts.
// Anything outside it fails closed (AC-001).
var claimKeyTree = keyTree{
	"claim_id":            leaf,
	"claim_revision":      leaf,
	"hazard":              keyTree{"description": leaf, "severity": leaf, "failure_event": leaf, "unit_of_observation": leaf},
	"workload_version_id": leaf,
	"autonomy_profile_id": leaf,
	"fingerprints": keyTree{
		"model": leaf, "harness": leaf, "tools": leaf, "policy": leaf,
		"monitor": leaf, "scenario_distribution": leaf, "environment": leaf,
	},
	"evidence_category":   leaf,
	"observation_window":  keyTree{"from": leaf, "to": leaf},
	"coverage_gaps":       leaf,
	"selection_procedure": leaf,
	"label_source":        leaf,
	"data_sources":        leaf,
	"injection_funnel": keyTree{
		"selected": leaf, "eligible": leaf, "triggered": leaf,
		"untriggered": leaf, "harness_error": leaf, "verified_outcomes": leaf,
	},
	"failures":                 leaf,
	"eligible":                 leaf,
	"unresolved":               leaf,
	"confidence_level":         leaf,
	"acceptance_threshold":     leaf,
	"dependence_model":         leaf,
	"cluster_unit":             leaf,
	"cluster_id_refs":          leaf,
	"dependence_description":   leaf,
	"population_applicability": leaf,
	"exclusions":               leaf,
	"valid_days":               leaf,
	"invalidation_triggers":    leaf,
	"created_at":               leaf,
}

// keyTree describes the accepted keys at one object level. leaf marks
// a scalar or array; a nested keyTree marks an object.
type keyTree map[string]any

var leaf = struct{}{}

// checkKeys walks a decoded request body against the tree and reports
// every unknown or misplaced key.
func checkKeys(document map[string]any, tree keyTree, path string) []string {
	var problems []string
	for key, value := range document {
		allowed, known := tree[key]
		if !known {
			problems = append(problems,
				fmt.Sprintf("unknown field %q fails closed", path+key))
			continue
		}
		subtree, isObject := allowed.(keyTree)
		if !isObject {
			continue
		}
		nested, ok := value.(map[string]any)
		if !ok {
			problems = append(problems,
				fmt.Sprintf("field %q must be an object", path+key))
			continue
		}
		problems = append(problems, checkKeys(nested, subtree, path+key+".")...)
	}
	return problems
}

// assessClaim computes and stores a fixed-cohort assurance claim (spec
// 14, 18.2). The statistics are exact and deterministic; the assurer
// validates the cohort before anything computes.
func (s *Server) assessClaim(w http.ResponseWriter, r *http.Request) {
	principal, requestID, ok := requireMutationPrincipal(w, r,
		supervisorRoles, "assess an assurance claim")
	if !ok {
		return
	}
	body, ok := readBody(w, requestID, r)
	if !ok {
		return
	}
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "claim_schema",
			"the claim request must be a JSON object", false)
		return
	}
	if problems := checkKeys(probe, claimKeyTree, "$."); len(problems) > 0 {
		writeProblem(w, requestID, http.StatusBadRequest, "claim_schema",
			"the claim request violates its contract", false, problems...)
		return
	}
	var request claimRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "claim_schema",
			"the claim request violates its contract: "+err.Error(), false)
		return
	}

	input := control.CohortInput{
		TenantID: principal.TenantID,
		ClaimID:  request.ClaimID,
		Revision: request.Revision,
		Hazard: control.HazardInput{
			Description:       request.Hazard.Description,
			Severity:          request.Hazard.Severity,
			FailureEvent:      request.Hazard.FailureEvent,
			UnitOfObservation: request.Hazard.UnitOfObservation,
		},
		WorkloadVersionID: request.WorkloadVersionID,
		AutonomyProfileID: request.AutonomyProfileID,
		Fingerprints: control.Fingerprints{
			Model:                request.Fingerprints.Model,
			Harness:              request.Fingerprints.Harness,
			Tools:                request.Fingerprints.Tools,
			Policy:               request.Fingerprints.Policy,
			Monitor:              request.Fingerprints.Monitor,
			ScenarioDistribution: request.Fingerprints.ScenarioDistribution,
			Environment:          request.Fingerprints.Environment,
		},
		EvidenceCategory:        request.EvidenceCategory,
		ObservationFrom:         request.ObservationWindow.From,
		ObservationTo:           request.ObservationWindow.To,
		CoverageGaps:            request.CoverageGaps,
		SelectionProcedure:      request.SelectionProcedure,
		LabelSource:             request.LabelSource,
		DataSources:             request.DataSources,
		Failures:                request.Failures,
		Eligible:                request.Eligible,
		Unresolved:              request.Unresolved,
		ConfidenceLevel:         request.ConfidenceLevel,
		AcceptanceThreshold:     request.AcceptanceThreshold,
		DependenceModel:         request.DependenceModel,
		ClusterUnit:             request.ClusterUnit,
		ClusterIDRefs:           request.ClusterIDRefs,
		DependenceDescription:   request.DependenceDescription,
		PopulationApplicability: request.PopulationApplicability,
		Exclusions:              request.Exclusions,
		ValidDays:               request.ValidDays,
		InvalidationTriggers:    request.InvalidationTriggers,
		CreatedAt:               request.CreatedAt,
	}
	if request.Funnel != nil {
		input.Funnel = &control.InjectionFunnelInput{
			Selected:         request.Funnel.Selected,
			Eligible:         request.Funnel.Eligible,
			Triggered:        request.Funnel.Triggered,
			Untriggered:      request.Funnel.Untriggered,
			HarnessError:     request.Funnel.HarnessError,
			VerifiedOutcomes: request.Funnel.VerifiedOutcomes,
		}
	}

	claim, err := s.Assurer.Assess(input)
	if err != nil {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "claim_refused",
			err.Error(), false)
		return
	}
	s.Claims.put(principal.TenantID, claim)
	writeJSON(w, http.StatusCreated, claim)
}

// getClaim returns a stored claim (spec 18.2: GET
// /v1/assurance-claims/{id}): scope and the evidence it rests on.
func (s *Server) getClaim(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	principal := principalFrom(r)
	if principal == nil {
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated",
			"caller identity headers are required", false)
		return
	}
	id := r.PathValue("id")
	if !reClaimID.MatchString(id) {
		writeProblem(w, requestID, http.StatusBadRequest, "claim_id_invalid",
			"claim id must match clm_[a-z0-9]{8,64}", false)
		return
	}
	claim := s.Claims.get(principal.TenantID, id)
	if claim == nil {
		writeProblem(w, requestID, http.StatusNotFound, "claim_unknown",
			"no such assurance claim in this tenant", false)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}
