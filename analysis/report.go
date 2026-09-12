package analysis

// Portable report export (spec 17.5, AC-025, T030): one document a
// pipeline can gate on, readable by humans and machines. The export
// carries the synthetic/production distinction in its title and
// metadata, names its artifacts by digest, references the evidence it
// rests on, and states a gate status that never infers a pass from
// absence.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Environment distinctions. Every report states which one it ran
// under; there is no default.
const (
	EnvironmentSynthetic  = "synthetic"
	EnvironmentProduction = "production"
)

// Gate statuses for the report and its runs. "passed" speaks only
// about the explicit gate, never about universal safety.
const (
	GatePassed       = "passed"
	GateFailed       = "failed"
	GateInconclusive = "inconclusive"
)

// ReportKind and reportAPIVersion identify the document.
const (
	ReportKind       = "PortableReport"
	ReportAPIVersion = "v1"
)

var (
	reDigest   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reClaimID  = regexp.MustCompile(`^clm_[0-9a-f]{16}$`)
	reHex16    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reAnyStamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`)
)

// ReportArtifact names one attached artifact by content digest.
type ReportArtifact struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Bytes       int64  `json:"bytes"`
	ContentType string `json:"content_type,omitempty"`
}

// ReportEvidence references the evidence plane records behind the
// report: the chain head, the event count, and the assurance claims.
type ReportEvidence struct {
	ChainHead string   `json:"chain_head,omitempty"`
	Events    int      `json:"events"`
	Claims    []string `json:"claims,omitempty"`
}

// ReportOutcomes aggregates the harness classification over every
// task in the cohort (spec 12).
type ReportOutcomes struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Unknown int `json:"unknown"`
}

// RunGateInput is one run's governor state as recorded.
type RunGateInput struct {
	RunID    string
	State    string
	Terminal string
}

// ReportRunGate is the derived gate for one run.
type ReportRunGate struct {
	RunID         string `json:"run_id"`
	State         string `json:"state"`
	TerminalState string `json:"terminal_state,omitempty"`
	Gate          string `json:"gate"`
	Note          string `json:"note"`
}

// ReportSubject names what was evaluated: the workload version, the
// autonomy profiles, the experiment, and the runs.
type ReportSubject struct {
	WorkloadVersionID string          `json:"workload_version_id"`
	AutonomyProfiles  []string        `json:"autonomy_profiles,omitempty"`
	ExperimentID      string          `json:"experiment_id,omitempty"`
	Runs              []ReportRunGate `json:"runs"`
}

// ReportGate is the roll-up gate over every run.
type ReportGate struct {
	Status string `json:"status"`
	Basis  string `json:"basis"`
}

// PortableReport is the export document.
type PortableReport struct {
	Kind        string           `json:"kind"`
	APIVersion  string           `json:"api_version"`
	Title       string           `json:"title"`
	Environment string           `json:"environment"`
	TenantID    string           `json:"tenant_id"`
	GeneratedAt string           `json:"generated_at"`
	Subject     ReportSubject    `json:"subject"`
	Gate        ReportGate       `json:"gate"`
	Outcomes    ReportOutcomes   `json:"outcomes"`
	Artifacts   []ReportArtifact `json:"artifacts"`
	Evidence    ReportEvidence   `json:"evidence"`
	Comparison  *Comparison      `json:"comparison,omitempty"`
	Cost        *CostReport      `json:"cost,omitempty"`
	Limitations []string         `json:"limitations"`
}

// ReportInput is everything the exporter needs. The caller assembles
// it from the planes; the exporter validates and never invents.
type ReportInput struct {
	Environment       string
	TenantID          string
	GeneratedAt       string
	WorkloadVersionID string
	AutonomyProfiles  []string
	ExperimentID      string
	Runs              []RunGateInput
	Outcomes          ReportOutcomes
	Artifacts         []ReportArtifact
	Evidence          ReportEvidence
	Comparison        *Comparison
	Cost              *CostReport
}

// ExportReport validates the input and assembles the portable
// document. Anything ambiguous fails closed: an unknown environment,
// a nameless artifact, a digest that is not a digest, or a report
// about zero runs all refuse rather than export half a story.
func ExportReport(input ReportInput) (*PortableReport, error) {
	if input.Environment != EnvironmentSynthetic &&
		input.Environment != EnvironmentProduction {
		return nil, fmt.Errorf(
			"environment must be %q or %q, not %q",
			EnvironmentSynthetic, EnvironmentProduction, input.Environment)
	}
	if !reHex16.MatchString(hexTail(input.WorkloadVersionID, "wlv_")) {
		return nil, fmt.Errorf("workload version id %q is not wlv_ plus 16 hex",
			input.WorkloadVersionID)
	}
	if input.GeneratedAt == "" || !reAnyStamp.MatchString(input.GeneratedAt) {
		return nil, fmt.Errorf("generated_at is required")
	}
	if _, err := time.Parse(time.RFC3339, input.GeneratedAt); err != nil {
		return nil, fmt.Errorf("generated_at %q is not RFC3339: %v",
			input.GeneratedAt, err)
	}
	if len(input.Runs) == 0 {
		return nil, fmt.Errorf("a report needs at least one run gate")
	}

	seenArtifacts := map[string]bool{}
	artifacts := make([]ReportArtifact, len(input.Artifacts))
	for i, artifact := range input.Artifacts {
		if artifact.Name == "" {
			return nil, fmt.Errorf("artifact %d has no name", i)
		}
		if seenArtifacts[artifact.Name] {
			return nil, fmt.Errorf("artifact %q listed twice", artifact.Name)
		}
		seenArtifacts[artifact.Name] = true
		if !reDigest.MatchString(artifact.Digest) {
			return nil, fmt.Errorf("artifact %q digest %q is not sha256",
				artifact.Name, artifact.Digest)
		}
		if artifact.Bytes < 0 {
			return nil, fmt.Errorf("artifact %q has negative size", artifact.Name)
		}
		artifacts[i] = artifact
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Name < artifacts[j].Name
	})

	claims := append([]string{}, input.Evidence.Claims...)
	for _, claim := range claims {
		if !reClaimID.MatchString(claim) {
			return nil, fmt.Errorf("claim reference %q is not clm_ plus 16 hex",
				claim)
		}
	}
	sort.Strings(claims)
	if input.Evidence.ChainHead != "" &&
		!reDigest.MatchString(input.Evidence.ChainHead) {
		return nil, fmt.Errorf("chain head %q is not a sha256 digest",
			input.Evidence.ChainHead)
	}

	profiles := sortedUnique(input.AutonomyProfiles)
	runs := make([]ReportRunGate, len(input.Runs))
	for i, run := range input.Runs {
		if run.RunID == "" {
			return nil, fmt.Errorf("run %d has no id", i)
		}
		gate, note := runGate(run)
		runs[i] = ReportRunGate{
			RunID: run.RunID, State: run.State, TerminalState: run.Terminal,
			Gate: gate, Note: note,
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].RunID < runs[j].RunID })

	report := &PortableReport{
		Kind:        ReportKind,
		APIVersion:  ReportAPIVersion,
		Title:       reportTitle(input.Environment, input.WorkloadVersionID),
		Environment: input.Environment,
		TenantID:    input.TenantID,
		GeneratedAt: input.GeneratedAt,
		Subject: ReportSubject{
			WorkloadVersionID: input.WorkloadVersionID,
			AutonomyProfiles:  profiles,
			ExperimentID:      input.ExperimentID,
			Runs:              runs,
		},
		Gate:      rollUpGate(runs),
		Outcomes:  input.Outcomes,
		Artifacts: artifacts,
		Evidence: ReportEvidence{
			ChainHead: input.Evidence.ChainHead,
			Events:    input.Evidence.Events,
			Claims:    claims,
		},
		Comparison:  input.Comparison,
		Cost:        input.Cost,
		Limitations: reportLimitations(input),
	}
	return report, nil
}

// RenderJSON renders the machine-readable export, indented for
// storage and diffing.
func RenderJSON(report *PortableReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// RenderText renders the readable export. Hostile content never
// executes here: every value prints as inert text.
func RenderText(report *PortableReport) string {
	text := &strings.Builder{}
	fmt.Fprintf(text, "%s\n", report.Title)
	fmt.Fprintf(text, "environment %s, generated %s, tenant %s\n",
		report.Environment, report.GeneratedAt, report.TenantID)
	fmt.Fprintf(text, "workload %s, profiles %s\n",
		report.Subject.WorkloadVersionID,
		strings.Join(report.Subject.AutonomyProfiles, ", "))
	if report.Subject.ExperimentID != "" {
		fmt.Fprintf(text, "experiment %s\n", report.Subject.ExperimentID)
	}
	fmt.Fprintf(text, "gate %s: %s\n", report.Gate.Status, report.Gate.Basis)
	for _, run := range report.Subject.Runs {
		fmt.Fprintf(text, "  run %s: state %s, terminal %s — %s (%s)\n",
			run.RunID, run.State, run.TerminalState, run.Gate, run.Note)
	}
	fmt.Fprintf(text, "outcomes %d passed, %d failed, %d unknown\n",
		report.Outcomes.Passed, report.Outcomes.Failed, report.Outcomes.Unknown)
	fmt.Fprintf(text, "evidence %d events, chain head %s, claims %s\n",
		report.Evidence.Events, report.Evidence.ChainHead,
		strings.Join(report.Evidence.Claims, ", "))
	if len(report.Artifacts) == 0 {
		fmt.Fprintln(text, "artifacts none")
	}
	for _, artifact := range report.Artifacts {
		fmt.Fprintf(text, "artifact %s %s (%d bytes)\n", artifact.Name,
			artifact.Digest, artifact.Bytes)
	}
	for _, limitation := range report.Limitations {
		fmt.Fprintf(text, "limitation %s\n", limitation)
	}
	return text.String()
}

// runGate derives one run's gate from the recorded governor state.
// A pass is never inferred from absence: only a stopped run with a
// recorded CLEAN terminal state passes.
func runGate(run RunGateInput) (gate, note string) {
	switch {
	case run.State == "stopped" && run.Terminal == "CLEAN":
		return GatePassed, "stopped clean"
	case run.State == "fenced":
		return GateFailed, "fenced by the governor"
	case run.Terminal == "DIRTY_QUARANTINED":
		return GateFailed, "terminal state dirty and quarantined"
	case run.Terminal == "UNKNOWN":
		return GateInconclusive, "terminal state unknown"
	case run.State == "stopped":
		return GateInconclusive, "stopped without a terminal state"
	default:
		return GateInconclusive, "still active: the gate is not evaluated"
	}
}

// rollUpGate folds the run gates into one report gate: any failure
// fails the report, and anything not decided leaves it inconclusive.
func rollUpGate(runs []ReportRunGate) ReportGate {
	failed, passed := 0, 0
	for _, run := range runs {
		switch run.Gate {
		case GateFailed:
			failed++
		case GatePassed:
			passed++
		}
	}
	switch {
	case failed > 0:
		return ReportGate{GateFailed,
			fmt.Sprintf("%d of %d runs failed their gate", failed, len(runs))}
	case passed == len(runs):
		return ReportGate{GatePassed,
			fmt.Sprintf("all %d runs stopped clean", len(runs))}
	default:
		return ReportGate{GateInconclusive,
			fmt.Sprintf("%d of %d runs are not decided", len(runs)-passed,
				len(runs))}
	}
}

// reportTitle states the environment distinction in the title itself
// (spec 17.5).
func reportTitle(environment, workload string) string {
	return fmt.Sprintf("AgentChaos report — %s evaluation of %s",
		environment, workload)
}

// reportLimitations collects the honesty notes of every embedded
// analysis, plus the report's own.
func reportLimitations(input ReportInput) []string {
	limitations := []string{
		"a passed gate speaks to the declared scope only, never to universal safety",
	}
	if input.Comparison != nil {
		limitations = append(limitations, input.Comparison.Limitations...)
	}
	if input.Cost != nil {
		limitations = append(limitations, input.Cost.Limitations...)
	}
	return limitations
}

// sortedUnique returns the sorted distinct values.
func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

// hexTail returns the part after the prefix, or a non-match so the
// pattern check fails.
func hexTail(value, prefix string) string {
	if len(value) > len(prefix) && value[:len(prefix)] == prefix {
		return value[len(prefix):]
	}
	return "\x00"
}

// DigestBytes is the canonical artifact digest helper for callers.
func DigestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
