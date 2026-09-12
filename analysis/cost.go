package analysis

// Cost and resource accounting (spec 16 / T025): fully loaded cost per
// workload version and control profile, split by the components the
// supervision-overhead metric must include — retries, failed
// experiments, storage, and review, alongside the worker's own cost.
// The ledger keeps every component visible even at zero and computes
// overhead only against a matched baseline profile: an unmatched
// workload reports its costs honestly and its overhead as not
// measured, never as zero.

import (
	"fmt"
	"math"
	"sort"
)

// Cost components. The set is closed: an entry with a component
// outside it refuses, because a cost the report cannot name is a cost
// it will silently drop.
const (
	CostWorker     = "worker"
	CostRetry      = "retry"
	CostMonitoring = "monitoring"
	CostStorage    = "storage"
	CostReview     = "review"
	CostExperiment = "experiment"
)

// CostComponents is the component set in report order.
var CostComponents = []string{
	CostWorker, CostRetry, CostMonitoring, CostStorage, CostReview,
	CostExperiment,
}

var knownCostComponents = map[string]bool{
	CostWorker: true, CostRetry: true, CostMonitoring: true,
	CostStorage: true, CostReview: true, CostExperiment: true,
}

// CostEntry is one measured cost in micro-currency units.
type CostEntry struct {
	WorkloadVersionID string `json:"workload_version_id"`
	// AutonomyProfileID is the control profile the workload ran under;
	// empty means the unprofiled baseline context.
	AutonomyProfileID string `json:"autonomy_profile_id"`
	TaskID            string `json:"task_id,omitempty"`
	Component         string `json:"component"`
	Micros            int64  `json:"micros"`
	Note              string `json:"note,omitempty"`
}

// ComponentCost is one component's total with its share of the
// profile's cost. A zero component keeps its row: absence of a cost is
// a measured zero, not an omission.
type ComponentCost struct {
	Component string  `json:"component"`
	Micros    int64   `json:"micros"`
	Share     float64 `json:"share"`
}

// ProfileCost is one control profile's fully loaded cost over one
// workload version.
type ProfileCost struct {
	Profile          string          `json:"profile"`
	Components       []ComponentCost `json:"components"`
	TotalMicros      int64           `json:"total_micros"`
	Tasks            int             `json:"tasks"`
	Entries          int             `json:"entries"`
	AvgPerTaskMicros float64         `json:"avg_per_task_micros"`
}

// OverheadRow is the spec 16 supervision-overhead metric for one
// profile against the matched baseline: the additional cost, never a
// ratio alone, so a 40% overhead of a small number cannot masquerade
// as a large one.
type OverheadRow struct {
	Profile        string  `json:"profile"`
	BaselineMicros int64   `json:"baseline_micros"`
	ProfileMicros  int64   `json:"profile_micros"`
	ExtraMicros    int64   `json:"extra_micros"`
	ExtraShare     float64 `json:"extra_share"`
	Unit           string  `json:"unit"`
}

// WorkloadCost is one workload version's costs across profiles.
type WorkloadCost struct {
	WorkloadVersionID string        `json:"workload_version_id"`
	Baseline          string        `json:"baseline"`
	Profiles          []ProfileCost `json:"profiles"`
	Overheads         []OverheadRow `json:"overheads"`
	// BaselineMissing marks a workload without baseline-profile
	// entries: its overhead is not measured, and the report says so.
	BaselineMissing bool `json:"baseline_missing,omitempty"`
}

// CostReport is the accounting output.
type CostReport struct {
	Kind             string         `json:"kind"`
	APIVersion       string         `json:"api_version"`
	Baseline         string         `json:"baseline"`
	Workloads        []WorkloadCost `json:"workloads"`
	GrandTotalMicros int64          `json:"grand_total_micros"`
	Limitations      []string       `json:"limitations"`
}

// AccountCosts aggregates entries into a report. Entries are additive
// facts; the ledger validates each one and refuses a component it
// cannot name or a negative amount.
func AccountCosts(entries []CostEntry) (*CostReport, error) {
	for i := range entries {
		entry := &entries[i]
		if entry.WorkloadVersionID == "" {
			return nil, fmt.Errorf("entry %d has no workload version id", i)
		}
		if !knownCostComponents[entry.Component] {
			return nil, fmt.Errorf("entry %d has unknown component %q",
				i, entry.Component)
		}
		if entry.Micros < 0 {
			return nil, fmt.Errorf("entry %d has a negative cost", i)
		}
	}

	report := &CostReport{
		Kind: "CostReport", APIVersion: "v1", Baseline: BaselineProfile,
	}
	// workload -> profile -> component -> micros, plus unit counts.
	type profileTotals struct {
		components map[string]int64
		tasks      map[string]bool
		entries    int
	}
	workloads := map[string]map[string]*profileTotals{}
	for i := range entries {
		entry := &entries[i]
		if workloads[entry.WorkloadVersionID] == nil {
			workloads[entry.WorkloadVersionID] =
				map[string]*profileTotals{}
		}
		profile := entry.AutonomyProfileID
		if profile == "" {
			profile = BaselineProfile
		}
		totals, seen := workloads[entry.WorkloadVersionID][profile]
		if !seen {
			totals = &profileTotals{
				components: map[string]int64{},
				tasks:      map[string]bool{},
			}
			workloads[entry.WorkloadVersionID][profile] = totals
		}
		totals.components[entry.Component] += entry.Micros
		totals.entries++
		if entry.TaskID != "" {
			totals.tasks[entry.TaskID] = true
		}
		report.GrandTotalMicros += entry.Micros
	}

	for _, workloadID := range sortedStringKeys(workloads) {
		profiles := workloads[workloadID]
		row := WorkloadCost{
			WorkloadVersionID: workloadID, Baseline: BaselineProfile,
		}
		_, hasBaseline := profiles[BaselineProfile]
		row.BaselineMissing = !hasBaseline

		profileIDs := sortedStringKeys(profiles)
		for _, profileID := range profileIDs {
			totals := profiles[profileID]
			profileCost := ProfileCost{
				Profile: profileID, Tasks: len(totals.tasks),
				Entries: totals.entries,
			}
			for _, component := range CostComponents {
				profileCost.Components = append(profileCost.Components,
					ComponentCost{
						Component: component,
						Micros:    totals.components[component],
					})
				profileCost.TotalMicros += totals.components[component]
			}
			for i := range profileCost.Components {
				if profileCost.TotalMicros > 0 {
					profileCost.Components[i].Share =
						float64(profileCost.Components[i].Micros) /
							float64(profileCost.TotalMicros)
				}
			}
			if profileCost.Tasks > 0 {
				profileCost.AvgPerTaskMicros = float64(
					profileCost.TotalMicros) / float64(profileCost.Tasks)
			}
			row.Profiles = append(row.Profiles, profileCost)

			if hasBaseline && profileID != BaselineProfile {
				baseline := profiles[BaselineProfile]
				baselineTotal := int64(0)
				for _, value := range baseline.components {
					baselineTotal += value
				}
				row.Overheads = append(row.Overheads, OverheadRow{
					Profile:        profileID,
					BaselineMicros: baselineTotal,
					ProfileMicros:  profileCost.TotalMicros,
					ExtraMicros:    profileCost.TotalMicros - baselineTotal,
					ExtraShare: overheadShare(baselineTotal,
						profileCost.TotalMicros),
					Unit: "micros",
				})
			}
		}
		report.Workloads = append(report.Workloads, row)
	}
	report.Limitations = costLimitations(report)
	return report, nil
}

// overheadShare is the overhead ratio; an unmatched or zero baseline
// reads as not measured, never as a free profile.
func overheadShare(baseline, profile int64) float64 {
	if baseline <= 0 {
		return math.NaN()
	}
	return float64(profile-baseline) / float64(baseline)
}

// costLimitations states what the accounting does not claim.
func costLimitations(report *CostReport) []string {
	out := []string{
		"costs are measured micro-units by component; no single " +
			"score blends them with utility or safety",
		"overhead is additional cost against the matched " +
			BaselineProfile + " baseline only",
	}
	for _, workload := range report.Workloads {
		if workload.BaselineMissing {
			out = append(out, fmt.Sprintf(
				"workload %s has no %s entries; its supervision overhead is not measured",
				workload.WorkloadVersionID, BaselineProfile))
		}
	}
	if report.GrandTotalMicros == 0 {
		out = append(out, "no costs recorded; zero totals mean no "+
			"entries, not free operation")
	}
	return out
}

func sortedStringKeys[V any](mapping map[string]V) []string {
	out := make([]string, 0, len(mapping))
	for key := range mapping {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
