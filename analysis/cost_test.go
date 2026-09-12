package analysis

// Spec 16 / T025: fully loaded cost by workload and control profile,
// every component visible at zero, overhead only against a matched
// baseline, and no blended score.

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

const costWorkload = "wlv_0a1b2c3d4e5f6071"
const costWorkloadB = "wlv_8888c3d4e5f6071"

// costFixture is one matched workload: the same task set under the
// baseline and the full-call profile, with the supervised profile
// paying for review, retries, storage, and monitoring.
func costFixture() []CostEntry {
	entries := []CostEntry{}
	profiles := []struct {
		id     string
		worker int64
		review int64
	}{
		{ProfileHardControls, 10_000_000, 0},
		{ProfileFullCall, 10_000_000, 6_000_000},
	}
	for _, profile := range profiles {
		for _, task := range []string{"task_a", "task_b", "task_c"} {
			entries = append(entries, CostEntry{
				WorkloadVersionID: costWorkload,
				AutonomyProfileID: profile.id,
				TaskID:            task,
				Component:         CostWorker,
				Micros:            profile.worker,
			})
			if profile.review > 0 {
				entries = append(entries, CostEntry{
					WorkloadVersionID: costWorkload,
					AutonomyProfileID: profile.id,
					TaskID:            task,
					Component:         CostReview,
					Micros:            profile.review,
				})
			}
		}
	}
	// Supervision costs beyond review: a retry, storage, monitoring,
	// and a failed experiment, all under the supervised profile.
	extra := []CostEntry{
		{WorkloadVersionID: costWorkload, AutonomyProfileID: ProfileFullCall,
			TaskID: "task_b", Component: CostRetry, Micros: 2_000_000},
		{WorkloadVersionID: costWorkload, AutonomyProfileID: ProfileFullCall,
			Component: CostStorage, Micros: 500_000},
		{WorkloadVersionID: costWorkload, AutonomyProfileID: ProfileFullCall,
			Component: CostMonitoring, Micros: 300_000},
		{WorkloadVersionID: costWorkload, AutonomyProfileID: ProfileFullCall,
			Component: CostExperiment, Micros: 1_200_000},
	}
	return append(entries, extra...)
}

func TestCostsGroupByWorkloadAndProfile(t *testing.T) {
	report, err := AccountCosts(costFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Workloads) != 1 {
		t.Fatalf("workloads: %+v", report.Workloads)
	}
	workload := report.Workloads[0]
	byProfile := map[string]ProfileCost{}
	for _, profile := range workload.Profiles {
		byProfile[profile.Profile] = profile
	}
	baseline, ok := byProfile[ProfileHardControls]
	if !ok || baseline.Tasks != 3 || baseline.Entries != 3 {
		t.Fatalf("baseline: %+v", baseline)
	}
	if baseline.TotalMicros != 30_000_000 {
		t.Fatalf("baseline total: %d", baseline.TotalMicros)
	}
	fullCall := byProfile[ProfileFullCall]
	// Worker 30M + review 18M + retry 2M + storage 0.5M + monitoring
	// 0.3M + experiment 1.2M = 52M.
	if fullCall.TotalMicros != 52_000_000 {
		t.Fatalf("fully loaded total: %d", fullCall.TotalMicros)
	}
	if fullCall.Entries != 3+3+4 {
		t.Fatalf("entry count: %d", fullCall.Entries)
	}
	if report.GrandTotalMicros != 82_000_000 {
		t.Fatalf("grand total: %d", report.GrandTotalMicros)
	}
}

func TestEveryComponentStaysVisibleAtZero(t *testing.T) {
	report, err := AccountCosts(costFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range report.Workloads[0].Profiles {
		if len(profile.Components) != len(CostComponents) {
			t.Fatalf("%s components: %+v", profile.Profile,
				profile.Components)
		}
		byName := map[string]ComponentCost{}
		for _, component := range profile.Components {
			byName[component.Component] = component
		}
		if byName[CostStorage].Micros == 0 && profile.Profile == ProfileHardControls {
			// The baseline stored nothing: a measured zero with a row.
			if byName[CostStorage].Share != 0 {
				t.Fatalf("zero share: %+v", byName[CostStorage])
			}
		}
	}
	// Shares sum to one where the profile cost anything.
	var fullCall ProfileCost
	for _, profile := range report.Workloads[0].Profiles {
		if profile.Profile == ProfileFullCall {
			fullCall = profile
		}
	}
	sum := 0.0
	for _, component := range fullCall.Components {
		sum += component.Share
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Fatalf("shares sum to %f", sum)
	}
}

func TestOverheadIsAbsoluteBeforeItIsARatio(t *testing.T) {
	report, err := AccountCosts(costFixture())
	if err != nil {
		t.Fatal(err)
	}
	overheads := report.Workloads[0].Overheads
	if len(overheads) != 1 || overheads[0].Profile != ProfileFullCall {
		t.Fatalf("overheads: %+v", overheads)
	}
	row := overheads[0]
	if row.BaselineMicros != 30_000_000 || row.ProfileMicros != 52_000_000 {
		t.Fatalf("matched totals: %+v", row)
	}
	if row.ExtraMicros != 22_000_000 {
		t.Fatalf("extra: %d", row.ExtraMicros)
	}
	// 22/30 of the baseline cost, unit attached.
	if math.Abs(row.ExtraShare-22.0/30.0) > 1e-9 || row.Unit != "micros" {
		t.Fatalf("share: %+v", row)
	}
	// The baseline never compares against itself.
	for _, workload := range report.Workloads {
		for _, other := range workload.Overheads {
			if other.Profile == BaselineProfile {
				t.Fatalf("self-overhead: %+v", other)
			}
		}
	}
}

func TestAnUnmatchedBaselineIsNotMeasuredNotZero(t *testing.T) {
	entries := []CostEntry{
		{WorkloadVersionID: costWorkloadB,
			AutonomyProfileID: ProfileContextual,
			Component:         CostWorker, Micros: 1_000},
	}
	report, err := AccountCosts(entries)
	if err != nil {
		t.Fatal(err)
	}
	workload := report.Workloads[0]
	if !workload.BaselineMissing || len(workload.Overheads) != 0 {
		t.Fatalf("unmatched workload: %+v", workload)
	}
	stated := false
	for _, limitation := range report.Limitations {
		if strings.Contains(limitation, "not measured") {
			stated = true
		}
	}
	if !stated {
		t.Fatalf("limitations: %v", report.Limitations)
	}
	// A zero-baseline share is not zero: it is not measured.
	if !math.IsNaN(overheadShare(0, 1_000)) {
		t.Fatal("a zero baseline produced a share")
	}
}

func TestTheLedgerFailsClosed(t *testing.T) {
	bad := costFixture()
	bad[0].Component = "vibes"
	if _, err := AccountCosts(bad); err == nil {
		t.Fatal("an unknown component was accepted")
	}
	negative := costFixture()
	negative[0].Micros = -1
	if _, err := AccountCosts(negative); err == nil {
		t.Fatal("a negative cost was accepted")
	}
	anonymous := costFixture()
	anonymous[0].WorkloadVersionID = ""
	if _, err := AccountCosts(anonymous); err == nil {
		t.Fatal("an anonymous workload was accepted")
	}
}

func TestAnEmptyLedgerSaysSo(t *testing.T) {
	report, err := AccountCosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.GrandTotalMicros != 0 || len(report.Workloads) != 0 {
		t.Fatalf("empty ledger: %+v", report)
	}
	says := false
	for _, limitation := range report.Limitations {
		if strings.Contains(limitation, "no costs recorded") {
			says = true
		}
	}
	if !says {
		t.Fatalf("empty ledger limitations: %v", report.Limitations)
	}
}

func TestCostsMarshalWithComponentsAndOverheads(t *testing.T) {
	report, err := AccountCosts(costFixture())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"baseline", "workloads",
		"grand_total_micros", "limitations"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("missing %s in %s", key, encoded)
		}
	}
	workloads, _ := document["workloads"].([]any)
	row, _ := workloads[0].(map[string]any)
	profiles, _ := row["profiles"].([]any)
	profile, _ := profiles[1].(map[string]any)
	components, _ := profile["components"].([]any)
	if len(components) != len(CostComponents) {
		t.Fatalf("components did not marshal: %s", encoded)
	}
	if _, ok := row["overheads"]; !ok {
		t.Fatalf("overheads did not marshal: %s", encoded)
	}
}
