package analysis

import (
	"fmt"
	"math/rand"
	"testing"
)

// Property tests for cost accounting (T040): aggregation is a pure
// function of the entry multiset, so no ordering of one set of facts
// may change a total, and every total is the plain sum of its parts.

// totalsByWorkload flattens a report into workload -> profile ->
// micros, the order-independent view of the ledger.
func totalsByWorkload(t *testing.T, report *CostReport) map[string]map[string]int64 {
	t.Helper()
	totals := map[string]map[string]int64{}
	for _, workload := range report.Workloads {
		totals[workload.WorkloadVersionID] = map[string]int64{}
		for _, profile := range workload.Profiles {
			totals[workload.WorkloadVersionID][profile.Profile] =
				profile.TotalMicros
		}
	}
	return totals
}

func sameTotals(a, b map[string]map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for workload, profiles := range a {
		other, ok := b[workload]
		if !ok || len(profiles) != len(other) {
			return false
		}
		for profile, micros := range profiles {
			if other[profile] != micros {
				return false
			}
		}
	}
	return true
}

func TestPropertyCostsAreInvariantUnderReordering(t *testing.T) {
	rng := rand.New(rand.NewSource(20260915))
	for trial := 0; trial < 100; trial++ {
		workloadCount := 1 + rng.Intn(3)
		var entries []CostEntry
		for w := 0; w < workloadCount; w++ {
			workload := fmt.Sprintf("wl_v%d_%d", trial, w)
			profileCount := 1 + rng.Intn(3)
			for p := 0; p < profileCount; p++ {
				profile := []string{BaselineProfile, "profile-supervised",
					"profile-supervised-tight"}[rng.Intn(3)]
				entryCount := 1 + rng.Intn(5)
				for e := 0; e < entryCount; e++ {
					entries = append(entries, CostEntry{
						WorkloadVersionID: workload,
						AutonomyProfileID: profile,
						TaskID: fmt.Sprintf("tsk_%06d",
							rng.Intn(1000)),
						Component: CostComponents[rng.Intn(len(CostComponents))],
						Micros:    int64(rng.Intn(100000)),
					})
				}
			}
		}

		ordered, err := AccountCosts(entries)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		shuffled := make([]CostEntry, len(entries))
		copy(shuffled, entries)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		reordered, err := AccountCosts(shuffled)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}

		if ordered.GrandTotalMicros != reordered.GrandTotalMicros {
			t.Fatalf("trial %d: grand total moved under reordering: %d vs %d",
				trial, ordered.GrandTotalMicros, reordered.GrandTotalMicros)
		}
		if !sameTotals(totalsByWorkload(t, ordered),
			totalsByWorkload(t, reordered)) {
			t.Fatalf("trial %d: a workload total moved under reordering",
				trial)
		}
	}
}

func TestPropertyTotalsAreAdditive(t *testing.T) {
	rng := rand.New(rand.NewSource(20260916))
	for trial := 0; trial < 100; trial++ {
		var entries []CostEntry
		sum := int64(0)
		for e := 0; e < 1+rng.Intn(20); e++ {
			micros := int64(rng.Intn(50000))
			sum += micros
			entries = append(entries, CostEntry{
				WorkloadVersionID: fmt.Sprintf("wl_add%d_%d", trial,
					rng.Intn(3)),
				AutonomyProfileID: BaselineProfile,
				Component:         CostComponents[rng.Intn(len(CostComponents))],
				Micros:            micros,
			})
		}
		report, err := AccountCosts(entries)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if report.GrandTotalMicros != sum {
			t.Fatalf("trial %d: grand total %d, entries sum %d", trial,
				report.GrandTotalMicros, sum)
		}
		// The workload rows partition the same sum: no entry is
		// counted twice and none is dropped.
		rows := int64(0)
		for _, totals := range totalsByWorkload(t, report) {
			for _, micros := range totals {
				rows += micros
			}
		}
		if rows != sum {
			t.Fatalf("trial %d: workload rows sum %d, entries sum %d",
				trial, rows, sum)
		}
	}
}

func TestPropertyTheLedgerRefusesWhatItCannotName(t *testing.T) {
	rng := rand.New(rand.NewSource(20260917))
	for trial := 0; trial < 100; trial++ {
		base := CostEntry{
			WorkloadVersionID: "wl_refuse0001",
			AutonomyProfileID: BaselineProfile,
			Component:         CostWorker,
			Micros:            int64(rng.Intn(10000)) + 1,
		}
		broken := base
		switch rng.Intn(3) {
		case 0:
			broken.Micros = -int64(rng.Intn(10000)) - 1
		case 1:
			broken.Component = fmt.Sprintf("component-%d", rng.Intn(100))
		case 2:
			broken.WorkloadVersionID = ""
		}
		// The bad entry hides at a random position among good ones.
		entries := []CostEntry{base, broken, base}
		rng.Shuffle(len(entries), func(i, j int) {
			entries[i], entries[j] = entries[j], entries[i]
		})
		if report, err := AccountCosts(entries); err == nil {
			t.Fatalf("trial %d: the ledger accepted a broken entry: %+v",
				trial, report)
		}
	}
}
