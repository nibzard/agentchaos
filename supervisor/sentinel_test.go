package supervisor

// Spec 15.1 / T024: a nonzero uniform random deep-review sample over
// clean traffic; risk-routed review is additional; inclusion
// probabilities are logged and the randomization key stays outside
// worker access.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

var sentinelKey = []byte("sentinel-key-material-0123456789abcdef")

func sampler(t *testing.T, rate float64) *SentinelSampler {
	t.Helper()
	sampler, err := NewSentinelSampler(sentinelKey, SentinelConfig{
		Rate: rate, SampleBy: SampleByUnit, Epoch: "2026-W37",
	})
	if err != nil {
		t.Fatal(err)
	}
	return sampler
}

// cleanUnits builds n clean, un-risk-routed units.
func cleanUnits(n int) []ReviewUnit {
	units := make([]ReviewUnit, 0, n)
	for i := 0; i < n; i++ {
		units = append(units, ReviewUnit{ID: fmt.Sprintf("run_unit-%04d", i)})
	}
	return units
}

func TestTheDrawIsDeterministicAndOrderIndependent(t *testing.T) {
	sampler := sampler(t, 0.25)
	first, firstSummary := sampler.Assign(cleanUnits(50))
	second, secondSummary := sampler.Assign(cleanUnits(50))
	if firstSummary.Sentinels != secondSummary.Sentinels {
		t.Fatalf("nondeterministic draw: %d vs %d",
			firstSummary.Sentinels, secondSummary.Sentinels)
	}
	for i := range first {
		if first[i].DeepReview != second[i].DeepReview {
			t.Fatalf("unit %s changed outcome", first[i].UnitID)
		}
	}
	// Reverse the batch: a unit's outcome cannot depend on arrival
	// order, or batching would change who gets reviewed.
	reversed := cleanUnits(50)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	reordered, _ := sampler.Assign(reversed)
	byID := map[string]bool{}
	for _, selection := range reordered {
		byID[selection.UnitID] = selection.DeepReview
	}
	for _, selection := range first {
		if byID[selection.UnitID] != selection.DeepReview {
			t.Fatalf("batching changed %s", selection.UnitID)
		}
	}
}

func TestEveryUnitCarriesItsInclusionProbability(t *testing.T) {
	selections, summary := sampler(t, 0.1).Assign(cleanUnits(40))
	if len(selections) != 40 {
		t.Fatalf("selection records: %d", len(selections))
	}
	sentinels := 0
	for _, selection := range selections {
		if selection.KeyID == "" || selection.Epoch == "" {
			t.Fatalf("unattributable record: %+v", selection)
		}
		if selection.DeepReview {
			sentinels++
			if selection.Method != MethodSentinel ||
				selection.InclusionProbability != 0.1 {
				t.Fatalf("sentinel record: %+v", selection)
			}
		} else if selection.Method != MethodNone ||
			selection.InclusionProbability != 0.1 {
			// Excluded units carry the same probability: exclusion is
			// a recorded outcome, not an absence.
			t.Fatalf("excluded record: %+v", selection)
		}
	}
	if summary.Sentinels != sentinels || summary.CleanConsidered != 40 {
		t.Fatalf("summary: %+v", summary)
	}
}

func TestTheRateHoldsInAggregate(t *testing.T) {
	selections, _ := sampler(t, 0.5).Assign(cleanUnits(1000))
	sentinels := 0
	for _, selection := range selections {
		if selection.DeepReview {
			sentinels++
		}
	}
	// Deterministic draw; five standard deviations of a fair coin over
	// 1000 draws is about 79 either way.
	if sentinels < 420 || sentinels > 580 {
		t.Fatalf("rate 0.5 drew %d of 1000", sentinels)
	}
}

func TestRiskRoutingIsAdditionalNotASubstitute(t *testing.T) {
	units := cleanUnits(40)
	// Half the traffic is risk routed; the uniform draw must still run
	// over the clean half at the same rate.
	for i := 0; i < 20; i++ {
		units[i].RiskRouted = true
	}
	selections, summary := sampler(t, 0.5).Assign(units)
	if summary.RiskRouted != 20 || summary.CleanConsidered != 20 {
		t.Fatalf("denominators: %+v", summary)
	}
	cleanSentinels := 0
	for _, selection := range selections {
		if selection.Method == MethodRiskRouted {
			if !selection.DeepReview || selection.InclusionProbability != 1 {
				t.Fatalf("risk routing is not certain: %+v", selection)
			}
			continue
		}
		if selection.DeepReview {
			cleanSentinels++
		}
	}
	// The clean-half draw matches what the same units draw alone.
	alone, aloneSummary := sampler(t, 0.5).Assign(cleanUnits(40)[20:])
	if cleanSentinels != aloneSummary.Sentinels {
		t.Fatalf("risk routing shrank the uniform sample: %d vs %d",
			cleanSentinels, aloneSummary.Sentinels)
	}
	if len(alone) != 20 {
		t.Fatalf("alone draw size: %d", len(alone))
	}
}

func TestClusterSamplingDrawsWholeClusters(t *testing.T) {
	sampler, err := NewSentinelSampler(sentinelKey, SentinelConfig{
		Rate: 0.5, SampleBy: SampleByCluster, Epoch: "2026-W37",
	})
	if err != nil {
		t.Fatal(err)
	}
	units := make([]ReviewUnit, 0, 80)
	for cluster := 0; cluster < 20; cluster++ {
		for member := 0; member < 4; member++ {
			units = append(units, ReviewUnit{
				ID:        fmt.Sprintf("run_clu-%02d-%02d", cluster, member),
				ClusterID: fmt.Sprintf("cid_clu-%02d", cluster),
			})
		}
	}
	selections, summary := sampler.Assign(units)
	if summary.SampleBy != SampleByCluster {
		t.Fatalf("design: %+v", summary)
	}
	byCluster := map[string]int{}
	clusterSentinels := map[string]bool{}
	for _, selection := range selections {
		if selection.DeepReview {
			byCluster[selection.ClusterID]++
			clusterSentinels[selection.ClusterID] = true
		}
		// Per-unit inclusion probability is the cluster rate: units of
		// one cluster rise and fall together.
		if selection.InclusionProbability != 0.5 {
			t.Fatalf("cluster inclusion probability: %+v", selection)
		}
	}
	if len(clusterSentinels) == 0 || len(clusterSentinels) == 20 {
		t.Fatalf("implausible cluster draw: %d of 20", len(clusterSentinels))
	}
	for _, count := range byCluster {
		if count != 4 {
			t.Fatal("a cluster was sampled partially")
		}
	}
}

func TestAZeroSentinelBatchReportsItself(t *testing.T) {
	// A 1% rate over 10 clean units often draws nobody. The record
	// must say so in the open, not by silence.
	units := cleanUnits(10)
	for start := 0; start < 200; start++ {
		batch := make([]ReviewUnit, 0, len(units))
		for i, unit := range units {
			batch = append(batch, ReviewUnit{ID: unit.ID})
			batch[i].ID = fmt.Sprintf("run_zero-%03d-%02d", start, i)
		}
		selections, summary := sampler(t, DefaultSentinelRate).Assign(batch)
		if summary.Sentinels == 0 {
			encoded, err := json.Marshal(summary)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(encoded), "\"sentinels\":0") {
				t.Fatalf("a zero draw hid itself: %s", encoded)
			}
			excluded := 0
			for _, selection := range selections {
				if !selection.DeepReview && selection.Method == MethodNone {
					excluded++
				}
			}
			if excluded != 10 {
				t.Fatalf("exclusions not recorded: %+v", selections)
			}
			return
		}
	}
	t.Fatal("200 batches at a 1% rate never drew zero; the fixture is blind")
}

func TestConfigurationFailsClosed(t *testing.T) {
	if _, err := NewSentinelSampler(
		[]byte("short"), SentinelConfig{Rate: 0.1}); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := NewSentinelSampler(
		sentinelKey, SentinelConfig{Rate: 0}); err == nil {
		t.Fatal("a zero rate was accepted: the sample must be nonzero")
	}
	if _, err := NewSentinelSampler(
		sentinelKey, SentinelConfig{Rate: 1.5}); err == nil {
		t.Fatal("an impossible rate was accepted")
	}
	if _, err := NewSentinelSampler(
		sentinelKey, SentinelConfig{Rate: 0.1, SampleBy: "vibes"}); err == nil {
		t.Fatal("an unknown sampling unit was accepted")
	}
	// One is a census, not a sample, and is legal.
	if _, err := NewSentinelSampler(
		sentinelKey, SentinelConfig{Rate: 1}); err != nil {
		t.Fatalf("a census refused: %v", err)
	}
}

func TestTheKeyNeverAppearsInRecords(t *testing.T) {
	sampler := sampler(t, 0.5)
	selections, _ := sampler.Assign(cleanUnits(20))
	for _, selection := range selections {
		encoded, err := json.Marshal(selection)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded),
			"sentinel-key-material") {
			t.Fatalf("key material leaked: %s", encoded)
		}
		if !strings.HasPrefix(selection.KeyID, "smkey_") {
			t.Fatalf("key id: %s", selection.KeyID)
		}
	}
	// A different key draws differently: the key is the randomness.
	other, err := NewSentinelSampler(
		[]byte("another-key-material-9876543210fedcba"),
		SentinelConfig{Rate: 0.5, Epoch: "2026-W37"})
	if err != nil {
		t.Fatal(err)
	}
	different := 0
	otherSelections, _ := other.Assign(cleanUnits(20))
	for i := range otherSelections {
		if otherSelections[i].DeepReview != selections[i].DeepReview {
			different++
		}
	}
	if different == 0 || other.KeyID() == sampler.KeyID() {
		t.Fatal("two keys drew identically")
	}
}

func TestTheEpochRotatesTheDraw(t *testing.T) {
	thisEpoch, err := NewSentinelSampler(sentinelKey, SentinelConfig{
		Rate: 0.5, Epoch: "2026-W37"})
	if err != nil {
		t.Fatal(err)
	}
	nextEpoch, err := NewSentinelSampler(sentinelKey, SentinelConfig{
		Rate: 0.5, Epoch: "2026-W38"})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := thisEpoch.Assign(cleanUnits(40))
	second, _ := nextEpoch.Assign(cleanUnits(40))
	changes := 0
	for i := range first {
		if first[i].DeepReview != second[i].DeepReview {
			changes++
		}
	}
	if changes == 0 {
		t.Fatal("the epoch never rotated the draw")
	}
}
