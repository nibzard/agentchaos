package governor

import (
	"fmt"
	"testing"
	"time"
)

// Benchmark for the fencing acknowledgment target (T043, spec 21):
// p99 <= 2 seconds from the local trip signal until the enrolled runs
// are fenced and the fenced state is observable. Each iteration
// builds a tenant with two live runs (setup excluded from timing),
// trips the emergency stop, and reads the run state back inside the
// timed window — acknowledgment means observable, not merely begun.

func BenchmarkEmergencyStopAcknowledgment(b *testing.B) {
	samples := make([]time.Duration, 0, 512)
	now := time.Now()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		g := New(func() time.Time { return now })
		envelope := testEnvelope()
		envelope.ExperimentID = fmt.Sprintf("exp_fencebench%03d", i)
		if _, err := g.RegisterEnvelope(servicePrincipal(),
			envelope); err != nil {
			b.Fatal(err)
		}
		runIDs := []string{
			fmt.Sprintf("run_fencebench%04da", i),
			fmt.Sprintf("run_fencebench%04db", i),
		}
		for _, runID := range runIDs {
			if _, err := g.StartRun(servicePrincipal(), runID,
				envelope.ExperimentID); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()

		start := time.Now()
		fenced, err := g.EmergencyStop(customerPrincipal(),
			&EmergencyStopScope{Kind: "tenant", Reason: "bench trip"})
		if err != nil {
			b.Fatal(err)
		}
		if fenced != 2 {
			b.Fatalf("fenced %d runs, wanted 2", fenced)
		}
		for _, runID := range runIDs {
			stored, err := g.Run(servicePrincipal(), runID)
			if err != nil {
				b.Fatal(err)
			}
			if stored.State != RunStateStopped {
				b.Fatalf("run %s not fenced: %s", runID,
					stored.State)
			}
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportFencePercentiles(b, samples)
}

func reportFencePercentiles(b *testing.B, samples []time.Duration) {
	if len(samples) == 0 {
		b.Fatal("no samples")
	}
	sorted := append([]time.Duration{}, samples...)
	sortDurations(sorted)
	pick := func(fraction float64) float64 {
		index := int(fraction * float64(len(sorted)-1))
		return float64(sorted[index]) / float64(time.Millisecond)
	}
	b.ReportMetric(pick(0.50), "fence-p50-ms")
	b.ReportMetric(pick(0.99), "fence-p99-ms")
}

func sortDurations(values []time.Duration) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
