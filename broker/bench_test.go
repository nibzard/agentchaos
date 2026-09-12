package broker

import (
	"sort"
	"testing"
	"time"
)

// Benchmarks for the beta nonfunctional targets (T043, spec 21):
// deterministic gate latency (p95 <= 10 ms) and broker throughput
// (500 decisions/second on a bounded policy set). Run with:
//
//	go test -bench=. -benchtime=2000x
//
// The gate benchmark reports p50/p95/p99 from per-decision samples,
// because the target is a tail figure, not a mean.

// benchBroker builds a broker without test-harness helpers so
// benchmarks can construct it with a *testing.B.
func benchBroker(b *testing.B) *Broker {
	b.Helper()
	policy, err := LoadPolicy(DefaultPolicyJSON)
	if err != nil {
		b.Fatal(err)
	}
	return New(policy, []*RunContext{testRun()},
		[]Sink{&SyntheticSink{}})
}

// benchRoot mints a root delegation whose budget cannot bind during a
// benchmark run, so every measured decision is an allow decision.
func benchRoot(b *testing.B, broker *Broker, id string) *Delegation {
	b.Helper()
	request := rootRequest()
	request.ID = id
	request.CumulativeBudget = Budget{
		MaxTotalCost:   Money{Currency: "USD", Micros: 1 << 44},
		MaxTotalTokens: 1 << 44,
		MaxEffects:     1 << 32,
	}
	root, err := broker.Delegate(servicePrincipal(), request)
	if err != nil {
		b.Fatal(err)
	}
	return root
}

func BenchmarkDeterministicGateLatency(b *testing.B) {
	broker := benchBroker(b)
	root := benchRoot(b, broker, "dlg_gatebench0001")

	// Warm caches with unmeasured decisions, then sample every
	// measured decision for tail statistics.
	for i := 0; i < 50; i++ {
		_, _, _ = broker.Authorize(servicePrincipal(),
			delegatedEffect(i, root.ID, root.ChildActor))
	}
	samples := make([]time.Duration, 0, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, decision, err := broker.Authorize(servicePrincipal(),
			delegatedEffect(50+i, root.ID, root.ChildActor))
		elapsed := time.Since(start)
		if err != nil {
			b.Fatal(err)
		}
		if decision.Verdict != "allow" {
			b.Fatalf("measured a refusal: %+v", decision)
		}
		samples = append(samples, elapsed)
	}
	b.StopTimer()
	reportPercentiles(b, "gate", samples)
}

func BenchmarkAuthorizeDecisionThroughput(b *testing.B) {
	broker := benchBroker(b)
	root := benchRoot(b, broker, "dlg_ratebench0001")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, decision, err := broker.Authorize(servicePrincipal(),
			delegatedEffect(i, root.ID, root.ChildActor))
		if err != nil {
			b.Fatal(err)
		}
		if decision.Verdict != "allow" {
			b.Fatalf("decision %d was not an allow: %+v", i, decision)
		}
	}
}

// BenchmarkExpiredGrantDecision measures the denial path against an
// expired grant: the safety check must be at least as fast as an
// allow, never a slow path that tempts a caller to skip it.
func BenchmarkExpiredGrantDecision(b *testing.B) {
	policy, err := LoadPolicy(DefaultPolicyJSON)
	if err != nil {
		b.Fatal(err)
	}
	run := testRun()
	run.GrantExpiresAt = time.Now().UTC().Add(-time.Minute).
		Format("2006-01-02T15:04:05Z")
	broker := New(policy, []*RunContext{run}, []Sink{&SyntheticSink{}})
	root := benchRoot(b, broker, "dlg_expgbench0001")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, decision, err := broker.Authorize(servicePrincipal(),
			delegatedEffect(i, root.ID, root.ChildActor))
		if err != nil {
			b.Fatal(err)
		}
		if decision.Verdict == "allow" {
			b.Fatal("an expired grant allowed an effect")
		}
	}
}

// reportPercentiles prints p50/p95/p99 in milliseconds as custom
// metrics, so the report can compare tails against the target.
func reportPercentiles(b *testing.B, name string, samples []time.Duration) {
	if len(samples) == 0 {
		b.Fatal("no samples")
	}
	sorted := append([]time.Duration{}, samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(fraction float64) float64 {
		index := int(fraction * float64(len(sorted)-1))
		return float64(sorted[index]) / float64(time.Millisecond)
	}
	b.ReportMetric(pick(0.50), name+"-p50-ms")
	b.ReportMetric(pick(0.95), name+"-p95-ms")
	b.ReportMetric(pick(0.99), name+"-p99-ms")
}
