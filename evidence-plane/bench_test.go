package evidence

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Benchmark for the beta event-ingest target (T043, spec 21): 5,000
// metadata events/second at a defined 1 KB event load. Each iteration
// ingests one batch of 100 inline events of 1 KB, with sequences
// continuing across batches as one collector stream and observed_at
// pinned near the recorder clock so no clock findings fire. Run with
// a bounded iteration count to bound recorder memory:
//
//	go test -bench=BenchmarkIngestMetadataEvents -benchtime=100x

func BenchmarkIngestMetadataEvents(b *testing.B) {
	recorder := New()
	principal := collectorPrincipal()
	const batchSize = 100
	oneKB := "m" + strings.Repeat("x", 1023)
	stamp := time.Now().UTC().Add(-time.Second).
		Format(time.RFC3339Nano)
	sequence := 0
	b.ResetTimer()
	for batch := 0; batch < b.N; batch++ {
		events := make([]*Event, 0, batchSize)
		for i := 0; i < batchSize; i++ {
			event := collectorEvent(sequence)
			event.ID = fmt.Sprintf("evt_bench%012d", sequence)
			event.Sequence = int64(sequence)
			event.ObservedAt = stamp
			event.Payload = EventPayload{
				Kind:    PayloadInline,
				Content: oneKB,
			}
			events = append(events, event)
			sequence++
		}
		if _, err := recorder.Ingest(principal,
			&Batch{Events: events}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	seconds := b.Elapsed().Seconds()
	if seconds > 0 {
		b.ReportMetric(float64(b.N*batchSize)/seconds, "events/sec")
	}
}
