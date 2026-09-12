package evidence

// Spec 15.1 / T038 interop: the recorder seals payload content at
// rest under a tenant-isolated context provided by the key custody
// service, the chain digests still bind the original bytes, and a
// sealer that fails closes the store.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"gauntlet/keycustody"
)

// custodySealer adapts the key custody service's tenant sealer to the
// recorder's interface, the way a deployment wires them.
type custodySealer struct {
	inner  *keycustody.TenantSealer
	sealed int
}

func (c *custodySealer) SealPayload(tenantID, plaintext string) (string, error) {
	c.sealed++
	return c.inner.Seal(tenantID, plaintext, nil)
}

func (c *custodySealer) OpenPayload(tenantID, sealed string) (string, error) {
	return c.inner.Open(tenantID, sealed, nil)
}

func TestPayloadContentIsSealedAtRestAndReadsBack(t *testing.T) {
	master := bytes.Repeat([]byte{3}, 32)
	sealer, err := keycustody.NewTenantSealer(master, keycustody.SealerUsageEvidencePayload)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &custodySealer{inner: sealer}
	recorder := testRecorder(t, WithPayloadSealer(adapter))

	batch := &Batch{Events: []*Event{collectorEvent(1), collectorEvent(2)}}
	if _, err := recorder.Ingest(collectorPrincipal(), batch); err != nil {
		t.Fatal(err)
	}
	if adapter.sealed != 2 {
		t.Fatalf("sealed payloads: %d", adapter.sealed)
	}

	// Readers see the original content, not ciphertext.
	events, err := recorder.Events(collectorPrincipal(), EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events: %d", len(events))
	}
	for _, event := range events {
		if !strings.HasPrefix(event.Payload.Content, `{"n":`) {
			t.Fatalf("payload content did not read back: %q", event.Payload.Content)
		}
	}

	// The chain still verifies: digests were computed over the
	// original bytes, before sealing.
	report, err := recorder.Verify(collectorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact || report.FirstBreak != "" {
		t.Fatalf("verification under sealing: %+v", report)
	}
}

// brokenSealer fails on every call.
type brokenSealer struct{}

func (brokenSealer) SealPayload(tenantID, plaintext string) (string, error) {
	return "", errors.New("sealer unavailable")
}

func (brokenSealer) OpenPayload(tenantID, sealed string) (string, error) {
	return "", errors.New("sealer unavailable")
}

func TestASealerFailureRefusesTheBatch(t *testing.T) {
	recorder := testRecorder(t, WithPayloadSealer(brokenSealer{}))
	batch := &Batch{Events: []*Event{collectorEvent(1)}}
	if _, err := recorder.Ingest(collectorPrincipal(), batch); err == nil {
		t.Fatal("ingest stored a batch whose payload could not be sealed")
	}
	events, err := recorder.Events(collectorPrincipal(), EventQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("a refused batch left events behind: %d", len(events))
	}
}

// openRefusal seals honestly but refuses every open.
type openRefusal struct {
	inner *keycustody.TenantSealer
}

func (o *openRefusal) SealPayload(tenantID, plaintext string) (string, error) {
	return o.inner.Seal(tenantID, plaintext, nil)
}

func (o *openRefusal) OpenPayload(tenantID, sealed string) (string, error) {
	return "", errors.New("context unavailable")
}

func TestContentThatCannotOpenNeverReachesAReader(t *testing.T) {
	master := bytes.Repeat([]byte{4}, 32)
	honest, err := keycustody.NewTenantSealer(master, keycustody.SealerUsageEvidencePayload)
	if err != nil {
		t.Fatal(err)
	}
	recorder := testRecorder(t, WithPayloadSealer(&openRefusal{inner: honest}))
	if _, err := recorder.Ingest(collectorPrincipal(),
		&Batch{Events: []*Event{collectorEvent(1)}}); err != nil {
		t.Fatal(err)
	}

	// A reader whose context cannot open the content gets an error —
	// ciphertext never passes through as payload content.
	if events, err := recorder.Events(collectorPrincipal(), EventQuery{}); err == nil {
		t.Fatalf("a failed open reached a reader: %+v", events)
	}
}
