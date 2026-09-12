package keycustody

// Spec 15.1 / T038: scoped signing keys whose private material never
// leaves the service, rotation without breaking old signatures, and
// tenant-isolated encryption contexts.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHKDFMatchesRFC5869(t *testing.T) {
	// RFC 5869 test case 1 (SHA-256).
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a" +
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865"
	got := hex.EncodeToString(hkdfSHA256(ikm, salt, info, 42))
	if got != want {
		t.Fatalf("hkdf: got %s want %s", got, want)
	}
}

func TestSigningRoundTrip(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	service := NewSigningService(func() time.Time { return now })
	record, err := service.CreateKey(UsageExperimentGrant)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record.KeyID, "key_experiment-grant-") {
		t.Fatalf("key id: %s", record.KeyID)
	}
	signature, err := service.Sign(record.KeyID, []byte("grant bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !service.Verify(record.KeyID, []byte("grant bytes"), signature.Bytes) {
		t.Fatal("a valid signature did not verify")
	}
	if service.Verify(record.KeyID, []byte("other bytes"), signature.Bytes) {
		t.Fatal("a signature verified over different bytes")
	}
	if service.Verify("key_none-0000", nil, nil) {
		t.Fatal("an unknown key verified")
	}
	if _, err := service.Sign("key_none-0000", nil); !errors.Is(err, ErrKeyUnknown) {
		t.Fatalf("unknown sign: %v", err)
	}
	if _, err := service.CreateKey("coffee_signing"); !errors.Is(err, ErrUsage) {
		t.Fatalf("unknown usage: %v", err)
	}
}

func TestARotationRetiresButNeverBreaksVerification(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := NewSigningService(func() time.Time { return now })
	first, err := service.CreateKey(UsageScenarioRelease)
	if err != nil {
		t.Fatal(err)
	}
	oldSignature, err := service.Sign(first.KeyID, []byte("scenario v1"))
	if err != nil {
		t.Fatal(err)
	}

	retired, successor, err := service.Rotate(first.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if retired.RetiredAt.IsZero() || retired.KeyID == successor.KeyID {
		t.Fatalf("rotation: %+v -> %+v", retired, successor)
	}
	if successor.Usage != UsageScenarioRelease {
		t.Fatalf("successor usage: %s", successor.Usage)
	}
	if _, err := service.Sign(first.KeyID, []byte("scenario v2")); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("a retired key signed: %v", err)
	}
	if !service.Verify(first.KeyID, []byte("scenario v1"), oldSignature.Bytes) {
		t.Fatal("rotation broke an old signature")
	}
	newSignature, err := service.Sign(successor.KeyID, []byte("scenario v2"))
	if err != nil {
		t.Fatal(err)
	}
	if !service.Verify(successor.KeyID, []byte("scenario v2"), newSignature.Bytes) {
		t.Fatal("the successor did not verify")
	}
	if _, _, err := service.Rotate(first.KeyID); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("double rotation: %v", err)
	}
}

func TestPrivateMaterialNeverLeavesTheRecords(t *testing.T) {
	service := NewSigningService(nil)
	record, err := service.CreateKey(UsagePrincipalToken)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private")) {
		t.Fatalf("a key record leaked a private field: %s", encoded)
	}
	if len(record.PublicKey()) != 32 {
		t.Fatalf("public key length: %d", len(record.PublicKey()))
	}
	for _, listed := range service.Keys() {
		if listed.KeyID == record.KeyID && len(listed.PublicKey()) != 32 {
			t.Fatal("the listing lost the public key")
		}
	}
}

func TestTenantSealerIsolatesContexts(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	evidence, err := NewTenantSealer(master, SealerUsageEvidencePayload)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := NewTenantSealer(master, "report_artifact")
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{8}, 32)

	tenantA := "tnt_9d4c1e2a3b4f5c67"
	tenantB := "tnt_0e1d2c3b4a5f6d78"
	secret := "the worker asked for the credential bait"

	sealed, err := evidence.Seal(tenantA, secret, []byte("evt_0000000000000001"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "acxseal.") {
		t.Fatalf("sealed form: %s", sealed)
	}
	if strings.Contains(sealed, secret) {
		t.Fatal("the sealed form carries plaintext")
	}

	opened, err := evidence.Open(tenantA, sealed, []byte("evt_0000000000000001"))
	if err != nil || opened != secret {
		t.Fatalf("round trip: %q %v", opened, err)
	}

	// Another tenant cannot open it — not by context, not by key.
	if _, err := evidence.Open(tenantB, sealed, nil); err == nil {
		t.Fatal("tenant B opened tenant A's ciphertext")
	}
	// Another usage cannot open it, even with the same master.
	if _, err := reports.Open(tenantA, sealed, nil); err == nil {
		t.Fatal("a different usage opened the ciphertext")
	}
	// A different master secret derives different keys.
	stranger, err := NewTenantSealer(other, SealerUsageEvidencePayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Open(tenantA, sealed, nil); err == nil {
		t.Fatal("a stranger master opened the ciphertext")
	}
	// The AAD is authenticated: same tenant, different binding.
	if _, err := evidence.Open(tenantA, sealed, []byte("evt_0000000000000002")); err == nil {
		t.Fatal("the ciphertext opened under a different AAD")
	}
	// Tampering fails authentication.
	tampered := sealed[:len(sealed)-4] + "AAA="
	if _, err := evidence.Open(tenantA, tampered, []byte("evt_0000000000000001")); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	// Not-sealed input refuses cleanly.
	if _, err := evidence.Open(tenantA, "plain text", nil); err == nil {
		t.Fatal("unsealed input opened")
	}
	// The master must be 32 bytes.
	if _, err := NewTenantSealer([]byte("short"), SealerUsageEvidencePayload); err == nil {
		t.Fatal("a short master built a sealer")
	}
}

func TestSealedValuesBindTheirContextExplicitly(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	evidence, _ := NewTenantSealer(master, SealerUsageEvidencePayload)
	sealed, err := evidence.Seal("tnt_9d4c1e2a3b4f5c67", "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	tenant, usage, ciphertext, err := decodeSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if tenant != "tnt_9d4c1e2a3b4f5c67" || usage != SealerUsageEvidencePayload ||
		len(ciphertext) == 0 {
		t.Fatalf("binding: %q %q %d", tenant, usage, len(ciphertext))
	}
}
