package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

var testPseudonymKey = []byte("0123456789abcdef0123456789abcdef")

func testMinimizer(t *testing.T) *Minimizer {
	t.Helper()
	minimizer, err := NewMinimizer(testPseudonymKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	return minimizer
}

func TestNewMinimizerRefusesWeakKeys(t *testing.T) {
	if _, err := NewMinimizer([]byte("short"), 0); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := NewMinimizer(nil, 0); err == nil {
		t.Fatal("a nil key was accepted")
	}
}

func TestZeroInlineBudgetTakesTheDefault(t *testing.T) {
	minimizer, err := NewMinimizer(testPseudonymKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if minimizer.inlineLimit != DefaultInlineBudget {
		t.Fatalf("inline limit: %d", minimizer.inlineLimit)
	}
}

func TestPseudonymsAreKeyedNotPlainHashes(t *testing.T) {
	minimizer := testMinimizer(t)
	identifier := "sk-live-tenant-secret-001"

	first := minimizer.Pseudonym(identifier)
	second := minimizer.Pseudonym(identifier)
	if first != second {
		t.Fatal("one identifier produced two pseudonyms")
	}
	if !strings.HasPrefix(first, "psd_") {
		t.Fatalf("pseudonym shape: %q", first)
	}

	// A plain digest of the identifier would let anyone confirm a
	// guessed secret by hashing candidates. The keyed pseudonym must
	// not equal one.
	digest := sha256.Sum256([]byte(identifier))
	if first == "psd_"+hex.EncodeToString(digest[:8]) {
		t.Fatal("the pseudonym is an unkeyed hash")
	}

	other, err := NewMinimizer([]byte("fedcba9876543210fedcba9876543210"),
		0)
	if err != nil {
		t.Fatal(err)
	}
	if other.Pseudonym(identifier) == first {
		t.Fatal("two keys produced the same pseudonym")
	}
}

func TestTokenizePreservesRelationships(t *testing.T) {
	minimizer := testMinimizer(t)
	content := "user alice@example.net wrote to bob@example.net; " +
		"alice@example.net attached the report"
	tokenized := minimizer.Tokenize(content,
		[]string{"alice@example.net", "bob@example.net"})

	alice := minimizer.Pseudonym("alice@example.net")
	bob := minimizer.Pseudonym("bob@example.net")
	if !strings.Contains(tokenized, alice) {
		t.Fatal("alice was not tokenized")
	}
	if !strings.Contains(tokenized, bob) {
		t.Fatal("bob was not tokenized")
	}
	// Both occurrences of one identifier map to one token: the
	// within-tenant relationship survives.
	if strings.Count(tokenized, alice) != 2 {
		t.Fatal("one identifier did not map to one token")
	}
	if strings.Contains(tokenized, "alice@example.net") {
		t.Fatal("the identifier survived tokenization")
	}
	if alice == bob {
		t.Fatal("two identifiers share a token")
	}
}

func TestDefaultRulesRedactEachClass(t *testing.T) {
	minimizer := testMinimizer(t)
	cases := []struct {
		name    string
		content string
		label   string
	}{
		{"authorization header",
			"Authorization: Bearer abc123def456ghi789._-~+/=",
			"[redacted bearer credential]"},
		{"bare bearer token",
			"the worker leaked bearer mF9-1xY2zA3bC4dE5fG6hI7jK8lM9nP0",
			"[redacted bearer credential]"},
		{"cloud access key",
			"credentials: AKIAIOSFODNN7EXAMPLE",
			"[redacted access key]"},
		{"private key block",
			"-----BEGIN RSA PRIVATE KEY-----",
			"[redacted private key block]"},
		{"email address",
			"contact ops@example.com for details",
			"[redacted email]"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			redacted, changed := minimizer.Redact(testCase.content,
				DefaultRedactionRules())
			if !changed {
				t.Fatal("nothing was redacted")
			}
			if !strings.Contains(redacted, testCase.label) {
				t.Fatalf("label missing: %q", redacted)
			}
		})
	}
	// The matched bytes are gone, not merely decorated.
	redacted, _ := minimizer.Redact(
		"contact ops@example.com for details", DefaultRedactionRules())
	if strings.Contains(redacted, "ops@example.com") {
		t.Fatalf("address survived: %q", redacted)
	}
}

func TestRedactReportsUnchangedContent(t *testing.T) {
	minimizer := testMinimizer(t)
	_, changed := minimizer.Redact("nothing sensitive here",
		DefaultRedactionRules())
	if changed {
		t.Fatal("clean content reported redacted")
	}
}

func TestPreparePassesObjectRefsThroughUntouched(t *testing.T) {
	minimizer := testMinimizer(t)
	payload := EventPayload{
		Kind: PayloadObjectRef,
		StorageRef:  "obj://runs/run_0f1e2d3c4b5a6970/blob-1",
		Digest:      "sha256:" + strings.Repeat("a1", 32),
		SizeBytes:   4096,
		ContentType: "application/octet-stream",
	}
	prepared := minimizer.Prepare(payload, DefaultRedactionRules())
	if prepared != payload {
		t.Fatalf("object reference was touched: %+v", prepared)
	}
}

func TestPrepareRedactsInlineContent(t *testing.T) {
	minimizer := testMinimizer(t)
	payload := EventPayload{
		Kind:    PayloadInline,
		Content: "wrote to alice@example.net about the incident",
	}
	prepared := minimizer.Prepare(payload, DefaultRedactionRules())
	if prepared.Kind != PayloadInline {
		t.Fatalf("small content was downgraded: %+v", prepared)
	}
	if !prepared.Redacted {
		t.Fatal("the redaction flag was not set")
	}
	if strings.Contains(prepared.Content, "alice@example.net") {
		t.Fatalf("address survived: %q", prepared.Content)
	}
}

func TestPrepareDowngradesOversizedInline(t *testing.T) {
	minimizer := testMinimizer(t)
	payload := EventPayload{
		Kind:    PayloadInline,
		Content: strings.Repeat("x", DefaultInlineBudget+1000),
	}
	prepared := minimizer.Prepare(payload, DefaultRedactionRules())
	if prepared.Kind != PayloadMetadataOnly {
		t.Fatalf("oversized content stayed inline: %+v", prepared)
	}
	if prepared.Content != "" || prepared.SizeBytes != 0 {
		t.Fatalf("bytes survived the downgrade: %+v", prepared)
	}
	if !prepared.Redacted {
		t.Fatal("the downgrade did not mark the payload redacted")
	}
}

func TestAPreparedPayloadSatisfiesTheContract(t *testing.T) {
	minimizer := testMinimizer(t)
	event := collectorEvent(0)
	event.Payload = minimizer.Prepare(event.Payload,
		DefaultRedactionRules())
	if errs := event.ValidateEvent(); len(errs) != 0 {
		t.Fatalf("prepared event left the contract: %+v", errs)
	}
	// The oversized downgrade too.
	big := collectorEvent(1)
	big.Payload = EventPayload{
		Kind: PayloadInline,
		Content: "user alice@example.net said " +
			strings.Repeat("y", DefaultInlineBudget+500),
	}
	big.Payload = minimizer.Prepare(big.Payload,
		DefaultRedactionRules())
	if errs := big.ValidateEvent(); len(errs) != 0 {
		t.Fatalf("downgraded event left the contract: %+v", errs)
	}
}

func TestPrepareRedactsBeforeMeasuring(t *testing.T) {
	// Content whose redacted form fits the budget stays inline; the
	// budget applies to what ships, not what was captured.
	minimizer, err := NewMinimizer(testPseudonymKey, 64)
	if err != nil {
		t.Fatal(err)
	}
	payload := EventPayload{
		Kind: PayloadInline,
		Content: "[redacted email] " + strings.Repeat("s", 600),
	}
	prepared := minimizer.Prepare(payload, DefaultRedactionRules())
	// The captured content is over budget even after redaction, so
	// it still downgrades.
	if prepared.Kind != PayloadMetadataOnly {
		t.Fatalf("over-budget content stayed inline: %+v", prepared)
	}

	payload.Content = "alice@example.net"
	prepared = minimizer.Prepare(payload, DefaultRedactionRules())
	if prepared.Kind != PayloadInline {
		t.Fatalf("content that fits after redaction was dropped: %+v",
			prepared)
	}
	if len(prepared.Content) >= len("alice@example.net") {
		t.Fatalf("redaction did not shrink the content: %q",
			prepared.Content)
	}
}
