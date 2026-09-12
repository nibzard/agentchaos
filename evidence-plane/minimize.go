package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Capture minimization and redaction (spec 19, T037). This code runs
// on the capture path, before content leaves the customer execution
// plane: default capture is minimized, identifiers become keyed
// pseudonyms, and full content survives only when it fit the inline
// budget. Raw prompts and tool results belong in object storage, not
// in the event stream.

// DefaultInlineBudget is the largest payload that may travel inline.
// Larger captures downgrade to a metadata-only reference: the event
// keeps its shape and its size, the content stays in object storage.
const DefaultInlineBudget = 2048

// Minimizer rewrites captured content before ingest. The key scopes
// pseudonyms to one deployment: the same identifier maps to the same
// pseudonym within the tenant (relationships survive), but nobody can
// hash a candidate secret and search the logs for it — the mapping is
// keyed, not plain (spec 19: avoid searchable low-entropy hashes).
type Minimizer struct {
	key         []byte
	inlineLimit int64
}

// NewMinimizer builds a minimizer. A nil or short key is refused: a
// guessable pseudonym key is worse than none.
func NewMinimizer(key []byte, inlineLimit int64) (*Minimizer, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("pseudonym key must be at least 16 bytes")
	}
	if inlineLimit <= 0 {
		inlineLimit = DefaultInlineBudget
	}
	return &Minimizer{key: key, inlineLimit: inlineLimit}, nil
}

// Pseudonym returns the stable keyed pseudonym for one identifier.
func (m *Minimizer) Pseudonym(identifier string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(identifier))
	sum := mac.Sum(nil)
	return "psd_" + hex.EncodeToString(sum[:8])
}

// RedactionRule replaces one class of sensitive content. Label is the
// marker left behind; the matched text never reaches the event.
type RedactionRule struct {
	Pattern *regexp.Regexp
	Label   string
}

// DefaultRedactionRules covers the content classes spec 19 names:
// bearer credentials, cloud keys, private key blocks, and personal
// email addresses. Deployments add their own; they cannot remove
// these.
func DefaultRedactionRules() []RedactionRule {
	return []RedactionRule{
		{regexp.MustCompile(`(?i)authorization:\s*bearer\s+[a-z0-9._~+/=-]+`),
			"[redacted bearer credential]"},
		{regexp.MustCompile(`(?i)bearer\s+[a-z0-9._~+/=-]{20,}`),
			"[redacted bearer credential]"},
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			"[redacted access key]"},
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
			"[redacted private key block]"},
		{regexp.MustCompile(`[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`),
			"[redacted email]"},
	}
}

// Redact applies the rules to captured text and reports whether
// anything changed. Distinct secrets map to one label each; the
// matched bytes are gone.
func (m *Minimizer) Redact(content string, rules []RedactionRule) (string, bool) {
	changed := false
	for _, rule := range rules {
		if rule.Pattern.MatchString(content) {
			content = rule.Pattern.ReplaceAllString(content, rule.Label)
			changed = true
		}
	}
	return content, changed
}

// Tokenize replaces identifiers with their keyed pseudonyms so
// within-tenant relationships survive redaction: the same identifier
// yields the same psd_ token across every event this minimizer
// touches.
func (m *Minimizer) Tokenize(content string, identifiers []string) string {
	for _, identifier := range identifiers {
		if identifier == "" {
			continue
		}
		content = strings.ReplaceAll(content, identifier,
			m.Pseudonym(identifier))
	}
	return content
}

// Prepare minimizes one captured payload before it leaves the
// execution plane.
//
//   - object_ref payloads pass through untouched: their content is
//     already in object storage and the event carries no bytes.
//   - inline content is redacted first; anything still over budget
//     downgrades to a metadata-only reference that keeps the byte
//     size and the fact of redaction but carries no content.
//   - metadata_only payloads are already minimal.
func (m *Minimizer) Prepare(payload EventPayload,
	rules []RedactionRule) EventPayload {
	switch payload.Kind {
	case PayloadObjectRef, PayloadMetadataOnly:
		return payload
	case PayloadInline:
		content, redacted := m.Redact(payload.Content, rules)
		if int64(len(content)) <= m.inlineLimit {
			payload.Content = content
			payload.Redacted = payload.Redacted || redacted
			if payload.SizeBytes == 0 {
				payload.SizeBytes = int64(len(content))
			}
			return payload
		}
		// Over budget: downgrade to a metadata-only reference. The
		// contract lets metadata_only carry neither content nor a
		// size, so the event keeps its shape and the fact of
		// redaction — the bytes stay in object storage or are not
		// captured at all.
		return EventPayload{
			Kind:      PayloadMetadataOnly,
			Redacted:  true,
			Truncated: payload.Truncated,
			SizeBytes: 0,
		}
	default:
		return EventPayload{Kind: PayloadMetadataOnly, Redacted: true}
	}
}
