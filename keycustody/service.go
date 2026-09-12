// Package keycustody is the signing-key service of the trusted
// computing base (spec 5, 15.1, T038). It holds the private keys for
// scenario releases, experiment grants, checkpoints, and principal
// tokens, and it never exports them: callers sign and verify through
// the service, and only public material leaves it.
//
// The service also derives tenant-isolated encryption contexts: one
// master secret per deployment, one subkey per tenant and usage, so
// ciphertext sealed for one tenant cannot open under another tenant's
// context even if the stored bytes leak.
package keycustody

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Usage names what a key may sign. A key created for one usage never
// signs for another: a scenario-release key cannot mint principal
// tokens, and a grant key cannot sign checkpoints.
const (
	UsageScenarioRelease = "scenario_release"
	UsageExperimentGrant = "experiment_grant"
	UsageCheckpoint      = "checkpoint"
	UsagePrincipalToken  = "principal_token"
)

// knownUsage is the closed set. Adding a usage is a policy decision.
var knownUsage = map[string]bool{
	UsageScenarioRelease: true,
	UsageExperimentGrant: true,
	UsageCheckpoint:      true,
	UsagePrincipalToken:  true,
}

// KeyRecord is the public view of a held key. It carries no private
// material.
type KeyRecord struct {
	KeyID     string    `json:"key_id"`
	Usage     string    `json:"usage"`
	CreatedAt time.Time `json:"created_at"`
	// RetiredAt is set when a successor took over. A retired key
	// verifies forever — retirement ends new signatures, it does not
	// break old ones.
	RetiredAt time.Time `json:"retired_at,omitempty"`

	public ed25519.PublicKey
}

// PublicKey returns the key's public half.
func (k *KeyRecord) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), k.public...)
}

// heldKey is the internal record: the private key exists only here.
type heldKey struct {
	record  KeyRecord
	private ed25519.PrivateKey
}

// Signature is one signing over a message.
type Signature struct {
	KeyID    string    `json:"key_id"`
	SignedAt time.Time `json:"signed_at"`
	Bytes    []byte    `json:"bytes"`
}

var (
	// ErrKeyUnknown reports a key id the service never held.
	ErrKeyUnknown = errors.New("no such key")
	// ErrKeyRetired reports a signing request for a retired key.
	ErrKeyRetired = errors.New("key is retired; sign with its successor")
	// ErrUsage reports an unknown usage on creation.
	ErrUsage = errors.New("unknown key usage")
)

// SigningService holds signing keys in process. The broker, governor,
// compiler, and API mint their signatures through it; the private
// keys stay behind this interface (spec 5: the signing-key service is
// trusted computing base, outside the worker environment).
type SigningService struct {
	mu   sync.Mutex
	keys map[string]*heldKey
	now  func() time.Time
}

// NewSigningService builds an empty service.
func NewSigningService(now func() time.Time) *SigningService {
	if now == nil {
		now = time.Now
	}
	return &SigningService{keys: map[string]*heldKey{}, now: now}
}

// CreateKey generates a key for one usage. The key signs until a
// rotation retires it; there is no expiry on signing, because keys
// retire by rotation, not by wall-clock guesswork.
func (s *SigningService) CreateKey(usage string) (KeyRecord, error) {
	if !knownUsage[usage] {
		return KeyRecord{}, fmt.Errorf("%w: %s", ErrUsage, usage)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyRecord{}, err
	}
	id := "key_" + strings.ReplaceAll(usage, "_", "-") + "-" +
		hex.EncodeToString(randomBytes(4))
	record := KeyRecord{
		KeyID:     id,
		Usage:     usage,
		CreatedAt: s.now(),
		public:    public,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = &heldKey{record: record, private: private}
	return record, nil
}

// Sign signs a message with the named key. Signing is the only
// operation that touches private material, and it never leaves the
// service: the caller gets the signature, not the key.
func (s *SigningService) Sign(keyID string, message []byte) (Signature, error) {
	s.mu.Lock()
	held, ok := s.keys[keyID]
	s.mu.Unlock()
	if !ok {
		return Signature{}, fmt.Errorf("%w: %s", ErrKeyUnknown, keyID)
	}
	if !held.record.RetiredAt.IsZero() {
		return Signature{}, fmt.Errorf("%w: %s", ErrKeyRetired, keyID)
	}
	return Signature{
		KeyID:    keyID,
		SignedAt: s.now(),
		Bytes:    ed25519.Sign(held.private, message),
	}, nil
}

// Verify checks a signature. It works for retired keys too:
// retirement ends new signatures, never old verification.
func (s *SigningService) Verify(keyID string, message []byte, signature []byte) bool {
	s.mu.Lock()
	held, ok := s.keys[keyID]
	s.mu.Unlock()
	if !ok {
		return false
	}
	return ed25519.Verify(held.record.public, message, signature)
}

// Rotate retires a key and creates its successor for the same usage.
// The old key still verifies; it never signs again. Signers race once
// at rotation — a signature minted just before retirement stays
// valid — and every later Sign on the old key refuses.
func (s *SigningService) Rotate(keyID string) (KeyRecord, KeyRecord, error) {
	s.mu.Lock()
	held, ok := s.keys[keyID]
	s.mu.Unlock()
	if !ok {
		return KeyRecord{}, KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyUnknown, keyID)
	}
	if !held.record.RetiredAt.IsZero() {
		return KeyRecord{}, KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyRetired, keyID)
	}
	successor, err := s.CreateKey(held.record.Usage)
	if err != nil {
		return KeyRecord{}, KeyRecord{}, err
	}
	s.mu.Lock()
	held.record.RetiredAt = s.now()
	s.mu.Unlock()
	return held.record, successor, nil
}

// Keys lists the public records. Private material never appears.
func (s *SigningService) Keys() []KeyRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyRecord, 0, len(s.keys))
	for _, held := range s.keys {
		out = append(out, held.record)
	}
	return out
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error()) // unrecoverable by design
	}
	return buf
}
