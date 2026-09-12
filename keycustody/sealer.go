package keycustody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SealerUsage labels the encryption context. A ciphertext sealed
// under one usage cannot open under another, so evidence payloads,
// report artifacts, and anything else sealed by the platform never
// swap contexts.
const SealerUsageEvidencePayload = "evidence_payload"

// TenantSealer derives one AES-256-GCM subkey per (tenant, usage)
// from a deployment master secret (spec 15.1: tenant-isolated
// encryption contexts). The master secret never leaves the sealer;
// tenants see only their own ciphertext.
//
// Two independent bindings keep contexts isolated:
//
//   - the subkey: HKDF-SHA256(master, info = usage + "|" + tenant),
//     so another tenant's derived key is a different key entirely;
//   - the AAD: usage and tenant are authenticated with every
//     ciphertext, so sealed bytes moved between tenants or usages
//     fail authentication even if a key ever collided.
type TenantSealer struct {
	master []byte
	usage  string
}

// NewTenantSealer derives a sealer from a 32-byte master secret.
func NewTenantSealer(master []byte, usage string) (*TenantSealer, error) {
	if len(master) != 32 {
		return nil, errors.New("master secret must be 32 bytes")
	}
	return &TenantSealer{master: append([]byte(nil), master...), usage: usage}, nil
}

// Seal encrypts plaintext under the tenant's context. A fresh random
// nonce travels prefixed to the ciphertext.
func (t *TenantSealer) Seal(tenantID, plaintext string, aad []byte) (string, error) {
	gcm, err := t.gcm(tenantID)
	if err != nil {
		return "", err
	}
	nonce := randomBytes(gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), append(append([]byte(nil), aad...), t.aad(tenantID)...))
	return encodeSealed(tenantID, t.usage, append(nonce, sealed...)), nil
}

// Open decrypts ciphertext under the tenant's context. Ciphertext
// from another tenant, another usage, or tampered bytes fails.
func (t *TenantSealer) Open(tenantID, sealed string, aad []byte) (string, error) {
	sealTenant, sealUsage, ciphertext, err := decodeSealed(sealed)
	if err != nil {
		return "", err
	}
	if sealTenant != tenantID || sealUsage != t.usage {
		return "", fmt.Errorf(
			"ciphertext bound to tenant %s usage %s cannot open under tenant %s usage %s",
			sealTenant, sealUsage, tenantID, t.usage)
	}
	gcm, err := t.gcm(tenantID)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext shorter than a nonce")
	}
	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():],
		append(append([]byte(nil), aad...), t.aad(tenantID)...))
	if err != nil {
		return "", fmt.Errorf("ciphertext failed authentication under tenant %s", tenantID)
	}
	return string(plaintext), nil
}

// gcm derives the tenant's subkey and builds the cipher.
func (t *TenantSealer) gcm(tenantID string) (cipher.AEAD, error) {
	key := hkdfSHA256(t.master, nil, []byte(t.usage+"|"+tenantID), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad authenticates the context with every ciphertext.
func (t *TenantSealer) aad(tenantID string) []byte {
	return []byte(t.usage + "|" + tenantID)
}

// sealedMark marks a string as keycustody ciphertext: the first dot
// part of the sealed form. Downstream stores can recognize it without
// knowing the key material.
const sealedMark = "gauntletseal"

// encodeSealed binds the tenant and usage into the sealed string:
// the mark, then base64 tenant, usage, and ciphertext as dot parts.
// The binding travels with the bytes, so a move between contexts is
// detectable before decryption.
func encodeSealed(tenantID, usage string, ciphertext []byte) string {
	return strings.Join([]string{
		sealedMark,
		base64.RawURLEncoding.EncodeToString([]byte(tenantID)),
		base64.RawURLEncoding.EncodeToString([]byte(usage)),
		base64.RawURLEncoding.EncodeToString(ciphertext),
	}, ".")
}

// decodeSealed reads the binding and ciphertext back.
func decodeSealed(sealed string) (tenantID, usage string, ciphertext []byte, err error) {
	parts := strings.Split(sealed, ".")
	if len(parts) != 4 || parts[0] != sealedMark {
		return "", "", nil, errors.New("not a sealed value")
	}
	tenant, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", nil, err
	}
	use, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", nil, err
	}
	ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", "", nil, err
	}
	return string(tenant), string(use), ciphertext, nil
}

// hkdfSHA256 is RFC 5869 HKDF with SHA-256, on the stdlib alone.
// Extract: PRK = HMAC-SHA256(salt, IKM). Expand: blocks of
// HMAC-SHA256(PRK, previous block | info | counter).
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	out := make([]byte, 0, length)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}
