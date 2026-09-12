# Key custody

The signing-key service of the trusted computing base (spec 5, 15.1,
T038). It owns the platform's private keys and the master secret
behind tenant-isolated encryption. Private material never leaves this
package: callers sign, verify, seal, and open through it.

## Where each guarantee lives

| Spec 15.1 requirement | Where it is implemented |
| --- | --- |
| Scoped service identities | Principal tokens: `api/auth.go` (T027) — Ed25519-signed actor, tenant, role, expiry |
| Short-lived credentials | Effect permits (5-minute TTL, broker), grant leases (10-second TTL, governor), token expiry |
| Tenant-isolated encryption contexts | `keycustody.TenantSealer`, wired into the evidence recorder through `WithPayloadSealer` |
| Authorization on every resource | Broker, governor, and recorder tenant scoping (T007, T009, T011) |
| Signed scenario artifacts | Scenario lifecycle Ed25519 release signatures (T016) |
| Signed experiment grants | Compiler grant signing (T003), checked by the runner against the plan digest |
| Signing-key service | This module |

## SigningService

Keys are created for one usage and never sign for another:
`scenario_release`, `experiment_grant`, `checkpoint`,
`principal_token`.

```go
service := keycustody.NewSigningService(nil)
grantKey, _ := service.CreateKey(keycustody.UsageExperimentGrant)
signature, _ := service.Sign(grantKey.KeyID, planBytes)
ok := service.Verify(grantKey.KeyID, planBytes, signature.Bytes)

retired, successor, _ := service.Rotate(grantKey.KeyID)
// retired still verifies old signatures; it never signs again
```

`Sign` is the only operation that touches private material. `Keys()`
and `KeyRecord` expose public halves only.

## TenantSealer

One AES-256-GCM subkey per (tenant, usage), derived from the
deployment master secret with HKDF-SHA256 (RFC 5869, on the stdlib).
Two independent bindings keep contexts isolated: the derived subkey
differs per tenant and usage, and the AAD authenticates the context
with every ciphertext. The sealed string carries its tenant and usage
binding, so moved ciphertext refuses before decryption.

```go
sealer, _ := keycustody.NewTenantSealer(master32, keycustody.SealerUsageEvidencePayload)
sealed, _ := sealer.Seal("tnt_9d4c1e2a3b4f5c67", content, eventID)
content, err := sealer.Open("tnt_9d4c1e2a3b4f5c67", sealed, eventID)
```

The evidence recorder consumes any `PayloadSealer`; a deployment
injects a `TenantSealer` through `evidence.WithPayloadSealer`. The
recorder seals the reader-facing copy of every payload at rest,
computes chain digests over the original bytes first (verification is
unchanged), opens content on read, and refuses batches that cannot be
sealed — plaintext at rest is not a degradation path.

## Tests

```bash
cd keycustody && go test ./...
cd evidence-plane && go test ./...   # interop with the recorder
```
