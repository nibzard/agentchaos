"""Plan and grant signing.

The signed grant is short-lived and consumed by the execution plane
(spec 8). Signatures are ed25519 over canonical bytes. Key management
is task T038; this module only signs and verifies with supplied keys.
"""

from __future__ import annotations

import base64
import re
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from acx_compiler.canonical import canonical_bytes

ALGORITHM = "ed25519"

# Same shape the signature contract allows (common.schema.json).
KEY_ID_PATTERN = re.compile(r"^key_[a-z0-9][a-z0-9-]{3,63}$")


class Signer(Protocol):
    """Signs canonical bytes and reports the key identity."""

    key_id: str
    key_algorithm: str

    def sign(self, payload: bytes) -> str: ...


class Ed25519Signer:
    """Signer over an ed25519 private key held in memory."""

    key_algorithm = ALGORITHM

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str):
        if not KEY_ID_PATTERN.match(key_id):
            raise ValueError(
                "key_id must match key_<name> with lowercase letters, "
                "digits, and hyphens"
            )
        self._key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate(), key_id)

    def sign(self, payload: bytes) -> str:
        raw = self._key.sign(payload)
        return base64.b64encode(raw).decode("ascii")

    def sign_document(self, document: object) -> str:
        return self.sign(canonical_bytes(document))

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()


def verify_signature(
    public_key_bytes: bytes, payload: bytes, value: str
) -> bool:
    """Return true when the signature matches the canonical payload."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(base64.b64decode(value, validate=True), payload)
        return True
    except Exception:
        return False
