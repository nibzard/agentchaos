"""Canonical serialization and digests.

Every digest in the control plane covers the canonical JSON encoding of a
document. The encoding is total and stable: sorted keys, no whitespace,
UTF-8, and shortest round-trip numbers. Money is integer micros; the only
floats in manifests are stop-rule thresholds, and shortest round-trip
encoding matches Go's strconv formatting for those values (RFC 8785 for
the number range the contracts accept).
"""

from __future__ import annotations

import hashlib
import json

_SEPARATOR = (",", ":")


def canonical_json(document: object) -> str:
    """Return the canonical JSON text of a document."""
    return json.dumps(
        document,
        sort_keys=True,
        separators=_SEPARATOR,
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(document: object) -> bytes:
    """Return the canonical UTF-8 bytes of a document."""
    return canonical_json(document).encode("utf-8")


def sha256_digest(document: object) -> str:
    """Return the `sha256:<hex>` digest of a document's canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()
