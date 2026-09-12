"""Canonical serialization behavior."""

import pytest

from gauntlet_compiler.canonical import canonical_json, sha256_digest


def test_keys_are_sorted_and_whitespace_removed():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_nested_documents_are_stable():
    document = {"z": [3, 1, 2], "a": {"y": True, "x": None}}
    assert canonical_json(document) == '{"a":{"x":null,"y":true},"z":[3,1,2]}'


def test_non_ascii_is_kept_verbatim():
    assert canonical_json({"k": "ä"}) == '{"k":"ä"}'


def test_nan_is_rejected():
    with pytest.raises(ValueError):
        canonical_json({"k": float("nan")})


def test_floats_encode_stably():
    assert canonical_json({"threshold": 0.95}) == '{"threshold":0.95}'


def test_digest_shape():
    digest = sha256_digest({"a": 1})
    assert digest.startswith("sha256:")
    assert len(digest) == 71  # 7 + 64


def test_same_document_same_digest():
    assert sha256_digest({"a": [1, 2]}) == sha256_digest({"a": [1, 2]})


def test_different_documents_different_digest():
    assert sha256_digest({"a": 1}) != sha256_digest({"a": 2})
