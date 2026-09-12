"""Property tests for canonical serialization (T040).

A digest covers content, not key order: any insertion order of the
same document must produce the same canonical bytes. Array order stays
meaningful. Randomized with fixed seeds.
"""

import json
import random

import pytest

from gauntlet_compiler.canonical import canonical_json, sha256_digest
from conftest import draft_experiment


def _shuffled_keys(value, rng):
    """Rebuild every mapping with its keys in a random order."""
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {key: _shuffled_keys(item, rng) for key, item in items}
    if isinstance(value, list):
        return [_shuffled_keys(item, rng) for item in value]
    return value


def _random_document(rng, depth=0):
    """Build a random JSON-compatible document."""
    kinds = ["dict", "list", "str", "int", "bool", "none"]
    if depth >= 4:
        kinds = ["str", "int", "bool", "none"]
    kind = rng.choice(kinds)
    if kind == "dict":
        return {
            f"key{rng.randrange(50)}_{rng.randrange(50)}":
                _random_document(rng, depth + 1)
            for _ in range(rng.randrange(4))
        }
    if kind == "list":
        return [_random_document(rng, depth + 1)
                for _ in range(rng.randrange(4))]
    if kind == "str":
        return rng.choice(["run_0f1e2d3c", "psd_ab12", "ä", "", "x" * 5])
    if kind == "int":
        return rng.randrange(-10**9, 10**9)
    if kind == "bool":
        return rng.choice([True, False])
    return None


def test_key_order_never_changes_canonical_bytes():
    rng = random.Random(20260924)
    for _ in range(300):
        document = _random_document(rng)
        expected = canonical_json(document)
        for _ordering in range(3):
            shuffled = _shuffled_keys(document, rng)
            assert canonical_json(shuffled) == expected


def test_digest_is_stable_under_key_reordering():
    rng = random.Random(20260925)
    for _ in range(100):
        document = _random_document(rng)
        expected = sha256_digest(document)
        assert sha256_digest(_shuffled_keys(document, rng)) == expected


def test_real_documents_digest_by_content_not_order():
    rng = random.Random(20260926)
    document = draft_experiment()
    expected = canonical_json(document)
    digest = sha256_digest(document)
    for _ in range(20):
        shuffled = _shuffled_keys(document, rng)
        assert canonical_json(shuffled) == expected
        assert sha256_digest(shuffled) == digest


def test_canonical_encoding_round_trips_idempotently():
    rng = random.Random(20260927)
    for _ in range(200):
        document = _random_document(rng)
        encoded = canonical_json(document)
        assert canonical_json(json.loads(encoded)) == encoded


def test_array_order_stays_meaningful():
    rng = random.Random(20260928)
    for _ in range(100):
        document = _random_document(rng)
        forward = [document, "sentinel"]
        backward = ["sentinel", document]
        assert sha256_digest(forward) != sha256_digest(backward)


def test_forbidden_numbers_refuse_at_any_depth():
    rng = random.Random(20260929)
    for _ in range(100):
        document = _random_document(rng)
        container = rng.choice([dict, list])
        if container is dict:
            poisoned = {"k": document, "nan": float("nan")}
        else:
            poisoned = [document, float("inf")]
        with pytest.raises(ValueError):
            canonical_json(poisoned)
