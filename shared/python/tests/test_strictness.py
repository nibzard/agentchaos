"""Strictness meta-checks over the schemas themselves (AC-001 spirit)."""

import pytest

from acx_schemas import StrictnessError, assert_schema_strict


def test_every_registered_schema_is_strict(registry):
    failures = []
    for name in sorted(registry._documents):
        try:
            assert_schema_strict(name, registry._documents[name], registry._store)
        except StrictnessError as exc:
            failures.extend(f"{name}: {v}" for v in exc.violations)
    assert not failures, "strictness violations:\n" + "\n".join(failures)


def test_strictness_catches_an_open_object(registry):
    """A schema with an open object shape must fail the walk."""
    bad = {
        "$id": "https://agentchaos.invalid/schemas/v1/bad.schema.json",
        "type": "object",
        "properties": {"a": {"type": "string"}},
    }
    with pytest.raises(StrictnessError):
        assert_schema_strict("bad", bad, registry._store)


def test_strictness_catches_true_additional_properties(registry):
    bad = {
        "$id": "https://agentchaos.invalid/schemas/v1/bad.schema.json",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "a": {"type": "object", "additionalProperties": True}
        },
    }
    with pytest.raises(StrictnessError):
        assert_schema_strict("bad", bad, registry._store)


def test_strictness_catches_format_keyword(registry):
    bad = {
        "$id": "https://agentchaos.invalid/schemas/v1/bad.schema.json",
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "string", "format": "date-time"}},
    }
    with pytest.raises(StrictnessError):
        assert_schema_strict("bad", bad, registry._store)


def test_strictness_catches_required_without_property(registry):
    bad = {
        "$id": "https://agentchaos.invalid/schemas/v1/bad.schema.json",
        "type": "object",
        "additionalProperties": False,
        "required": ["missing"],
        "properties": {"a": {"type": "string"}},
    }
    with pytest.raises(StrictnessError):
        assert_schema_strict("bad", bad, registry._store)
