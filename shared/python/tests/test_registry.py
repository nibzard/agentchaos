"""Registry integrity: every entry resolves, ids match, kinds map."""

import pytest

from acx_schemas.errors import UnknownResourceKind


def test_registry_covers_every_resource(registry):
    expected = {
        "WorkloadVersion",
        "AutonomyProfile",
        "ScenarioVersion",
        "Experiment",
        "Run",
        "Delegation",
        "Effect",
        "EvidenceEvent",
        "Finding",
        "AssuranceClaim",
        "Target",
        "StopReport",
    }
    assert set(registry.known_kinds) == expected


def test_unknown_kind_fails_closed(registry):
    with pytest.raises(UnknownResourceKind):
        registry.validate({}, "DefinitelyNotAResource")


def test_common_has_no_resource_kind(registry):
    document = registry.document("common")
    assert "const" not in document.get("properties", {}).get("kind", {})


def test_every_resource_schema_requires_kind_api_version_and_tenant(registry):
    """Every resource carries identity and tenancy (spec 18.3)."""
    for kind in registry.known_kinds:
        document = registry.document(registry.schema_name(kind))
        required = set(document.get("required", []))
        assert "kind" in required, kind
        assert "api_version" in required, kind
        assert "tenant_id" in required, kind
