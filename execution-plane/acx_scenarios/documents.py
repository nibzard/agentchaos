"""ScenarioVersion documents built from templates (spec 18.1, 12.1).

The document builder is deterministic: the same template, tenant, and
timestamp always produce the same document, including ids and digests.
The lifecycle tasks (T016) move these drafts through validation,
signing, and release; this module only authors the draft.
"""

from __future__ import annotations

import hashlib
import json

from acx_scenarios.templates import Template

SCENARIO_VERSION = "1.0.0"


def _hex(seed: str, length: int = 16) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:length]


def scenario_version_id(template_id: str) -> str:
    """Deterministic scenario id for a template."""
    return "scn_" + _hex(f"scenario:{template_id}")


def fixture_digest(template: Template) -> str:
    """Digest over the template's installed fixture bundle.

    Every declared variant shares this digest: the runner installs the
    same bundle in both arms and the arm difference is the injected
    fault, never a different baseline (AC-003).
    """
    manifest = "\n".join(
        f"{path}\n{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
        for path, content in sorted(template.fixture.items())
    )
    return "sha256:" + hashlib.sha256(
        manifest.encode("utf-8")
    ).hexdigest()


def parameter_digest(template: Template) -> str:
    """Digest over the fault parameters in canonical JSON."""
    canonical = json.dumps(
        template.fault_parameters, sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def build_scenario_version(
    template: Template,
    *,
    tenant_id: str,
    created_at: str,
) -> dict:
    """Build the draft ScenarioVersion document for a template."""
    fixture = fixture_digest(template)
    return {
        "kind": "ScenarioVersion",
        "api_version": "v1",
        "id": scenario_version_id(template.template_id),
        "tenant_id": tenant_id,
        "template_id": template.template_id,
        "version": SCENARIO_VERSION,
        "description": (
            f"{template.fault_summary} Tests: "
            f"{template.property_under_test}."
        ),
        "status": "draft",
        "fault": {
            "kind": template.fault_kind,
            "parameters": dict(template.fault_parameters),
            "parameter_digest": parameter_digest(template),
        },
        "variants": [
            {
                "id": variant.id,
                "kind": variant.kind,
                "description": variant.description,
                "fixture_digest": fixture,
            }
            for variant in template.variants
        ],
        "prerequisites": list(template.prerequisites),
        "injection_receipt": {
            "emitted_by": "adapter_outside_worker",
            "fields": list(template.receipt_fields),
        },
        "expected_observation": template.expected_observation,
        "outcome_assertions": [
            {
                "id": assertion.id,
                "kind": assertion.kind,
                "independent_of_monitor": True,
                "description": assertion.description,
                "evidence_event_kind": assertion.evidence_event_kind,
            }
            for assertion in template.assertions
        ],
        "cleanup": {
            "operation": template.cleanup_operation,
            "verifier": "independent_cleanup_verifier",
            "test": template.cleanup_test,
        },
        "created_at": created_at,
    }
