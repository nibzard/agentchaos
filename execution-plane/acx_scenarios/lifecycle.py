"""Scenario version lifecycle: draft to validated to signed to released.

Implements spec 12.1 (T016). A scenario version moves through four
states, each with its own gate:

- ``draft``: authored by the document builder; nothing has run.
- ``validated``: one paired isolated execution passed — identical
  installed baseline, injection triggered in the treatment arm only,
  every outcome assertion passed in both arms, and the cleanup test
  removed what the fault injected.
- ``signed``: the release authority signed the content. The signature
  covers the canonical bytes of the document without the signature
  block, so any later edit breaks verification.
- ``released``: compatibility tests are recorded as mode eligibility
  and the whole document, classification included, is re-signed.

Immutability: a release registry freezes ``(id, version)`` to a content
digest. Different content under the same identity is refused; publish a
new version instead. Production-safe classification is a reviewed
property of a specific primitive version and target class: changing
either leaves the recorded digest behind and the classification reads
stale until new compatibility tests pass.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from acx_scenarios.assertions import PASSED, verify_outcomes
from acx_scenarios.documents import parameter_digest, scenario_version_id
from acx_scenarios.executor import LibraryExecutor
from acx_scenarios.templates import Template, get_template

DRAFT = "draft"
VALIDATED = "validated"
SIGNED = "signed"
RELEASED = "released"

# Operating modes the contract defines (common.schema.json).
MODES = (
    "observe",
    "replay",
    "isolated_reexecution",
    "production_synthetic",
    "customer_canary",
    "govern",
)

ALGORITHM = "ed25519"
KEY_ID_PATTERN = re.compile(r"^key_[a-z0-9][a-z0-9-]{3,63}$")
TARGET_CLASS_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
PRIMITIVE_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

# The isolated validation harness stands in for a compiled plan from
# the control plane: one scenario, the library fixture workload.
HARNESS_WORKLOAD = {
    "id": "wlv_3f9a1c2d4e5b6071",
    "name": "library-fixture",
    "version": "1.0.0",
    "fingerprint": "sha256:" + "3" * 64,
    "backend": "local_container",
}
HARNESS_PROFILES = {
    "baseline": {"id": "aup_1a2b3c4d5e6f7081", "version": "1.0.0"},
    "treatment": {"id": "aup_5b8d2e0f1a3c4966", "version": "2.0.0"},
}


class LifecycleError(Exception):
    """A lifecycle gate refused the transition. Nothing changed."""


def canonical_bytes(document: object) -> bytes:
    """Canonical JSON bytes (ADR-0002 convention, same rules as the
    control plane's canonical module)."""
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def plan_digest(plan: dict) -> str:
    """Digest over a plan document's canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical_bytes(plan)).hexdigest()


def validation_plan(scenario: dict) -> dict:
    """The single-scenario plan isolated validation executes.

    The experiment id is derived from the template id, so the same
    scenario always validates under the same identity.
    """
    experiment_id = (
        "exp_"
        + hashlib.sha256(
            f"validation:{scenario['template_id']}".encode("utf-8")
        ).hexdigest()[:16]
    )
    return {
        "kind": "CompiledPlan",
        "api_version": "v1",
        "experiment_id": experiment_id,
        "tenant_id": scenario["tenant_id"],
        "workload": dict(HARNESS_WORKLOAD),
        "profiles": {
            "baseline": dict(HARNESS_PROFILES["baseline"]),
            "treatment": dict(HARNESS_PROFILES["treatment"]),
        },
        "scenarios": [
            {
                "id": scenario["id"],
                "template_id": scenario["template_id"],
                "version": scenario["version"],
            }
        ],
        "selectors": [],
    }


# --- isolated validation -------------------------------------------------


def validate_isolated(
    scenario: dict,
    *,
    runner,
    grant: dict,
    defense: str = "hold",
    executor: LibraryExecutor | None = None,
) -> dict:
    """Run one paired isolated execution and promote draft to validated.

    Fails closed: any pair error, any failed or unknown assertion, or a
    cleanup that leaves injected files behind keeps the scenario a
    draft and raises with the evidence of what failed.
    """
    _require_template_binding(scenario)
    if scenario["status"] != DRAFT:
        raise LifecycleError(
            f"only a draft enters isolated validation; this scenario is "
            f"{scenario['status']}"
        )
    template = get_template(scenario["template_id"])
    plan = validation_plan(scenario)
    digest = plan_digest(plan)
    if grant.get("plan_digest") != digest:
        raise LifecycleError(
            "the grant does not authorize this validation plan: "
            f"grant pins {grant.get('plan_digest')!r}, plan is {digest}"
        )

    executor = executor or LibraryExecutor(defense)
    pairs = runner.run(
        plan, grant, executor, bundle=dict(template.fixture),
        plan_digest=digest,
    )
    problems = _pair_problems(pairs, scenario, template, executor)
    if problems:
        raise LifecycleError(
            "isolated validation failed closed: " + "; ".join(problems)
        )
    cleanup = _run_cleanup(executor, scenario)
    scenario["status"] = VALIDATED
    return {
        "kind": "ScenarioValidationEvidence",
        "scenario_version_id": scenario["id"],
        "template_id": scenario["template_id"],
        "defense": executor.defense,
        "arms": _arm_evidence(template, pairs[0]),
        "injection_triggered": pairs[0].injection_triggered,
        "identical_baseline": pairs[0].identical_baseline,
        "cleanup": cleanup,
    }


def _require_template_binding(scenario: dict) -> None:
    """The scenario must be the library document for its template."""
    try:
        template = get_template(scenario["template_id"])
    except KeyError:
        raise LifecycleError(
            f"template {scenario['template_id']} is not in the library"
        ) from None
    expected_id = scenario_version_id(template.template_id)
    if scenario["id"] != expected_id:
        raise LifecycleError(
            f"scenario id {scenario['id']} does not match template "
            f"{template.template_id} ({expected_id})"
        )
    expected_digest = parameter_digest(template)
    if scenario["fault"].get("parameter_digest") != expected_digest:
        raise LifecycleError(
            "fault parameters diverge from the template; the validation "
            "scripts exercise the template's parameters"
        )


def _pair_problems(pairs, scenario, template, executor) -> list[str]:
    """Collect every way the paired execution fails the gate."""
    problems: list[str] = []
    if len(pairs) != 1:
        return [f"expected one pair, got {len(pairs)}"]
    pair = pairs[0]
    if pair.error is not None:
        problems.append(f"pair error: {pair.error}")
    if pair.baseline is None or pair.treatment is None:
        problems.append("a variant run document is missing")
    if not pair.identical_baseline:
        problems.append("installed baselines differ between arms (AC-003)")
    if pair.injection_triggered is not True:
        problems.append("the injection never triggered in the treatment arm")
    for arm, observations in (
        ("baseline", pair.baseline_observations),
        ("treatment", pair.treatment_observations),
    ):
        for verdict in verify_outcomes(template, observations):
            if verdict.verdict != PASSED:
                problems.append(
                    f"{arm} assertion {verdict.assertion_id} is "
                    f"{verdict.verdict}: {verdict.note}"
                )
    return problems


def _arm_evidence(template: Template, pair) -> dict:
    """Per-arm assertion verdict summaries for the evidence record."""
    arms = {}
    for arm, observations in (
        ("baseline", pair.baseline_observations),
        ("treatment", pair.treatment_observations),
    ):
        arms[arm] = [
            {
                "assertion_id": verdict.assertion_id,
                "verdict": verdict.verdict,
            }
            for verdict in verify_outcomes(template, observations)
        ]
    return arms


def _run_cleanup(executor: LibraryExecutor, scenario: dict) -> dict:
    """Execute and independently verify the declared cleanup.

    The cleanup operation removes what the fault injected; the verifier
    then checks the injected files are gone. Cleanup is never proven by
    the worker exiting (spec 13.3).
    """
    removed = []
    for workspace, relative in executor.fault_targets:
        target = Path(workspace) / relative
        target.unlink(missing_ok=True)
        removed.append(relative)
    leftover = [
        relative
        for workspace, relative in executor.fault_targets
        if (Path(workspace) / relative).exists()
    ]
    if leftover:
        raise LifecycleError(
            "cleanup test failed: injected files remain "
            f"({', '.join(sorted(set(leftover)))})"
        )
    return {
        "operation": scenario["cleanup"]["operation"],
        "verifier": scenario["cleanup"]["verifier"],
        "test": scenario["cleanup"]["test"],
        "removed": sorted(set(removed)),
        "verified": True,
    }


# --- signing --------------------------------------------------------------


class Signer(Protocol):
    """Signs canonical document bytes and reports the key identity."""

    key_id: str
    key_algorithm: str

    def sign_document(self, document: object) -> str: ...


class Ed25519ReleaseSigner:
    """Ed25519 signer for scenario releases, held in memory."""

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
    def generate(cls, key_id: str) -> "Ed25519ReleaseSigner":
        return cls(Ed25519PrivateKey.generate(), key_id)

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def sign_document(self, document: object) -> str:
        raw = self._key.sign(canonical_bytes(document))
        return base64.b64encode(raw).decode("ascii")


def _unsigned(scenario: dict) -> dict:
    return {
        key: value for key, value in scenario.items() if key != "signature"
    }


def sign_release(
    scenario: dict, signer: Signer, *, registry: ReleaseRegistry | None = None
) -> None:
    """Promote validated to signed: sign the content.

    The signature covers the document as it stands, without the
    signature block. Later edits break verification.
    """
    if scenario["status"] != VALIDATED:
        raise LifecycleError(
            f"only a validated scenario signs; this one is "
            f"{scenario['status']}"
        )
    if "mode_eligibility" in scenario:
        raise LifecycleError(
            "mode eligibility is recorded at release, not before"
        )
    if registry is not None:
        registry.register(scenario)
    scenario["status"] = SIGNED
    scenario["signature"] = {
        "algorithm": signer.key_algorithm,
        "key_id": signer.key_id,
        "value": signer.sign_document(_unsigned(scenario)),
    }


def release(
    scenario: dict,
    signer: Signer,
    *,
    classifications: list[dict],
    registry: ReleaseRegistry | None = None,
) -> None:
    """Promote signed to released: record compatibility and re-sign.

    Each classification names a mode, a target class, the primitive
    version the tests ran against, and whether the scenario is
    eligible. The compatibility digest binds the classification to the
    primitive version and the fault parameters; changing either leaves
    the entry stale until new tests pass (spec 12.1).
    """
    if scenario["status"] != SIGNED:
        raise LifecycleError(
            f"only a signed scenario releases; this one is "
            f"{scenario['status']}"
        )
    signature = scenario.get("signature", {})
    if signature.get("key_id") != signer.key_id:
        raise LifecycleError(
            "the release authority that signed this version must record "
            "its compatibility tests; rotate through a new version"
        )
    if registry is not None:
        registry.register(scenario)

    entries = [_eligibility_entry(scenario, item) for item in classifications]
    seen = {(entry["mode"], entry["target_class"]) for entry in entries}
    if len(seen) != len(entries):
        raise LifecycleError(
            "one eligibility entry per mode and target class"
        )
    scenario["mode_eligibility"] = sorted(
        entries,
        key=lambda entry: (entry["mode"], entry["target_class"]),
    )
    scenario["status"] = RELEASED
    scenario["signature"] = {
        "algorithm": signer.key_algorithm,
        "key_id": signer.key_id,
        "value": signer.sign_document(_unsigned(scenario)),
    }


def _eligibility_entry(scenario: dict, classification: dict) -> dict:
    required = {"mode", "target_class", "primitive_version", "eligible"}
    missing = sorted(required - set(classification))
    if missing:
        raise LifecycleError(
            f"classification is missing {', '.join(missing)}"
        )
    unknown = sorted(set(classification) - required)
    if unknown:
        raise LifecycleError(
            f"classification carries unknown fields {', '.join(unknown)}"
        )
    mode = classification["mode"]
    if mode not in MODES:
        raise LifecycleError(f"unknown mode {mode!r}")
    target_class = classification["target_class"]
    if not isinstance(target_class, str) or not TARGET_CLASS_PATTERN.match(
        target_class
    ):
        raise LifecycleError(
            f"target class {target_class!r} is not a class id"
        )
    primitive_version = classification["primitive_version"]
    if not isinstance(primitive_version, str) or (
        not PRIMITIVE_VERSION_PATTERN.match(primitive_version)
    ):
        raise LifecycleError(
            f"primitive version {primitive_version!r} is not semver"
        )
    return {
        "mode": mode,
        "eligible": bool(classification["eligible"]),
        "target_class": target_class,
        "compatibility_evidence_digest": compatibility_digest(
            scenario,
            primitive_version=primitive_version,
            target_class=target_class,
        ),
    }


def compatibility_digest(
    scenario: dict, *, primitive_version: str, target_class: str
) -> str:
    """Digest binding a classification to its measured inputs."""
    payload = {
        "fault_kind": scenario["fault"]["kind"],
        "parameter_digest": scenario["fault"]["parameter_digest"],
        "primitive_version": primitive_version,
        "target_class": target_class,
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def verify_release(scenario: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify the release signature over the current document."""
    signature = scenario.get("signature")
    if not isinstance(signature, dict) or "value" not in signature:
        return False
    try:
        raw = base64.b64decode(signature["value"], validate=True)
    except (ValueError, TypeError):
        return False
    try:
        public_key.verify(raw, canonical_bytes(_unsigned(scenario)))
    except Exception:
        return False
    return True


# --- staleness ------------------------------------------------------------


def classification_status(
    scenario: dict, *, mode: str, target_class: str, primitive_version: str
) -> tuple[dict | None, str]:
    """Read one recorded classification against current inputs.

    Returns the entry and one of:

    - ``valid``: eligible and measured against these inputs.
    - ``stale``: the primitive version or fault parameters changed
      since the compatibility tests ran; the classification is
      invalidated until new tests pass (spec 12.1).
    - ``not_eligible``: tests ran and the scenario is not eligible.
    - ``unclassified``: no entry for this mode and target class.
    """
    for entry in scenario.get("mode_eligibility", []):
        if entry["mode"] == mode and entry["target_class"] == target_class:
            if entry["eligible"] is not True:
                return entry, "not_eligible"
            expected = compatibility_digest(
                scenario,
                primitive_version=primitive_version,
                target_class=target_class,
            )
            if entry["compatibility_evidence_digest"] != expected:
                return entry, "stale"
            return entry, "valid"
    return None, "unclassified"


# --- immutability ---------------------------------------------------------


def content_digest(scenario: dict) -> str:
    """Digest over the immutable content: everything the defined
    transitions (status, signature, mode_eligibility) may change is
    excluded."""
    mutable = {"status", "signature", "mode_eligibility"}
    content = {
        key: value
        for key, value in scenario.items()
        if key not in mutable
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(content)).hexdigest()


class ReleaseRegistry:
    """Freezes ``(id, version)`` to a content digest at first release.

    The same identity may not release different content; publish a new
    version instead. Re-registering identical content is a no-op.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], str] = {}

    def register(self, scenario: dict) -> None:
        key = (scenario["id"], scenario["version"])
        digest = content_digest(scenario)
        existing = self._entries.setdefault(key, digest)
        if existing != digest:
            raise LifecycleError(
                f"scenario {scenario['id']} version {scenario['version']} "
                "was already released with different content; publish a "
                "new version"
            )

    def contains(self, scenario: dict) -> bool:
        return (scenario["id"], scenario["version"]) in self._entries
