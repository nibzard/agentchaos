"""The fault adapter contract (spec 8.2, 9.3, AC-028).

An adapter MUST advertise its capabilities, its unsupported paths, its
interception location, its side-effect semantics, and its cleanup
guarantee. It must pass the conformance suite before the product calls
it contained. The manifest is the advertisement; `conformance.py`
tests that the adapter's behavior keeps every promise the manifest
makes.

Validation is strict and closed: every field is required, unknown
fields fail, and every enumerated value comes from a fixed set. An
adapter that is silent about a fault family is ambiguous, and
ambiguity fails validation here so the conformance suite never has to
guess.
"""

from __future__ import annotations

import re

ADAPTER_ID = re.compile(r"^adp_[a-z0-9]{8,64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

# Fault families an adapter may target (spec 9.3).
FAULT_FAMILIES = frozenset(
    {
        "model_response",
        "tool_result",
        "file",
        "memory_snapshot",
        "peer_channel",
        "permission",
        "dependency",
        "budget",
        "monitor_component",
    }
)

# Where an adapter may sit. Every site is outside the worker: an
# adapter that runs inside the worker cannot emit a receipt the worker
# did not author (spec 9.3, AC-004).
INTERCEPTION_SITES = frozenset(
    {
        "model_client",
        "tool_transport",
        "filesystem",
        "process_boundary",
        "network_edge",
        "harness_service",
    }
)

# Side-effect classes an adapter may declare. `none` means apply
# changes nothing observable; `workspace_write` confines writes to the
# variant workspace; `external_write` reaches outside it.
EFFECT_CLASSES = frozenset({"none", "workspace_write", "external_write"})

# Cleanup guarantees (spec 9.3): what teardown promises to undo.
CLEANUP_GUARANTEES = frozenset(
    {"none", "workspace_restore", "external_undo"}
)

MANIFEST_KEYS = frozenset(
    {
        "kind",
        "api_version",
        "adapter_id",
        "version",
        "capabilities",
        "unsupported_paths",
        "interception_location",
        "side_effect_semantics",
        "logging",
        "cleanup",
    }
)
INTERCEPTION_KEYS = frozenset({"site", "outside_worker", "description"})
EFFECTS_KEYS = frozenset({"declared_effects", "reversible"})
LOGGING_KEYS = frozenset({"emits_injection_receipt", "receipt_fields"})
CLEANUP_KEYS = frozenset({"operation", "guarantee", "verified_by"})

# Receipt fields every adapter must record (AC-004; matches the
# scenario library's injection receipt contract).
REQUIRED_RECEIPT_FIELDS = frozenset(
    {"scenario_version_id", "trigger_state", "receipt_event_id"}
)


class ContractError(ValueError):
    """A manifest violated the adapter contract."""


def _fail(path: str, message: str) -> None:
    raise ContractError(f"{path}: {message}")


def _check_keys(document: dict, expected: frozenset, path: str) -> None:
    if not isinstance(document, dict):
        _fail(path, "must be an object")
    keys = frozenset(document)
    unknown = sorted(keys - expected)
    if unknown:
        _fail(path, f"unknown fields {unknown}")
    missing = sorted(expected - keys)
    if missing:
        _fail(path, f"missing fields {missing}")


def validate_manifest(manifest: dict) -> list[str]:
    """Validate an adapter manifest; return every violation found.

    A list instead of one raised error: an adapter author needs the
    whole repair list at once. Each section reports its first problem
    and validation moves on to the next section.
    """
    errors: list[str] = []
    sections = (
        _validate_header,
        _validate_capabilities,
        _validate_unsupported_paths,
        _validate_interception_location,
        _validate_side_effect_semantics,
        _validate_logging,
        _validate_cleanup,
    )
    for section in sections:
        try:
            section(manifest)
        except ContractError as error:
            errors.append(str(error))
        except (KeyError, TypeError) as error:
            errors.append(f"manifest: malformed at {error!r}")
    return errors


def _validate_header(manifest: dict) -> None:
    _check_keys(manifest, MANIFEST_KEYS, "manifest")
    if manifest["kind"] != "AdapterManifest":
        _fail("manifest.kind", "must be AdapterManifest")
    if manifest["api_version"] != "v1":
        _fail("manifest.api_version", "must be v1")
    if not ADAPTER_ID.match(manifest["adapter_id"]):
        _fail("manifest.adapter_id", "must be adp_ plus 8-64 [a-z0-9]")
    if not VERSION.match(manifest["version"]):
        _fail("manifest.version", "must be semantic x.y.z")


def _validate_capabilities(manifest: dict) -> None:
    capabilities = manifest["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        _fail("manifest.capabilities", "must be a non-empty list")
    for family in capabilities:
        if family not in FAULT_FAMILIES:
            _fail("manifest.capabilities", f"unknown fault family {family!r}")
    if len(set(capabilities)) != len(capabilities):
        _fail("manifest.capabilities", "a family is advertised twice")


def _validate_unsupported_paths(manifest: dict) -> None:
    capabilities = manifest["capabilities"]
    unsupported = manifest["unsupported_paths"]
    if not isinstance(unsupported, list):
        _fail("manifest.unsupported_paths", "must be a list")
    covered = set(capabilities)
    problems: list[str] = []
    for index, entry in enumerate(unsupported):
        path = f"manifest.unsupported_paths[{index}]"
        try:
            _check_keys(entry, frozenset({"family", "reason"}), path)
            if entry["family"] not in FAULT_FAMILIES:
                _fail(path, f"unknown fault family {entry['family']!r}")
            if not isinstance(entry["reason"], str) or not (
                entry["reason"].strip()
            ):
                _fail(path, "needs a reason")
            if entry["family"] in covered:
                _fail(path, "family is both advertised and unsupported")
            covered.add(entry["family"])
        except ContractError as error:
            # Every entry reports, not just the first broken one.
            problems.append(str(error))
    missing = sorted(FAULT_FAMILIES - covered)
    if missing:
        problems.append(
            "manifest: fault families neither advertised nor rejected: "
            f"{missing}"
        )
    if problems:
        _fail("manifest", "; ".join(problems))


def _validate_interception_location(manifest: dict) -> None:
    location = manifest["interception_location"]
    _check_keys(location, INTERCEPTION_KEYS, "manifest.interception_location")
    if location["site"] not in INTERCEPTION_SITES:
        _fail("manifest.interception_location.site", "unknown interception site")
    if location["outside_worker"] is not True:
        _fail("manifest.interception_location.outside_worker",
              "must be true: receipts must come from outside the worker")
    if not isinstance(location["description"], str) or not (
        location["description"].strip()
    ):
        _fail("manifest.interception_location.description",
              "must be a non-empty string")


def _validate_side_effect_semantics(manifest: dict) -> None:
    effects = manifest["side_effect_semantics"]
    _check_keys(effects, EFFECTS_KEYS, "manifest.side_effect_semantics")
    declared = effects["declared_effects"]
    if not isinstance(declared, list) or not declared:
        _fail("manifest.side_effect_semantics.declared_effects",
              "must be a non-empty list")
    for effect in declared:
        if effect not in EFFECT_CLASSES:
            _fail("manifest.side_effect_semantics.declared_effects",
                  f"unknown effect class {effect!r}")
    if not isinstance(effects["reversible"], bool):
        _fail("manifest.side_effect_semantics.reversible", "must be boolean")


def _validate_logging(manifest: dict) -> None:
    logging = manifest["logging"]
    _check_keys(logging, LOGGING_KEYS, "manifest.logging")
    if logging["emits_injection_receipt"] is not True:
        _fail("manifest.logging.emits_injection_receipt",
              "must be true: every adapter emits an injection receipt")
    fields = logging["receipt_fields"]
    if not isinstance(fields, list) or not fields:
        _fail("manifest.logging.receipt_fields", "must be a non-empty list")
    missing_fields = sorted(REQUIRED_RECEIPT_FIELDS - frozenset(fields))
    if missing_fields:
        _fail("manifest.logging.receipt_fields",
              f"missing required fields {missing_fields}")


def _validate_cleanup(manifest: dict) -> None:
    cleanup = manifest["cleanup"]
    _check_keys(cleanup, CLEANUP_KEYS, "manifest.cleanup")
    if cleanup["guarantee"] not in CLEANUP_GUARANTEES:
        _fail("manifest.cleanup.guarantee", "unknown cleanup guarantee")
    for field in ("operation", "verified_by"):
        if not isinstance(cleanup[field], str) or not cleanup[field].strip():
            _fail(f"manifest.cleanup.{field}", "must be a non-empty string")
