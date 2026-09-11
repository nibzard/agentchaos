"""Fail-closed meta-checks over the contract schemas themselves.

A strict contract must not admit unknown fields. These checks walk
every schema, resolve references, and verify that every object shape
is closed. Task T003's compiler relies on this guarantee; task T042
fuzzes it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

_SUBSCHEMA_ARRAY_KEYWORDS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SUBSCHEMA_KEYWORDS = (
    "additionalProperties",
    "contains",
    "else",
    "if",
    "items",
    "not",
    "patternProperties",
    "propertyNames",
    "then",
)
_PROPERTY_MAP_KEYWORDS = ("properties", "$defs")


class StrictnessError(Exception):
    """Raised when a schema violates the strictness rules."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__("schema strictness violations:\n  " + "\n  ".join(violations))


def _resolve_ref(ref: str, base_uri: str, store: dict[str, Any]) -> tuple[str, Any]:
    uri, _, fragment = ref.partition("#")
    absolute = urljoin(base_uri, uri) if uri else base_uri
    if absolute not in store:
        raise KeyError(absolute)
    node = store[absolute]
    if fragment not in ("", "/"):
        for raw_token in fragment.lstrip("/").split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                node = node[int(token)]
            else:
                node = node[token]
    return absolute, node


def _possible_object(node: dict) -> bool:
    type_keyword = node.get("type")
    if type_keyword == "object":
        return True
    if isinstance(type_keyword, list) and "object" in type_keyword:
        return True
    if "properties" in node or "patternProperties" in node:
        return True
    return False


def _walk(
    node: Any,
    base_uri: str,
    location: str,
    store: dict[str, Any],
    ref_stack: tuple[str, ...],
    violations: list[str],
    defining: bool,
) -> None:
    if not isinstance(node, dict):
        return

    if "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str):
            violations.append(f"{location}: $ref must be a string")
        else:
            try:
                absolute, target = _resolve_ref(ref, base_uri, store)
            except (KeyError, ValueError, IndexError, TypeError) as exc:
                violations.append(f"{location}: unresolvable $ref {ref!r}: {exc}")
            else:
                if absolute in ref_stack:
                    violations.append(
                        f"{location}: circular $ref {ref!r} (cycles are not "
                        "supported in these contracts)"
                    )
                else:
                    target_base = (
                        target.get("$id")
                        if isinstance(target, dict) and "$id" in target
                        else absolute
                    )
                    _walk(
                        target,
                        target_base,
                        f"{location}/$ref({ref})",
                        store,
                        ref_stack + (absolute,),
                        violations,
                        defining,
                    )

    if "format" in node:
        violations.append(
            f"{location}: uses 'format' ({node['format']!r}); contracts use "
            "explicit patterns so validation does not depend on format checkers"
        )
    for banned in ("unevaluatedProperties", "unevaluatedItems"):
        if banned in node:
            violations.append(f"{location}: uses {banned}")

    enum = node.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or len(enum) == 0:
            violations.append(f"{location}: enum must be a non-empty array")

    has_properties = "properties" in node
    has_pattern_properties = "patternProperties" in node
    additional = node.get("additionalProperties", None)

    # Closure rules apply only in defining positions: subschemas that
    # give the shape of an actual value. Applicator conditions (if,
    # then, else, not, contains) add constraints; they cannot open an
    # object that its defining schema closes.
    if defining:
        if has_properties or has_pattern_properties:
            if "additionalProperties" not in node:
                violations.append(
                    f"{location}: declares properties without additionalProperties; "
                    "object shape is open"
                )
            elif additional is True:
                violations.append(
                    f"{location}: additionalProperties is true; object shape is open"
                )
        elif _possible_object(node):
            if "additionalProperties" not in node:
                violations.append(
                    f"{location}: object type without properties or "
                    "additionalProperties; object shape is open"
                )
            elif node["additionalProperties"] is True:
                violations.append(
                    f"{location}: additionalProperties is true; object shape is open"
                )

    required = node.get("required")
    if isinstance(required, list) and has_properties:
        properties = node["properties"]
        for key in required:
            if key not in properties:
                violations.append(
                    f"{location}: required key {key!r} has no property definition"
                )

    for keyword in _PROPERTY_MAP_KEYWORDS:
        for key, sub in node.get(keyword, {}).items():
            _walk(
                sub,
                base_uri,
                f"{location}/{keyword}/{key}",
                store,
                ref_stack,
                violations,
                defining=defining,
            )
    for keyword in _SUBSCHEMA_ARRAY_KEYWORDS:
        for index, sub in enumerate(node.get(keyword, [])):
            _walk(
                sub,
                base_uri,
                f"{location}/{keyword}/{index}",
                store,
                ref_stack,
                violations,
                defining=defining and keyword == "prefixItems",
            )
    for keyword in _SUBSCHEMA_KEYWORDS:
        sub = node.get(keyword)
        if isinstance(sub, dict):
            _walk(
                sub,
                base_uri,
                f"{location}/{keyword}",
                store,
                ref_stack,
                violations,
                defining=defining
                and keyword in ("additionalProperties", "items", "propertyNames"),
            )
        elif isinstance(sub, list):
            for index, entry in enumerate(sub):
                _walk(
                    entry,
                    base_uri,
                    f"{location}/{keyword}/{index}",
                    store,
                    ref_stack,
                    violations,
                    defining=False,
                )


def assert_schema_strict(name: str, document: dict, store: dict[str, Any]) -> None:
    """Assert that one schema document follows the strictness rules.

    Raises StrictnessError listing every violation with its location.
    """
    violations: list[str] = []
    base_uri = document.get("$id", "")
    _walk(document, base_uri, name, store, (), violations, defining=True)
    if violations:
        raise StrictnessError(violations)
