"""Load the AgentChaos contract registry and build validators.

The registry file shared/schemas/registry.json lists every contract.
Each resource schema declares its resource kind through a ``kind``
const, which this loader verifies against the registry entry. Cross-
file references resolve against the shared common.schema.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

from acx_schemas.errors import ContractErrorEntry, ContractViolation, UnknownResourceKind

_PACKAGE_ROOT = Path(__file__).resolve().parent
SCHEMA_DIR = _PACKAGE_ROOT.parent.parent / "schemas"


def _format_path(path) -> str:
    """Render a jsonschema error path as a stable JSON-pointer-like string."""
    parts = list(path)
    if not parts:
        return "$"
    rendered = "$"
    for part in parts:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}"
    return rendered


class ContractRegistry:
    """A loaded set of resource contracts with fail-closed lookup."""

    def __init__(self, schema_dir: Path):
        self.schema_dir = schema_dir
        registry_file = schema_dir / "registry.json"
        if not registry_file.is_file():
            raise FileNotFoundError(f"contract registry not found: {registry_file}")
        self._registry = json.loads(registry_file.read_text(encoding="utf-8"))

        self._documents: dict[str, dict] = {}
        self._by_kind: dict[str, str] = {}
        self._by_name: dict[str, str] = {}

        for entry in self._registry["schemas"]:
            name = entry["name"]
            schema_path = schema_dir / entry["file"]
            document = json.loads(schema_path.read_text(encoding="utf-8"))
            if document.get("$id") != entry["$id"]:
                raise ValueError(
                    f"registry $id mismatch for {name}: "
                    f"file declares {document.get('$id')!r}, "
                    f"registry declares {entry['$id']!r}"
                )
            declared_kind = entry["resource_kind"]
            if declared_kind is not None:
                const_kind = (
                    document.get("properties", {}).get("kind", {}).get("const")
                )
                if const_kind != declared_kind:
                    raise ValueError(
                        f"kind const mismatch for {name}: schema declares "
                        f"{const_kind!r}, registry declares {declared_kind!r}"
                    )
                self._by_kind[declared_kind] = name
            if name in self._by_name:
                raise ValueError(f"duplicate schema name in registry: {name}")
            self._by_name[name] = name
            self._documents[name] = document

        self._store = {
            document["$id"]: document for document in self._documents.values()
        }
        self._validators: dict[str, Draft202012Validator] = {}

    @property
    def known_kinds(self) -> list[str]:
        return sorted(self._by_kind)

    def schema_name(self, kind: str) -> str:
        """Return the registry schema name for a resource kind."""
        try:
            return self._by_kind[kind]
        except KeyError:
            raise UnknownResourceKind(kind, self.known_kinds) from None

    def document(self, name: str) -> dict:
        try:
            return self._documents[name]
        except KeyError:
            raise UnknownResourceKind(name, self.known_kinds) from None

    def validator_for_kind(self, kind: str) -> Draft202012Validator:
        return self._validator(kind, self._by_kind, "resource kind", UnknownResourceKind)

    def validator_for_name(self, name: str) -> Draft202012Validator:
        return self._validator(name, self._by_name, "schema name", UnknownResourceKind)

    def _validator(self, key, table, label, missing_type) -> Draft202012Validator:
        cached = self._validators.get(key)
        if cached is not None:
            return cached
        if key not in table:
            raise missing_type(key, list(table))
        name = table[key]
        document = self._documents[name]
        resolver = RefResolver(
            base_uri=document["$id"], referrer=document, store=self._store
        )
        validator = Draft202012Validator(document, resolver=resolver)
        self._validators[key] = validator
        return validator

    def validate(self, instance: dict, kind: str) -> None:
        """Validate an instance against the contract for ``kind``.

        Fail closed: an unknown kind is an error, and every schema
        violation is reported. Returns None on success.
        """
        validator = self.validator_for_kind(kind)
        entries = [
            ContractErrorEntry(
                path=_format_path(error.absolute_path),
                message=error.message,
                schema_path=_format_path(error.absolute_schema_path),
            )
            for error in sorted(
                validator.iter_errors(instance),
                key=lambda e: (list(e.absolute_path), e.message),
            )
        ]
        if entries:
            raise ContractViolation(kind, entries)


def default_registry(schema_dir: Path | None = None) -> ContractRegistry:
    """Load the contract registry from the repository checkout."""
    return ContractRegistry(schema_dir if schema_dir is not None else SCHEMA_DIR)
