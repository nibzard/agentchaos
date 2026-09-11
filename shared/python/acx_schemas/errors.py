"""Error types for contract validation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContractErrorEntry:
    """One validation failure at a concrete location in the instance."""

    path: str
    message: str
    schema_path: str

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "message": self.message,
            "schema_path": self.schema_path,
        }


class ContractViolation(Exception):
    """Raised when an instance does not conform to its contract.

    Errors are structured so callers can fail closed on the exact
    violation instead of parsing a message string.
    """

    def __init__(self, kind: str, errors: list[ContractErrorEntry]):
        self.kind = kind
        self.errors = errors
        rendered = "; ".join(f"{e.path}: {e.message}" for e in errors)
        super().__init__(f"{kind} contract violation: {rendered}")

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "errors": [e.as_dict() for e in self.errors],
        }


class UnknownResourceKind(Exception):
    """Raised when a kind has no registered contract."""

    def __init__(self, kind: str, known: list[str]):
        self.kind = kind
        self.known = known
        super().__init__(
            f"unknown resource kind {kind!r}; known kinds: {', '.join(sorted(known))}"
        )
