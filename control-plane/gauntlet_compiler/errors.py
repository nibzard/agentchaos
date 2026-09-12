"""Compiler failures.

Compilation fails closed. Every problem is collected into one violation
with a code, a JSON path, and a message. Nothing is a warning that
execution may ignore (spec 9.1).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompileErrorEntry:
    """One compile failure."""

    code: str
    message: str
    path: str = "$"

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "path": self.path}


class CompileViolation(Exception):
    """Raised when a manifest cannot compile. Carries every failure."""

    def __init__(self, entries: list[CompileErrorEntry]):
        self.entries = list(entries)
        summary = "; ".join(f"{e.code}: {e.message}" for e in self.entries)
        super().__init__(f"manifest compilation failed ({summary})")

    def as_dict(self) -> dict:
        return {"errors": [e.as_dict() for e in self.entries]}
