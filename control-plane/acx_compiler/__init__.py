"""Deterministic experiment manifest compiler.

Public surface:

- `compile_manifest` turns an Experiment record plus a ResourceStore
  into a signed plan (spec 9.1).
- `CompileViolation` carries every failure; compilation fails closed.
- `MemoryResourceStore` supplies records for tests and examples.
- `EnrollmentRegistry` owns the explicit target lifecycle (spec 7,
  13.1, AC-002).
- `expand_selectors`, `resolve_selectors`, and `revalidate_selection`
  resolve selectors to an explicit enrolled set and re-check it
  immediately before each injection.
"""

from acx_compiler.compiler import DEFAULT_GRANT_TTL_S, compile_manifest
from acx_compiler.enrollment import (
    EnrollmentError,
    EnrollmentRegistry,
    TRANSITIONS,
)
from acx_compiler.errors import CompileErrorEntry, CompileViolation
from acx_compiler.plan import ArtifactPathCollision, CompiledPlan
from acx_compiler.records import MemoryResourceStore, ResourceStore
from acx_compiler.risk import RiskPolicy, classify_risk
from acx_compiler.selection import (
    PRODUCTION_MODES,
    SelectionOutcome,
    SelectionPolicy,
    expand_selectors,
    resolve_selectors,
    revalidate_selection,
)
from acx_compiler.signing import Ed25519Signer, Signer, verify_signature

__all__ = [
    "DEFAULT_GRANT_TTL_S",
    "ArtifactPathCollision",
    "CompileErrorEntry",
    "CompileViolation",
    "CompiledPlan",
    "EnrollmentError",
    "EnrollmentRegistry",
    "MemoryResourceStore",
    "PRODUCTION_MODES",
    "ResourceStore",
    "RiskPolicy",
    "SelectionOutcome",
    "SelectionPolicy",
    "TRANSITIONS",
    "classify_risk",
    "compile_manifest",
    "Ed25519Signer",
    "expand_selectors",
    "resolve_selectors",
    "revalidate_selection",
    "Signer",
    "verify_signature",
]
