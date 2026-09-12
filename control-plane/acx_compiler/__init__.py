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

from __future__ import annotations

import sys
from pathlib import Path

# The shared contracts package (acx_schemas) sits outside this package's
# tree, at <repo>/shared/python. Add it so importing acx_compiler works
# without a preinstalled acx_schemas — the compiler validates every
# record against the shared contracts and cannot run without them.
_repo_root = Path(__file__).resolve().parents[2]
_shared_python = str(_repo_root / "shared" / "python")
if _shared_python not in sys.path:
    sys.path.insert(0, _shared_python)

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
