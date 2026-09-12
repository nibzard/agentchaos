"""Local fixture runner for Gauntlet experiments (spec 9.2).

Public surface:

- `FixtureRunner` executes baseline and treatment variants per
  scenario, in fresh disposable environments, under a short-lived
  grant.
- `VariantExecutor` is the plug point for workload execution; the
  executor receives a `VariantSpec` and returns a `VariantOutcome`.
- `build_export` pairs the results with the workload fingerprint and
  plan digest; `write_export` persists the bundle.
"""

from acx_runner.environments import (
    Environment,
    InstallError,
    LocalFixtureEnvironments,
)
from acx_runner.export import build_export, write_export
from acx_runner.outcomes import (
    MAX_INJECTIONS,
    normalize_injections,
    provisional_outcome,
    terminal_state_for,
)
from acx_runner.runner import (
    FixtureRunner,
    GrantExpired,
    PairedRun,
    VariantExecutor,
    VariantOutcome,
    VariantSpec,
    utc_now,
)

__all__ = [
    "Environment",
    "FixtureRunner",
    "GrantExpired",
    "InstallError",
    "LocalFixtureEnvironments",
    "MAX_INJECTIONS",
    "PairedRun",
    "VariantExecutor",
    "VariantOutcome",
    "VariantSpec",
    "build_export",
    "normalize_injections",
    "provisional_outcome",
    "terminal_state_for",
    "utc_now",
    "write_export",
]
