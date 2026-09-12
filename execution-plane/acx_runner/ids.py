"""Runtime id minting for runs and environments.

Ids follow the shared contract patterns (`run_` plus hex, `env_` plus
kebab-case). Randomness is fine here: these ids identify executions,
and the export binds them to the plan digest for audit.
"""

from __future__ import annotations

import secrets

_RUN_SUFFIX_CHARS = 16
_ENV_SUFFIX_CHARS = 12


def mint_run_id() -> str:
    return "run_" + secrets.token_hex(_RUN_SUFFIX_CHARS // 2)


def mint_environment_id() -> str:
    return "env_lfx-" + secrets.token_hex(_ENV_SUFFIX_CHARS // 2)


def is_run_id(value: str) -> bool:
    from acx_runner.patterns import RUN_ID

    return isinstance(value, str) and RUN_ID.match(value) is not None


def is_evidence_event_id(value: str) -> bool:
    from acx_runner.patterns import EVIDENCE_EVENT_ID

    return (
        isinstance(value, str)
        and EVIDENCE_EVENT_ID.match(value) is not None
    )


def is_scenario_version_id(value: str) -> bool:
    from acx_runner.patterns import SCENARIO_VERSION_ID

    return (
        isinstance(value, str)
        and SCENARIO_VERSION_ID.match(value) is not None
    )
