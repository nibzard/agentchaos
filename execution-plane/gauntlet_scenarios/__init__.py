"""The initial scenario template library, F01 through F24 (spec 12).

Each template is authored once as data and carries everything spec 12
demands: benign and treatment variants, prerequisites, an injection
receipt contract, an expected observation, independent outcome
assertions, and a cleanup test.

`build_scenario_version` turns a template into a draft ScenarioVersion
document under the shared contract. `LibraryExecutor` plays a
template's deterministic fixture scripts inside the runner. The
scripts model three outcomes per template — the benign run without the
fault, the treatment run where the system under test holds the
property, and a break script where it does not, so every assertion can
be shown to fail, not just to pass.
"""

from gauntlet_scenarios.assertions import AssertionVerdict, verify_outcomes, worst
from gauntlet_scenarios.documents import (
    build_scenario_version,
    fixture_digest,
    scenario_version_id,
)
from gauntlet_scenarios.executor import LibraryExecutor
from gauntlet_scenarios.templates import (
    TEMPLATE_IDS,
    Script,
    Step,
    Template,
    get_template,
    library,
)

from gauntlet_scenarios.lifecycle import (
    DRAFT,
    RELEASED,
    SIGNED,
    VALIDATED,
    Ed25519ReleaseSigner,
    LifecycleError,
    ReleaseRegistry,
    classification_status,
    compatibility_digest,
    content_digest,
    release,
    sign_release,
    validate_isolated,
    verify_release,
)

__all__ = [
    "TEMPLATE_IDS",
    "AssertionVerdict",
    "DRAFT",
    "Ed25519ReleaseSigner",
    "LibraryExecutor",
    "LifecycleError",
    "RELEASED",
    "ReleaseRegistry",
    "SIGNED",
    "Script",
    "Step",
    "Template",
    "VALIDATED",
    "build_scenario_version",
    "classification_status",
    "compatibility_digest",
    "content_digest",
    "fixture_digest",
    "get_template",
    "library",
    "release",
    "scenario_version_id",
    "sign_release",
    "validate_isolated",
    "verify_outcomes",
    "verify_release",
    "worst",
]
