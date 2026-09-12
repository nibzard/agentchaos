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

`SandboxGenerator` (T054) adds generated long-horizon scenarios: pure
spec in, deterministic scenarios out, stored as digest-verified
artifacts, gated by containment before scheduling, split between
public suites and private holdouts, and minimized into fixtures that
refuse training-data or public-example use without an explicit data
authorization.
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

from gauntlet_scenarios.production import (
    CLEAN,
    DIRTY_QUARANTINED,
    POPULATION,
    UNKNOWN,
    Enrollment,
    IndependentKillPath,
    PrimitiveRegistry,
    ProductionRefusal,
    ProductionSession,
    ProductionSyntheticMode,
    RecordingProductionPath,
    SinkCleanupVerifier,
    separate_statistics,
)

from gauntlet_scenarios.generated import (
    CONTAINED,
    ESCAPE,
    MIN_HORIZON,
    RESTRICTED_USES,
    SUITE_PRIVATE_HOLDOUT,
    SUITE_PUBLIC,
    GeneratedScenarioError,
    GenerationSpec,
    SandboxGenerator,
    SuiteRegistry,
    authorize_use,
    check_use,
    evaluate_containment,
    load_artifact,
    minimize_to_fixture,
    scenario_digest,
    schedule,
)

__all__ = [
    "CONTAINED",
    "ESCAPE",
    "MIN_HORIZON",
    "RESTRICTED_USES",
    "SUITE_PRIVATE_HOLDOUT",
    "SUITE_PUBLIC",
    "TEMPLATE_IDS",
    "AssertionVerdict",
    "CLEAN",
    "DIRTY_QUARANTINED",
    "DRAFT",
    "Ed25519ReleaseSigner",
    "Enrollment",
    "GeneratedScenarioError",
    "GenerationSpec",
    "IndependentKillPath",
    "LibraryExecutor",
    "LifecycleError",
    "POPULATION",
    "PrimitiveRegistry",
    "ProductionRefusal",
    "ProductionSession",
    "ProductionSyntheticMode",
    "RELEASED",
    "RecordingProductionPath",
    "ReleaseRegistry",
    "SIGNED",
    "SandboxGenerator",
    "Script",
    "SinkCleanupVerifier",
    "Step",
    "SuiteRegistry",
    "Template",
    "UNKNOWN",
    "VALIDATED",
    "authorize_use",
    "build_scenario_version",
    "check_use",
    "classification_status",
    "compatibility_digest",
    "content_digest",
    "evaluate_containment",
    "fixture_digest",
    "get_template",
    "library",
    "load_artifact",
    "minimize_to_fixture",
    "release",
    "scenario_digest",
    "scenario_version_id",
    "schedule",
    "separate_statistics",
    "sign_release",
    "validate_isolated",
    "verify_outcomes",
    "verify_release",
    "worst",
]
