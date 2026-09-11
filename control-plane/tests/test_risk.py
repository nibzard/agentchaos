"""Risk classification is a pure, predictable function."""

import pytest

from acx_compiler.risk import classify_risk


def test_isolated_conservate_setup_is_low():
    assert (
        classify_risk(
            "isolated_reexecution",
            [["A0", "A1"], ["A0", "A1"]],
            "synthetic_dedicated",
            ["synthetic"],
        )
        == "low"
    )


def test_a2_arm_raises_one_step():
    assert (
        classify_risk(
            "isolated_reexecution",
            [["A0", "A1"], ["A0", "A2"]],
            "synthetic_dedicated",
            ["synthetic"],
        )
        == "moderate"
    )


def test_real_identities_raise_one_step():
    assert (
        classify_risk(
            "isolated_reexecution",
            [["A0"], ["A0"]],
            "enrolled_opt_in",
            ["synthetic"],
        )
        == "moderate"
    )


def test_enrolled_service_sink_raises_one_step():
    assert (
        classify_risk(
            "isolated_reexecution",
            [["A0"], ["A0"]],
            "synthetic_dedicated",
            ["enrolled_service"],
        )
        == "moderate"
    )


def test_production_synthetic_starts_moderate():
    assert (
        classify_risk(
            "production_synthetic",
            [["A0"], ["A0"]],
            "synthetic_dedicated",
            ["synthetic"],
        )
        == "moderate"
    )


def test_customer_canary_is_always_high():
    assert (
        classify_risk(
            "customer_canary",
            [["A0"], ["A0"]],
            "enrolled_opt_in",
            ["synthetic"],
        )
        == "high"
    )


def test_classification_capped_at_high():
    assert (
        classify_risk(
            "production_synthetic",
            [["A0", "A2"], ["A2"]],
            "enrolled_opt_in",
            ["enrolled_service"],
        )
        == "high"
    )


@pytest.mark.parametrize(
    "mode", ["observe", "replay", "isolated_reexecution", "govern"]
)
def test_all_safe_modes_start_low(mode):
    assert (
        classify_risk(mode, [["A0"], ["A0"]], "synthetic_dedicated", ["synthetic"])
        == "low"
    )
