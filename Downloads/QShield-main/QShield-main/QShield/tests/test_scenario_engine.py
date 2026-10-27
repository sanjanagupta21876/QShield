"""Unit tests for core/scenario_engine.py."""

import pytest
from core.scenario_engine import calculate_planning_margin, simulate_quantum_threat_scenario


def test_calculate_planning_margin_formula():
    """Verify Planning Margin = Z - (X + Y)."""
    # Negative margin: X=6, Y=3, Z=7 -> 7 - (6 + 3) = -2
    assert calculate_planning_margin(confidentiality_years_x=6, migration_years_y=3, horizon_years_z=7) == -2

    # Zero buffer: X=5, Y=2, Z=7 -> 7 - (5 + 2) = 0
    assert calculate_planning_margin(confidentiality_years_x=5, migration_years_y=2, horizon_years_z=7) == 0

    # Positive buffer: X=3, Y=2, Z=7 -> 7 - (3 + 2) = 2
    assert calculate_planning_margin(confidentiality_years_x=3, migration_years_y=2, horizon_years_z=7) == 2


def test_empty_assets_scenario():
    result = simulate_quantum_threat_scenario(assets=[], target_year=2033, current_year=2026)
    assert result["total_assets_evaluated"] == 0
    assert result["exposed_assets_count"] == 0
    assert result["exposure_percentage"] == 0.0
    assert "heuristic_disclaimer" in result


def test_scenario_planning_margin_classification():
    """Test scenario evaluation with negative, zero, and positive planning margins."""
    current_year = 2026
    target_year = 2033  # Z = 7 years
    migration_y = 2     # Y = 2 years

    assets = [
        # Asset 1: RSA with X=6. Margin = 7 - (6 + 2) = -1 (Negative Margin -> Exposed)
        {
            "id": 1,
            "name": "Legacy RSA Key Exchange",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 6,
        },
        # Asset 2: RSA with X=5. Margin = 7 - (5 + 2) = 0 (Zero Buffer)
        {
            "id": 2,
            "name": "Borderline RSA Key",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 5,
        },
        # Asset 3: RSA with X=2. Margin = 7 - (2 + 2) = +3 (Positive Margin)
        {
            "id": 3,
            "name": "Short-lived RSA Key",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 2,
        },
        # Asset 4: ML-KEM with X=8. Margin = 7 - (8 + 2) = -3, but quantum-resilient (NOT exposed)
        {
            "id": 4,
            "name": "Post-Quantum Gateway",
            "crypto_algorithm": "ML-KEM",
            "crypto_role": "Key Establishment",
            "key_size": 768,
            "data_shelf_life_years": 8,
        },
    ]

    result = simulate_quantum_threat_scenario(
        assets=assets,
        target_year=target_year,
        migration_duration_years=migration_y,
        current_year=current_year,
    )

    assert result["threat_horizon_years_Z"] == 7
    assert result["migration_duration_years_Y"] == 2
    assert result["total_assets_evaluated"] == 4

    # Margin counts
    assert result["negative_margin_count"] == 2  # Asset 1 (-1) and Asset 4 (-3)
    assert result["zero_margin_count"] == 1      # Asset 2 (0)
    assert result["positive_margin_count"] == 1  # Asset 3 (+3)

    # Exposed assets: only Asset 1 (quantum vulnerable AND negative margin)
    assert result["exposed_assets_count"] == 1
    assert result["vulnerable_assets"][0]["id"] == 1
    assert result["vulnerable_assets"][0]["planning_margin"] == -1
    assert result["vulnerable_assets"][0]["buffer_status"] == "NEGATIVE_MARGIN"


def test_unknown_algorithm_not_counted_as_confirmed_exposure():
    """Verify unknown/unclassified algorithms are categorized as requires_assessment and NOT confirmed exposed."""
    assets = [
        {
            "id": 101,
            "name": "Proprietary Core Cipher",
            "crypto_algorithm": "UnknownCustomCipherX",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,  # Negative margin: 7 - (10 + 2) = -5
        },
        {
            "id": 102,
            "name": "Classical RSA Exchange",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 10,  # Negative margin: 7 - (10 + 2) = -5
        },
    ]

    result = simulate_quantum_threat_scenario(
        assets=assets,
        target_year=2033,  # Z = 7
        migration_duration_years=2,  # Y = 2
        current_year=2026,
    )

    assert result["total_assets_evaluated"] == 2
    assert result["negative_margin_count"] == 2

    # Confirmed exposed: only the known quantum-vulnerable primitive (RSA)
    assert result["confirmed_exposed_assets_count"] == 1
    assert result["exposed_assets_count"] == 1
    assert result["confirmed_exposed_assets"][0]["id"] == 102

    # Unknown mechanism: tracked under requires_assessment
    assert result["requires_assessment_count"] == 1
    assert result["requires_assessment_negative_margin_count"] == 1
    assert result["requires_assessment_assets"][0]["id"] == 101


def test_different_threat_years_and_margins():
    """Verify horizon year variation shifts planning margins by exactly the year delta."""
    assets = [
        {
            "id": 1,
            "name": "Database Transport",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 5,
        }
    ]

    # Z = 2028 - 2026 = 2. Margin = 2 - (5 + 3) = -6
    res_2028 = simulate_quantum_threat_scenario(assets, target_year=2028, migration_duration_years=3, current_year=2026)
    assert res_2028["threat_horizon_years_Z"] == 2
    assert res_2028["evaluated_assets"][0]["planning_margin"] == -6

    # Z = 2033 - 2026 = 7. Margin = 7 - (5 + 3) = -1
    res_2033 = simulate_quantum_threat_scenario(assets, target_year=2033, migration_duration_years=3, current_year=2026)
    assert res_2033["threat_horizon_years_Z"] == 7
    assert res_2033["evaluated_assets"][0]["planning_margin"] == -1

    # Z = 2040 - 2026 = 14. Margin = 14 - (5 + 3) = +6
    res_2040 = simulate_quantum_threat_scenario(assets, target_year=2040, migration_duration_years=3, current_year=2026)
    assert res_2040["threat_horizon_years_Z"] == 14
    assert res_2040["evaluated_assets"][0]["planning_margin"] == 6


def test_different_migration_durations():
    """Verify organizational migration duration Y shifts margins inversely."""
    assets = [
        {
            "id": 1,
            "name": "Identity Token Signer",
            "crypto_algorithm": "ECDSA",
            "crypto_role": "Digital Signature",
            "key_size": 256,
            "data_shelf_life_years": 4,
        }
    ]
    target_year = 2033  # Z = 7

    # Y = 1: Margin = 7 - (4 + 1) = +2
    r1 = simulate_quantum_threat_scenario(assets, target_year=target_year, migration_duration_years=1, current_year=2026)
    assert r1["evaluated_assets"][0]["planning_margin"] == 2

    # Y = 3: Margin = 7 - (4 + 3) = 0
    r3 = simulate_quantum_threat_scenario(assets, target_year=target_year, migration_duration_years=3, current_year=2026)
    assert r3["evaluated_assets"][0]["planning_margin"] == 0

    # Y = 6: Margin = 7 - (4 + 6) = -3
    r6 = simulate_quantum_threat_scenario(assets, target_year=target_year, migration_duration_years=6, current_year=2026)
    assert r6["evaluated_assets"][0]["planning_margin"] == -3


def test_asset_specific_migration_overrides():
    """Verify individual assets can have specific migration duration assumptions."""
    assets = [
        {
            "id": 1,
            "name": "Standard TLS Gateway",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 5,
        },
        {
            "id": 2,
            "name": "Legacy Mainframe Cryptosystem",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 5,
        },
    ]

    # Global Y = 2, but asset 2 has complex mainframe dependencies requiring Y = 8
    overrides = {2: 8}

    result = simulate_quantum_threat_scenario(
        assets=assets,
        target_year=2033,  # Z = 7
        migration_duration_years=2,
        current_year=2026,
        asset_migration_overrides=overrides,
    )

    asset1_res = next(a for a in result["evaluated_assets"] if a["id"] == 1)
    asset2_res = next(a for a in result["evaluated_assets"] if a["id"] == 2)

    # Asset 1 uses global Y = 2: 7 - (5 + 2) = 0 (ZERO_BUFFER)
    assert asset1_res["migration_duration_Y"] == 2
    assert asset1_res["planning_margin"] == 0
    assert asset1_res["buffer_status"] == "ZERO_BUFFER"

    # Asset 2 uses override Y = 8: 7 - (5 + 8) = -6 (NEGATIVE_MARGIN)
    assert asset2_res["migration_duration_Y"] == 8
    assert asset2_res["planning_margin"] == -6
    assert asset2_res["buffer_status"] == "NEGATIVE_MARGIN"


def test_invalid_inputs_validation():
    """Verify input validation handles negative values, past years, and invalid types."""
    # Past target year
    with pytest.raises(ValueError, match="cannot be earlier than baseline"):
        simulate_quantum_threat_scenario([], target_year=2020, current_year=2026)

    # Negative migration duration
    with pytest.raises(ValueError, match="cannot be negative"):
        simulate_quantum_threat_scenario([], migration_duration_years=-1)

    # Invalid types
    with pytest.raises(TypeError):
        simulate_quantum_threat_scenario([], target_year="2033")

    with pytest.raises(TypeError):
        calculate_planning_margin(confidentiality_years_x="5", migration_years_y=2, horizon_years_z=7)

    # Negative asset override
    with pytest.raises(ValueError, match="non-negative integer"):
        simulate_quantum_threat_scenario(
            assets=[{"id": 1, "crypto_algorithm": "RSA", "data_shelf_life_years": 5}],
            asset_migration_overrides={1: -3},
        )


def test_data_consistency_between_counts_and_tables():
    """Verify mathematical consistency between summary counts and asset-level tables."""
    assets = [
        {"id": 1, "crypto_algorithm": "RSA", "data_shelf_life_years": 8},
        {"id": 2, "crypto_algorithm": "AES", "data_shelf_life_years": 3, "key_size": 256},
        {"id": 3, "crypto_algorithm": "ML-KEM", "data_shelf_life_years": 10, "key_size": 768},
        {"id": 4, "crypto_algorithm": "ProprietaryAlg", "data_shelf_life_years": 6},
    ]

    result = simulate_quantum_threat_scenario(assets, target_year=2033, migration_duration_years=3, current_year=2026)

    # Sum of margin buckets must equal total assets evaluated
    assert (
        result["negative_margin_count"] + result["zero_margin_count"] + result["positive_margin_count"]
        == result["total_assets_evaluated"]
    )

    # Sum of vulnerability categorizations must equal total assets evaluated
    assert (
        result["quantum_vulnerable_count"] + result["quantum_safe_count"] + result["requires_assessment_count"]
        == result["total_assets_evaluated"]
    )

    # List lengths match count fields
    assert len(result["evaluated_assets"]) == result["total_assets_evaluated"]
    assert len(result["confirmed_exposed_assets"]) == result["confirmed_exposed_assets_count"]
    assert len(result["requires_assessment_assets"]) == result["requires_assessment_count"]


def test_multi_scenario_comparison():
    """Verify compare_scenarios produces sorted, consistent evaluations across years."""
    from core.scenario_engine import compare_scenarios

    assets = [
        {"id": 1, "crypto_algorithm": "RSA", "crypto_role": "Key Establishment", "data_shelf_life_years": 6},
        {"id": 2, "crypto_algorithm": "ML-KEM", "crypto_role": "Key Establishment", "data_shelf_life_years": 6, "key_size": 768},
    ]

    years = [2038, 2029, 2033]
    scenarios = compare_scenarios(assets, target_years=years, migration_duration_years=2, current_year=2026)

    # Results are sorted by year
    assert [s["scenario_target_year"] for s in scenarios] == [2029, 2033, 2038]

    # Earlier year (2029, Z=3) has more negative margins than later year (2038, Z=12)
    # At 2029 (Z=3): RSA margin = 3 - (6+2) = -5 (Exposed); ML-KEM margin = 3 - (6+2) = -5 (Safe)
    assert scenarios[0]["confirmed_exposed_assets_count"] == 1
    assert scenarios[0]["negative_margin_count"] == 2

    # At 2038 (Z=12): RSA margin = 12 - (6+2) = +4 (Buffer maintained); ML-KEM margin = +4 (Buffer maintained)
    assert scenarios[2]["confirmed_exposed_assets_count"] == 0
    assert scenarios[2]["positive_margin_count"] == 2

