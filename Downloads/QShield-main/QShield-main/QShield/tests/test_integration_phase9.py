"""Phase 9: Comprehensive Integration, Edge Case, and Reliability Test Suite for QShield.

Covers:
1. Complete 10-step end-to-end integration workflow:
   - Start with empty database
   - Add several cryptographic assets
   - View, search, edit, and delete assets
   - Generate risk assessments
   - Inspect assessment explanations (7 dimensions)
   - Run threat horizon scenarios
   - Review role-aware migration recommendations
   - Update migration statuses
   - Export inventory and risk assessment reports to CSV
   - Reopen database connection to verify full persistence
2. Edge cases:
   - Empty inventory across risk engine, scenario engine, and CSV export
   - Invalid and missing inputs
   - Unknown and unclassified algorithms
   - Conflicting algorithm and role assignments
   - Invalid key sizes (0, negative, non-int) for keyed vs unkeyed primitives
   - Zero confidentiality lifetime (X = 0)
   - Zero migration duration (Y = 0)
   - Negative planning margins (Z - (X + Y) < 0)
   - Missing or incomplete asset data
   - Database schema re-initialization and persistence
   - CSV special characters (commas, quotes, newlines, Unicode, formula injection)
   - Consistency between metrics, tables, and chart categorizations
"""

import csv
import io
import sqlite3
import pytest
from core.database import (
    get_db_connection,
    init_db,
    insert_asset,
    get_all_assets,
    get_asset_by_id,
    update_asset,
    update_asset_migration_status,
    delete_asset,
    search_assets,
)
from core.risk_engine import (
    evaluate_quantum_risk,
    classify_cryptographic_primitive,
    check_algorithm_role_compatibility,
    get_cryptographic_category,
)
from core.scenario_engine import (
    simulate_quantum_threat_scenario,
    compare_scenarios,
    calculate_planning_margin,
)
from core.recommendations import get_pqc_recommendation
from core.validation import validate_asset_data, validate_cryptographic_parameters
from core.export import (
    export_inventory_to_csv,
    export_risk_assessment_to_csv,
    export_scenario_to_csv,
    sanitize_csv_cell,
)
from components.charts import (
    create_risk_distribution_chart,
    create_planning_margin_distribution_chart,
    create_scenario_exposure_breakdown_chart,
    create_asset_margins_comparison_chart,
    create_scenario_comparison_chart,
)


# ==============================================================================
# 1. Complete Workflow Integration Test (10 Steps)
# ==============================================================================

def test_complete_end_to_end_workflow(tmp_path):
    """Execute and verify the complete 10-step sequence requested in Phase 9."""
    db_file = tmp_path / "integration_workflow.db"

    # Step 1: Start application with an empty database
    init_db(db_file)
    with get_db_connection(db_file) as conn:
        initial_assets = get_all_assets(conn)
        assert len(initial_assets) == 0, "Initial database should be empty"

    # Step 2: Add several cryptographic assets covering various mechanisms
    assets_to_create = [
        {
            "name": "TLS Gateway Key",
            "system_name": "API Gateway",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 8,
            "migration_status": "Not Started",
        },
        {
            "name": "User Auth Token Signer",
            "system_name": "Identity Service",
            "crypto_algorithm": "ECDSA",
            "crypto_role": "Digital Signature",
            "key_size": 256,
            "data_shelf_life_years": 3,
            "migration_status": "Planning",
        },
        {
            "name": "Customer Records DB Cipher",
            "system_name": "Core Banking",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 256,
            "data_shelf_life_years": 15,
            "migration_status": "In Progress",
        },
        {
            "name": "Password Hash Verifier",
            "system_name": "Auth DB",
            "crypto_algorithm": "SHA-256",
            "crypto_role": "Cryptographic Hash",
            "key_size": None,  # Unkeyed primitive
            "data_shelf_life_years": 20,
            "migration_status": "Completed",
        },
        {
            "name": "Quantum-Resilient Backbone Link",
            "system_name": "Inter-Datacenter WAN",
            "crypto_algorithm": "ML-KEM",
            "crypto_role": "Key Establishment",
            "key_size": 768,
            "data_shelf_life_years": 25,
            "migration_status": "Completed",
        },
        {
            "name": "Temporary Legacy Cert",
            "system_name": "Old Portal",
            "crypto_algorithm": "DSA",
            "crypto_role": "Digital Signature",
            "key_size": 1024,
            "data_shelf_life_years": 2,
            "migration_status": "Not Started",
        },
    ]

    inserted_ids = []
    with get_db_connection(db_file) as conn:
        for a_data in assets_to_create:
            is_valid, errors = validate_asset_data(a_data)
            assert is_valid, f"Validation failed for {a_data['name']}: {errors}"
            a_id = insert_asset(conn, a_data)
            assert a_id > 0
            inserted_ids.append(a_id)

    # Step 3: View, search, edit, and delete assets
    with get_db_connection(db_file) as conn:
        all_stored = get_all_assets(conn)
        assert len(all_stored) == 6

        # Search by keyword
        search_res = search_assets(conn, search_term="Banking")
        assert len(search_res) == 1
        assert search_res[0]["name"] == "Customer Records DB Cipher"

        # Filter by algorithm
        filter_res = search_assets(conn, algorithm="ML-KEM")
        assert len(filter_res) == 1
        assert filter_res[0]["crypto_algorithm"] == "ML-KEM"

        # Edit an asset
        rsa_id = inserted_ids[0]
        edit_payload = {
            "name": "TLS Gateway Key (Updated)",
            "system_name": "API Gateway v2",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 4096,
            "data_shelf_life_years": 12,
            "migration_status": "Planning",
        }
        update_ok = update_asset(conn, rsa_id, edit_payload)
        assert update_ok is True
        updated_rsa = get_asset_by_id(conn, rsa_id)
        assert updated_rsa["name"] == "TLS Gateway Key (Updated)"
        assert updated_rsa["key_size"] == 4096
        assert updated_rsa["data_shelf_life_years"] == 12

        # Delete the temporary asset (DSA)
        temp_id = inserted_ids[-1]
        delete_ok = delete_asset(conn, temp_id)
        assert delete_ok is True
        assert get_asset_by_id(conn, temp_id) is None
        remaining = get_all_assets(conn)
        assert len(remaining) == 5

    # Step 4: Generate risk assessments
    with get_db_connection(db_file) as conn:
        current_assets = get_all_assets(conn)
        assessments = {}
        for a in current_assets:
            risk = evaluate_quantum_risk(
                algorithm=a["crypto_algorithm"],
                key_size=a["key_size"],
                data_shelf_life_years=a["data_shelf_life_years"],
                crypto_role=a.get("crypto_role"),
            )
            assessments[a["id"]] = risk
            assert risk["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

        # Step 5: Inspect assessment explanations
        # Check RSA (X=12 -> CRITICAL HNDL)
        rsa_risk = assessments[rsa_id]
        assert rsa_risk["risk_level"] == "CRITICAL"
        assert rsa_risk["shor_vulnerable"] is True
        assert "threat_relevance" in rsa_risk
        assert "confidentiality_impact" in rsa_risk
        assert "timeline_exposure_distinction" in rsa_risk
        assert "result_rigor" in rsa_risk
        assert "recommended_next_action" in rsa_risk
        assert len(rsa_risk["assumptions"]) > 0
        assert len(rsa_risk["limitations"]) > 0

        # Check ML-KEM (PQC Resilient)
        mlkem_id = inserted_ids[4]
        mlkem_risk = assessments[mlkem_id]
        assert mlkem_risk["risk_level"] == "LOW"
        assert mlkem_risk["quantum_vulnerable"] is False

    # Step 6: Run scenarios using different threat horizons
    sim_2030 = simulate_quantum_threat_scenario(
        assets=current_assets,
        target_year=2030,
        migration_duration_years=3,
        current_year=2026,
    )
    assert sim_2030["threat_horizon_years_Z"] == 4
    assert sim_2030["total_assets_evaluated"] == 5
    # Verification of consistent counts: confirmed exposed + requires assessment + buffer/resilient == total
    assert (
        sim_2030["confirmed_exposed_assets_count"]
        + sim_2030["requires_assessment_count"]
        + sim_2030["resilient_or_buffered_count"]
    ) == 5

    sim_2040 = simulate_quantum_threat_scenario(
        assets=current_assets,
        target_year=2040,
        migration_duration_years=3,
        current_year=2026,
    )
    assert sim_2040["threat_horizon_years_Z"] == 14
    # Longer horizon should result in fewer or equal confirmed exposures
    assert sim_2040["confirmed_exposed_assets_count"] <= sim_2030["confirmed_exposed_assets_count"]

    # Step 7: Review migration recommendations
    for a in current_assets:
        rec = get_pqc_recommendation(
            algorithm=a["crypto_algorithm"],
            key_size=a["key_size"] or 0,
            crypto_role=a.get("crypto_role"),
        )
        assert rec["target_pqc_algorithm"] is not None
        assert rec["nist_standard"] is not None
        assert rec["priority"] in {"Critical", "Immediate", "High", "Medium", "Maintain", "Assessment Needed"}

    # Step 8: Update migration statuses
    with get_db_connection(db_file) as conn:
        status_ok = update_asset_migration_status(conn, rsa_id, "In Progress")
        assert status_ok is True
        rsa_updated = get_asset_by_id(conn, rsa_id)
        assert rsa_updated["migration_status"] == "In Progress"

    # Step 9: Export inventory and assessment reports
    with get_db_connection(db_file) as conn:
        assets_for_export = get_all_assets(conn)

    inv_csv_str = export_inventory_to_csv(assets_for_export)
    assert "Asset ID,Asset Name,System / Application" in inv_csv_str
    assert "TLS Gateway Key (Updated)" in inv_csv_str
    reader = csv.reader(io.StringIO(inv_csv_str))
    rows = list(reader)
    assert len(rows) == 6  # Header + 5 records

    risk_csv_str = export_risk_assessment_to_csv(assets_for_export)
    assert "Risk Level,Heuristic Risk Score,Quantum Vulnerable" in risk_csv_str
    assert "CRITICAL" in risk_csv_str
    risk_reader = csv.reader(io.StringIO(risk_csv_str))
    risk_rows = list(risk_reader)
    assert len(risk_rows) == 6

    scen_csv_str = export_scenario_to_csv(sim_2030)
    assert "Planning Margin: Z - (X + Y)" in scen_csv_str
    scen_reader = csv.reader(io.StringIO(scen_csv_str))
    scen_rows = list(scen_reader)
    assert len(scen_rows) == 6

    # Step 10: Restart application and verify persistence
    # Simulating a new application launch with a fresh connection to the database
    with get_db_connection(db_file) as new_conn:
        reopened_assets = get_all_assets(new_conn)
        assert len(reopened_assets) == 5
        persisted_rsa = get_asset_by_id(new_conn, rsa_id)
        assert persisted_rsa["name"] == "TLS Gateway Key (Updated)"
        assert persisted_rsa["migration_status"] == "In Progress"
        assert persisted_rsa["key_size"] == 4096
        assert persisted_rsa["data_shelf_life_years"] == 12


# ==============================================================================
# 2. Edge Case Tests
# ==============================================================================

def test_edge_case_empty_inventory(tmp_path):
    """Verify system behavior when asset inventory is completely empty."""
    db_file = tmp_path / "empty.db"
    init_db(db_file)

    with get_db_connection(db_file) as conn:
        assets = get_all_assets(conn)
        assert len(assets) == 0

        # Search on empty inventory
        assert search_assets(conn, search_term="RSA") == []
        assert search_assets(conn, algorithm="AES") == []

    # Scenario simulation with empty inventory
    sim = simulate_quantum_threat_scenario(assets=[], target_year=2033)
    assert sim["total_assets_evaluated"] == 0
    assert sim["negative_margin_count"] == 0
    assert sim["zero_margin_count"] == 0
    assert sim["positive_margin_count"] == 0
    assert sim["confirmed_exposed_assets_count"] == 0
    assert sim["exposure_percentage"] == 0.0

    # Multi-scenario comparison with empty inventory
    cmp_res = compare_scenarios(assets=[], target_years=[2029, 2033, 2038])
    assert len(cmp_res) == 3
    for s in cmp_res:
        assert s["total_assets_evaluated"] == 0

    # Chart generation on empty inventory
    fig_empty = create_scenario_exposure_breakdown_chart(0, 0, 0)
    assert fig_empty is not None

    fig_asset_bars = create_asset_margins_comparison_chart([])
    assert fig_asset_bars is not None

    fig_multi_empty = create_scenario_comparison_chart([])
    assert fig_multi_empty is not None

    # CSV exports with empty inventory
    inv_csv = export_inventory_to_csv([])
    assert inv_csv.startswith("Asset ID,")
    assert len(list(csv.reader(io.StringIO(inv_csv)))) == 1  # Header only

    risk_csv = export_risk_assessment_to_csv([])
    assert risk_csv.startswith("Asset ID,")
    assert len(list(csv.reader(io.StringIO(risk_csv)))) == 1


def test_edge_case_unknown_algorithms():
    """Verify unknown or unclassified algorithms are handled safely without assumptions."""
    result = evaluate_quantum_risk(
        algorithm="Custom_Proprietary_Cipher_X9",
        key_size=256,
        data_shelf_life_years=10,
        crypto_role="Symmetric Encryption",
    )
    assert result["risk_level"] == "UNKNOWN"
    assert result["risk_score"] is None
    assert result["quantum_vulnerable"] is None
    assert result["shor_vulnerable"] is None
    assert result["grover_affected"] is None
    assert result["assessment_status"] == "INSUFFICIENT_INFORMATION"
    assert "manual cryptographic inventory" in result["reasoning"].lower()

    # In scenario simulation, unknown algorithms must NOT be counted as confirmed exposures
    asset = {
        "id": 1,
        "name": "Proprietary Vault",
        "system_name": "Core",
        "crypto_algorithm": "Custom_Proprietary_Cipher_X9",
        "crypto_role": "Symmetric Encryption",
        "key_size": 256,
        "data_shelf_life_years": 15,
    }
    sim = simulate_quantum_threat_scenario([asset], target_year=2030, migration_duration_years=5)
    # 2030 - 2026 = 4. 4 - (15 + 5) = -16. Margin is negative, but algorithm is unknown
    assert sim["negative_margin_count"] == 1
    assert sim["confirmed_exposed_assets_count"] == 0  # NEVER count unknown as confirmed exposure
    assert sim["requires_assessment_count"] == 1
    assert sim["requires_assessment_negative_margin_count"] == 1


def test_edge_case_conflicting_algorithm_and_role():
    """Verify algorithm-role conflicts return INCOMPATIBLE_ROLE rather than erroneous scores."""
    # AES cannot be used for Digital Signature
    res = evaluate_quantum_risk(
        algorithm="AES",
        key_size=256,
        crypto_role="Digital Signature",
    )
    assert res["assessment_status"] == "INCOMPATIBLE_ROLE"
    assert res["risk_level"] == "UNKNOWN"
    assert res["risk_score"] is None
    assert res["quantum_vulnerable"] is None
    assert "incompatible" in res["reasoning"].lower()

    # ML-KEM cannot be used for Digital Signature
    res_kem = evaluate_quantum_risk(
        algorithm="ML-KEM",
        key_size=768,
        crypto_role="Digital Signature",
    )
    assert res_kem["assessment_status"] == "INCOMPATIBLE_ROLE"

    # ML-DSA cannot be used for Key Establishment
    res_dsa = evaluate_quantum_risk(
        algorithm="ML-DSA",
        key_size=65,
        crypto_role="Key Establishment",
    )
    assert res_dsa["assessment_status"] == "INCOMPATIBLE_ROLE"


def test_edge_case_unkeyed_primitives_and_key_sizes():
    """Verify hashes and unkeyed primitives allow None or 0 key size while keyed primitives enforce positive int."""
    # Hash function with None key_size works cleanly
    hash_none = evaluate_quantum_risk(
        algorithm="SHA-256",
        key_size=None,
        data_shelf_life_years=5,
        crypto_role="Cryptographic Hash",
    )
    assert hash_none["risk_level"] == "LOW"
    assert hash_none["quantum_vulnerable"] is False

    # Hash function with 0 key_size works cleanly
    hash_zero = evaluate_quantum_risk(
        algorithm="SHA-512",
        key_size=0,
        data_shelf_life_years=10,
        crypto_role="Cryptographic Hash",
    )
    assert hash_zero["risk_level"] == "LOW"
    assert hash_zero["quantum_vulnerable"] is False

    # Keyed primitive with 0 or negative key_size raises ValueError
    with pytest.raises(ValueError, match="positive integer"):
        evaluate_quantum_risk("RSA", 0)

    with pytest.raises(ValueError, match="positive integer"):
        evaluate_quantum_risk("AES", -256)

    # Keyed primitive with non-int raises TypeError
    with pytest.raises(TypeError, match="must be an integer"):
        evaluate_quantum_risk("AES", "256")

    with pytest.raises(TypeError, match="must be an integer"):
        evaluate_quantum_risk("AES", True)


def test_edge_case_zero_confidentiality_lifetime():
    """Verify zero confidentiality lifetime (X = 0) is valid and evaluated correctly."""
    # X = 0 for RSA: algorithm is still Shor-vulnerable, but HNDL urgency is reduced
    rsa_zero_x = evaluate_quantum_risk(
        algorithm="RSA",
        key_size=2048,
        data_shelf_life_years=0,
        crypto_role="Key Establishment",
    )
    assert rsa_zero_x["risk_level"] == "HIGH"
    assert rsa_zero_x["quantum_vulnerable"] is True
    assert rsa_zero_x["data_shelf_life_years"] == 0

    # In scenario simulation with X = 0
    asset = {
        "id": 1,
        "name": "Ephemeral Session Key",
        "system_name": "TLS Gateway",
        "crypto_algorithm": "ECDH",
        "crypto_role": "Key Establishment",
        "key_size": 256,
        "data_shelf_life_years": 0,
    }
    # Z = 2033 - 2026 = 7. Y = 3. Margin = 7 - (0 + 3) = +4. Buffer maintained!
    sim = simulate_quantum_threat_scenario([asset], target_year=2033, migration_duration_years=3)
    assert sim["evaluated_assets"][0]["planning_margin"] == 4
    assert sim["evaluated_assets"][0]["buffer_status"] == "POSITIVE_MARGIN"
    assert sim["confirmed_exposed_assets_count"] == 0


def test_edge_case_zero_migration_duration():
    """Verify zero migration duration (Y = 0) is valid in planning margin calculations."""
    margin = calculate_planning_margin(confidentiality_years_x=5, migration_years_y=0, horizon_years_z=10)
    assert margin == 5

    asset = {
        "id": 1,
        "name": "Agile Cloud Asset",
        "crypto_algorithm": "RSA",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 8,
    }
    # Z = 10 (target 2036). Y = 0. Margin = 10 - (8 + 0) = +2.
    sim = simulate_quantum_threat_scenario(
        [asset],
        target_year=2036,
        migration_duration_years=0,
        current_year=2026,
    )
    assert sim["evaluated_assets"][0]["migration_duration_Y"] == 0
    assert sim["evaluated_assets"][0]["planning_margin"] == 2
    assert sim["positive_margin_count"] == 1


def test_edge_case_negative_planning_margins():
    """Verify negative planning margins are correctly flagged and categorized."""
    asset = {
        "id": 1,
        "name": "Legacy Storage Key",
        "crypto_algorithm": "ECDH",
        "crypto_role": "Key Establishment",
        "key_size": 256,
        "data_shelf_life_years": 15,
    }
    # Z = 2029 - 2026 = 3. Y = 4. Margin = 3 - (15 + 4) = -16
    sim = simulate_quantum_threat_scenario(
        [asset],
        target_year=2029,
        migration_duration_years=4,
        current_year=2026,
    )
    assert sim["negative_margin_count"] == 1
    assert sim["confirmed_exposed_assets_count"] == 1
    assert sim["evaluated_assets"][0]["planning_margin"] == -16
    assert sim["evaluated_assets"][0]["buffer_status"] == "NEGATIVE_MARGIN"
    assert sim["evaluated_assets"][0]["exposure_status"] == "CONFIRMED_EXPOSURE"


def test_edge_case_missing_and_incomplete_data():
    """Verify validation functions reject missing and malformed inputs."""
    # None input
    is_valid, errors = validate_asset_data(None)
    assert not is_valid
    assert any("must be a dictionary" in e for e in errors)

    # Empty dictionary
    is_valid, errors = validate_asset_data({})
    assert not is_valid
    assert any("Asset name is required" in e for e in errors)
    assert any("System name is required" in e for e in errors)

    # Whitespace names
    is_valid, errors = validate_asset_data({
        "name": "   ",
        "system_name": "  ",
        "crypto_algorithm": "RSA",
        "key_size": 2048,
    })
    assert not is_valid
    assert any("Asset name is required" in e for e in errors)

    # Negative shelf-life
    is_valid, errors = validate_asset_data({
        "name": "Test",
        "system_name": "TestSys",
        "crypto_algorithm": "RSA",
        "key_size": 2048,
        "data_shelf_life_years": -5,
    })
    assert not is_valid
    assert any("shelf-life years cannot be negative" in e for e in errors)

    # Invalid migration status
    is_valid, errors = validate_asset_data({
        "name": "Test",
        "system_name": "TestSys",
        "crypto_algorithm": "RSA",
        "key_size": 2048,
        "migration_status": "InvalidStatus123",
    })
    assert not is_valid
    assert any("Invalid migration status" in e for e in errors)


def test_edge_case_csv_special_characters(tmp_path):
    """Verify CSV export properly handles quotes, commas, newlines, semicolons, Unicode, and formula injection."""
    assets_with_special_chars = [
        {
            "id": 1,
            "name": 'Key, with "quotes", commas & semicolons; here',
            "system_name": "System\nWith\nNewlines",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 256,
            "data_shelf_life_years": 5,
            "migration_status": "Planning",
            "created_at": "2026-10-27 12:00:00",
        },
        {
            "id": 2,
            "name": "=cmd|' /C calc'!A0",  # CSV formula injection test
            "system_name": "@AdminPortal",
            "crypto_algorithm": "+RSA-Legacy",
            "crypto_role": "-Key Establishment",
            "key_size": 2048,
            "data_shelf_life_years": 10,
            "migration_status": "Not Started",
            "created_at": "2026-10-27 12:00:00",
        },
        {
            "id": 3,
            "name": "🛡️ Post-Quantum Key (ML-KEM 768) 🚀",  # Unicode / Emojis
            "system_name": "Café & Naïve System 🌐",
            "crypto_algorithm": "ML-KEM",
            "crypto_role": "Key Establishment",
            "key_size": 768,
            "data_shelf_life_years": 15,
            "migration_status": "Completed",
            "created_at": "2026-10-27 12:00:00",
        },
    ]

    # Test formula neutralization helper
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd") == "'+cmd"
    assert sanitize_csv_cell("-secret") == "'-secret"
    assert sanitize_csv_cell("@sum") == "'@sum"
    assert sanitize_csv_cell("Normal Text") == "Normal Text"

    csv_output = export_inventory_to_csv(assets_with_special_chars)

    # Parse exported CSV using standard library csv.reader
    reader = list(csv.reader(io.StringIO(csv_output)))
    assert len(reader) == 4  # Header + 3 records

    row1 = reader[1]
    assert row1[1] == 'Key, with "quotes", commas & semicolons; here'
    assert row1[2] == "System\nWith\nNewlines"

    row2 = reader[2]
    # Verify formula prefixes were neutralized with leading single quote
    assert row2[1].startswith("'=")
    assert row2[2].startswith("'@")

    row3 = reader[3]
    # Verify Unicode preserved intact
    assert "🛡️ Post-Quantum Key" in row3[1]
    assert "Café & Naïve System 🌐" in row3[2]


def test_edge_case_consistency_between_tables_metrics_charts():
    """Verify that tables, metrics, and chart counts are 100% consistent and sum to total assets."""
    mixed_assets = [
        # 1. Confirmed Exposed (Shor-vulnerable + Negative margin)
        {"id": 1, "name": "A1", "crypto_algorithm": "RSA", "crypto_role": "Key Establishment", "key_size": 2048, "data_shelf_life_years": 12},
        # 2. Shor-vulnerable BUT buffer maintained (Positive margin)
        {"id": 2, "name": "A2", "crypto_algorithm": "ECDSA", "crypto_role": "Digital Signature", "key_size": 256, "data_shelf_life_years": 1},
        # 3. Grover-resilient (Quantum safe) + Negative margin
        {"id": 3, "name": "A3", "crypto_algorithm": "AES", "crypto_role": "Symmetric Encryption", "key_size": 256, "data_shelf_life_years": 15},
        # 4. Standardized PQC (Quantum safe) + Positive margin
        {"id": 4, "name": "A4", "crypto_algorithm": "ML-KEM", "crypto_role": "Key Establishment", "key_size": 768, "data_shelf_life_years": 2},
        # 5. Unknown algorithm (Requires assessment) + Negative margin
        {"id": 5, "name": "A5", "crypto_algorithm": "UnknownAlg1", "crypto_role": "Symmetric Encryption", "key_size": 256, "data_shelf_life_years": 15},
        # 6. Unknown algorithm (Requires assessment) + Positive margin
        {"id": 6, "name": "A6", "crypto_algorithm": "UnknownAlg2", "crypto_role": "Symmetric Encryption", "key_size": 256, "data_shelf_life_years": 1},
    ]

    total = len(mixed_assets)
    target_year = 2031  # Z = 2031 - 2026 = 5 years
    migration_y = 3     # X + Y threshold: 5 years buffer

    sim = simulate_quantum_threat_scenario(mixed_assets, target_year=target_year, migration_duration_years=migration_y)

    # 1. Timeline Planning Margin distribution check: Negative + Zero + Positive == Total
    assert (sim["negative_margin_count"] + sim["zero_margin_count"] + sim["positive_margin_count"]) == total

    # 2. Exposure Categorization check: Confirmed Exposed + Requires Assessment + Resilient/Buffer == Total
    assert (
        sim["confirmed_exposed_assets_count"]
        + sim["requires_assessment_count"]
        + sim["resilient_or_buffered_count"]
    ) == total

    # 3. Evaluated assets list length matches total
    assert len(sim["evaluated_assets"]) == total

    # 4. Chart generators do not crash with mixed assets
    margin_counts = {
        "NEGATIVE_MARGIN": sim["negative_margin_count"],
        "ZERO_BUFFER": sim["zero_margin_count"],
        "POSITIVE_MARGIN": sim["positive_margin_count"],
    }
    fig_dist = create_planning_margin_distribution_chart(margin_counts)
    assert fig_dist is not None

    fig_pie = create_scenario_exposure_breakdown_chart(
        confirmed_exposed=sim["confirmed_exposed_assets_count"],
        requires_assessment=sim["requires_assessment_count"],
        buffer_maintained=sim["resilient_or_buffered_count"],
    )
    assert fig_pie is not None

    fig_bars = create_asset_margins_comparison_chart(sim["evaluated_assets"])
    assert fig_bars is not None

    multi = compare_scenarios(mixed_assets, target_years=[2029, 2033, 2038], migration_duration_years=migration_y)
    for sc in multi:
        assert (
            sc["confirmed_exposed_assets_count"]
            + sc["requires_assessment_count"]
            + sc["resilient_or_buffered_count"]
        ) == total
    fig_cmp = create_scenario_comparison_chart(multi)
    assert fig_cmp is not None


# ==============================================================================
# 3. Reliability and Bug Fix Verification
# ==============================================================================

def test_database_update_status_and_validation(tmp_path):
    """Verify update_asset_migration_status handles valid and invalid statuses."""
    db_file = tmp_path / "status_test.db"
    init_db(db_file)
    with get_db_connection(db_file) as conn:
        a_id = insert_asset(conn, {
            "name": "Status Test Key",
            "system_name": "TestSys",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 2048,
        })
        assert a_id > 0

        # Valid status transitions
        for status in ["Planning", "In Progress", "Completed", "Decommissioned", "Not Started"]:
            ok = update_asset_migration_status(conn, a_id, status)
            assert ok is True
            assert get_asset_by_id(conn, a_id)["migration_status"] == status

        # Invalid status raises ValueError
        with pytest.raises(ValueError, match="Invalid migration status"):
            update_asset_migration_status(conn, a_id, "NonExistentStatus")

        # Non-existent asset ID returns False
        assert update_asset_migration_status(conn, 99999, "Planning") is False
