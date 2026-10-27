"""Tests for core/demo_data.py synthetic demonstration dataset and loader."""

import sqlite3
import pytest
from core.database import get_db_connection, init_db, get_all_assets, insert_asset
from core.demo_data import SYNTHETIC_DEMO_ASSETS, load_demo_dataset
from core.validation import validate_asset_data


def test_synthetic_demo_assets_schema_and_labels():
    """Verify all demonstration assets are valid, synthetic, and follow standards."""
    assert len(SYNTHETIC_DEMO_ASSETS) == 10

    algorithms = set()
    roles = set()
    statuses = set()
    shelf_lives = set()

    for asset in SYNTHETIC_DEMO_ASSETS:
        # Must be explicitly labeled as demo/synthetic
        assert asset["name"].startswith("[DEMO] Synthetic"), f"Asset {asset['name']} must be marked synthetic"
        assert asset["system_name"].startswith("Synthetic"), f"System {asset['system_name']} must be marked synthetic"

        # Valid according to asset validation rules
        is_valid, errors = validate_asset_data(asset)
        assert is_valid, f"Demo asset {asset['name']} failed validation: {errors}"

        algorithms.add(asset["crypto_algorithm"])
        roles.add(asset["crypto_role"])
        statuses.add(asset["migration_status"])
        shelf_lives.add(asset["data_shelf_life_years"])

    # Verify coverage of required mechanisms
    # 1. Asymmetric Shor-vulnerable
    assert "RSA" in algorithms
    assert "ECDSA" in algorithms
    assert "Diffie-Hellman" in algorithms

    # 2. Symmetric
    assert "AES" in algorithms
    assert "3DES" in algorithms

    # 3. Hash
    assert "SHA-256" in algorithms

    # 4. Standardized PQC
    assert "ML-KEM" in algorithms
    assert "ML-DSA" in algorithms

    # 5. Unknown / Needs Assessment
    assert "Custom_Obfuscation_Cipher_v2" in algorithms

    # 6. Diverse confidentiality lifetimes
    assert min(shelf_lives) <= 2
    assert max(shelf_lives) >= 25

    # 7. Complete migration status coverage
    expected_statuses = {"Not Started", "Planning", "In Progress", "Completed", "Decommissioned"}
    assert statuses == expected_statuses


def test_load_demo_dataset_into_empty_db(tmp_path):
    """Verify loading demo data into an empty database inserts all records."""
    test_db = tmp_path / "test_demo_load.db"
    init_db(test_db)

    with get_db_connection(test_db) as conn:
        res = load_demo_dataset(conn, clear_existing=False)
        assert res["inserted"] == 10
        assert res["skipped"] == 0
        assert res["total"] == 10

        stored = get_all_assets(conn)
        assert len(stored) == 10


def test_load_demo_dataset_no_duplicates_on_repeated_calls(tmp_path):
    """Verify repeatedly calling load_demo_dataset never duplicates existing records."""
    test_db = tmp_path / "test_no_dupes.db"
    init_db(test_db)

    with get_db_connection(test_db) as conn:
        # First load
        res1 = load_demo_dataset(conn, clear_existing=False)
        assert res1["inserted"] == 10
        assert res1["skipped"] == 0

        # Second load without clearing: all 10 should be skipped
        res2 = load_demo_dataset(conn, clear_existing=False)
        assert res2["inserted"] == 0
        assert res2["skipped"] == 10
        assert res2["total"] == 10

        # Third load without clearing
        res3 = load_demo_dataset(conn, clear_existing=False)
        assert res3["inserted"] == 0
        assert res3["skipped"] == 10
        assert res3["total"] == 10

        stored = get_all_assets(conn)
        assert len(stored) == 10


def test_load_demo_dataset_preserves_existing_user_assets(tmp_path):
    """Verify loading demo data does not delete or alter user's custom assets."""
    test_db = tmp_path / "test_preserve_user.db"
    init_db(test_db)

    with get_db_connection(test_db) as conn:
        # User adds their own custom asset
        user_asset = {
            "name": "My Proprietary User Asset",
            "system_name": "Production User System",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 256,
            "data_shelf_life_years": 7,
            "migration_status": "Planning",
        }
        u_id = insert_asset(conn, user_asset)
        assert u_id > 0

        # Now load demo data without clear_existing
        res = load_demo_dataset(conn, clear_existing=False)
        assert res["inserted"] == 10
        assert res["skipped"] == 0
        assert res["total"] == 11

        stored = get_all_assets(conn)
        assert len(stored) == 11
        user_names = [a["name"] for a in stored]
        assert "My Proprietary User Asset" in user_names


def test_load_demo_dataset_clear_existing(tmp_path):
    """Verify explicit clear_existing=True replaces inventory."""
    test_db = tmp_path / "test_clear_existing.db"
    init_db(test_db)

    with get_db_connection(test_db) as conn:
        # Insert a scratch asset
        insert_asset(conn, {
            "name": "Old Deprecated Key",
            "system_name": "Old Sys",
            "crypto_algorithm": "RSA",
            "crypto_role": "Key Establishment",
            "key_size": 1024,
        })
        assert len(get_all_assets(conn)) == 1

        # Clear and load demo dataset
        res = load_demo_dataset(conn, clear_existing=True)
        assert res["inserted"] == 10
        assert res["cleared_existing"] is True
        assert res["total"] == 10

        stored = get_all_assets(conn)
        assert len(stored) == 10
        assert "Old Deprecated Key" not in [a["name"] for a in stored]
