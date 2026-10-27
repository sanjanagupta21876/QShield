"""Unit tests for core/database.py."""

import sqlite3
import pytest
from core.database import (
    get_db_connection,
    init_db,
    insert_asset,
    get_all_assets,
    get_asset_by_id,
    update_asset,
    delete_asset,
    search_assets,
)


def test_init_db_creates_schema_and_crud_works(tmp_path):
    """Test that init_db creates expected tables and columns on an isolated database."""
    test_db = tmp_path / "test_qshield.db"

    # Verify database does not exist initially
    assert not test_db.exists()

    # 1. Initialize schema via init_db
    init_db(test_db)
    assert test_db.exists()

    # 2. Verify schema created by init_db directly
    conn = get_db_connection(test_db)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='assets'")
    assert cursor.fetchone() is not None, "assets table was not created by init_db"

    cursor.execute("PRAGMA table_info(assets)")
    columns = {row["name"]: row["type"] for row in cursor.fetchall()}
    expected_columns = [
        "id",
        "name",
        "system_name",
        "crypto_algorithm",
        "crypto_role",
        "key_size",
        "data_shelf_life_years",
        "migration_status",
        "created_at",
    ]
    for col in expected_columns:
        assert col in columns, f"Expected column '{col}' missing from assets schema"

    # 3. Test asset insertion using the schema created by init_db
    asset_data = {
        "name": "Core Banking TLS Cert",
        "system_name": "E-Banking Portal",
        "crypto_algorithm": "RSA",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 7,
        "migration_status": "Planning",
    }
    inserted_id = insert_asset(conn, asset_data)
    assert inserted_id > 0

    # 4. Test retrieval and content validation
    all_assets = get_all_assets(conn)
    assert len(all_assets) == 1
    retrieved = all_assets[0]
    assert retrieved["id"] == inserted_id
    assert retrieved["name"] == "Core Banking TLS Cert"
    assert retrieved["crypto_algorithm"] == "RSA"
    assert retrieved["crypto_role"] == "Key Establishment"
    assert retrieved["key_size"] == 2048
    assert retrieved["data_shelf_life_years"] == 7
    assert retrieved["migration_status"] == "Planning"

    conn.close()


def test_get_asset_by_id(tmp_path):
    """Verify retrieving single asset by ID and handling non-existent ID."""
    test_db = tmp_path / "test_get_by_id.db"
    init_db(test_db)
    conn = get_db_connection(test_db)

    asset_data = {
        "name": "Auth Signing Key",
        "system_name": "Identity Provider",
        "crypto_algorithm": "ECDSA",
        "crypto_role": "Digital Signature",
        "key_size": 256,
        "data_shelf_life_years": 3,
        "migration_status": "Not Started",
    }
    asset_id = insert_asset(conn, asset_data)

    # Valid ID lookup
    retrieved = get_asset_by_id(conn, asset_id)
    assert retrieved is not None
    assert retrieved["id"] == asset_id
    assert retrieved["name"] == "Auth Signing Key"
    assert retrieved["crypto_algorithm"] == "ECDSA"

    # Non-existent ID lookup
    non_existent = get_asset_by_id(conn, 99999)
    assert non_existent is None

    conn.close()


def test_update_asset(tmp_path):
    """Verify updating existing assets and error handling for missing records."""
    test_db = tmp_path / "test_update.db"
    init_db(test_db)
    conn = get_db_connection(test_db)

    asset_data = {
        "name": "Initial Database Key",
        "system_name": "Legacy DB",
        "crypto_algorithm": "3DES",
        "crypto_role": "Symmetric Encryption",
        "key_size": 168,
        "data_shelf_life_years": 5,
        "migration_status": "Not Started",
    }
    asset_id = insert_asset(conn, asset_data)

    # Perform update
    updated_fields = {
        "name": "Upgraded Database Key",
        "system_name": "Modern Cloud DB",
        "crypto_algorithm": "AES",
        "crypto_role": "Symmetric Encryption",
        "key_size": 256,
        "data_shelf_life_years": 10,
        "migration_status": "Completed",
    }
    success = update_asset(conn, asset_id, updated_fields)
    assert success is True

    # Verify changes persisted in database
    retrieved = get_asset_by_id(conn, asset_id)
    assert retrieved is not None
    assert retrieved["name"] == "Upgraded Database Key"
    assert retrieved["system_name"] == "Modern Cloud DB"
    assert retrieved["crypto_algorithm"] == "AES"
    assert retrieved["key_size"] == 256
    assert retrieved["data_shelf_life_years"] == 10
    assert retrieved["migration_status"] == "Completed"

    # Updating non-existent record returns False
    missing_success = update_asset(conn, 88888, updated_fields)
    assert missing_success is False

    conn.close()


def test_delete_asset(tmp_path):
    """Verify deleting asset by ID and handling non-existent records."""
    test_db = tmp_path / "test_delete.db"
    init_db(test_db)
    conn = get_db_connection(test_db)

    asset_data = {
        "name": "Temporary Session Key",
        "system_name": "API Gateway",
        "crypto_algorithm": "ECDH",
        "crypto_role": "Key Establishment",
        "key_size": 256,
        "data_shelf_life_years": 1,
        "migration_status": "Decommissioned",
    }
    asset_id = insert_asset(conn, asset_data)
    assert get_asset_by_id(conn, asset_id) is not None

    # Delete asset
    del_success = delete_asset(conn, asset_id)
    assert del_success is True

    # Confirm asset no longer exists
    assert get_asset_by_id(conn, asset_id) is None
    assert len(get_all_assets(conn)) == 0

    # Deleting non-existent record returns False
    missing_del = delete_asset(conn, 77777)
    assert missing_del is False

    conn.close()


def test_search_assets_filtering_and_sorting(tmp_path):
    """Verify searching, filtering by algorithm/role/status, and sorting."""
    test_db = tmp_path / "test_search.db"
    init_db(test_db)
    conn = get_db_connection(test_db)

    # Insert 3 diverse assets
    insert_asset(conn, {
        "name": "Payment Gateway Cert",
        "system_name": "E-Commerce",
        "crypto_algorithm": "RSA",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 15,
        "migration_status": "Planning",
    })
    insert_asset(conn, {
        "name": "Customer Data Token",
        "system_name": "CRM Service",
        "crypto_algorithm": "AES",
        "crypto_role": "Symmetric Encryption",
        "key_size": 256,
        "data_shelf_life_years": 5,
        "migration_status": "In Progress",
    })
    insert_asset(conn, {
        "name": "Audit Log Digest",
        "system_name": "E-Commerce",
        "crypto_algorithm": "SHA-256",
        "crypto_role": "Cryptographic Hash",
        "key_size": None,
        "data_shelf_life_years": 2,
        "migration_status": "Completed",
    })

    # 1. Search term match on name
    res_name = search_assets(conn, search_term="Payment")
    assert len(res_name) == 1
    assert res_name[0]["name"] == "Payment Gateway Cert"

    # 2. Search term match on system_name
    res_sys = search_assets(conn, search_term="E-Commerce")
    assert len(res_sys) == 2

    # 3. Filter by algorithm
    res_algo = search_assets(conn, algorithm="AES")
    assert len(res_algo) == 1
    assert res_algo[0]["crypto_algorithm"] == "AES"

    # 4. Filter by role
    res_role = search_assets(conn, role="Cryptographic Hash")
    assert len(res_role) == 1
    assert res_role[0]["crypto_algorithm"] == "SHA-256"

    # 5. Filter by migration status
    res_stat = search_assets(conn, migration_status="In Progress")
    assert len(res_stat) == 1
    assert res_stat[0]["name"] == "Customer Data Token"

    # 6. Sorting by data_shelf_life_years ascending vs descending
    sorted_asc = search_assets(conn, sort_by="data_shelf_life_years", sort_asc=True)
    assert [a["data_shelf_life_years"] for a in sorted_asc] == [2, 5, 15]

    sorted_desc = search_assets(conn, sort_by="data_shelf_life_years", sort_asc=False)
    assert [a["data_shelf_life_years"] for a in sorted_desc] == [15, 5, 2]

    conn.close()


def test_key_size_none_and_not_applicable_handling(tmp_path):
    """Verify that unkeyed primitives (hashes) can store None/0 without constraint errors."""
    test_db = tmp_path / "test_unkeyed.db"
    init_db(test_db)
    conn = get_db_connection(test_db)

    # Insert hash asset with key_size = None
    hash_data = {
        "name": "File Integrity Hash",
        "system_name": "Storage Engine",
        "crypto_algorithm": "SHA-256",
        "crypto_role": "Cryptographic Hash",
        "key_size": None,
        "data_shelf_life_years": 5,
        "migration_status": "Completed",
    }
    inserted_id = insert_asset(conn, hash_data)
    assert inserted_id > 0

    retrieved = get_asset_by_id(conn, inserted_id)
    assert retrieved is not None
    assert retrieved["key_size"] in (None, 0)

    # Update hash asset with key_size = 0
    hash_data["name"] = "Updated File Integrity Hash"
    hash_data["key_size"] = 0
    assert update_asset(conn, inserted_id, hash_data) is True

    updated = get_asset_by_id(conn, inserted_id)
    assert updated["key_size"] in (None, 0)
    assert updated["name"] == "Updated File Integrity Hash"

    conn.close()


def test_database_persistence_across_connections(tmp_path):
    """Verify data written to SQLite persists to disk across connection lifecycles."""
    test_db = tmp_path / "test_persistence.db"
    init_db(test_db)

    # Connection 1: Insert record and close
    conn1 = get_db_connection(test_db)
    inserted_id = insert_asset(conn1, {
        "name": "Persistent TLS Key",
        "system_name": "Web Proxy",
        "crypto_algorithm": "RSA",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 8,
        "migration_status": "Planning",
    })
    conn1.close()

    # Connection 2: Re-open database from disk and verify data persists
    conn2 = get_db_connection(test_db)
    retrieved = get_asset_by_id(conn2, inserted_id)
    assert retrieved is not None
    assert retrieved["name"] == "Persistent TLS Key"
    assert retrieved["system_name"] == "Web Proxy"
    assert retrieved["crypto_algorithm"] == "RSA"
    assert retrieved["key_size"] == 2048
    conn2.close()


def test_schema_migration_preserves_existing_data(tmp_path):
    """Verify schema migrations add missing columns without dropping or modifying existing data."""
    test_db = tmp_path / "test_migration.db"
    conn = sqlite3.connect(str(test_db))
    cursor = conn.cursor()

    # Create old table without crypto_role column
    cursor.execute(
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            system_name TEXT NOT NULL,
            crypto_algorithm TEXT NOT NULL,
            key_size INTEGER,
            data_shelf_life_years INTEGER NOT NULL DEFAULT 5,
            migration_status TEXT NOT NULL DEFAULT 'Not Started',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        """
        INSERT INTO assets (name, system_name, crypto_algorithm, key_size, data_shelf_life_years)
        VALUES ('Legacy Asset', 'Legacy App', 'RSA', 2048, 5)
        """
    )
    conn.commit()
    conn.close()

    # Run init_db to perform schema migration
    init_db(test_db)

    # Verify column was added and existing data remains intact
    conn_migrated = get_db_connection(test_db)
    assets = get_all_assets(conn_migrated)
    assert len(assets) == 1
    assert assets[0]["name"] == "Legacy Asset"
    assert assets[0]["crypto_role"] == "Unknown / Unclassified"
    conn_migrated.close()
