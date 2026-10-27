"""Unit tests for core/reports.py - Report generation and CSV export."""

import pytest
import csv
import io
import sqlite3
import tempfile
import os
from pathlib import Path
from core.reports import (
    sanitize_csv_field,
    generate_inventory_report,
    generate_risk_assessment_report,
    generate_scenario_report,
    generate_migration_recommendations_report,
    generate_comprehensive_report,
)
from core.database import init_db, get_db_connection, insert_asset, delete_asset


@pytest.fixture
def test_db():
    """Create a temporary file-based database for tests."""
    # Create a temporary file
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    init_db(db_path)
    yield db_path
    
    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


def test_sanitize_csv_field_prevents_formula_injection():
    """Test that CSV formula injection is prevented."""
    # Test cases that should be sanitized
    assert sanitize_csv_field("=SUM(A1:A10)") == "\t=SUM(A1:A10)"
    assert sanitize_csv_field("+SUM(A1:A10)") == "\t+SUM(A1:A10)"
    assert sanitize_csv_field("-SUM(A1:A10)") == "\t-SUM(A1:A10)"
    assert sanitize_csv_field("@SUM(A1:A10)") == "\t@SUM(A1:A10)"
    
    # Test normal values
    assert sanitize_csv_field("test") == "test"
    assert sanitize_csv_field("123") == "123"
    assert sanitize_csv_field("") == ""
    assert sanitize_csv_field(None) == ""


def test_sanitize_csv_field_handles_special_characters():
    """Test that special characters are handled correctly."""
    assert sanitize_csv_field("test, value") == "test, value"
    assert sanitize_csv_field("test\"quote") == "test\"quote"
    assert sanitize_csv_field("test'quote") == "test'quote"
    assert sanitize_csv_field("test\nnewline") == "test\nnewline"
    assert sanitize_csv_field("test\ttab") == "test\ttab"


def test_generate_inventory_report_empty(test_db):
    """Test inventory report with no assets."""
    report = generate_inventory_report(db_path=test_db)
    assert report == "No assets in inventory"


def test_generate_inventory_report_populated(test_db):
    """Test inventory report with assets."""
    with get_db_connection(test_db) as conn:
        # Add test assets
        insert_asset(conn, {
            "name": "Test Asset 1",
            "system_name": "System A",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 256,
            "data_shelf_life_years": 5,
            "data_sensitivity": "High",
            "migration_status": "Not Started",
        })
        
        insert_asset(conn, {
            "name": "Test Asset 2",
            "system_name": "System B",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,
            "data_sensitivity": "Critical",
            "migration_status": "Planning",
        })
    
    report = generate_inventory_report(db_path=test_db)
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    assert len(rows) == 2
    assert rows[0]["Asset Name"] == "Test Asset 1"
    assert rows[0]["Algorithm"] == "AES"
    assert rows[1]["Asset Name"] == "Test Asset 2"
    assert rows[1]["Algorithm"] == "ECDH"


def test_generate_inventory_report_special_characters(test_db):
    """Test inventory report with special characters in data."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Asset with, comma",
            "system_name": "System with \"quote\"",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 256,
            "data_shelf_life_years": 5,
            "data_sensitivity": "Medium",
            "migration_status": "Not Started",
        })
    
    report = generate_inventory_report(db_path=test_db)
    
    # Should not raise error
    assert "Asset with, comma" in report
    # CSV properly escapes quotes by doubling them
    assert "System with" in report and "quote" in report


def test_generate_risk_assessment_report_empty(test_db):
    """Test risk assessment report with no assets."""
    report = generate_risk_assessment_report(db_path=test_db)
    assert report == "No assets in inventory"


def test_generate_risk_assessment_report_populated(test_db):
    """Test risk assessment report with assets."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "AES Asset",
            "system_name": "System A",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 128,
            "data_shelf_life_years": 5,
            "data_sensitivity": "Medium",
            "migration_status": "Not Started",
        })
        
        insert_asset(conn, {
            "name": "ECDH Asset",
            "system_name": "System B",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,
            "data_sensitivity": "High",
            "migration_status": "Planning",
        })
    
    report = generate_risk_assessment_report(db_path=test_db)
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    assert len(rows) == 2
    assert "Risk Level" in rows[0]
    assert "Risk Score" in rows[0]
    assert "Quantum Vulnerable" in rows[0]
    assert rows[0]["Algorithm"] == "AES"
    assert rows[1]["Algorithm"] == "ECDH"


def test_generate_risk_assessment_report_consistency(test_db):
    """Test that risk assessment data is consistent with engine."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Test Asset",
            "system_name": "System A",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 15,
            "data_sensitivity": "Critical",
            "migration_status": "Not Started",
        })
    
    report = generate_risk_assessment_report(db_path=test_db)
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    assert len(rows) == 1
    # ECDH with long shelf-life should be CRITICAL
    assert rows[0]["Risk Level"] == "CRITICAL"
    assert rows[0]["Quantum Vulnerable"] == "True"
    assert rows[0]["Shor Vulnerable"] == "True"


def test_generate_scenario_report_empty(test_db):
    """Test scenario report with no assets."""
    report = generate_scenario_report(target_year=2033, migration_duration_years=3, db_path=test_db)
    assert report == "No assets in inventory"


def test_generate_scenario_report_populated(test_db):
    """Test scenario report with assets."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Test Asset",
            "system_name": "System A",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,
            "data_sensitivity": "High",
            "migration_status": "Not Started",
        })
    
    report = generate_scenario_report(
        target_year=2033,
        migration_duration_years=3,
        current_year=2026,
        db_path=test_db,
    )
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    # First row should be metadata
    assert "Scenario Target Year" in rows[0]
    assert rows[0]["Scenario Target Year"] == "2033"
    assert rows[0]["Threat Horizon (Z) years"] == "7"
    
    # Second row should be asset data
    assert "Asset Name" in rows[1]
    assert "Planning Margin" in rows[1]
    assert "Buffer Status" in rows[1]


def test_generate_scenario_report_with_asset_filter(test_db):
    """Test scenario report with specific asset IDs."""
    with get_db_connection(test_db) as conn:
        id1 = insert_asset(conn, {
            "name": "Asset 1",
            "system_name": "System A",
            "crypto_algorithm": "AES",
            "crypto_role": "Symmetric Encryption",
            "key_size": 256,
            "data_shelf_life_years": 5,
            "data_sensitivity": "Medium",
            "migration_status": "Not Started",
        })
        
        id2 = insert_asset(conn, {
            "name": "Asset 2",
            "system_name": "System B",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,
            "data_sensitivity": "High",
            "migration_status": "Planning",
        })
    
    # Request only asset 1
    report = generate_scenario_report(
        target_year=2033,
        migration_duration_years=3,
        current_year=2026,
        asset_ids=[id1],
        db_path=test_db,
    )
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    # Should have metadata + 1 asset
    assert len(rows) == 2
    assert rows[1]["Asset Name"] == "Asset 1"


def test_generate_migration_recommendations_report_empty(test_db):
    """Test migration recommendations report with no assets."""
    report = generate_migration_recommendations_report(db_path=test_db)
    assert report == "No assets in inventory"


def test_generate_migration_recommendations_report_populated(test_db):
    """Test migration recommendations report with assets."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Test Asset",
            "system_name": "System A",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,
            "data_sensitivity": "High",
            "migration_status": "Not Started",
        })
    
    report = generate_migration_recommendations_report(db_path=test_db)
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    assert len(rows) == 1
    assert "Migration Priority" in rows[0]
    assert "Target PQC Algorithm" in rows[0]
    assert "NIST Specification" in rows[0]
    assert "Recommended Action" in rows[0]
    assert "Current Migration Status" in rows[0]
    
    # ECDH should recommend ML-KEM
    assert "ML-KEM" in rows[0]["Target PQC Algorithm"]
    assert "FIPS 203" in rows[0]["NIST Specification"]


def test_generate_comprehensive_report_empty(test_db):
    """Test comprehensive report with no assets."""
    report = generate_comprehensive_report(db_path=test_db)
    assert report == "No assets in inventory"


def test_generate_comprehensive_report_populated(test_db):
    """Test comprehensive report with assets."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Test Asset",
            "system_name": "System A",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 10,
            "data_sensitivity": "High",
            "migration_status": "Not Started",
        })
    
    report = generate_comprehensive_report(
        target_year=2033,
        migration_duration_years=3,
        current_year=2026,
        db_path=test_db,
    )
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(report))
    rows = list(reader)
    
    # Should have metadata + asset data
    assert len(rows) == 2
    assert "Report Generated" in rows[0]
    assert "Scenario Target Year" in rows[0]
    
    # Second row should have all fields
    assert "Asset Name" in rows[1]
    assert "Risk Level" in rows[1]
    assert "Migration Priority" in rows[1]
    assert "Planning Margin" in rows[1]
    assert "Exposure Status" in rows[1]


def test_all_reports_use_same_assessment_logic(test_db):
    """Test that all reports use the same assessment logic as the application."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Consistency Test Asset",
            "system_name": "System A",
            "crypto_algorithm": "ECDH",
            "crypto_role": "Key Establishment",
            "key_size": 256,
            "data_shelf_life_years": 15,
            "data_sensitivity": "Critical",
            "migration_status": "Not Started",
        })
    
    # Get risk assessment from reports
    risk_report = generate_risk_assessment_report(db_path=test_db)
    migration_report = generate_migration_recommendations_report(db_path=test_db)
    comprehensive_report = generate_comprehensive_report(db_path=test_db)
    
    # Parse risk report
    risk_reader = csv.DictReader(io.StringIO(risk_report))
    risk_rows = list(risk_reader)
    
    # Parse migration report
    migration_reader = csv.DictReader(io.StringIO(migration_report))
    migration_rows = list(migration_reader)
    
    # Parse comprehensive report
    comprehensive_reader = csv.DictReader(io.StringIO(comprehensive_report))
    comprehensive_rows = list(comprehensive_reader)
    
    # All should report the same risk level for the same asset
    assert risk_rows[0]["Risk Level"] == "CRITICAL"
    assert risk_rows[0]["Quantum Vulnerable"] == "True"
    
    assert migration_rows[0]["Risk Level"] == "CRITICAL"
    
    assert comprehensive_rows[1]["Risk Level"] == "CRITICAL"


def test_report_includes_uncertainty_labels(test_db):
    """Test that reports include uncertainty labels for unknown data."""
    with get_db_connection(test_db) as conn:
        insert_asset(conn, {
            "name": "Unknown Algorithm Asset",
            "system_name": "System A",
            "crypto_algorithm": "CustomProprietaryCipher",
            "crypto_role": "Unknown / Unclassified",
            "key_size": 256,
            "data_shelf_life_years": 5,
            "data_sensitivity": "Medium",
            "migration_status": "Not Started",
        })
    
    risk_report = generate_risk_assessment_report(db_path=test_db)
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(risk_report))
    rows = list(reader)
    
    # Should include UNKNOWN risk level
    assert rows[0]["Risk Level"] == "UNKNOWN"
    assert rows[0]["Quantum Vulnerable"] == "None" or rows[0]["Quantum Vulnerable"] == ""
