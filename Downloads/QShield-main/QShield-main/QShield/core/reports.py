"""Report generation and CSV export module for QShield.

Provides export functionality for:
- Cryptographic asset inventory
- Asset-level risk assessment results
- Scenario simulation results
- Migration recommendations and statuses

All exports use the same assessment logic as the application and include
relevant context, timestamps, and assumptions.
"""

import csv
import io
from datetime import datetime
from typing import Any, Dict, List, Optional
import pandas as pd

from core.database import get_db_connection, get_all_assets
from core.risk_engine import evaluate_quantum_risk
from core.recommendations import get_pqc_recommendation, get_explainable_recommendations
from core.scenario_engine import simulate_quantum_threat_scenario


def sanitize_csv_field(value: Any) -> str:
    """Sanitize a field value to prevent CSV formula injection.
    
    Prevents spreadsheet formula injection by ensuring values that start with
    '=', '+', '-', '@' are prefixed with a tab character.
    
    Args:
        value: The value to sanitize.
    
    Returns:
        Sanitized string value.
    """
    if value is None:
        return ""
    
    str_value = str(value).strip()
    
    # Prevent formula injection
    if str_value and str_value[0] in "=+-@":
        return f"\t{str_value}"
    
    return str_value


def generate_inventory_report(db_path: str = "data/qshield.db") -> str:
    """Generate CSV report of cryptographic asset inventory.
    
    Args:
        db_path: Path to the database file.
    
    Returns:
        CSV string containing all asset inventory data.
    """
    with get_db_connection(db_path) as conn:
        assets = get_all_assets(conn)
    
    if not assets:
        return "No assets in inventory"
    
    output = io.StringIO()
    fieldnames = [
        "ID",
        "Asset Name",
        "System Name",
        "Algorithm",
        "Cryptographic Role",
        "Key Size (bits)",
        "Data Shelf-Life (years)",
        "Data Sensitivity",
        "Migration Status",
        "Created At",
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for asset in assets:
        ks = asset.get("key_size")
        ks_str = "N/A" if (ks is None or ks == 0) else f"{ks}"
        
        writer.writerow({
            "ID": sanitize_csv_field(asset.get("id")),
            "Asset Name": sanitize_csv_field(asset.get("name")),
            "System Name": sanitize_csv_field(asset.get("system_name")),
            "Algorithm": sanitize_csv_field(asset.get("crypto_algorithm")),
            "Cryptographic Role": sanitize_csv_field(asset.get("crypto_role")),
            "Key Size (bits)": sanitize_csv_field(ks_str),
            "Data Shelf-Life (years)": sanitize_csv_field(asset.get("data_shelf_life_years")),
            "Data Sensitivity": sanitize_csv_field(asset.get("data_sensitivity", "Medium")),
            "Migration Status": sanitize_csv_field(asset.get("migration_status")),
            "Created At": sanitize_csv_field(asset.get("created_at")),
        })
    
    return output.getvalue()


def generate_risk_assessment_report(db_path: str = "data/qshield.db") -> str:
    """Generate CSV report of asset-level risk assessment results.
    
    Args:
        db_path: Path to the database file.
    
    Returns:
        CSV string containing risk assessment data for all assets.
    """
    with get_db_connection(db_path) as conn:
        assets = get_all_assets(conn)
    
    if not assets:
        return "No assets in inventory"
    
    output = io.StringIO()
    fieldnames = [
        "ID",
        "Asset Name",
        "System Name",
        "Algorithm",
        "Cryptographic Role",
        "Key Size (bits)",
        "Risk Level",
        "Risk Score",
        "Quantum Vulnerable",
        "Shor Vulnerable",
        "Grover Affected",
        "Cryptographic Category",
        "Assessment Status",
        "Assessment Rigor",
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for asset in assets:
        ks = asset.get("key_size")
        ks_val = ks if (ks is not None and ks > 0) else 256
        
        assessment = evaluate_quantum_risk(
            algorithm=asset.get("crypto_algorithm"),
            key_size=ks_val,
            data_shelf_life_years=asset.get("data_shelf_life_years", 5),
            crypto_role=asset.get("crypto_role"),
        )
        
        writer.writerow({
            "ID": sanitize_csv_field(asset.get("id")),
            "Asset Name": sanitize_csv_field(asset.get("name")),
            "System Name": sanitize_csv_field(asset.get("system_name")),
            "Algorithm": sanitize_csv_field(asset.get("crypto_algorithm")),
            "Cryptographic Role": sanitize_csv_field(asset.get("crypto_role")),
            "Key Size (bits)": sanitize_csv_field(ks),
            "Risk Level": sanitize_csv_field(assessment.get("risk_level")),
            "Risk Score": sanitize_csv_field(assessment.get("risk_score")),
            "Quantum Vulnerable": sanitize_csv_field(assessment.get("quantum_vulnerable")),
            "Shor Vulnerable": sanitize_csv_field(assessment.get("shor_vulnerable")),
            "Grover Affected": sanitize_csv_field(assessment.get("grover_affected")),
            "Cryptographic Category": sanitize_csv_field(assessment.get("cryptographic_category")),
            "Assessment Status": sanitize_csv_field(assessment.get("assessment_status")),
            "Assessment Rigor": sanitize_csv_field(assessment.get("result_rigor")),
        })
    
    return output.getvalue()


def generate_scenario_report(
    target_year: int,
    migration_duration_years: int,
    current_year: int = 2026,
    asset_ids: Optional[List[int]] = None,
    db_path: str = "data/qshield.db",
) -> str:
    """Generate CSV report of scenario simulation results.
    
    Args:
        target_year: Hypothetical CRQC threat horizon year.
        migration_duration_years: Estimated migration duration in years.
        current_year: Reference baseline year.
        asset_ids: Optional list of asset IDs to include. If None, includes all assets.
        db_path: Path to the database file.
    
    Returns:
        CSV string containing scenario simulation data.
    """
    with get_db_connection(db_path) as conn:
        all_assets = get_all_assets(conn)
    
    if not all_assets:
        return "No assets in inventory"
    
    # Filter assets if specific IDs provided
    if asset_ids:
        assets = [a for a in all_assets if a.get("id") in asset_ids]
    else:
        assets = all_assets
    
    if not assets:
        return "No assets matching selection"
    
    # Run simulation
    sim_result = simulate_quantum_threat_scenario(
        assets=assets,
        target_year=target_year,
        migration_duration_years=migration_duration_years,
        current_year=current_year,
    )
    
    output = io.StringIO()
    fieldnames = [
        "Report Generated",
        "Scenario Target Year",
        "Threat Horizon (Z) years",
        "Migration Duration (Y) years",
        "---",
        "Asset ID",
        "Asset Name",
        "System Name",
        "Algorithm",
        "Cryptographic Role",
        "Shelf-Life (X) years",
        "Migration (Y) years",
        "Planning Margin",
        "Buffer Status",
        "Risk Level",
        "Quantum Vulnerable",
        "Exposure Status",
        "Target Recommendation",
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    # Write scenario metadata
    writer.writerow({
        "Report Generated": sanitize_csv_field(datetime.now().isoformat()),
        "Scenario Target Year": sanitize_csv_field(target_year),
        "Threat Horizon (Z) years": sanitize_csv_field(target_year - current_year),
        "Migration Duration (Y) years": sanitize_csv_field(migration_duration_years),
    })
    
    # Write asset-level results
    for item in sim_result["evaluated_assets"]:
        writer.writerow({
            "Asset ID": sanitize_csv_field(item.get("id")),
            "Asset Name": sanitize_csv_field(item.get("name")),
            "System Name": sanitize_csv_field(item.get("system_name")),
            "Algorithm": sanitize_csv_field(item.get("crypto_algorithm")),
            "Cryptographic Role": sanitize_csv_field(item.get("crypto_role")),
            "Shelf-Life (X) years": sanitize_csv_field(item.get("confidentiality_duration_X")),
            "Migration (Y) years": sanitize_csv_field(item.get("migration_duration_Y")),
            "Planning Margin": sanitize_csv_field(item.get("planning_margin")),
            "Buffer Status": sanitize_csv_field(item.get("buffer_status")),
            "Risk Level": sanitize_csv_field(item.get("risk_level")),
            "Quantum Vulnerable": sanitize_csv_field(item.get("quantum_vulnerable")),
            "Exposure Status": sanitize_csv_field(item.get("exposure_status")),
            "Target Recommendation": sanitize_csv_field(item.get("target_pqc_recommendation")),
        })
    
    return output.getvalue()


def generate_migration_recommendations_report(db_path: str = "data/qshield.db") -> str:
    """Generate CSV report of migration recommendations and statuses.
    
    Args:
        db_path: Path to the database file.
    
    Returns:
        CSV string containing migration recommendations for all assets.
    """
    with get_db_connection(db_path) as conn:
        assets = get_all_assets(conn)
    
    if not assets:
        return "No assets in inventory"
    
    output = io.StringIO()
    fieldnames = [
        "ID",
        "Asset Name",
        "System Name",
        "Algorithm",
        "Cryptographic Role",
        "Key Size (bits)",
        "Risk Level",
        "Migration Priority",
        "Target PQC Algorithm",
        "NIST Specification",
        "Recommended Action",
        "Current Migration Status",
        "Data Shelf-Life (years)",
        "Data Sensitivity",
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for asset in assets:
        ks = asset.get("key_size")
        ks_val = ks if (ks is not None and ks > 0) else 0
        
        # Get risk assessment
        assessment = evaluate_quantum_risk(
            algorithm=asset.get("crypto_algorithm"),
            key_size=ks_val,
            data_shelf_life_years=asset.get("data_shelf_life_years", 5),
            crypto_role=asset.get("crypto_role"),
        )
        
        # Get recommendation
        recommendation = get_pqc_recommendation(
            algorithm=asset.get("crypto_algorithm"),
            key_size=ks_val,
            crypto_role=asset.get("crypto_role"),
        )
        
        writer.writerow({
            "ID": sanitize_csv_field(asset.get("id")),
            "Asset Name": sanitize_csv_field(asset.get("name")),
            "System Name": sanitize_csv_field(asset.get("system_name")),
            "Algorithm": sanitize_csv_field(asset.get("crypto_algorithm")),
            "Cryptographic Role": sanitize_csv_field(asset.get("crypto_role")),
            "Key Size (bits)": sanitize_csv_field(ks),
            "Risk Level": sanitize_csv_field(assessment.get("risk_level")),
            "Migration Priority": sanitize_csv_field(recommendation.get("priority")),
            "Target PQC Algorithm": sanitize_csv_field(recommendation.get("target_pqc_algorithm")),
            "NIST Specification": sanitize_csv_field(recommendation.get("nist_standard")),
            "Recommended Action": sanitize_csv_field(recommendation.get("action")),
            "Current Migration Status": sanitize_csv_field(asset.get("migration_status")),
            "Data Shelf-Life (years)": sanitize_csv_field(asset.get("data_shelf_life_years")),
            "Data Sensitivity": sanitize_csv_field(asset.get("data_sensitivity", "Medium")),
        })
    
    return output.getvalue()


def generate_comprehensive_report(
    target_year: int = 2033,
    migration_duration_years: int = 3,
    current_year: int = 2026,
    db_path: str = "data/qshield.db",
) -> str:
    """Generate comprehensive CSV report with all data.
    
    Args:
        target_year: Hypothetical CRQC threat horizon year.
        migration_duration_years: Estimated migration duration in years.
        current_year: Reference baseline year.
        db_path: Path to the database file.
    
    Returns:
        CSV string containing comprehensive data.
    """
    with get_db_connection(db_path) as conn:
        assets = get_all_assets(conn)
    
    if not assets:
        return "No assets in inventory"
    
    output = io.StringIO()
    fieldnames = [
        "Report Generated",
        "Scenario Target Year",
        "Threat Horizon (Z) years",
        "Migration Duration (Y) years",
        "---",
        "Asset ID",
        "Asset Name",
        "System Name",
        "Algorithm",
        "Cryptographic Role",
        "Key Size (bits)",
        "Data Shelf-Life (years)",
        "Data Sensitivity",
        "Migration Status",
        "Risk Level",
        "Risk Score",
        "Quantum Vulnerable",
        "Shor Vulnerable",
        "Grover Affected",
        "Cryptographic Category",
        "Migration Priority",
        "Target PQC Algorithm",
        "NIST Specification",
        "Planning Margin",
        "Buffer Status",
        "Exposure Status",
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    # Write scenario metadata
    writer.writerow({
        "Report Generated": sanitize_csv_field(datetime.now().isoformat()),
        "Scenario Target Year": sanitize_csv_field(target_year),
        "Threat Horizon (Z) years": sanitize_csv_field(target_year - current_year),
        "Migration Duration (Y) years": sanitize_csv_field(migration_duration_years),
    })
    
    # Run simulation for planning margin
    sim_result = simulate_quantum_threat_scenario(
        assets=assets,
        target_year=target_year,
        migration_duration_years=migration_duration_years,
        current_year=current_year,
    )
    
    # Create asset ID to margin mapping
    margin_map = {item["id"]: item for item in sim_result["evaluated_assets"]}
    
    for asset in assets:
        ks = asset.get("key_size")
        ks_val = ks if (ks is not None and ks > 0) else 0
        
        # Get risk assessment
        assessment = evaluate_quantum_risk(
            algorithm=asset.get("crypto_algorithm"),
            key_size=ks_val,
            data_shelf_life_years=asset.get("data_shelf_life_years", 5),
            crypto_role=asset.get("crypto_role"),
        )
        
        # Get recommendation
        recommendation = get_pqc_recommendation(
            algorithm=asset.get("crypto_algorithm"),
            key_size=ks_val,
            crypto_role=asset.get("crypto_role"),
        )
        
        # Get planning margin
        margin_data = margin_map.get(asset.get("id"), {})
        
        writer.writerow({
            "Asset ID": sanitize_csv_field(asset.get("id")),
            "Asset Name": sanitize_csv_field(asset.get("name")),
            "System Name": sanitize_csv_field(asset.get("system_name")),
            "Algorithm": sanitize_csv_field(asset.get("crypto_algorithm")),
            "Cryptographic Role": sanitize_csv_field(asset.get("crypto_role")),
            "Key Size (bits)": sanitize_csv_field(ks),
            "Data Shelf-Life (years)": sanitize_csv_field(asset.get("data_shelf_life_years")),
            "Data Sensitivity": sanitize_csv_field(asset.get("data_sensitivity", "Medium")),
            "Migration Status": sanitize_csv_field(asset.get("migration_status")),
            "Risk Level": sanitize_csv_field(assessment.get("risk_level")),
            "Risk Score": sanitize_csv_field(assessment.get("risk_score")),
            "Quantum Vulnerable": sanitize_csv_field(assessment.get("quantum_vulnerable")),
            "Shor Vulnerable": sanitize_csv_field(assessment.get("shor_vulnerable")),
            "Grover Affected": sanitize_csv_field(assessment.get("grover_affected")),
            "Cryptographic Category": sanitize_csv_field(assessment.get("cryptographic_category")),
            "Migration Priority": sanitize_csv_field(recommendation.get("priority")),
            "Target PQC Algorithm": sanitize_csv_field(recommendation.get("target_pqc_algorithm")),
            "NIST Specification": sanitize_csv_field(recommendation.get("nist_standard")),
            "Planning Margin": sanitize_csv_field(margin_data.get("planning_margin")),
            "Buffer Status": sanitize_csv_field(margin_data.get("buffer_status")),
            "Exposure Status": sanitize_csv_field(margin_data.get("exposure_status")),
        })
    
    return output.getvalue()
