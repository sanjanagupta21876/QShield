"""Export utilities for generating CSV and structured reports from QShield data.

Ensures strict RFC 4180 compliance, safe handling of special characters
(commas, quotes, newlines, semicolons, Unicode), and protection against
CSV/Formula Injection (CWE-1236).
"""

import csv
import io
from typing import Any, Dict, List, Optional
from core.risk_engine import evaluate_quantum_risk
from core.recommendations import get_pqc_recommendation


def sanitize_csv_cell(value: Any) -> Any:
    """Sanitize cell value to prevent CSV Formula Injection (CWE-1236).

    If a text field begins with characters that spreadsheet programs
    (Excel, LibreOffice, Google Sheets) interpret as formulas
    ('=', '+', '-', '@', tab, carriage return), prepend a single quote (')
    to force text interpretation.

    Args:
        value: Any cell value.

    Returns:
        Sanitized value safe for spreadsheet export.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in ("=", "+", "-", "@", "\t", "\r"):
            # Prepend a single quote to neutralize formula execution
            return f"'{value}"
    return value


def export_inventory_to_csv(assets: List[Dict[str, Any]]) -> str:
    """Export cryptographic asset inventory to a CSV string.

    Args:
        assets: List of asset dictionaries from the database.

    Returns:
        RFC 4180 compliant CSV formatted string with UTF-8 encoding support.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Asset ID",
        "Asset Name",
        "System / Application",
        "Cryptographic Algorithm",
        "Operational Role",
        "Key Size (bits)",
        "Confidentiality Shelf-Life (Years, X)",
        "Migration Status",
        "Created At",
    ]
    writer.writerow(headers)

    for asset in assets:
        ks = asset.get("key_size")
        ks_display = "N/A" if (ks is None or ks == 0) else str(ks)
        row = [
            sanitize_csv_cell(asset.get("id")),
            sanitize_csv_cell(asset.get("name")),
            sanitize_csv_cell(asset.get("system_name")),
            sanitize_csv_cell(asset.get("crypto_algorithm")),
            sanitize_csv_cell(asset.get("crypto_role")),
            sanitize_csv_cell(ks_display),
            sanitize_csv_cell(asset.get("data_shelf_life_years")),
            sanitize_csv_cell(asset.get("migration_status")),
            sanitize_csv_cell(asset.get("created_at", "")),
        ]
        writer.writerow(row)

    return output.getvalue()


def export_risk_assessment_to_csv(assets: List[Dict[str, Any]]) -> str:
    """Export comprehensive quantum risk assessments for assets to a CSV string.

    Args:
        assets: List of asset dictionaries from the database.

    Returns:
        RFC 4180 compliant CSV string containing explainable assessment details.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Asset ID",
        "Asset Name",
        "System / Application",
        "Cryptographic Algorithm",
        "Cryptographic Category",
        "Operational Role",
        "Key Size (bits)",
        "Shelf-Life (Years, X)",
        "Risk Level",
        "Heuristic Risk Score",
        "Quantum Vulnerable",
        "Shor Susceptible",
        "Grover Affected",
        "Assessment Status",
        "Assessment Rigor",
        "Target PQC Algorithm",
        "NIST Standard",
        "Migration Priority",
        "Recommended Next Action",
    ]
    writer.writerow(headers)

    for asset in assets:
        raw_ks = asset.get("key_size")
        ks_val = int(raw_ks) if (raw_ks is not None and isinstance(raw_ks, int) and raw_ks > 0) else None
        shelf_life = int(asset.get("data_shelf_life_years", 5))

        risk = evaluate_quantum_risk(
            algorithm=str(asset.get("crypto_algorithm", "")),
            key_size=ks_val,
            data_shelf_life_years=shelf_life,
            crypto_role=asset.get("crypto_role"),
        )
        rec = get_pqc_recommendation(
            algorithm=str(asset.get("crypto_algorithm", "")),
            key_size=ks_val or 0,
            crypto_role=asset.get("crypto_role"),
        )

        ks_display = "N/A" if (raw_ks is None or raw_ks == 0) else str(raw_ks)
        qv_str = "Yes" if risk.get("quantum_vulnerable") is True else (
            "No" if risk.get("quantum_vulnerable") is False else "Unknown"
        )
        shor_str = "Yes" if risk.get("shor_vulnerable") is True else (
            "No" if risk.get("shor_vulnerable") is False else "Unknown"
        )
        grover_str = "Yes" if risk.get("grover_affected") is True else (
            "No" if risk.get("grover_affected") is False else "Unknown"
        )
        score_display = str(risk.get("risk_score")) if risk.get("risk_score") is not None else "N/A"

        row = [
            sanitize_csv_cell(asset.get("id")),
            sanitize_csv_cell(asset.get("name")),
            sanitize_csv_cell(asset.get("system_name")),
            sanitize_csv_cell(asset.get("crypto_algorithm")),
            sanitize_csv_cell(risk.get("cryptographic_category", "N/A")),
            sanitize_csv_cell(asset.get("crypto_role")),
            sanitize_csv_cell(ks_display),
            sanitize_csv_cell(shelf_life),
            sanitize_csv_cell(risk.get("risk_level")),
            sanitize_csv_cell(score_display),
            sanitize_csv_cell(qv_str),
            sanitize_csv_cell(shor_str),
            sanitize_csv_cell(grover_str),
            sanitize_csv_cell(risk.get("assessment_status")),
            sanitize_csv_cell(risk.get("result_rigor")),
            sanitize_csv_cell(rec.get("target_pqc_algorithm")),
            sanitize_csv_cell(rec.get("nist_standard")),
            sanitize_csv_cell(rec.get("priority")),
            sanitize_csv_cell(risk.get("recommended_next_action")),
        ]
        writer.writerow(row)

    return output.getvalue()


def export_scenario_to_csv(scenario_result: Dict[str, Any]) -> str:
    """Export threat scenario simulation results to a CSV string.

    Args:
        scenario_result: Output dictionary from simulate_quantum_threat_scenario.

    Returns:
        RFC 4180 compliant CSV string with asset-level planning margin evaluations.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Asset ID",
        "Asset Name",
        "System / Application",
        "Cryptographic Algorithm",
        "Operational Role",
        "Shelf-Life X (Years)",
        "Migration Duration Y (Years)",
        "Threat Horizon Z (Years)",
        "Planning Margin: Z - (X + Y)",
        "Buffer Status",
        "Quantum Vulnerable",
        "Exposure Status",
        "Risk Level",
        "Target Recommendation",
    ]
    writer.writerow(headers)

    evaluated = scenario_result.get("evaluated_assets", [])
    for item in evaluated:
        qv_str = "Yes" if item.get("quantum_vulnerable") is True else (
            "No" if item.get("quantum_vulnerable") is False else "Unknown"
        )
        row = [
            sanitize_csv_cell(item.get("id")),
            sanitize_csv_cell(item.get("name")),
            sanitize_csv_cell(item.get("system_name")),
            sanitize_csv_cell(item.get("crypto_algorithm")),
            sanitize_csv_cell(item.get("crypto_role")),
            sanitize_csv_cell(item.get("confidentiality_duration_X")),
            sanitize_csv_cell(item.get("migration_duration_Y")),
            sanitize_csv_cell(item.get("threat_horizon_Z")),
            sanitize_csv_cell(item.get("planning_margin")),
            sanitize_csv_cell(item.get("buffer_status")),
            sanitize_csv_cell(qv_str),
            sanitize_csv_cell(item.get("exposure_status")),
            sanitize_csv_cell(item.get("risk_level")),
            sanitize_csv_cell(item.get("target_pqc_recommendation")),
        ]
        writer.writerow(row)

    return output.getvalue()
