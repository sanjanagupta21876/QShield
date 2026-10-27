"""Hypothetical quantum-threat scenario simulation engine.

Planning Margin Heuristic:
--------------------------
This module implements a timeline evaluation based on Mosca's Theorem:
    Planning Margin = Z - (X + Y)
where:
    - X = Required data confidentiality duration in years (shelf-life).
    - Y = Estimated migration duration in years.
    - Z = Hypothetical years until the quantum-threat horizon (CRQC emergence).

Interpretation:
    - Negative Result (< 0): The combined confidentiality and migration timeline (X + Y)
      extends beyond the assumed threat horizon (Z). Indicates potential exposure.
    - Zero Result (== 0): No planning buffer exists under these assumptions.
    - Positive Result (> 0): A positive planning buffer exists under these assumptions.

Rigorous Exposure Categorization:
    - Confirmed Quantum Exposure: The primitive is mathematically vulnerable to quantum cryptanalysis
      (e.g., Shor's algorithm) AND the planning margin is negative.
    - Requires Additional Assessment: The algorithm is unrecognized or unclassified, or the role is incompatible.
      Such mechanisms are NEVER counted as confirmed quantum exposures.
    - Resilient / Buffer Maintained: Standardized PQC or algorithms maintaining positive/zero margin.

Disclaimer:
    This is a simplified planning heuristic, NOT a validated probability of compromise
    or an empirical prediction of when quantum computers will break cryptography.
"""

from typing import Any, Dict, List, Optional
from core.risk_engine import evaluate_quantum_risk
from core.recommendations import get_explainable_recommendations


def calculate_planning_margin(
    confidentiality_years_x: int,
    migration_years_y: int,
    horizon_years_z: int,
) -> int:
    """Calculate the planning margin: Z - (X + Y).

    Args:
        confidentiality_years_x: Required data confidentiality duration (X).
        migration_years_y: Estimated migration duration (Y).
        horizon_years_z: Hypothetical years until quantum-threat horizon (Z).

    Returns:
        Integer planning margin in years.
    """
    if type(confidentiality_years_x) is bool or not isinstance(confidentiality_years_x, int):
        raise TypeError(f"Confidentiality years X must be an integer, got {type(confidentiality_years_x).__name__}")
    if type(migration_years_y) is bool or not isinstance(migration_years_y, int):
        raise TypeError(f"Migration years Y must be an integer, got {type(migration_years_y).__name__}")
    if type(horizon_years_z) is bool or not isinstance(horizon_years_z, int):
        raise TypeError(f"Horizon years Z must be an integer, got {type(horizon_years_z).__name__}")

    return horizon_years_z - (confidentiality_years_x + migration_years_y)


def simulate_quantum_threat_scenario(
    assets: List[Dict[str, Any]],
    target_year: int = 2033,
    migration_duration_years: int = 3,
    current_year: int = 2026,
    asset_migration_overrides: Optional[Dict[Any, int]] = None,
) -> Dict[str, Any]:
    """Simulate organizational exposure under a hypothetical quantum-threat horizon.

    Uses the planning margin heuristic: Planning Margin = Z - (X + Y).

    Args:
        assets: List of cryptographic asset dictionaries.
        target_year: Hypothetical year when CRQC emerges (user-supplied assumption).
        migration_duration_years: Default time to complete PQC migration (Y).
        current_year: Reference baseline year.
        asset_migration_overrides: Optional dictionary mapping asset ID or name to custom Y years.

    Returns:
        Structured scenario assessment containing exposure counts, planning margins,
        and heuristic metrics.
    """
    # 1. Input Validation
    if type(target_year) is bool or not isinstance(target_year, int):
        raise TypeError(f"Target year must be an integer, got {type(target_year).__name__}")
    if type(current_year) is bool or not isinstance(current_year, int):
        raise TypeError(f"Current year must be an integer, got {type(current_year).__name__}")
    if type(migration_duration_years) is bool or not isinstance(migration_duration_years, int):
        raise TypeError(f"Migration duration must be an integer, got {type(migration_duration_years).__name__}")

    if target_year < current_year:
        raise ValueError(
            f"Hypothetical target year ({target_year}) cannot be earlier than baseline year ({current_year})."
        )
    if migration_duration_years < 0:
        raise ValueError(f"Migration duration cannot be negative ({migration_duration_years}).")

    z_years = target_year - current_year
    default_y = migration_duration_years
    overrides = asset_migration_overrides or {}

    total_assets = len(assets)
    evaluated_assets: List[Dict[str, Any]] = []
    confirmed_exposed_assets: List[Dict[str, Any]] = []
    requires_assessment_assets: List[Dict[str, Any]] = []
    quantum_vulnerable_assets: List[Dict[str, Any]] = []
    quantum_safe_assets: List[Dict[str, Any]] = []

    negative_margin_count = 0
    zero_margin_count = 0
    positive_margin_count = 0
    requires_assessment_negative_margin_count = 0

    for asset in assets:
        asset_id = asset.get("id")
        asset_name = asset.get("name")

        # Determine Y: use override if specified, otherwise global organizational Y
        if asset_id is not None and asset_id in overrides:
            y_years = overrides[asset_id]
        elif asset_name is not None and asset_name in overrides:
            y_years = overrides[asset_name]
        else:
            y_years = default_y

        if type(y_years) is bool or not isinstance(y_years, int) or y_years < 0:
            raise ValueError(f"Asset-specific migration duration must be a non-negative integer, got {y_years}")

        x_years = int(asset.get("data_shelf_life_years", 5))
        algo = str(asset.get("crypto_algorithm", ""))
        raw_ks = asset.get("key_size")
        # Unkeyed hash functions or omitted key sizes use a safe positive fallback for risk engine
        key_size = int(raw_ks) if (raw_ks is not None and isinstance(raw_ks, int) and raw_ks > 0) else 256
        role = asset.get("crypto_role")

        eval_result = evaluate_quantum_risk(
            algorithm=algo,
            key_size=key_size,
            data_shelf_life_years=x_years,
            crypto_role=role,
        )

        # Planning Margin = Z - (X + Y)
        planning_margin = calculate_planning_margin(
            confidentiality_years_x=x_years,
            migration_years_y=y_years,
            horizon_years_z=z_years,
        )

        if planning_margin < 0:
            buffer_status = "NEGATIVE_MARGIN"
            negative_margin_count += 1
        elif planning_margin == 0:
            buffer_status = "ZERO_BUFFER"
            zero_margin_count += 1
        else:
            buffer_status = "POSITIVE_MARGIN"
            positive_margin_count += 1

        is_quantum_vuln = eval_result.get("quantum_vulnerable")

        # Rigorous Exposure Classification:
        # 1. Confirmed Quantum Exposure: Vulnerable primitive AND negative planning margin
        # 2. Unknown / Incompatible: Classified separately; NEVER counted as confirmed exposure
        # 3. Safe / Resilient: Standardized PQC or Grover-resilient primitives
        if is_quantum_vuln is True:
            quantum_vulnerable_assets.append(asset)
            if planning_margin < 0:
                is_confirmed_exposed = True
                exposure_status = "CONFIRMED_EXPOSURE"
            else:
                is_confirmed_exposed = False
                exposure_status = "TIMELINE_BUFFER_MAINTAINED"
        elif is_quantum_vuln is False:
            quantum_safe_assets.append(asset)
            is_confirmed_exposed = False
            exposure_status = "QUANTUM_RESILIENT"
        else:
            # is_quantum_vuln is None (UNKNOWN or INCOMPATIBLE_ROLE)
            requires_assessment_assets.append(asset)
            is_confirmed_exposed = False  # NEVER count unknown as confirmed exposure
            if planning_margin < 0:
                requires_assessment_negative_margin_count += 1
                exposure_status = "POTENTIAL_EXPOSURE_UNCONFIRMED"
            else:
                exposure_status = "REQUIRES_ASSESSMENT"

        # Generate explainable recommendations for this asset
        asset_recommendations = get_explainable_recommendations(
            algorithm=algo,
            key_size=key_size,
            crypto_role=role,
            data_shelf_life_years=x_years,
            risk_assessment=eval_result,
            planning_margin=planning_margin,
            data_sensitivity=asset.get("data_sensitivity"),
        )

        asset_summary = {
            "id": asset_id,
            "name": asset_name,
            "system_name": asset.get("system_name"),
            "crypto_algorithm": algo,
            "crypto_role": role,
            "confidentiality_duration_X": x_years,
            "migration_duration_Y": y_years,
            "threat_horizon_Z": z_years,
            "planning_margin": planning_margin,
            "buffer_status": buffer_status,
            "risk_level": eval_result["risk_level"],
            "quantum_vulnerable": is_quantum_vuln,
            "exposure_status": exposure_status,
            "is_exposed": is_confirmed_exposed,
            "result_rigor": eval_result.get("result_rigor", "Heuristic"),
            "target_pqc_recommendation": eval_result.get("recommended_next_action", "Maintain or migrate"),
            "recommendations": asset_recommendations,
        }

        evaluated_assets.append(asset_summary)
        if is_confirmed_exposed:
            confirmed_exposed_assets.append(asset_summary)

    confirmed_exposed_count = len(confirmed_exposed_assets)
    exposure_percentage = (confirmed_exposed_count / total_assets * 100) if total_assets > 0 else 0.0

    margins = [a["planning_margin"] for a in evaluated_assets]
    min_margin = min(margins) if margins else 0

    simulation_assumptions = [
        f"Reference baseline year is set to {current_year}.",
        f"Hypothetical threat horizon year is {target_year} (Z = {z_years} years until hypothetical CRQC emergence).",
        f"Default organizational migration duration is {default_y} years (Y).",
        "Planning margin formula: Planning Margin = Z - (X + Y).",
        "Confirmed quantum exposure strictly requires both algorithmic vulnerability (e.g. Shor's algorithm) AND a negative planning margin.",
        "Unrecognized, proprietary, or incompatible mechanisms are categorized under 'Requires Additional Assessment' and are NOT counted as confirmed exposures.",
        "A positive planning margin indicates migration lead time, not guaranteed end-to-end security.",
        "A negative planning margin highlights migration urgency, not an empirical compromise of the algorithm today.",
    ]

    return {
        "scenario_target_year": target_year,
        "current_year": current_year,
        "threat_horizon_years_Z": z_years,
        "migration_duration_years_Y": default_y,
        "total_assets_evaluated": total_assets,
        "negative_margin_count": negative_margin_count,
        "zero_margin_count": zero_margin_count,
        "positive_margin_count": positive_margin_count,
        "quantum_vulnerable_count": len(quantum_vulnerable_assets),
        "quantum_safe_count": len(quantum_safe_assets),
        "requires_assessment_count": len(requires_assessment_assets),
        "confirmed_exposed_assets_count": confirmed_exposed_count,
        "exposed_assets_count": confirmed_exposed_count,  # Backwards compatibility alias
        "requires_assessment_negative_margin_count": requires_assessment_negative_margin_count,
        "exposure_percentage": round(exposure_percentage, 1),
        "minimum_planning_margin": min_margin,
        "evaluated_assets": evaluated_assets,
        "confirmed_exposed_assets": confirmed_exposed_assets,
        "vulnerable_assets": confirmed_exposed_assets,  # Backwards compatibility alias
        "requires_assessment_assets": requires_assessment_assets,
        "assumptions": simulation_assumptions,
        "heuristic_disclaimer": (
            "Planning Margin = Z - (X + Y) is a simplified planning heuristic, "
            "not a validated probability of compromise or an empirical prediction "
            "of when quantum computers will break cryptography."
        ),
    }


def compare_scenarios(
    assets: List[Dict[str, Any]],
    target_years: List[int],
    migration_duration_years: int = 3,
    current_year: int = 2026,
    asset_migration_overrides: Optional[Dict[Any, int]] = None,
) -> List[Dict[str, Any]]:
    """Compare multiple quantum-threat horizon scenarios against the same asset inventory.

    Args:
        assets: List of cryptographic asset dictionaries.
        target_years: List of hypothetical CRQC emergence years to evaluate.
        migration_duration_years: Default migration duration Y in years.
        current_year: Reference baseline year.
        asset_migration_overrides: Optional per-asset migration duration overrides.

    Returns:
        List of scenario result dictionaries, sorted by target_year.
    """
    if not target_years:
        return []

    results = []
    for yr in sorted(target_years):
        sim = simulate_quantum_threat_scenario(
            assets=assets,
            target_year=yr,
            migration_duration_years=migration_duration_years,
            current_year=current_year,
            asset_migration_overrides=asset_migration_overrides,
        )
        results.append(sim)
    return results
