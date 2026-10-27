"""QShield — Standalone Demonstration Helper & Workflow Script.

Usage:
    python demo.py
    python demo.py --clear
"""

import sys
from pathlib import Path

# Ensure QShield package path is available
sys.path.insert(0, str(Path(__file__).resolve().parent / "QShield"))

from core.database import init_db, get_db_connection, get_all_assets
from core.demo_data import load_demo_dataset
from core.risk_engine import evaluate_quantum_risk
from core.scenario_engine import simulate_quantum_threat_scenario


def run_demonstration_summary():
    """Load demonstration dataset and print a high-level summary of the demo workflow."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    clear_existing = "--clear" in sys.argv

    print("=" * 72)
    print("[QShield] Quantum-Safe Migration Planner (Demonstration Suite)")
    print("=" * 72)

    init_db()
    with get_db_connection() as conn:
        res = load_demo_dataset(conn, clear_existing=clear_existing)
        assets = get_all_assets(conn)

    print(f"\n[1] Demonstration Dataset Status:")
    print(f"    - New demo assets inserted : {res['inserted']}")
    print(f"    - Existing assets skipped  : {res['skipped']}")
    print(f"    - Total registered assets  : {len(assets)}")

    print(f"\n[2] Sample Asset Evaluations:")
    for a in assets[:4]:
        eval_res = evaluate_quantum_risk(
            algorithm=a["crypto_algorithm"],
            key_size=a["key_size"],
            data_shelf_life_years=a["data_shelf_life_years"],
            crypto_role=a.get("crypto_role"),
        )
        print(f"    • {a['name']}")
        print(f"      Algo: {a['crypto_algorithm']} | Role: {a['crypto_role']} | Shelf-Life: {a['data_shelf_life_years']}y")
        print(f"      Risk Level: {eval_res['risk_level']} | Score: {eval_res['risk_score']} | Shor Vuln: {eval_res.get('shor_vulnerable')}")

    print(f"\n[3] Baseline Threat Scenario Simulation (Horizon 2033, Y=3):")
    sim = simulate_quantum_threat_scenario(assets, target_year=2033, migration_duration_years=3)
    print(f"    - Total Assessed        : {sim['total_assets_evaluated']}")
    print(f"    - Confirmed Exposed     : {sim['confirmed_exposed_assets_count']} (Shor-vulnerable + Negative margin)")
    print(f"    - Requires Assessment   : {sim['requires_assessment_count']} (Unclassified mechanisms)")
    print(f"    - Resilient / Buffered  : {sim['resilient_or_buffered_count']}")
    print(f"    - Exposure Percentage   : {sim['exposure_percentage']}%")

    print("\n" + "=" * 72)
    print("Launch the interactive Web UI with:")
    print("    cd QShield && streamlit run app.py")
    print("Or from root:")
    print("    streamlit run QShield/app.py")
    print("=" * 72)


if __name__ == "__main__":
    run_demonstration_summary()
