"""QShield — Quantum-Safe Migration Planner
Phase 1: Project Setup & Architectural Baseline
"""

import sys
from pathlib import Path

# Ensure project root / app directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st
import pandas as pd

# Core imports
from core.database import (
    init_db,
    get_db_connection,
    insert_asset,
    get_all_assets,
    get_asset_by_id,
    update_asset,
    update_asset_migration_status,
    delete_asset,
    search_assets,
)
from core.risk_engine import evaluate_quantum_risk
from core.scenario_engine import (
    simulate_quantum_threat_scenario,
    compare_scenarios,
    calculate_planning_margin,
)
from core.recommendations import get_pqc_recommendation
from core.validation import KNOWN_ALGORITHMS, KNOWN_ROLES, VALID_MIGRATION_STATUSES
from core.export import (
    export_inventory_to_csv,
    export_risk_assessment_to_csv,
    export_scenario_to_csv,
)
from core.demo_data import load_demo_dataset, SYNTHETIC_DEMO_ASSETS
from components.forms import render_asset_intake_form, render_asset_edit_form
from components.charts import (
    create_risk_distribution_chart,
    create_planning_margin_distribution_chart,
    create_asset_margins_comparison_chart,
    create_scenario_comparison_chart,
    create_scenario_exposure_breakdown_chart,
)

# Page configuration
st.set_page_config(
    page_title="QShield — Quantum-Safe Migration Planner",
    page_icon="🛡️",
    layout="wide",
)

# Initialize database
init_db()


def main():
    st.title("🛡️ QShield — Quantum-Safe Migration Planner")
    st.caption("IDEATHON 2026 | Cybersecurity & Post-Quantum Cryptography Planning Tool")

    # Sidebar: System Environment & Architecture Status
    with st.sidebar:
        st.header("⚙️ System Status")
        st.success("Core Architecture: Initialized")
        st.info("Storage: SQLite (`data/qshield.db`)")
        st.markdown("---")
        st.subheader("Architectural Modules")
        st.markdown(
            """
            - `core.database`: Active
            - `core.risk_engine`: Active
            - `core.scenario_engine`: Active
            - `core.recommendations`: Active
            - `core.validation`: Active
            - `core.export`: Active
            - `core.demo_data`: Active
            - `components.charts`: Active
            - `components.forms`: Active
            """
        )
        st.markdown("---")
        st.subheader("🎯 Demonstration Tools")
        with st.expander("✨ Load Demonstration Dataset", expanded=False):
            st.caption(
                "Load 10 curated synthetic assets spanning RSA, ECDSA, AES, Hashes, and NIST PQC. "
                "Preserves existing inventory unless explicitly checked."
            )
            side_clear = st.checkbox("Clear existing inventory first", value=False, key="side_clear_demo_check")
            if st.button("🚀 Load Synthetic Data", use_container_width=True, key="side_load_demo_btn"):
                with get_db_connection() as conn:
                    res = load_demo_dataset(conn, clear_existing=side_clear)
                    st.success(f"Loaded: {res['inserted']} inserted, {res['skipped']} already present.")
                    st.rerun()

        st.markdown("---")
        st.caption("QShield v1.0 — Demonstration & Evaluation Release")

    # Main navigation tabs
    tab_overview, tab_inventory, tab_assessment, tab_simulator, tab_calculator = st.tabs(
        [
            "📋 Overview & Architecture",
            "🗄️ Asset Inventory",
            "🛡️ Explainable Risk Assessment",
            "🔮 Threat Scenario Simulator",
            "🔬 Quantum Risk Calculator",
        ]
    )

    # Tab 1: Overview & Architecture
    with tab_overview:
        st.subheader("Welcome to QShield")
        st.markdown(
            """
            **QShield** is a software-based cybersecurity planning platform designed to assist organizations 
            in identifying cryptographic exposure to future quantum computers and planning structured migration 
            to **Post-Quantum Cryptography (PQC)**.
            
            ### Implemented Platform Capabilities
            - **Modular Core Architecture**: Decoupled backend business logic (`core/`) and Plotly visualization UI (`components/`).
            - **Cryptographic Inventory Layer**: SQLite database tracking algorithm families, operational roles, key lengths, confidentiality shelf-life ($X$), and migration statuses.
            - **Explainable Quantum Risk Engine**: Transparent evaluation of Shor-vulnerable public-key algorithms, Grover-affected symmetric ciphers, hash functions, standardized PQC, and explicit unknown handling.
            - **7-Dimension Asset Profiling**: Provides cryptanalytic threat relevance, Harvest Now Decrypt Later (HNDL) implications, mathematical vulnerability vs. timeline exposure distinction, assessment rigor, and next actions.
            - **Interactive Scenario Simulator**: Dynamic modeling of Mosca's Theorem:
              $$\\text{Planning Margin} = Z - (X + Y)$$
              evaluating organizational readiness across custom threat horizons ($Z$) and migration durations ($Y$).
            - **Multi-Scenario Comparison Dashboard**: Side-by-side comparison across user-configured threat horizons (e.g. 2029, 2033, 2038).
            - **Role-Aware NIST PQC Recommendations**: Specific targets aligned with NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and SP 800-38D (AES-256).
            - **Audit-Ready Report Exports**: Exporting inventory, risk evaluations, and scenario results to CSV with formula injection sanitization.
            - **Demonstration Suite**: Pre-configured synthetic demonstration dataset covering 10 diverse cryptographic mechanisms for testing and evaluation.
            """
        )

        st.warning(
            "**Important Architectural Disclaimers:**\n\n"
            "1. **Planning Margin Heuristic**: The formula $Z - (X + Y)$ is a simplified planning heuristic, "
            "not a validated empirical probability of compromise or a calendar prediction of when quantum computers will break cryptography.\n\n"
            "2. **System vs. Primitive Scope**: Assessing an individual algorithm as quantum-resilient does not label "
            "an entire system or communication channel quantum-safe. End-to-end security requires that all components "
            "(key exchange, signatures, certificates, symmetric encryption, and hashes) are protected."
        )

        st.info(
            "💡 **Getting Started**: Explore registered assets in the **Asset Inventory** tab, inspect 7-dimension explainability profiles "
            "in **Explainable Risk Assessment**, model threat horizons in **Threat Scenario Simulator**, or load the synthetic dataset from the sidebar."
        )

    # Tab 2: Asset Inventory
    with tab_inventory:
        st.subheader("🗄️ Cryptographic Asset Inventory")

        # Fetch current assets from database
        with get_db_connection() as conn:
            all_assets = get_all_assets(conn)

        # Form to add assets (expanded by default if inventory is empty)
        with st.expander("➕ Register New Cryptographic Asset", expanded=(len(all_assets) == 0)):
            new_asset = render_asset_intake_form()
            if new_asset:
                with get_db_connection() as conn:
                    inserted_id = insert_asset(conn, new_asset)
                    st.success(f"Asset '{new_asset['name']}' successfully registered (ID: {inserted_id}).")
                    st.rerun()

        # Demonstration dataset quick loader
        with st.expander("✨ Demonstration Dataset Controls", expanded=(len(all_assets) == 0)):
            st.markdown(
                "Quickly populate the database with a pre-configured, realistic synthetic dataset "
                "spanning 10 assets (RSA, ECDSA, Diffie-Hellman, AES-128, AES-256, SHA-256, ML-KEM, ML-DSA, 3DES, Custom Cipher)."
            )
            col_demo_opt, col_demo_btn = st.columns([3, 1])
            with col_demo_opt:
                tab_clear_first = st.checkbox(
                    "⚠️ Purge existing inventory before loading demo data",
                    value=False,
                    key="tab_demo_clear_first",
                    help="Unchecked by default. When unchecked, existing user assets are fully preserved and duplicate names are skipped.",
                )
            with col_demo_btn:
                if st.button("🚀 Load Demo Assets", use_container_width=True, key="tab_demo_load_btn"):
                    with get_db_connection() as conn:
                        res = load_demo_dataset(conn, clear_existing=tab_clear_first)
                        st.success(f"Demonstration data loaded: {res['inserted']} inserted, {res['skipped']} already present (Total: {res['total']} assets).")
                        st.rerun()

        if all_assets:
            st.markdown("---")
            st.markdown("### 🔍 Search & Filter Inventory")

            # Search and Filter Controls
            col_search, col_f_algo, col_f_role, col_f_status = st.columns([3, 2, 2, 2])
            with col_search:
                search_term = st.text_input("Search Assets", placeholder="Search name, system, algorithm...")
            with col_f_algo:
                existing_algos = ["All"] + sorted(list({a["crypto_algorithm"] for a in all_assets}))
                filter_algo = st.selectbox("Algorithm", options=existing_algos)
            with col_f_role:
                existing_roles = ["All"] + sorted(list({a["crypto_role"] for a in all_assets}))
                filter_role = st.selectbox("Operational Role", options=existing_roles)
            with col_f_status:
                existing_statuses = ["All"] + sorted(list({a["migration_status"] for a in all_assets}))
                filter_status = st.selectbox("Migration Status", options=existing_statuses)

            col_sort1, col_sort2 = st.columns([3, 1])
            with col_sort1:
                sort_col_map = {
                    "ID": "id",
                    "Asset Name": "name",
                    "System Name": "system_name",
                    "Algorithm": "crypto_algorithm",
                    "Role": "crypto_role",
                    "Shelf-Life": "data_shelf_life_years",
                    "Status": "migration_status",
                    "Created At": "created_at",
                }
                sort_display = st.selectbox("Sort By", options=list(sort_col_map.keys()), index=0)
                sort_key = sort_col_map[sort_display]
            with col_sort2:
                sort_dir = st.radio("Order", ["Ascending", "Descending"], horizontal=True)
                sort_asc = (sort_dir == "Ascending")

            # Execute parameterized search & filter
            with get_db_connection() as conn:
                filtered_assets = search_assets(
                    conn=conn,
                    search_term=search_term,
                    algorithm=filter_algo,
                    role=filter_role,
                    migration_status=filter_status,
                    sort_by=sort_key,
                    sort_asc=sort_asc,
                )

            st.markdown(f"**Showing {len(filtered_assets)} of {len(all_assets)} registered assets**")

            if filtered_assets:
                # Format dataframe for clean display
                display_rows = []
                for a in filtered_assets:
                    ks = a["key_size"]
                    ks_str = "N/A" if (ks is None or ks == 0) else f"{ks} bits"
                    display_rows.append({
                        "ID": a["id"],
                        "Name": a["name"],
                        "System": a["system_name"],
                        "Algorithm": a["crypto_algorithm"],
                        "Role": a["crypto_role"],
                        "Key Size": ks_str,
                        "Shelf-Life (X)": f"{a['data_shelf_life_years']} yrs",
                        "Migration Status": a["migration_status"],
                        "Created At": a.get("created_at", ""),
                    })
                df = pd.DataFrame(display_rows)
                st.dataframe(df, use_container_width=True, hide_index=True)

                # Export Inventory Report
                inv_csv = export_inventory_to_csv(filtered_assets)
                st.download_button(
                    label="📥 Export Inventory (CSV)",
                    data=inv_csv,
                    file_name="qshield_asset_inventory.csv",
                    mime="text/csv",
                    key="btn_export_inventory_csv",
                )

                # Real Plotly risk distribution chart
                risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
                for a in filtered_assets:
                    assessment = evaluate_quantum_risk(
                        algorithm=a["crypto_algorithm"],
                        key_size=a["key_size"],
                        data_shelf_life_years=a["data_shelf_life_years"],
                        crypto_role=a.get("crypto_role"),
                    )
                    level = assessment.get("risk_level", "UNKNOWN")
                    risk_counts[level] = risk_counts.get(level, 0) + 1

                fig = create_risk_distribution_chart(risk_counts)
                st.plotly_chart(fig, use_container_width=True)

                # Asset Details, Edit, and Delete Section
                st.markdown("---")
                st.subheader("🛠️ Asset Inspection, Edit & Deletion")

                asset_id_options = [a["id"] for a in filtered_assets]
                id_to_label = {a["id"]: f"ID #{a['id']} — {a['name']} ({a['crypto_algorithm']})" for a in filtered_assets}

                selected_asset_id = st.selectbox(
                    "Select an asset to view details, update, or remove:",
                    options=asset_id_options,
                    format_func=lambda x: id_to_label.get(x, f"ID #{x}"),
                    key="inventory_selected_asset_id",
                )

                selected_asset = next((a for a in filtered_assets if a["id"] == selected_asset_id), None)

                if selected_asset:
                    # Risk evaluation and recommendation for selected asset
                    asset_risk = evaluate_quantum_risk(
                        algorithm=selected_asset["crypto_algorithm"],
                        key_size=selected_asset["key_size"],
                        data_shelf_life_years=selected_asset["data_shelf_life_years"],
                        crypto_role=selected_asset.get("crypto_role"),
                    )
                    asset_rec = get_pqc_recommendation(
                        algorithm=selected_asset["crypto_algorithm"],
                        key_size=selected_asset["key_size"] or 0,
                        crypto_role=selected_asset.get("crypto_role"),
                    )

                    tab_detail, tab_edit, tab_delete = st.tabs(["📋 Asset Details", "✏️ Edit Record", "🗑️ Delete Record"])

                    with tab_detail:
                        det_c1, det_c2 = st.columns(2)
                        with det_c1:
                            ks_display = "N/A" if (selected_asset["key_size"] is None or selected_asset["key_size"] == 0) else f"{selected_asset['key_size']} bits"
                            st.write(f"**Asset Name:** `{selected_asset['name']}`")
                            st.write(f"**System / Application:** `{selected_asset['system_name']}`")
                            st.write(f"**Algorithm:** `{selected_asset['crypto_algorithm']}`")
                            st.write(f"**Category:** `{asset_risk.get('cryptographic_category', 'N/A')}`")
                            st.write(f"**Role:** `{selected_asset['crypto_role']}`")
                            st.write(f"**Key Size:** `{ks_display}`")
                            st.write(f"**Confidentiality Shelf-Life (X):** `{selected_asset['data_shelf_life_years']} years`")
                            st.write(f"**Migration Status:** `{selected_asset['migration_status']}`")
                        with det_c2:
                            st.write(f"**Quantum Risk Level:** `{asset_risk['risk_level']}`")
                            st.write(f"**Heuristic Risk Score:** `{asset_risk['risk_score']} / 10.0`")
                            st.write(f"**Assessment Rigor:** `{asset_risk.get('result_rigor', 'Heuristic')}`")
                            st.write(f"**Target PQC Migration:** `{asset_rec['target_pqc_algorithm']}`")
                            st.write(f"**NIST Specification:** `{asset_rec['nist_standard']}`")
                            st.write(f"**Migration Priority:** `{asset_rec['priority']}`")
                            st.info(f"**Risk Analysis:** {asset_risk['reasoning']}")

                        st.markdown("---")
                        st.markdown("**🛡️ Threat & Timeline Explainability:**")
                        st.markdown(f"- **Quantum Threat Relevance:** {asset_risk.get('threat_relevance', 'N/A')}")
                        st.markdown(f"- **Confidentiality Lifetime & HNDL:** {asset_risk.get('confidentiality_impact', 'N/A')}")
                        st.markdown(f"- **Vulnerability vs. Timeline Exposure:** {asset_risk.get('timeline_exposure_distinction', 'N/A')}")
                        st.markdown(f"- **Next Recommended Action:** {asset_risk.get('recommended_next_action', 'N/A')}")

                        st.markdown("---")
                        st.markdown("**🔄 Quick Migration Status Update:**")
                        col_stat_sel, col_stat_btn = st.columns([3, 1])
                        with col_stat_sel:
                            curr_stat = selected_asset["migration_status"]
                            stat_opts = sorted(VALID_MIGRATION_STATUSES)
                            s_idx = stat_opts.index(curr_stat) if curr_stat in stat_opts else 0
                            new_quick_status = st.selectbox(
                                "Update Status",
                                options=stat_opts,
                                index=s_idx,
                                key=f"quick_status_sel_{selected_asset_id}",
                                label_visibility="collapsed",
                            )
                        with col_stat_btn:
                            if st.button("Update Status", key=f"btn_quick_status_{selected_asset_id}"):
                                with get_db_connection() as conn:
                                    update_asset_migration_status(conn, selected_asset_id, new_quick_status)
                                    st.success(f"Status updated to '{new_quick_status}'")
                                    st.rerun()

                    with tab_edit:
                        updated_asset = render_asset_edit_form(selected_asset)
                        if updated_asset:
                            with get_db_connection() as conn:
                                success = update_asset(conn, selected_asset_id, updated_asset)
                                if success:
                                    st.success(f"Asset ID #{selected_asset_id} updated successfully!")
                                    st.rerun()
                                else:
                                    st.error("Failed to update asset. Record not found.")

                    with tab_delete:
                        st.error(f"⚠️ **Caution: Destructive Action**")
                        st.markdown(
                            f"You are about to permanently delete asset **ID #{selected_asset_id}** (`{selected_asset['name']}`). "
                            "This action cannot be undone."
                        )
                        confirm_deletion = st.checkbox(
                            f"I confirm that I want to permanently delete asset #{selected_asset_id}.",
                            key=f"confirm_delete_{selected_asset_id}",
                        )
                        if st.button("🗑️ Permanently Delete Asset", type="primary", disabled=not confirm_deletion, key=f"btn_delete_{selected_asset_id}"):
                            with get_db_connection() as conn:
                                success = delete_asset(conn, selected_asset_id)
                                if success:
                                    for k in ["inventory_selected_asset_id", "assessment_tab_selected_aid"]:
                                        if k in st.session_state and st.session_state[k] == selected_asset_id:
                                            del st.session_state[k]
                                    st.success(f"Asset ID #{selected_asset_id} permanently deleted.")
                                    st.rerun()
                                else:
                                    st.error("Failed to delete asset. Record not found.")
            else:
                st.info("No assets match the current search or filter criteria.")
        else:
            st.info("No cryptographic assets registered yet. Use the intake form above to add an asset, or load the pre-configured synthetic demonstration dataset.")

    # Tab 3: Explainable Risk Assessment (Phase 4)
    with tab_assessment:
        st.subheader("🛡️ Explainable Quantum Risk Assessment")
        st.caption("Transparent, non-alarming cryptographic risk evaluation distinguishing algorithmic vulnerability from timeline exposure.")

        with get_db_connection() as conn:
            assessment_assets = get_all_assets(conn)

        if assessment_assets:
            # 1. Overall Summary Metrics
            evaluated_list = []
            shor_count = 0
            grover_count = 0
            pqc_count = 0
            unknown_count = 0
            hndl_urgent_count = 0

            for a in assessment_assets:
                eval_res = evaluate_quantum_risk(
                    algorithm=a["crypto_algorithm"],
                    key_size=a["key_size"],
                    data_shelf_life_years=a["data_shelf_life_years"],
                    crypto_role=a.get("crypto_role"),
                )
                evaluated_list.append((a, eval_res))
                if eval_res.get("shor_vulnerable"):
                    shor_count += 1
                    if eval_res.get("risk_level") == "CRITICAL":
                        hndl_urgent_count += 1
                elif eval_res.get("mechanism_type") == "STANDARDIZED_PQC":
                    pqc_count += 1
                elif eval_res.get("grover_affected"):
                    grover_count += 1
                else:
                    unknown_count += 1

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Total Cryptographic Assets", len(assessment_assets))
            m2.metric("Shor-Vulnerable (Public-Key)", shor_count, help="Algorithms broken by Shor's polynomial-time factoring/discrete log algorithm on a CRQC.")
            m3.metric("Grover-Affected (Symmetric/Hash)", grover_count, help="Algorithms subject to Grover's quadratic search (halving effective security bits).")
            m4.metric("Standardized PQC (Resilient)", pqc_count, help="Algorithms standardized under NIST FIPS 203/204/205.")
            m5.metric("Unclassified / Audit Needed", unknown_count, help="Unrecognized mechanisms requiring manual inventory and expert assessment.")

            # Export Risk Assessment Report Button
            assess_csv = export_risk_assessment_to_csv(assessment_assets)
            st.download_button(
                label="📥 Export Risk Assessment Report (CSV)",
                data=assess_csv,
                file_name="qshield_risk_assessment_report.csv",
                mime="text/csv",
                key="btn_export_risk_assessment_csv",
            )

            st.markdown("---")
            st.subheader("📖 Core Cryptanalytic Principles")

            c_prin1, c_prin2, c_prin3 = st.columns(3)
            with c_prin1:
                st.markdown("##### 🔬 Shor vs. Grover Threats")
                st.write(
                    "A CRQC affects cryptographic primitives through two fundamentally distinct mechanisms:\n\n"
                    "- **Shor's Algorithm:** Breaks public-key cryptography (RSA, ECC, DH) in polynomial time by solving factoring and discrete logarithms.\n"
                    "- **Grover's Algorithm:** Halves effective symmetric search space (AES-256 -> 128 bits; AES-128 -> 64 bits). It does NOT mathematically break symmetric encryption."
                )
            with c_prin2:
                st.markdown("##### ⏱️ Harvest Now, Decrypt Later")
                st.write(
                    "Adversaries can intercept and archive encrypted communications today, intending to decrypt them once a CRQC emerges:\n\n"
                    "- **Confidentiality Shelf-Life ($X$):** If data must remain confidential for 10+ years, HNDL exposure is an immediate threat.\n"
                    "- **Signatures:** Protect integrity and authentication. While historical signatures are not 'decrypted', future quantum computers could forge signatures on long-lived trust anchors."
                )
            with c_prin3:
                st.markdown("##### ⚖️ Vulnerability vs. Timeline")
                st.write(
                    "It is vital to distinguish intrinsic vulnerability from timeline exposure:\n\n"
                    "- **Cryptographic Vulnerability:** An absolute mathematical reality under Shor's algorithm.\n"
                    "- **Timeline Planning:** An organizational scheduling metric. A positive timeline buffer provides migration time but does NOT imply safety; a negative buffer is a planning signal, not an empirical compromise."
                )

            st.markdown("---")
            st.subheader("🔍 Asset-Level Explainability Inspector")

            sel_aid = st.selectbox(
                "Select a registered asset to view its complete 7-dimension explainability profile:",
                options=[a["id"] for a in assessment_assets],
                format_func=lambda aid: next((f"ID #{a['id']}: {a['name']} ({a['crypto_algorithm']})" for a in assessment_assets if a["id"] == aid), f"ID #{aid}"),
                key="assessment_tab_selected_aid",
            )

            chosen_asset, chosen_risk = next(((a, r) for a, r in evaluated_list if a["id"] == sel_aid), (None, None))

            if chosen_asset and chosen_risk:
                chosen_rec = get_pqc_recommendation(
                    algorithm=chosen_asset["crypto_algorithm"],
                    key_size=chosen_asset["key_size"] or 0,
                    crypto_role=chosen_asset.get("crypto_role"),
                )

                card_col1, card_col2 = st.columns([1, 1])
                with card_col1:
                    st.markdown("#### 1. Identity & Operational Role")
                    st.write(f"- **Asset Name:** `{chosen_asset['name']}`")
                    st.write(f"- **System / Application:** `{chosen_asset['system_name']}`")
                    st.write(f"- **Cryptographic Algorithm:** `{chosen_asset['crypto_algorithm']}`")
                    st.write(f"- **Cryptographic Category:** `{chosen_risk.get('cryptographic_category', 'N/A')}`")
                    st.write(f"- **Operational Role:** `{chosen_asset['crypto_role']}`")
                    ks_str = "N/A" if (chosen_asset["key_size"] is None or chosen_asset["key_size"] == 0) else f"{chosen_asset['key_size']} bits"
                    st.write(f"- **Key Size:** `{ks_str}`")

                    st.markdown("#### 2. Risk Classification & Evaluation")
                    risk_badge = {
                        "CRITICAL": "🔴 CRITICAL",
                        "HIGH": "🟠 HIGH",
                        "MEDIUM": "🟡 MEDIUM",
                        "LOW": "🟢 LOW",
                        "UNKNOWN": "⚪ UNKNOWN / INSUFFICIENT DATA",
                    }.get(chosen_risk["risk_level"], "⚪ UNKNOWN")
                    st.write(f"- **Calculated Risk Level:** {risk_badge}")
                    st.write(f"- **Heuristic Priority Index:** `{chosen_risk['risk_score']} / 10.0` (Qualitative index, not compromise probability)")
                    st.write(f"- **Shor's Susceptible:** `{'Yes' if chosen_risk.get('shor_vulnerable') else ('No' if chosen_risk.get('shor_vulnerable') is False else 'Unknown')}`")
                    st.write(f"- **Grover's Affected:** `{'Yes' if chosen_risk.get('grover_affected') else ('No' if chosen_risk.get('grover_affected') is False else 'Unknown')}`")

                with card_col2:
                    st.markdown("#### 3. Quantum Threat Relevance")
                    st.info(chosen_risk.get("threat_relevance", "N/A"))

                    st.markdown("#### 4. Confidentiality Lifetime & HNDL Exposure")
                    st.warning(chosen_risk.get("confidentiality_impact", "N/A"))

                st.markdown("#### 5. Cryptographic Vulnerability vs. Timeline Exposure")
                st.write(chosen_risk.get("timeline_exposure_distinction", "N/A"))

                col_rigor1, col_rigor2 = st.columns(2)
                with col_rigor1:
                    st.markdown("#### 6. Assessment Rigor & Confidence")
                    st.success(f"**Rigor Classification:** `{chosen_risk.get('result_rigor', 'Heuristic')}`")
                    st.write(f"**Status:** `{chosen_risk.get('assessment_status', 'COMPLETED')}`")
                with col_rigor2:
                    st.markdown("#### 7. Next Recommended Action")
                    st.success(f"**Recommended Action:** {chosen_risk.get('recommended_next_action', 'N/A')}")
                    st.write(f"**NIST Migration Target:** `{chosen_rec['target_pqc_algorithm']}` ({chosen_rec['nist_standard']})")

                with st.expander("🔍 Scientific Assumptions & Heuristic Limitations"):
                    st.markdown(f"**Scoring Methodology:** {chosen_risk.get('scoring_methodology', 'N/A')}")
                    st.markdown("**Assessment Assumptions:**")
                    for asm in chosen_risk.get("assumptions", []):
                        st.markdown(f"- {asm}")
                    st.markdown("**Heuristic Limitations:**")
                    for lim in chosen_risk.get("limitations", []):
                        st.markdown(f"- {lim}")
        else:
            st.info("No cryptographic assets registered yet. Add assets in the 'Asset Inventory' tab to generate an explainable risk assessment.")

    # Tab 4: Interactive Quantum-Threat Scenario Simulator (Phase 5)
    with tab_simulator:
        st.subheader("🔮 Interactive Quantum-Threat Scenario Simulator")
        st.caption("Model hypothetical CRQC threat timelines and evaluate organizational preparedness using Mosca's Theorem.")

        # Planning Tool Disclaimer Banner
        st.warning(
            "**⚠️ Scenario Planning Tool Disclaimer:**\n\n"
            "- **Planning Tool, Not a Prediction:** The hypothetical threat horizon year is a **user-supplied planning assumption**, "
            "NOT an empirical prediction or a scientifically validated probability-of-compromise model.\n"
            "- **Planning Margin Formula:** $\\text{Planning Margin} = Z - (X + Y)$ evaluates whether an organization's combined "
            "confidentiality lifetime ($X$) and migration duration ($Y$) fit within the assumed horizon ($Z = \\text{Target Year} - 2026$).\n"
            "- **Vulnerability vs. Timeline Exposure:** A positive planning margin provides migration lead time but does not guarantee safety; "
            "a negative margin indicates migration urgency but does not prove an algorithm has been compromised today."
        )

        with get_db_connection() as conn:
            sim_inventory_assets = get_all_assets(conn)

        if not sim_inventory_assets:
            st.info("No cryptographic assets registered yet. Add assets in the 'Asset Inventory' tab to run threat timeline simulations.")
        else:
            # 1. User Controls
            st.markdown("### 🎛️ Scenario Simulation Parameters")
            ctrl_col1, ctrl_col2 = st.columns([1, 1])

            with ctrl_col1:
                st.markdown("##### ⏱️ Timeline Horizon Assumptions")
                current_year_val = 2026
                sim_target_year = st.slider(
                    "Hypothetical CRQC Threat Horizon Year (Target Year)",
                    min_value=2027,
                    max_value=2045,
                    value=2033,
                    step=1,
                    help="User-supplied hypothetical year when a Cryptanalytically Relevant Quantum Computer (CRQC) emerges. This is an assumption, not a forecast.",
                    key="sim_target_year",
                )
                sim_z_years = sim_target_year - current_year_val
                st.info(f"**Threat Horizon Buffer ($Z$):** `{sim_z_years} years` ({sim_target_year} − {current_year_val})")

                sim_migration_y = st.slider(
                    "Estimated Organizational Migration Duration ($Y$, Years)",
                    min_value=0,
                    max_value=15,
                    value=3,
                    step=1,
                    help="Estimated time in years required to fully discover, test, and deploy post-quantum cryptography across systems.",
                    key="sim_migration_y",
                )

            with ctrl_col2:
                st.markdown("##### 🎯 Inventory Scope & Custom Overrides")
                scope_choice = st.radio(
                    "Asset Assessment Scope",
                    options=["All Registered Assets", "Filter by System", "Select Specific Assets"],
                    index=0,
                    key="sim_scope_choice",
                )

                selected_sim_assets = list(sim_inventory_assets)
                if scope_choice == "Filter by System":
                    avail_systems = sorted(list({a["system_name"] for a in sim_inventory_assets if a.get("system_name")}))
                    chosen_systems = st.multiselect(
                        "Select Systems to Assess",
                        options=avail_systems,
                        default=avail_systems[:1] if avail_systems else [],
                        key="sim_chosen_systems",
                    )
                    selected_sim_assets = [a for a in sim_inventory_assets if a.get("system_name") in chosen_systems]
                elif scope_choice == "Select Specific Assets":
                    avail_asset_options = {a["id"]: f"ID #{a['id']}: {a['name']} ({a['crypto_algorithm']})" for a in sim_inventory_assets}
                    chosen_ids = st.multiselect(
                        "Select Assets to Include",
                        options=list(avail_asset_options.keys()),
                        format_func=lambda aid: avail_asset_options[aid],
                        default=list(avail_asset_options.keys())[:min(5, len(avail_asset_options))],
                        key="sim_chosen_asset_ids",
                    )
                    selected_sim_assets = [a for a in sim_inventory_assets if a["id"] in chosen_ids]

                st.caption(f"Currently Assessing: **{len(selected_sim_assets)}** of **{len(sim_inventory_assets)}** assets.")

                # Optional Asset-Specific Migration Overrides
                asset_overrides = {}
                with st.expander("⚙️ Optional Asset-Specific Migration Overrides"):
                    st.write("Specify unique migration timelines ($Y$) for assets with exceptional complexity (e.g. legacy hardware or distributed infrastructure).")
                    for a in selected_sim_assets:
                        override_val = st.number_input(
                            f"{a['name']} (ID #{a['id']}) Migration Y (yrs)",
                            min_value=0,
                            max_value=25,
                            value=sim_migration_y,
                            step=1,
                            key=f"override_y_{a['id']}",
                        )
                        if override_val != sim_migration_y:
                            asset_overrides[a["id"]] = override_val

            if not selected_sim_assets:
                st.warning("No assets selected for simulation. Please select at least one asset above.")
            else:
                # 2. Execute Simulation
                sim_result = simulate_quantum_threat_scenario(
                    assets=selected_sim_assets,
                    target_year=sim_target_year,
                    migration_duration_years=sim_migration_y,
                    current_year=current_year_val,
                    asset_migration_overrides=asset_overrides,
                )

                st.markdown("---")
                st.subheader(f"📈 Scenario Simulation Results: Horizon {sim_target_year} ($Z = {sim_z_years}$ yrs)")

                # Top Metrics Row
                met1, met2, met3, met4, met5, met6 = st.columns(6)
                met1.metric("Assets Assessed", sim_result["total_assets_evaluated"])
                met2.metric("Negative Margin (< 0)", sim_result["negative_margin_count"], help="Combined timeline X + Y extends beyond horizon Z.")
                met3.metric("Zero Buffer (== 0)", sim_result["zero_margin_count"], help="Timeline exactly matches horizon Z - (X + Y) = 0.")
                met4.metric("Positive Margin (> 0)", sim_result["positive_margin_count"], help="Positive buffer cushion remains.")
                met5.metric("Confirmed Exposed", sim_result["confirmed_exposed_assets_count"], help="Confirmed quantum-vulnerable primitives with negative planning margins.")
                met6.metric("Requires Assessment", sim_result["requires_assessment_count"], help="Unrecognized or unclassified mechanisms; tracked separately from confirmed exposures.")

                # Interactive Visualizations
                st.markdown("---")
                st.subheader("📊 Scenario Visualizations")
                c_row1_col1, c_row1_col2 = st.columns(2)

                with c_row1_col1:
                    margin_counts = {
                        "NEGATIVE_MARGIN": sim_result["negative_margin_count"],
                        "ZERO_BUFFER": sim_result["zero_margin_count"],
                        "POSITIVE_MARGIN": sim_result["positive_margin_count"],
                    }
                    fig_dist = create_planning_margin_distribution_chart(margin_counts)
                    st.plotly_chart(fig_dist, use_container_width=True)

                with c_row1_col2:
                    resilient_or_buf = sim_result.get(
                        "resilient_or_buffered_count",
                        len(selected_sim_assets)
                        - sim_result["confirmed_exposed_assets_count"]
                        - sim_result["requires_assessment_count"],
                    )
                    fig_pie = create_scenario_exposure_breakdown_chart(
                        confirmed_exposed=sim_result["confirmed_exposed_assets_count"],
                        requires_assessment=sim_result["requires_assessment_count"],
                        buffer_maintained=resilient_or_buf,
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)

                # Export Scenario Report Button
                scen_csv = export_scenario_to_csv(sim_result)
                st.download_button(
                    label="📥 Export Scenario Simulation Report (CSV)",
                    data=scen_csv,
                    file_name=f"qshield_scenario_{sim_target_year}_y{sim_migration_y}.csv",
                    mime="text/csv",
                    key="btn_export_scenario_csv",
                )

                # Asset-Level Margins Comparison Chart
                fig_asset_bars = create_asset_margins_comparison_chart(sim_result["evaluated_assets"])
                st.plotly_chart(fig_asset_bars, use_container_width=True)

                # Detailed Asset-Level Planning Margins Table
                st.markdown("### 📋 Asset-Level Planning Margin Details")
                st.caption("Planning Margin = Z - (X + Y). Negative margins indicate migration urgency.")

                table_rows = []
                for item in sim_result["evaluated_assets"]:
                    margin_val = item["planning_margin"]
                    margin_badge = f"{margin_val:+d} yrs" if margin_val != 0 else "0 yrs (Zero Buffer)"
                    table_rows.append({
                        "ID": item["id"],
                        "Asset Name": item["name"],
                        "System": item["system_name"],
                        "Algorithm": item["crypto_algorithm"],
                        "Role": item["crypto_role"],
                        "Shelf-Life (X)": f"{item['confidentiality_duration_X']}y",
                        "Migration (Y)": f"{item['migration_duration_Y']}y",
                        "Horizon (Z)": f"{item['threat_horizon_Z']}y",
                        "Planning Margin": margin_badge,
                        "Buffer Status": item["buffer_status"],
                        "Quantum Vulnerable": "Yes" if item["quantum_vulnerable"] is True else ("No" if item["quantum_vulnerable"] is False else "Unknown"),
                        "Exposure Status": item["exposure_status"],
                        "Target Recommendation": item["target_pqc_recommendation"],
                    })

                df_sim = pd.DataFrame(table_rows)
                st.dataframe(df_sim, use_container_width=True, hide_index=True)

                # Assumptions Panel
                with st.expander("🔍 Simulation Assumptions & Methodology Details"):
                    st.markdown("**Core Assumptions for this Run:**")
                    for asm in sim_result["assumptions"]:
                        st.markdown(f"- {asm}")
                    st.markdown(f"**Disclaimer:** {sim_result['heuristic_disclaimer']}")

                # Multi-Scenario Horizon Comparison Section
                st.markdown("---")
                st.subheader("🔄 Multi-Scenario Threat Horizon Comparison")
                st.write(
                    "Compare organizational exposure across varying hypothetical CRQC arrival years. "
                    "Notice how shifting the threat horizon affects confirmed exposures and planning cushions."
                )

                cmp_col1, cmp_col2 = st.columns([1, 2])
                with cmp_col1:
                    st.markdown("##### Configure Horizons to Compare")
                    cmp_years = st.multiselect(
                        "Select Target Years to Compare",
                        options=list(range(2027, 2046)),
                        default=[2029, 2033, 2038],
                        help="Select multiple hypothetical threat years to compare exposure transitions.",
                        key="multi_scenario_years",
                    )
                with cmp_col2:
                    if cmp_years:
                        multi_scenarios = compare_scenarios(
                            assets=selected_sim_assets,
                            target_years=cmp_years,
                            migration_duration_years=sim_migration_y,
                            current_year=current_year_val,
                            asset_migration_overrides=asset_overrides,
                        )
                        fig_cmp = create_scenario_comparison_chart(multi_scenarios)
                        st.plotly_chart(fig_cmp, use_container_width=True)

                        # Comparison summary table
                        cmp_table_rows = []
                        for sc in multi_scenarios:
                            cmp_table_rows.append({
                                "Target Year": sc["scenario_target_year"],
                                "Horizon (Z)": f"{sc['threat_horizon_years_Z']} yrs",
                                "Negative Margins (< 0)": sc["negative_margin_count"],
                                "Zero Buffer (== 0)": sc["zero_margin_count"],
                                "Positive Margins (> 0)": sc["positive_margin_count"],
                                "Confirmed Exposed": sc["confirmed_exposed_assets_count"],
                                "Requires Assessment": sc["requires_assessment_count"],
                                "Exposure %": f"{sc['exposure_percentage']}%",
                            })
                        df_cmp = pd.DataFrame(cmp_table_rows)
                        st.dataframe(df_cmp, use_container_width=True, hide_index=True)
                    else:
                        st.info("Select at least one comparison year above.")

    # Tab 5: Interactive Quantum Risk Calculator
    with tab_calculator:
        st.subheader("Interactive Cryptographic Risk & Recommendation Inspector")
        st.markdown(
            "Evaluate individual cryptographic primitives against quantum cryptanalysis principles and NIST PQC standards."
        )

        calc_algo_options = [
            "RSA",
            "ECDSA",
            "ECDH",
            "Diffie-Hellman",
            "DSA",
            "AES",
            "3DES",
            "ChaCha20",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "SHA-3",
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
            "Falcon",
            "Unknown_Proprietary_Cipher",
        ]
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            calc_algo = st.selectbox(
                "Algorithm",
                options=calc_algo_options,
                key="calc_algo",
            )
        with c2:
            # Determine appropriate role default based on algorithm family
            algo_upper = calc_algo.upper()
            if "ECDSA" in algo_upper or algo_upper in {"DSA", "ML-DSA", "SLH-DSA", "FALCON"}:
                default_role = "Digital Signature"
            elif "ECDH" in algo_upper or "DIFFIE" in algo_upper or algo_upper in {"ML-KEM", "KYBER"}:
                default_role = "Key Establishment"
            elif algo_upper in {"AES", "3DES", "CHACHA20"} or "CHACHA" in algo_upper:
                default_role = "Symmetric Encryption"
            elif "SHA" in algo_upper:
                default_role = "Cryptographic Hash"
            else:
                default_role = "Key Establishment"

            calc_role = st.selectbox(
                "Cryptographic Role",
                options=sorted(KNOWN_ROLES),
                index=sorted(KNOWN_ROLES).index(default_role) if default_role in KNOWN_ROLES else 0,
                key="calc_role",
            )
        with c3:
            # Default key size based on selected algorithm
            if calc_algo == "RSA" or "Diffie" in calc_algo or calc_algo == "DSA":
                def_keysize = 2048
            elif calc_algo == "3DES":
                def_keysize = 168
            elif calc_algo == "ML-KEM":
                def_keysize = 768
            elif calc_algo == "ML-DSA":
                def_keysize = 65
            elif calc_algo == "SLH-DSA":
                def_keysize = 128
            elif calc_algo in ["SHA-384"]:
                def_keysize = 384
            elif calc_algo in ["SHA-512"]:
                def_keysize = 512
            else:
                def_keysize = 256

            calc_keysize = st.number_input(
                "Key Size (bits)",
                min_value=16,
                max_value=8192,
                value=def_keysize,
                step=16,
                key="calc_keysize",
            )
        with c4:
            calc_shelflife = st.slider(
                "Confidentiality Shelf-Life (X, Years)",
                min_value=0,
                max_value=30,
                value=5,
                key="calc_shelflife",
            )

        # Run risk assessment and recommendation
        risk = evaluate_quantum_risk(
            algorithm=calc_algo,
            key_size=calc_keysize,
            data_shelf_life_years=calc_shelflife,
            crypto_role=calc_role,
        )
        recommendation = get_pqc_recommendation(
            algorithm=calc_algo,
            key_size=calc_keysize,
            crypto_role=calc_role,
        )

        # Warn if algorithm and role are incompatible
        if risk.get("assessment_status") == "INCOMPATIBLE_ROLE":
            st.warning(f"⚠️ **Incompatible Configuration:** {risk['reasoning']}")

        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.markdown("#### Quantum Risk Assessment")
            risk_badge = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🟢 LOW",
                "UNKNOWN": "⚪ UNKNOWN / INSUFFICIENT DATA",
            }.get(risk["risk_level"], "⚪ UNKNOWN")

            score_str = f"{risk['risk_score']} / 10.0" if risk["risk_score"] is not None else "N/A (Insufficient Data)"
            qv_str = (
                "Unknown / Needs Assessment"
                if risk["quantum_vulnerable"] is None
                else ("Yes" if risk["quantum_vulnerable"] else "No")
            )
            shor_str = (
                "Unknown"
                if risk.get("shor_vulnerable") is None
                else ("Yes" if risk["shor_vulnerable"] else "No")
            )
            grover_str = (
                "Unknown"
                if risk.get("grover_affected") is None
                else ("Yes" if risk["grover_affected"] else "No")
            )

            st.write(f"**Risk Level:** {risk_badge}")
            st.write(f"**Calculated Score:** {score_str}")
            st.write(f"**Cryptographic Category:** `{risk.get('cryptographic_category', 'N/A')}`")
            st.write(f"**Quantum Vulnerable:** {qv_str}")
            st.write(f"**Shor's Algorithm Susceptible:** {shor_str}")
            st.write(f"**Grover's Algorithm Susceptible:** {grover_str}")
            st.write(f"**Assessment Status:** `{risk.get('assessment_status', 'COMPLETED')}`")
            st.info(f"**Analysis:** {risk['reasoning']}")

        with res_col2:
            st.markdown("#### Role-Aware Migration Target")
            st.write(f"**Cryptographic Role:** `{recommendation['crypto_role']}`")
            st.write(f"**Recommended Target:** `{recommendation['target_pqc_algorithm']}`")
            st.write(f"**NIST Specification:** {recommendation['nist_standard']}")
            st.write(f"**Migration Priority:** {recommendation['priority']}")
            st.write(f"**Assessment Rigor:** `{risk.get('result_rigor', 'Heuristic')}`")
            st.success(f"**Recommended Action:** {recommendation['action']}")

        st.markdown("---")
        st.markdown("##### 🛡️ Cryptanalytic & Timeline Explainability")
        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            st.markdown(f"**Quantum Threat Relevance:** {risk.get('threat_relevance', 'N/A')}")
            st.markdown(f"**Confidentiality Lifetime & HNDL:** {risk.get('confidentiality_impact', 'N/A')}")
        with exp_col2:
            st.markdown(f"**Vulnerability vs. Timeline Exposure:** {risk.get('timeline_exposure_distinction', 'N/A')}")
            st.markdown(f"**Next Action:** {risk.get('recommended_next_action', 'N/A')}")

        # Expandable explainability & assumptions panel
        with st.expander("🔍 Scientific Assumptions & Heuristic Limitations"):
            st.markdown(f"**Scoring Methodology:** {risk.get('scoring_methodology', 'Qualitative Quantum Urgency Index')}")
            st.markdown("**Underlying Assumptions:**")
            for asm in risk.get("assumptions", []):
                st.markdown(f"- {asm}")
            st.markdown("**Assessment Limitations:**")
            for lim in risk.get("limitations", []):
                st.markdown(f"- {lim}")

        st.caption(
            "⚠️ Note: This evaluation applies specifically to the selected primitive. "
            "An entire system is not quantum-safe merely because one primitive is evaluated as low risk."
        )


if __name__ == "__main__":
    main()
