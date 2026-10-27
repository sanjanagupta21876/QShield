"""What-If Simulator page module for QShield."""

import streamlit as st
import pandas as pd
from core.database import get_db_connection, get_all_assets
from core.scenario_engine import (
    simulate_quantum_threat_scenario,
    compare_scenarios,
)
from components.charts import (
    create_planning_margin_distribution_chart,
    create_asset_margins_comparison_chart,
    create_scenario_comparison_chart,
    create_scenario_exposure_breakdown_chart,
)


def render_simulator_page():
    """Render the what-if simulator page."""
    st.markdown("### 🔮 Interactive Quantum-Threat Scenario Simulator")
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
                min_value=1,
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
            st.markdown(f"### 📈 Scenario Simulation Results: Horizon {sim_target_year} ($Z = {sim_z_years}$ yrs)")
            
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
            st.markdown("### 📊 Scenario Visualizations")
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
                fig_pie = create_scenario_exposure_breakdown_chart(
                    confirmed_exposed=sim_result["confirmed_exposed_assets_count"],
                    requires_assessment=sim_result["requires_assessment_count"],
                    buffer_maintained=sim_result["positive_margin_count"] + sim_result["zero_margin_count"],
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            
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
            
            # Explainable Recommendations for Selected Assets
            st.markdown("---")
            st.markdown("### 📋 Context-Aware Recommendations")
            st.caption("Recommendations based on assessment results, planning margins, and data sensitivity.")
            
            selected_asset_for_rec = st.selectbox(
                "Select an asset to view detailed recommendations:",
                options=sorted([a["id"] for a in sim_result["evaluated_assets"]]),
                format_func=lambda aid: next(f"ID #{a['id']}: {a['name']} ({a['crypto_algorithm']})" for a in sim_result["evaluated_assets"] if a["id"] == aid),
                key="sim_rec_asset_id",
            )
            
            selected_asset_rec = next((a for a in sim_result["evaluated_assets"] if a["id"] == selected_asset_for_rec), None)
            if selected_asset_rec and selected_asset_rec.get("recommendations"):
                for i, rec in enumerate(selected_asset_rec["recommendations"], 1):
                    with st.expander(f"Recommendation {i}: {rec['action']}", expanded=(i == 1)):
                        st.markdown(f"**Why Relevant:** {rec['relevance']}")
                        st.markdown(f"**Triggered By:** {rec['trigger']}")
                        st.markdown(f"**Next Step:** {rec['next_step']}")
                        st.markdown(f"**Reference:** {rec['reference']}")
            
            # Assumptions Panel
            with st.expander("🔍 Simulation Assumptions & Methodology Details"):
                st.markdown("**Core Assumptions for this Run:**")
                for asm in sim_result["assumptions"]:
                    st.markdown(f"- {asm}")
                st.markdown(f"**Disclaimer:** {sim_result['heuristic_disclaimer']}")
            
            # Multi-Scenario Horizon Comparison Section
            st.markdown("---")
            st.markdown("### 🔄 Multi-Scenario Threat Horizon Comparison")
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
