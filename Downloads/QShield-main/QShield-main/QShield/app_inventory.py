"""Asset Inventory page module for QShield."""

import streamlit as st
import pandas as pd
from core.database import (
    get_db_connection,
    insert_asset,
    get_all_assets,
    update_asset,
    delete_asset,
    search_assets,
)
from core.risk_engine import evaluate_quantum_risk
from core.recommendations import get_pqc_recommendation, get_explainable_recommendations
from components.forms import render_asset_intake_form, render_asset_edit_form
from components.charts import create_risk_distribution_chart


def render_inventory_page():
    """Render the asset inventory page."""
    st.markdown("### 🗄️ Cryptographic Asset Inventory")
    st.caption("Manage your cryptographic asset inventory with search, filter, and editing capabilities.")
    
    # Fetch current assets from database
    with get_db_connection() as conn:
        all_assets = get_all_assets(conn)
    
    # Form to add assets (expanded by default if inventory is empty)
    with st.expander("➕ Register New Cryptographic Asset", expanded=(len(all_assets) == 0)):
        new_asset = render_asset_intake_form()
        if new_asset:
            with get_db_connection() as conn:
                inserted_id = insert_asset(conn, new_asset)
                st.success(f"✅ Asset '{new_asset['name']}' successfully registered (ID: {inserted_id}).")
                st.rerun()
    
    if all_assets:
        st.markdown("---")
        st.markdown("### 🔍 Search & Filter Inventory")
        
        # Search and Filter Controls
        col_search, col_f_algo, col_f_role, col_f_sens, col_f_status = st.columns([3, 2, 2, 2, 2])
        with col_search:
            search_term = st.text_input("Search Assets", placeholder="Search name, system, algorithm...")
        with col_f_algo:
            existing_algos = ["All"] + sorted(list({a["crypto_algorithm"] for a in all_assets}))
            filter_algo = st.selectbox("Algorithm", options=existing_algos)
        with col_f_role:
            existing_roles = ["All"] + sorted(list({a["crypto_role"] for a in all_assets}))
            filter_role = st.selectbox("Operational Role", options=existing_roles)
        with col_f_sens:
            existing_sensitivities = ["All"] + sorted(list({a.get("data_sensitivity", "Medium") for a in all_assets}))
            filter_sensitivity = st.selectbox("Data Sensitivity", options=existing_sensitivities)
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
                data_sensitivity=filter_sensitivity,
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
                    "Sensitivity": a.get("data_sensitivity", "Medium"),
                    "Migration Status": a["migration_status"],
                    "Created At": a.get("created_at", ""),
                })
            df = pd.DataFrame(display_rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
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
            st.markdown("### 🛠️ Asset Inspection, Edit & Deletion")
            
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
                    st.markdown("**📋 Explainable Recommendations:**")
                    explainable_recs = get_explainable_recommendations(
                        algorithm=selected_asset["crypto_algorithm"],
                        key_size=selected_asset["key_size"] or 0,
                        crypto_role=selected_asset.get("crypto_role"),
                        data_shelf_life_years=selected_asset["data_shelf_life_years"],
                        risk_assessment=asset_risk,
                        data_sensitivity=selected_asset.get("data_sensitivity"),
                    )
                    
                    for i, rec in enumerate(explainable_recs, 1):
                        with st.expander(f"Recommendation {i}: {rec['action']}", expanded=(i == 1)):
                            st.markdown(f"**Why Relevant:** {rec['relevance']}")
                            st.markdown(f"**Triggered By:** {rec['trigger']}")
                            st.markdown(f"**Next Step:** {rec['next_step']}")
                            st.markdown(f"**Reference:** {rec['reference']}")
                
                with tab_edit:
                    updated_asset = render_asset_edit_form(selected_asset)
                    if updated_asset:
                        with get_db_connection() as conn:
                            success = update_asset(conn, selected_asset_id, updated_asset)
                            if success:
                                st.success(f"✅ Asset ID #{selected_asset_id} updated successfully!")
                                st.rerun()
                            else:
                                st.error("❌ Failed to update asset. Record not found.")
                
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
                                st.success(f"✅ Asset ID #{selected_asset_id} permanently deleted.")
                                st.rerun()
                            else:
                                st.error("❌ Failed to delete asset. Record not found.")
        else:
            st.info("No assets match the current search or filter criteria.")
    else:
        st.info("No cryptographic assets registered yet. Use the form above to add an asset.")
