"""QShield — Quantum-Safe Migration Planner
Phase 7: Professional UI/UX Enhancement
"""

import streamlit as st
import pandas as pd
from pathlib import Path

# Core imports
from core.database import (
    init_db,
    get_db_connection,
    insert_asset,
    get_all_assets,
    get_asset_by_id,
    update_asset,
    delete_asset,
    search_assets,
)
from core.risk_engine import evaluate_quantum_risk
from core.scenario_engine import (
    simulate_quantum_threat_scenario,
    compare_scenarios,
    calculate_planning_margin,
)
from core.recommendations import get_pqc_recommendation, get_explainable_recommendations
from core.validation import KNOWN_ALGORITHMS, KNOWN_ROLES, VALID_MIGRATION_STATUSES
from app_inventory import render_inventory_page
from app_risk_analysis import render_risk_analysis_page
from app_simulator import render_simulator_page
from app_calculator import render_calculator_page
from components.forms import render_asset_intake_form, render_asset_edit_form
from components.charts import (
    create_risk_distribution_chart,
    create_planning_margin_distribution_chart,
    create_asset_margins_comparison_chart,
    create_scenario_comparison_chart,
    create_scenario_exposure_breakdown_chart,
)

# Page configuration with professional theme
st.set_page_config(
    page_title="QShield — Quantum-Safe Migration Planner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for professional dark theme
st.markdown("""
<style>
    /* Main container styling */
    .main {
        background-color: #0a1929;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #e3f2fd;
    }
    
    /* Metrics cards */
    [data-testid="stMetricValue"] {
        color: #64b5f6;
        font-size: 2rem;
    }
    
    /* Warning indicators */
    .stAlert {
        border-radius: 8px;
    }
    
    /* Tables */
    [data-testid="stDataFrame"] {
        border-radius: 8px;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #102030;
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 8px;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        color: #e3f2fd;
    }
</style>
""", unsafe_allow_html=True)

# Initialize database
init_db()


def render_empty_state(icon, title, description, action_text=None, action_callback=None):
    """Render a professional empty state component."""
    st.markdown(f"""
    <div style="
        text-align: center;
        padding: 3rem;
        border: 2px dashed #37474f;
        border-radius: 12px;
        background-color: #102030;
        margin: 2rem 0;
    ">
        <div style="font-size: 4rem; margin-bottom: 1rem;">{icon}</div>
        <h3 style="color: #e3f2fd; margin-bottom: 0.5rem;">{title}</h3>
        <p style="color: #90a4ae; margin-bottom: 1.5rem;">{description}</p>
    </div>
    """, unsafe_allow_html=True)
    
    if action_text and action_callback:
        if st.button(action_text, type="primary"):
            action_callback()


def calculate_dashboard_metrics():
    """Calculate real dashboard metrics from database."""
    with get_db_connection() as conn:
        all_assets = get_all_assets(conn)
    
    if not all_assets:
        return {
            "total_assets": 0,
            "priority_assessment": 0,
            "quantum_vulnerable": 0,
            "insufficient_info": 0,
            "priority_distribution": {},
            "highest_priority": [],
            "scenario_assumptions": None,
        }
    
    priority_assessment = 0
    quantum_vulnerable = 0
    insufficient_info = 0
    priority_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    highest_priority = []
    
    for asset in all_assets:
        assessment = evaluate_quantum_risk(
            algorithm=asset["crypto_algorithm"],
            key_size=asset["key_size"],
            data_shelf_life_years=asset["data_shelf_life_years"],
            crypto_role=asset.get("crypto_role"),
        )
        
        risk_level = assessment.get("risk_level", "UNKNOWN")
        priority_dist[risk_level] = priority_dist.get(risk_level, 0) + 1
        
        if risk_level in {"CRITICAL", "HIGH"}:
            priority_assessment += 1
            highest_priority.append(asset)
        
        if assessment.get("quantum_vulnerable") is True:
            quantum_vulnerable += 1
        
        if risk_level == "UNKNOWN":
            insufficient_info += 1
    
    # Sort highest priority by risk score
    highest_priority.sort(
        key=lambda a: evaluate_quantum_risk(
            algorithm=a["crypto_algorithm"],
            key_size=a["key_size"],
            data_shelf_life_years=a["data_shelf_life_years"],
            crypto_role=a.get("crypto_role"),
        ).get("risk_score", 0),
        reverse=True,
    )
    
    return {
        "total_assets": len(all_assets),
        "priority_assessment": priority_assessment,
        "quantum_vulnerable": quantum_vulnerable,
        "insufficient_info": insufficient_info,
        "priority_distribution": priority_dist,
        "highest_priority": highest_priority[:5],
        "scenario_assumptions": {
            "current_year": 2026,
            "default_migration_years": 3,
            "default_target_year": 2033,
        },
    }


def render_dashboard():
    """Render the dashboard with real metrics."""
    st.markdown("### 📊 Cryptographic Asset Overview")
    
    metrics = calculate_dashboard_metrics()
    
    if metrics["total_assets"] == 0:
        render_empty_state(
            icon="📭",
            title="No Assets Registered",
            description="Start by adding cryptographic assets to your inventory to see dashboard metrics.",
            action_text="Add Your First Asset",
            action_callback=lambda: st.session_state.update(nav_page="Add Asset"),
        )
        return
    
    # Top metrics row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            "Total Assets",
            metrics["total_assets"],
            help="Total number of cryptographic assets in inventory"
        )
    with col2:
        st.metric(
            "Priority Assessment",
            metrics["priority_assessment"],
            help="Assets requiring immediate attention (CRITICAL or HIGH risk)"
        )
    with col3:
        st.metric(
            "Quantum Vulnerable",
            metrics["quantum_vulnerable"],
            help="Assets with quantum-vulnerable cryptographic mechanisms"
        )
    with col4:
        st.metric(
            "Insufficient Info",
            metrics["insufficient_info"],
            help="Assets requiring additional information for accurate assessment"
        )
    
    st.markdown("---")
    
    # Priority distribution chart
    col_chart, col_table = st.columns([1, 1])
    
    with col_chart:
        st.markdown("#### Risk Level Distribution")
        fig = create_risk_distribution_chart(metrics["priority_distribution"])
        st.plotly_chart(fig, use_container_width=True)
    
    with col_table:
        st.markdown("#### Highest Priority Assets")
        if metrics["highest_priority"]:
            priority_df = pd.DataFrame([
                {
                    "Name": a["name"],
                    "Algorithm": a["crypto_algorithm"],
                    "Risk": evaluate_quantum_risk(
                        algorithm=a["crypto_algorithm"],
                        key_size=a["key_size"],
                        data_shelf_life_years=a["data_shelf_life_years"],
                        crypto_role=a.get("crypto_role"),
                    ).get("risk_level", "UNKNOWN"),
                }
                for a in metrics["highest_priority"]
            ])
            st.dataframe(priority_df, use_container_width=True, hide_index=True)
        else:
            st.info("No high-priority assets detected.")
    
    st.markdown("---")
    st.markdown("#### Current Scenario Assumptions")
    assumptions = metrics["scenario_assumptions"]
    c1, c2, c3 = st.columns(3)
    with c1:
        st.info(f"**Current Year:** {assumptions['current_year']}")
    with c2:
        st.info(f"**Default Migration Duration:** {assumptions['default_migration_years']} years")
    with c3:
        st.info(f"**Default Target Year:** {assumptions['default_target_year']}")


def render_add_asset():
    """Render the dedicated add asset page."""
    st.markdown("### ➕ Register New Cryptographic Asset")
    st.caption("Add a new cryptographic asset to your inventory for quantum risk assessment.")
    
    new_asset = render_asset_intake_form()
    if new_asset:
        with get_db_connection() as conn:
            inserted_id = insert_asset(conn, new_asset)
            st.success(f"✅ Asset '{new_asset['name']}' successfully registered (ID: {inserted_id}).")
            st.balloons()
            if st.button("Add Another Asset"):
                st.rerun()


def render_recommendations_page():
    """Render the dedicated recommendations page."""
    st.markdown("### 📋 Context-Aware Recommendations")
    st.caption("Review explainable recommendations for all assets based on their assessment results.")
    
    with get_db_connection() as conn:
        all_assets = get_all_assets(conn)
    
    if not all_assets:
        render_empty_state(
            icon="📭",
            title="No Assets to Recommend",
            description="Add cryptographic assets to generate context-aware recommendations.",
            action_text="Go to Asset Inventory",
            action_callback=lambda: st.session_state.update(nav_page="Asset Inventory"),
        )
        return
    
    # Select asset for recommendations
    asset_options = {a["id"]: f"{a['name']} ({a['crypto_algorithm']})" for a in all_assets}
    selected_id = st.selectbox(
        "Select an asset to view recommendations:",
        options=list(asset_options.keys()),
        format_func=lambda x: asset_options[x],
    )
    
    selected_asset = next((a for a in all_assets if a["id"] == selected_id), None)
    
    if selected_asset:
        # Get risk assessment
        risk_assessment = evaluate_quantum_risk(
            algorithm=selected_asset["crypto_algorithm"],
            key_size=selected_asset["key_size"],
            data_shelf_life_years=selected_asset["data_shelf_life_years"],
            crypto_role=selected_asset.get("crypto_role"),
        )
        
        # Get explainable recommendations
        recommendations = get_explainable_recommendations(
            algorithm=selected_asset["crypto_algorithm"],
            key_size=selected_asset["key_size"] or 0,
            crypto_role=selected_asset.get("crypto_role"),
            data_shelf_life_years=selected_asset["data_shelf_life_years"],
            risk_assessment=risk_assessment,
            data_sensitivity=selected_asset.get("data_sensitivity"),
        )
        
        # Display asset summary
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info(f"**Algorithm:** {selected_asset['crypto_algorithm']}")
        with col2:
            st.info(f"**Risk Level:** {risk_assessment['risk_level']}")
        with col3:
            st.info(f"**Sensitivity:** {selected_asset.get('data_sensitivity', 'Medium')}")
        
        # Display recommendations
        st.markdown("---")
        st.markdown(f"#### Generated {len(recommendations)} Recommendation(s)")
        
        for i, rec in enumerate(recommendations, 1):
            with st.expander(f"Recommendation {i}: {rec['action']}", expanded=(i == 1)):
                st.markdown(f"**Why Relevant:** {rec['relevance']}")
                st.markdown(f"**Triggered By:** {rec['trigger']}")
                st.markdown(f"**Next Step:** {rec['next_step']}")
                st.markdown(f"**Reference:** {rec['reference']}")


def render_reports_page():
    """Render the reports page with export options."""
    st.markdown("### 📊 Reports & Exports")
    st.caption("Generate and export reports on your cryptographic inventory and risk assessments.")
    
    with get_db_connection() as conn:
        all_assets = get_all_assets(conn)
    
    if not all_assets:
        render_empty_state(
            icon="📊",
            title="No Data to Report",
            description="Add assets to generate reports.",
            action_text="Go to Asset Inventory",
            action_callback=lambda: st.session_state.update(nav_page="Asset Inventory"),
        )
        return
    
    report_type = st.radio(
        "Select Report Type",
        ["Asset Inventory", "Risk Assessment Summary", "Migration Priority"],
        horizontal=True,
    )
    
    if report_type == "Asset Inventory":
        st.markdown("#### Asset Inventory Report")
        df = pd.DataFrame(all_assets)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        if st.button("📥 Download CSV"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Asset Inventory",
                data=csv,
                file_name="qshield_inventory.csv",
                mime="text/csv",
            )
    
    elif report_type == "Risk Assessment Summary":
        st.markdown("#### Risk Assessment Summary")
        risk_data = []
        for asset in all_assets:
            assessment = evaluate_quantum_risk(
                algorithm=asset["crypto_algorithm"],
                key_size=asset["key_size"],
                data_shelf_life_years=asset["data_shelf_life_years"],
                crypto_role=asset.get("crypto_role"),
            )
            risk_data.append({
                "Asset Name": asset["name"],
                "Algorithm": asset["crypto_algorithm"],
                "Risk Level": assessment.get("risk_level", "UNKNOWN"),
                "Risk Score": assessment.get("risk_score", "N/A"),
                "Quantum Vulnerable": assessment.get("quantum_vulnerable"),
            })
        
        df = pd.DataFrame(risk_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        if st.button("📥 Download Risk Report"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Risk Assessment",
                data=csv,
                file_name="qshield_risk_assessment.csv",
                mime="text/csv",
            )
    
    elif report_type == "Migration Priority":
        st.markdown("#### Migration Priority Report")
        risk_data = []
        for asset in all_assets:
            assessment = evaluate_quantum_risk(
                algorithm=asset["crypto_algorithm"],
                key_size=asset["key_size"],
                data_shelf_life_years=asset["data_shelf_life_years"],
                crypto_role=asset.get("crypto_role"),
            )
            rec = get_pqc_recommendation(
                algorithm=asset["crypto_algorithm"],
                key_size=asset["key_size"] or 0,
                crypto_role=asset.get("crypto_role"),
            )
            risk_data.append({
                "Asset Name": asset["name"],
                "Algorithm": asset["crypto_algorithm"],
                "Risk Level": assessment.get("risk_level", "UNKNOWN"),
                "Priority": rec.get("priority", "N/A"),
                "Target PQC": rec.get("target_pqc_algorithm", "N/A"),
            })
        
        df = pd.DataFrame(risk_data)
        df = df.sort_values(by=["Risk Level", "Priority"], ascending=False)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        if st.button("📥 Download Priority Report"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Migration Priority",
                data=csv,
                file_name="qshield_migration_priority.csv",
                mime="text/csv",
            )


def render_about_page():
    """Render the about page."""
    st.markdown("### ℹ️ About QShield")
    
    st.markdown("""
    #### Mission
    
    QShield is a software-based cybersecurity planning platform designed to assist organizations 
    in identifying cryptographic exposure to future quantum computers and planning structured migration 
    to **Post-Quantum Cryptography (PQC)**.
    
    #### Core Features
    
    - **Cryptographic Inventory Management**: Track all cryptographic assets across your organization
    - **Explainable Risk Assessment**: Evaluate quantum risk with transparent, non-alarming analysis
    - **Context-Aware Recommendations**: Get tailored guidance based on actual assessment results
    - **What-If Scenario Simulator**: Model hypothetical CRQC threat timelines using Mosca's Theorem
    - **NIST-Aligned Guidance**: Recommendations based on FIPS 203, 204, and 205 standards
    
    #### Architecture
    
    - **Modular Design**: Decoupled `core/` business logic and `components/` UI layer
    - **SQLite Persistence**: Local database for cryptographic inventory tracking
    - **Unit Test Coverage**: Comprehensive test suite for all core modules
    
    #### Important Disclaimers
    
    **Planning Margin Heuristic**: The formula $Z - (X + Y)$ is a simplified planning heuristic, 
    not a validated empirical probability of compromise or a prediction of when quantum computers will break cryptography.
    
    **System vs. Primitive Scope**: Assessing an individual algorithm as quantum-resilient does not label 
    an entire system or communication channel quantum-safe. End-to-end security requires that all components 
    (key exchange, signatures, certificates, symmetric encryption, and hashes) are protected.
    
    #### Version
    
    QShield v0.2.0 — Professional UI/UX Enhancement
    
    #### Acknowledgments
    
    - NIST Post-Quantum Cryptography Standardization Project
    - NSA CNSA 2.0 Timeline Guidance
    - Cryptographic research community
    """)


def main():
    # Custom sidebar navigation
    with st.sidebar:
        st.markdown("### 🛡️ QShield")
        st.caption("Quantum-Safe Migration Planner")
        st.markdown("---")
        
        # Navigation
        nav_options = [
            "Overview",
            "Asset Inventory",
            "Add Asset",
            "Risk Analysis",
            "What-If Simulator",
            "Risk Calculator",
            "Recommendations",
            "Reports",
            "About QShield",
        ]
        
        # Initialize session state for navigation
        if "nav_page" not in st.session_state:
            st.session_state.nav_page = "Overview"
        
        # Render navigation
        for option in nav_options:
            icon = {
                "Overview": "📊",
                "Asset Inventory": "🗄️",
                "Add Asset": "➕",
                "Risk Analysis": "🛡️",
                "What-If Simulator": "🔮",
                "Risk Calculator": "🔬",
                "Recommendations": "📋",
                "Reports": "📊",
                "About QShield": "ℹ️",
            }[option]
            
            if st.button(f"{icon} {option}", key=f"nav_{option}", use_container_width=True):
                st.session_state.nav_page = option
                st.rerun()
        
        st.markdown("---")
        st.caption("QShield v0.2.0")
        st.caption("IDEATHON 2026")
    
    # Render selected page
    page = st.session_state.nav_page
    
    if page == "Overview":
        render_dashboard()
    elif page == "Asset Inventory":
        render_inventory_page()
    elif page == "Add Asset":
        render_add_asset()
    elif page == "Risk Analysis":
        render_risk_analysis_page()
    elif page == "What-If Simulator":
        render_simulator_page()
    elif page == "Risk Calculator":
        render_calculator_page()
    elif page == "Recommendations":
        render_recommendations_page()
    elif page == "Reports":
        render_reports_page()
    elif page == "About QShield":
        render_about_page()


if __name__ == "__main__":
    main()
