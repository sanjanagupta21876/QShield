"""Risk Analysis page module for QShield."""

import streamlit as st
from core.database import get_db_connection, get_all_assets
from core.risk_engine import evaluate_quantum_risk
from core.recommendations import get_pqc_recommendation, get_explainable_recommendations


def render_risk_analysis_page():
    """Render the risk analysis page."""
    st.markdown("### 🛡️ Explainable Quantum Risk Assessment")
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
            elif eval_res.get("grover_affected"):
                grover_count += 1
            elif eval_res.get("mechanism_type") == "STANDARDIZED_PQC":
                pqc_count += 1
            elif eval_res.get("mechanism_type") == "UNKNOWN":
                unknown_count += 1
        
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Cryptographic Assets", len(assessment_assets))
        m2.metric("Shor-Vulnerable (Public-Key)", shor_count, help="Algorithms broken by Shor's polynomial-time factoring/discrete log algorithm on a CRQC.")
        m3.metric("Grover-Affected (Symmetric/Hash)", grover_count, help="Algorithms subject to Grover's quadratic search (halving effective security bits).")
        m4.metric("Standardized PQC (Resilient)", pqc_count, help="Algorithms standardized under NIST FIPS 203/204/205.")
        m5.metric("Unclassified / Audit Needed", unknown_count, help="Unrecognized mechanisms requiring manual inventory and expert assessment.")
        
        st.markdown("---")
        st.markdown("### 📖 Core Cryptanalytic Principles")
        
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
        st.markdown("### 🔍 Asset-Level Explainability Inspector")
        
        sel_aid = st.selectbox(
            "Select a registered asset to view its complete 7-dimension explainability profile:",
            options=[a["id"] for a in assessment_assets],
            format_func=lambda aid: next(f"ID #{a['id']}: {a['name']} ({a['crypto_algorithm']})" for a in assessment_assets if a["id"] == aid),
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
            
            st.markdown("---")
            st.markdown("#### 8. Explainable Context-Aware Recommendations")
            explainable_recs = get_explainable_recommendations(
                algorithm=chosen_asset["crypto_algorithm"],
                key_size=chosen_asset["key_size"] or 0,
                crypto_role=chosen_asset.get("crypto_role"),
                data_shelf_life_years=chosen_asset["data_shelf_life_years"],
                risk_assessment=chosen_risk,
                data_sensitivity=chosen_asset.get("data_sensitivity"),
            )
            
            for i, rec in enumerate(explainable_recs, 1):
                with st.expander(f"Recommendation {i}: {rec['action']}", expanded=(i == 1)):
                    st.markdown(f"**Why Relevant:** {rec['relevance']}")
                    st.markdown(f"**Triggered By:** {rec['trigger']}")
                    st.markdown(f"**Next Step:** {rec['next_step']}")
                    st.markdown(f"**Reference:** {rec['reference']}")
            
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
