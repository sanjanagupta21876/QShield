"""Quantum Risk Calculator page module for QShield."""

import streamlit as st
from core.risk_engine import evaluate_quantum_risk
from core.recommendations import get_pqc_recommendation
from core.validation import KNOWN_ALGORITHMS, KNOWN_ROLES


def render_calculator_page():
    """Render the quantum risk calculator page."""
    st.markdown("### 🔬 Interactive Cryptographic Risk & Recommendation Inspector")
    st.caption("Evaluate individual cryptographic primitives against quantum cryptanalysis principles and NIST PQC standards.")
    
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
