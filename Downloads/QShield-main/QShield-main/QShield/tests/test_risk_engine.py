"""Unit tests for core/risk_engine.py."""

import pytest
from core.risk_engine import (
    classify_cryptographic_primitive,
    evaluate_quantum_risk,
    get_cryptographic_category,
    normalize_algorithm_identifier,
    check_algorithm_role_compatibility,
)


def test_classify_no_accidental_substring_matches():
    """Verify that DSA, ECDSA, ML-DSA, SLH-DSA, DH, and ECDH are distinguished without collision."""
    # DSA vs ECDSA vs ML-DSA vs SLH-DSA
    assert classify_cryptographic_primitive("DSA") == ("DSA", "ASYMMETRIC_PUBLIC_KEY")
    assert classify_cryptographic_primitive("ECDSA") == ("ECDSA", "ASYMMETRIC_PUBLIC_KEY")
    assert classify_cryptographic_primitive("ML-DSA") == ("ML-DSA", "STANDARDIZED_PQC")
    assert classify_cryptographic_primitive("SLH-DSA") == ("SLH-DSA", "STANDARDIZED_PQC")

    # DH vs ECDH
    assert classify_cryptographic_primitive("DH") == ("DIFFIE-HELLMAN", "ASYMMETRIC_PUBLIC_KEY")
    assert classify_cryptographic_primitive("DIFFIE-HELLMAN") == ("DIFFIE-HELLMAN", "ASYMMETRIC_PUBLIC_KEY")
    assert classify_cryptographic_primitive("ECDH") == ("ECDH", "ASYMMETRIC_PUBLIC_KEY")
    assert classify_cryptographic_primitive("ECDHE") == ("ECDH", "ASYMMETRIC_PUBLIC_KEY")


def test_rsa_is_shor_vulnerable():
    result = evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=5)
    assert result["quantum_vulnerable"] is True
    assert result["shor_vulnerable"] is True
    assert result["grover_affected"] is False
    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] == 8.0


def test_rsa_long_shelf_life_is_critical_hndl():
    result = evaluate_quantum_risk("RSA", 4096, data_shelf_life_years=12)
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] == 9.5
    assert "HNDL" in result["reasoning"] or "Harvest Now" in result["reasoning"]


def test_ecdh_and_dh_are_shor_vulnerable():
    ecdh_res = evaluate_quantum_risk("ECDH", 256, data_shelf_life_years=5)
    dh_res = evaluate_quantum_risk("Diffie-Hellman", 2048, data_shelf_life_years=5)

    assert ecdh_res["quantum_vulnerable"] is True
    assert ecdh_res["shor_vulnerable"] is True
    assert dh_res["quantum_vulnerable"] is True
    assert dh_res["shor_vulnerable"] is True


def test_pqc_algorithms_are_low_risk_not_vulnerable():
    for pqc_algo in ["ML-KEM", "ML-DSA", "SLH-DSA", "Falcon"]:
        result = evaluate_quantum_risk(pqc_algo, 768, data_shelf_life_years=15)
        assert result["quantum_vulnerable"] is False
        assert result["risk_level"] == "LOW"
        assert result["risk_score"] == 1.0


def test_aes_grover_analysis():
    # AES-128: Effective security halved to 64 bits (< 112 floor) -> MEDIUM risk
    aes128_res = evaluate_quantum_risk("AES", 128, data_shelf_life_years=5)
    assert aes128_res["quantum_vulnerable"] is True
    assert aes128_res["grover_affected"] is True
    assert aes128_res["shor_vulnerable"] is False
    assert aes128_res["risk_level"] == "MEDIUM"

    # AES-256: Effective security halved to 128 bits (>= 128 floor) -> LOW risk, not vulnerable
    aes256_res = evaluate_quantum_risk("AES", 256, data_shelf_life_years=5)
    assert aes256_res["quantum_vulnerable"] is False
    assert aes256_res["grover_affected"] is True
    assert aes256_res["shor_vulnerable"] is False
    assert aes256_res["risk_level"] == "LOW"


def test_3des_legacy_analysis():
    result = evaluate_quantum_risk("3DES", 168, data_shelf_life_years=5)
    assert result["quantum_vulnerable"] is True
    assert result["risk_level"] == "HIGH"
    assert result["grover_affected"] is True


def test_sha256_hash_analysis():
    result = evaluate_quantum_risk("SHA-256", 256, data_shelf_life_years=10)
    assert result["quantum_vulnerable"] is False
    assert result["shor_vulnerable"] is False
    assert result["risk_level"] == "LOW"


def test_unknown_algorithm_not_automatically_quantum_vulnerable():
    """Verify unknown algorithms return explicit UNKNOWN with None score/vulnerability."""
    result = evaluate_quantum_risk("ProprietaryCustomCipher99", 512, data_shelf_life_years=5)
    assert result["risk_level"] == "UNKNOWN"
    assert result["quantum_vulnerable"] is None
    assert result["risk_score"] is None
    assert result["shor_vulnerable"] is None
    assert result["grover_affected"] is None
    assert "manual cryptographic inventory" in result["reasoning"].lower()


# ==============================================================================
# Phase 2 New Comprehensive Tests
# ==============================================================================

def test_every_supported_algorithm_family():
    """Verify classification and distinction of all 15 supported algorithm families."""
    expected = {
        "RSA": ("RSA", "ASYMMETRIC_PUBLIC_KEY"),
        "ECDSA": ("ECDSA", "ASYMMETRIC_PUBLIC_KEY"),
        "ECDH": ("ECDH", "ASYMMETRIC_PUBLIC_KEY"),
        "Diffie-Hellman": ("DIFFIE-HELLMAN", "ASYMMETRIC_PUBLIC_KEY"),
        "DSA": ("DSA", "ASYMMETRIC_PUBLIC_KEY"),
        "AES": ("AES", "SYMMETRIC_CIPHER"),
        "3DES": ("3DES", "SYMMETRIC_CIPHER"),
        "ChaCha20": ("CHACHA20", "SYMMETRIC_CIPHER"),
        "SHA-256": ("SHA-256", "HASH_FUNCTION"),
        "SHA-384": ("SHA-384", "HASH_FUNCTION"),
        "SHA-512": ("SHA-512", "HASH_FUNCTION"),
        "SHA-3": ("SHA-3", "HASH_FUNCTION"),
        "ML-KEM": ("ML-KEM", "STANDARDIZED_PQC"),
        "ML-DSA": ("ML-DSA", "STANDARDIZED_PQC"),
        "SLH-DSA": ("SLH-DSA", "STANDARDIZED_PQC"),
    }

    for algo_input, (exp_family, exp_mech) in expected.items():
        fam, mech = classify_cryptographic_primitive(algo_input)
        assert fam == exp_family, f"Failed family for {algo_input}: expected {exp_family}, got {fam}"
        assert mech == exp_mech, f"Failed mechanism for {algo_input}: expected {exp_mech}, got {mech}"


def test_algorithm_name_normalization():
    """Verify consistent normalization across spacing, hyphens, casing, and underscores."""
    test_cases = [
        ("  ml   kem 768  ", "ML-KEM", "STANDARDIZED_PQC"),
        ("ML_DSA_65", "ML-DSA", "STANDARDIZED_PQC"),
        ("slh_dsa_128s", "SLH-DSA", "STANDARDIZED_PQC"),
        ("kyber-768", "ML-KEM", "STANDARDIZED_PQC"),
        ("dilithium3", "ML-DSA", "STANDARDIZED_PQC"),
        ("sphincs+", "SLH-DSA", "STANDARDIZED_PQC"),
        ("diffie   hellman", "DIFFIE-HELLMAN", "ASYMMETRIC_PUBLIC_KEY"),
        ("diffie_hellman_2048", "DIFFIE-HELLMAN", "ASYMMETRIC_PUBLIC_KEY"),
        ("ecdsa-p256", "ECDSA", "ASYMMETRIC_PUBLIC_KEY"),
        ("ecdh-p384", "ECDH", "ASYMMETRIC_PUBLIC_KEY"),
        ("aes_256_gcm", "AES", "SYMMETRIC_CIPHER"),
        ("chacha20-poly1305", "CHACHA20", "SYMMETRIC_CIPHER"),
        ("triple des", "3DES", "SYMMETRIC_CIPHER"),
        ("3-des", "3DES", "SYMMETRIC_CIPHER"),
        ("sha_256", "SHA-256", "HASH_FUNCTION"),
        ("sha 512", "SHA-512", "HASH_FUNCTION"),
        ("sha3-256", "SHA-3", "HASH_FUNCTION"),
    ]

    for raw_name, exp_family, exp_mech in test_cases:
        fam, mech = classify_cryptographic_primitive(raw_name)
        assert fam == exp_family, f"Normalization failed for '{raw_name}': expected {exp_family}, got {fam}"
        assert mech == exp_mech, f"Mechanism failed for '{raw_name}': expected {exp_mech}, got {mech}"


def test_ecdsa_versus_ecdh_classification():
    """Verify ECDSA and ECDH are distinctly separated into Signature vs Key Establishment."""
    ecdsa_fam, ecdsa_mech = classify_cryptographic_primitive("ECDSA")
    ecdh_fam, ecdh_mech = classify_cryptographic_primitive("ECDH")

    assert ecdsa_fam == "ECDSA"
    assert ecdh_fam == "ECDH"
    assert ecdsa_fam != ecdh_fam

    # Category distinction
    assert get_cryptographic_category("ECDSA") == "Public-Key Digital Signature"
    assert get_cryptographic_category("ECDH") == "Public-Key Key Establishment"

    # Role compatibility check
    compat_ecdsa_sig, _ = check_algorithm_role_compatibility("ECDSA", "Digital Signature")
    compat_ecdsa_kem, err_ecdsa_kem = check_algorithm_role_compatibility("ECDSA", "Key Establishment")
    assert compat_ecdsa_sig is True
    assert compat_ecdsa_kem is False
    assert "Digital Signature" in str(err_ecdsa_kem)

    compat_ecdh_kem, _ = check_algorithm_role_compatibility("ECDH", "Key Establishment")
    compat_ecdh_sig, err_ecdh_sig = check_algorithm_role_compatibility("ECDH", "Digital Signature")
    assert compat_ecdh_kem is True
    assert compat_ecdh_sig is False
    assert "Key Establishment" in str(err_ecdh_sig)


def test_dsa_versus_mldsa_classification():
    """Verify classical DSA is cleanly separated from ML-DSA and SLH-DSA."""
    dsa_fam, dsa_mech = classify_cryptographic_primitive("DSA")
    mldsa_fam, mldsa_mech = classify_cryptographic_primitive("ML-DSA")
    slhdsa_fam, slhdsa_mech = classify_cryptographic_primitive("SLH-DSA")

    assert dsa_fam == "DSA"
    assert dsa_mech == "ASYMMETRIC_PUBLIC_KEY"

    assert mldsa_fam == "ML-DSA"
    assert mldsa_mech == "STANDARDIZED_PQC"

    assert slhdsa_fam == "SLH-DSA"
    assert slhdsa_mech == "STANDARDIZED_PQC"

    # Quantum vulnerability differences
    dsa_risk = evaluate_quantum_risk("DSA", 2048, data_shelf_life_years=5)
    assert dsa_risk["quantum_vulnerable"] is True
    assert dsa_risk["shor_vulnerable"] is True

    mldsa_risk = evaluate_quantum_risk("ML-DSA", 65, data_shelf_life_years=5)
    assert mldsa_risk["quantum_vulnerable"] is False
    assert mldsa_risk["shor_vulnerable"] is False


def test_standardized_pqc_roles_distinction():
    """Verify ML-KEM is key establishment while ML-DSA and SLH-DSA are digital signatures."""
    assert get_cryptographic_category("ML-KEM") == "Post-Quantum Key Establishment (KEM)"
    assert get_cryptographic_category("ML-DSA") == "Post-Quantum Digital Signature"
    assert get_cryptographic_category("SLH-DSA") == "Post-Quantum Digital Signature"

    # ML-KEM should be compatible with Key Establishment, incompatible with Digital Signature
    compat_kem, _ = check_algorithm_role_compatibility("ML-KEM", "Key Establishment")
    incompat_kem, _ = check_algorithm_role_compatibility("ML-KEM", "Digital Signature")
    assert compat_kem is True
    assert incompat_kem is False

    # ML-DSA should be compatible with Digital Signature, incompatible with Key Establishment
    compat_dsa, _ = check_algorithm_role_compatibility("ML-DSA", "Digital Signature")
    incompat_dsa, _ = check_algorithm_role_compatibility("ML-DSA", "Key Establishment")
    assert compat_dsa is True
    assert incompat_dsa is False


def test_public_key_versus_symmetric_differences():
    """Verify Shor attacks apply to public key, while Grover applies to symmetric/hash."""
    # Asymmetric (Shor-vulnerable)
    rsa_res = evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=5)
    assert rsa_res["shor_vulnerable"] is True
    assert rsa_res["grover_affected"] is False

    # Symmetric cipher (Grover-affected, NOT Shor-vulnerable)
    aes_res = evaluate_quantum_risk("AES", 256, data_shelf_life_years=5)
    assert aes_res["shor_vulnerable"] is False
    assert aes_res["grover_affected"] is True
    assert aes_res["quantum_vulnerable"] is False
    assert aes_res["risk_level"] == "LOW"

    # Hash function (Grover-affected, NOT Shor-vulnerable)
    sha_res = evaluate_quantum_risk("SHA-512", 512, data_shelf_life_years=10)
    assert sha_res["shor_vulnerable"] is False
    assert sha_res["grover_affected"] is True
    assert sha_res["quantum_vulnerable"] is False
    assert sha_res["risk_level"] == "LOW"


def test_invalid_inputs_raise_errors():
    """Verify invalid parameters are rejected rather than converted into misleading scores."""
    # Missing / empty algorithm name
    with pytest.raises(ValueError, match="algorithm name is required"):
        evaluate_quantum_risk("", 2048)

    with pytest.raises(ValueError, match="algorithm name is required"):
        evaluate_quantum_risk("   ", 2048)

    # Invalid algorithm type
    with pytest.raises(ValueError, match="algorithm name is required"):
        evaluate_quantum_risk(None, 2048)

    # Invalid key size (negative, zero, or non-integer)
    with pytest.raises(ValueError, match="positive integer"):
        evaluate_quantum_risk("RSA", 0)

    with pytest.raises(ValueError, match="positive integer"):
        evaluate_quantum_risk("RSA", -1024)

    with pytest.raises(TypeError, match="must be an integer"):
        evaluate_quantum_risk("RSA", True)  # bool is instance of int in Python

    with pytest.raises(TypeError, match="must be an integer"):
        evaluate_quantum_risk("RSA", "2048")

    # Negative data shelf life
    with pytest.raises(ValueError, match="cannot be negative"):
        evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=-1)

    with pytest.raises(TypeError, match="must be an integer"):
        evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=False)


def test_incompatible_algorithm_and_role_handling():
    """Verify incompatible algorithm and role combinations are safely handled without misleading scores."""
    # Standard mode returns INCOMPATIBLE_ROLE with UNKNOWN risk
    res = evaluate_quantum_risk("AES", 256, crypto_role="Digital Signature")
    assert res["assessment_status"] == "INCOMPATIBLE_ROLE"
    assert res["risk_level"] == "UNKNOWN"
    assert res["risk_score"] is None
    assert res["quantum_vulnerable"] is None
    assert "incompatible" in res["reasoning"].lower()

    # Strict mode raises ValueError
    with pytest.raises(ValueError, match="incompatible"):
        evaluate_quantum_risk("AES", 256, crypto_role="Digital Signature", raise_on_incompatible=True)

    with pytest.raises(ValueError, match="incompatible"):
        evaluate_quantum_risk("ML-KEM", 768, crypto_role="Digital Signature", raise_on_incompatible=True)

    with pytest.raises(ValueError, match="incompatible"):
        evaluate_quantum_risk("ECDSA", 256, crypto_role="Key Establishment", raise_on_incompatible=True)


def test_structured_output_fields():
    """Verify all required explainability, category, assumption, and limitation fields are populated."""
    result = evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=5, crypto_role="Key Establishment")

    required_keys = [
        "algorithm",
        "canonical_family",
        "cryptographic_category",
        "mechanism_type",
        "crypto_role",
        "key_size",
        "data_shelf_life_years",
        "quantum_vulnerable",
        "shor_vulnerable",
        "grover_affected",
        "risk_level",
        "risk_score",
        "reasoning",
        "explanation",
        "threat_relevance",
        "confidentiality_impact",
        "timeline_exposure_distinction",
        "result_rigor",
        "recommended_next_action",
        "assumptions",
        "limitations",
        "assessment_status",
        "recommended_status",
        "scoring_methodology",
    ]

    for key in required_keys:
        assert key in result, f"Missing required output key: '{key}'"

    assert len(result["assumptions"]) > 0
    assert len(result["limitations"]) > 0
    assert result["assessment_status"] == "COMPLETED"
    assert "Qualitative" in result["scoring_methodology"]


def test_consistency_between_classification_and_risk():
    """Verify consistent canonical families and mechanism types between classification and risk output."""
    algorithms = ["RSA", "ECDSA", "ECDH", "Diffie-Hellman", "DSA", "AES", "3DES", "ChaCha20", "SHA-256", "ML-KEM"]
    for algo in algorithms:
        fam, mech = classify_cryptographic_primitive(algo)
        res = evaluate_quantum_risk(algo, 2048 if algo in {"RSA", "Diffie-Hellman", "DSA"} else 256)
        assert res["canonical_family"] == fam
        assert res["mechanism_type"] == mech


# ==============================================================================
# Phase 4 Explainable Risk Assessment Tests
# ==============================================================================

def test_hndl_explanation_key_establishment_vs_signatures():
    """Verify that HNDL (confidentiality) applies to key exchange while signatures address forgery."""
    # Key establishment with long shelf-life: High HNDL urgency
    ecdh_res = evaluate_quantum_risk("ECDH", 256, data_shelf_life_years=12, crypto_role="Key Establishment")
    assert "HNDL" in ecdh_res["confidentiality_impact"] or "Harvest Now" in ecdh_res["confidentiality_impact"]
    assert "archive" in ecdh_res["confidentiality_impact"].lower() or "intercept" in ecdh_res["confidentiality_impact"].lower()
    assert "retroactive" in ecdh_res["confidentiality_impact"].lower() or "decrypt" in ecdh_res["confidentiality_impact"].lower()

    # Digital signature: Integrity and authenticity, not ciphertext decryption
    ecdsa_res = evaluate_quantum_risk("ECDSA", 256, data_shelf_life_years=12, crypto_role="Digital Signature")
    assert "forgery" in ecdsa_res["confidentiality_impact"].lower()
    assert "not subject to hndl" in ecdsa_res["confidentiality_impact"].lower() or "authenticity" in ecdsa_res["confidentiality_impact"].lower()


def test_threat_relevance_shor_versus_grover():
    """Verify threat relevance explicitly explains Shor factoring/DLOG vs. Grover search."""
    # RSA: Vulnerable to Shor's algorithm
    rsa_res = evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=5)
    assert "Shor" in rsa_res["threat_relevance"]
    assert "polynomial time" in rsa_res["threat_relevance"].lower()
    assert "factorization" in rsa_res["threat_relevance"].lower()

    # AES: Affected by Grover's algorithm, NOT Shor's algorithm
    aes_res = evaluate_quantum_risk("AES", 256, data_shelf_life_years=5)
    assert "Grover" in aes_res["threat_relevance"]
    assert "NOT susceptible to Shor" in aes_res["threat_relevance"]

    # ML-KEM: Resilient against both
    mlkem_res = evaluate_quantum_risk("ML-KEM", 768, data_shelf_life_years=10)
    assert "resilient" in mlkem_res["threat_relevance"].lower()
    assert "lattice" in mlkem_res["threat_relevance"].lower()


def test_vulnerability_versus_timeline_exposure_distinction():
    """Verify explicit distinction between mathematical vulnerability and timeline margins."""
    res = evaluate_quantum_risk("RSA", 2048, data_shelf_life_years=5, crypto_role="Key Establishment")
    expl = res["timeline_exposure_distinction"]
    assert "mathematical" in expl.lower()
    assert "positive planning margin" in expl.lower() or "safety" in expl.lower()
    assert "negative margin" in expl.lower() or "compromise" in expl.lower()


def test_assessment_rigor_classification():
    """Verify appropriate confidence/rigor labels across primitives."""
    # PQC: Confirmed Standardized Resilient
    pqc_res = evaluate_quantum_risk("ML-KEM", 768)
    assert "Confirmed" in pqc_res["result_rigor"]
    assert "FIPS 203" in pqc_res["result_rigor"]

    # Shor Asymmetric: Heuristic Priority Index (Mathematically Shor-Vulnerable)
    rsa_res = evaluate_quantum_risk("RSA", 2048)
    assert "Heuristic" in rsa_res["result_rigor"]
    assert "Shor" in rsa_res["result_rigor"]

    # Grover Symmetric: Heuristic Priority Index (Grover Key-Halving Bound)
    aes_res = evaluate_quantum_risk("AES", 256)
    assert "Heuristic" in aes_res["result_rigor"]
    assert "Grover" in aes_res["result_rigor"]

    # Hash: Confirmed Standardized Resilient
    sha_res = evaluate_quantum_risk("SHA-256", 256)
    assert "Confirmed" in sha_res["result_rigor"]

    # Unknown: Requires Additional Information
    unk_res = evaluate_quantum_risk("UnknownProprietaryCipher", 512)
    assert "Requires Additional Information" in unk_res["result_rigor"]
    assert "Unclassified" in unk_res["result_rigor"]

    # Incompatible: Requires Additional Information
    incomp_res = evaluate_quantum_risk("AES", 256, crypto_role="Digital Signature")
    assert "Requires Additional Information" in incomp_res["result_rigor"]
    assert "Incompatible" in incomp_res["result_rigor"]


def test_actionable_next_steps_provided():
    """Verify clear, non-alarming, actionable next steps for migration and maintenance."""
    # RSA Key Est -> ML-KEM
    rsa_res = evaluate_quantum_risk("RSA", 2048, crypto_role="Key Establishment")
    assert "ML-KEM" in rsa_res["recommended_next_action"]

    # ECDSA -> ML-DSA / SLH-DSA
    ecdsa_res = evaluate_quantum_risk("ECDSA", 256, crypto_role="Digital Signature")
    assert "ML-DSA" in ecdsa_res["recommended_next_action"] or "SLH-DSA" in ecdsa_res["recommended_next_action"]

    # 3DES -> AES-256-GCM
    des_res = evaluate_quantum_risk("3DES", 168)
    assert "Decommission" in des_res["recommended_next_action"]
    assert "AES-256" in des_res["recommended_next_action"]

    # AES-128 -> AES-256
    aes128_res = evaluate_quantum_risk("AES", 128)
    assert "AES-256" in aes128_res["recommended_next_action"]

    # Unknown -> Inventory audit
    unk_res = evaluate_quantum_risk("CustomCipher99", 512)
    assert "inventory audit" in unk_res["recommended_next_action"].lower()


def test_all_canonical_algorithms_explainability_consistency():
    """Verify all canonical algorithms populate the full 7-dimension explainability structure."""
    test_cases = [
        ("RSA", 2048, "Key Establishment"),
        ("RSA", 2048, "Digital Signature"),
        ("ECDSA", 256, "Digital Signature"),
        ("ECDH", 256, "Key Establishment"),
        ("Diffie-Hellman", 2048, "Key Establishment"),
        ("DSA", 2048, "Digital Signature"),
        ("AES", 128, "Symmetric Encryption"),
        ("AES", 256, "Symmetric Encryption"),
        ("3DES", 168, "Symmetric Encryption"),
        ("ChaCha20", 256, "Symmetric Encryption"),
        ("SHA-256", 256, "Cryptographic Hash"),
        ("SHA-384", 384, "Cryptographic Hash"),
        ("SHA-512", 512, "Cryptographic Hash"),
        ("SHA-3", 256, "Cryptographic Hash"),
        ("ML-KEM", 768, "Key Establishment"),
        ("ML-DSA", 65, "Digital Signature"),
        ("SLH-DSA", 128, "Digital Signature"),
    ]

    for algo, ks, role in test_cases:
        res = evaluate_quantum_risk(algo, ks, data_shelf_life_years=7, crypto_role=role)
        assert res["threat_relevance"], f"Empty threat_relevance for {algo}"
        assert res["confidentiality_impact"], f"Empty confidentiality_impact for {algo}"
        assert res["timeline_exposure_distinction"], f"Empty timeline_exposure_distinction for {algo}"
        assert res["result_rigor"], f"Empty result_rigor for {algo}"
        assert res["recommended_next_action"], f"Empty recommended_next_action for {algo}"
        assert isinstance(res["assumptions"], list) and len(res["assumptions"]) > 0
        assert isinstance(res["limitations"], list) and len(res["limitations"]) > 0


def test_shelf_life_edge_cases_and_non_alarming_language():
    """Verify boundary conditions for shelf-life (0, 50, 100) and ensure non-alarming terminology."""
    alarming_words = ["catastrophic", "certain doom", "100% hacked", "hackers will definitely", "armageddon", "apocalypse"]

    for shelf_life in [0, 1, 5, 10, 50, 100]:
        res = evaluate_quantum_risk("ECDH", 256, data_shelf_life_years=shelf_life, crypto_role="Key Establishment")
        full_text = " ".join([
            res["reasoning"],
            res["threat_relevance"],
            res["confidentiality_impact"],
            res["timeline_exposure_distinction"],
            res["recommended_next_action"],
        ]).lower()

        for bad_word in alarming_words:
            assert bad_word not in full_text, f"Alarming word '{bad_word}' found in explanation for shelf_life={shelf_life}"

        # Zero shelf-life is valid and handled properly
        if shelf_life == 0:
            assert "0 years" in res["confidentiality_impact"] or "0-year" in res["confidentiality_impact"] or "immediate" in res["confidentiality_impact"]


def test_pqc_signature_rigor_and_recommendations():
    """Verify ML-DSA and SLH-DSA produce specific FIPS standards in rigor and clear next actions."""
    mldsa_res = evaluate_quantum_risk("ML-DSA", 65, crypto_role="Digital Signature")
    assert "FIPS 204" in mldsa_res["result_rigor"]
    assert "Confirmed" in mldsa_res["result_rigor"]
    assert "ML-DSA" in mldsa_res["recommended_next_action"]

    slhdsa_res = evaluate_quantum_risk("SLH-DSA", 128, crypto_role="Digital Signature")
    assert "FIPS 205" in slhdsa_res["result_rigor"]
    assert "Confirmed" in slhdsa_res["result_rigor"]
    assert "SLH-DSA" in slhdsa_res["recommended_next_action"]


