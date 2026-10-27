"""Explainable Quantum Risk Engine for assessing cryptographic exposure.

Theoretical & Architectural Foundations:
-----------------------------------------
This module provides a deterministic, transparent, and explainable evaluation
of cryptographic exposure to future Cryptanalytically Relevant Quantum Computers (CRQCs).

Key Principles:
1. Threat Differentiation (Shor vs. Grover):
   - Asymmetric Public-Key Cryptography (RSA, ECDSA, ECDH, Diffie-Hellman, DSA)
     relies on integer factorization or discrete logarithms, which are solvable in
     polynomial time by Shor's algorithm on a CRQC.
   - Symmetric Ciphers (AES, ChaCha20, 3DES) and Hash Functions (SHA-2, SHA-3) are
     affected by Grover's algorithm, which provides a quadratic speedup for unstructured
     search (halving effective security bits: k -> k/2). They are NOT vulnerable to Shor's algorithm.
   - Standardized Post-Quantum Cryptography (ML-KEM under FIPS 203, ML-DSA under FIPS 204,
     SLH-DSA under FIPS 205) is specifically designed to resist both classical and quantum cryptanalysis.

2. Harvest Now, Decrypt Later (HNDL):
   - Key establishment mechanisms (e.g., ECDH, Diffie-Hellman, RSA key encapsulation)
     protect confidentiality. Intercepted ciphertext stored today can be decrypted once a CRQC
     emerges if the required confidentiality lifetime (shelf-life X) extends into the threat horizon.
   - Digital signature mechanisms protect authentication and integrity; while vital for identity
     and non-repudiation, historical signatures cannot be "harvested and decrypted" in the same manner.

3. Heuristic Urgency Scoring Methodology:
   - The numerical score (0.0 to 10.0 scale) is a qualitative prioritization index,
     NOT a scientifically validated empirical probability of compromise or a calendar prediction
     of when a quantum computer will be constructed.
   - Scoring Factors:
     * Vulnerability mechanism (Shor vs. Grover vs. PQC resilient)
     * Threat relevance (Key Establishment with shelf-life X >= 10 poses severe HNDL urgency)
     * Effective quantum security margin relative to the NIST 128-bit post-quantum security floor
   - Assumptions:
     * CRQC capability will be sufficient to execute Shor's algorithm for standard public key sizes.
     * Adversaries are actively capturing long-shelf-life encrypted traffic today (HNDL).
     * Grover's algorithm halves effective symmetric key bits.
   - Limitations:
     * Does not predict exact CRQC emergence dates.
     * Evaluates cryptographic primitives in isolation; system-level security requires
       all pipeline components (certificates, transport, storage) to be post-quantum secure.
     * Implementation-specific vulnerabilities (side channels, weak RNG) are not evaluated.

4. Safe Unknown Handling:
   - Unrecognized or proprietary algorithms return an explicit UNKNOWN status with None
     for vulnerability flags and risk score. They are NEVER treated as automatically vulnerable
     or automatically safe.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# Canonical identifiers for standardized Post-Quantum Cryptographic primitives
PQC_CANONICAL = {
    "ML-KEM",
    "ML-DSA",
    "SLH-DSA",
    "FALCON",
    "SPHINCS+",
    "KYBER",
    "DILITHIUM",
}

# Supported canonical algorithm families
CANONICAL_FAMILIES = {
    "RSA",
    "ECDSA",
    "ECDH",
    "DIFFIE-HELLMAN",
    "DSA",
    "AES",
    "3DES",
    "CHACHA20",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-3",
    "SHA-2",
    "ML-KEM",
    "ML-DSA",
    "SLH-DSA",
    "FALCON",
}


def normalize_algorithm_identifier(algorithm: str) -> str:
    """Normalize algorithm name for consistent, robust matching.

    Handles variations in spacing, underscores, hyphens, and capitalization.

    Args:
        algorithm: Raw algorithm string (e.g. 'ml kem 768', 'sha_256', 'Diffie-Hellman').

    Returns:
        Cleaned, uppercase, hyphen-separated identifier.
    """
    if not isinstance(algorithm, str):
        return ""
    # Strip whitespace, replace multiple spaces/underscores with a single hyphen
    cleaned = re.sub(r"[\s_]+", "-", algorithm.strip().upper())
    # Collapse multiple consecutive hyphens
    return re.sub(r"-+", "-", cleaned)


def classify_cryptographic_primitive(
    algorithm: str,
) -> Tuple[str, str]:
    """Classify an algorithm name into a canonical family and primary mechanism type.

    Avoids unsafe substring collisions (e.g., distinguishing DSA from ECDSA and ML-DSA,
    and DH from ECDH).

    Returns:
        Tuple of (canonical_family, mechanism_type)
        where mechanism_type is one of:
        'ASYMMETRIC_PUBLIC_KEY', 'SYMMETRIC_CIPHER', 'HASH_FUNCTION', 'STANDARDIZED_PQC', 'UNKNOWN'
    """
    algo = normalize_algorithm_identifier(algorithm)
    if not algo:
        return ("", "UNKNOWN")

    # 1. Standardized Post-Quantum Cryptography (NIST FIPS 203, 204, 205)
    # Must check before classical DSA/KEM to prevent collision with ML-DSA / SLH-DSA
    if (
        algo in {"ML-KEM", "MLKEM", "KYBER"}
        or algo.startswith(("ML-KEM-", "MLKEM-", "KYBER-", "KYBER"))
    ):
        return ("ML-KEM", "STANDARDIZED_PQC")

    if (
        algo in {"ML-DSA", "MLDSA", "DILITHIUM"}
        or algo.startswith(("ML-DSA-", "MLDSA-", "DILITHIUM-", "DILITHIUM"))
    ):
        return ("ML-DSA", "STANDARDIZED_PQC")

    if (
        algo in {"SLH-DSA", "SLHDSA", "SPHINCS+", "SPHINCSPLUS", "SPHINCS-PLUS", "SPHINCS"}
        or algo.startswith(("SLH-DSA-", "SLHDSA-", "SPHINCS+-", "SPHINCS-PLUS-", "SPHINCS"))
    ):
        return ("SLH-DSA", "STANDARDIZED_PQC")

    if algo in {"FALCON"} or algo.startswith(("FALCON-", "FALCON")):
        return ("FALCON", "STANDARDIZED_PQC")

    # 2. Asymmetric Public-Key Primitives (Vulnerable to Shor's Algorithm)
    # Check ECDSA before DSA
    if (
        algo in {"ECDSA", "EC-DSA"}
        or algo.startswith(("ECDSA-", "EC-DSA-"))
        or algo.endswith("-ECDSA")
    ):
        return ("ECDSA", "ASYMMETRIC_PUBLIC_KEY")

    # Check ECDH before DH
    if (
        algo in {"ECDH", "ECDHE", "EC-DH", "EC-DHE", "X25519", "X448"}
        or algo.startswith(("ECDH-", "ECDHE-", "EC-DH-", "EC-DHE-", "X25519-", "X448-"))
    ):
        return ("ECDH", "ASYMMETRIC_PUBLIC_KEY")

    # Classical Diffie-Hellman (DH / DHE / FFDHE / MODP)
    if (
        algo in {"DH", "DHE", "DIFFIE-HELLMAN", "DIFFIEHELLMAN", "FFDHE", "MODP"}
        or algo.startswith(("DH-", "DHE-", "DIFFIE-HELLMAN-", "FFDHE-", "MODP-"))
    ):
        return ("DIFFIE-HELLMAN", "ASYMMETRIC_PUBLIC_KEY")


    # Classical DSA (only match if NOT ECDSA, ML-DSA, or SLH-DSA)
    if (
        algo in {"DSA", "DSS", "DIGITAL-SIGNATURE-ALGORITHM"}
        or algo.startswith(("DSA-", "DSS-"))
    ):
        return ("DSA", "ASYMMETRIC_PUBLIC_KEY")

    # RSA
    if (
        algo in {"RSA", "RSASSA", "RSA-PSS", "RSASSA-PSS", "RSA-OAEP"}
        or algo.startswith(("RSA-", "RSASSA-", "RSA_"))
    ):
        return ("RSA", "ASYMMETRIC_PUBLIC_KEY")

    # 3. Symmetric Ciphers (Affected by Grover's Algorithm)
    if algo in {"3DES", "3-DES", "TRIPLE-DES", "TRIPLEDES", "TDEA", "DES-EDE3", "DES3"}:
        return ("3DES", "SYMMETRIC_CIPHER")

    if (
        algo in {"CHACHA20", "CHACHA-20", "CHACHA"}
        or algo.startswith(("CHACHA20-", "CHACHA-20-", "CHACHA-"))
    ):
        return ("CHACHA20", "SYMMETRIC_CIPHER")

    if algo in {"AES", "RIJNDAEL"} or algo.startswith(("AES-", "RIJNDAEL-")):
        return ("AES", "SYMMETRIC_CIPHER")

    # 4. Cryptographic Hash Functions
    if (
        algo in {"SHA-256", "SHA256", "SHA-2-256", "SHA2-256"}
        or algo.startswith(("SHA-256-", "SHA256-"))
    ):
        return ("SHA-256", "HASH_FUNCTION")

    if (
        algo in {"SHA-384", "SHA384", "SHA-2-384", "SHA2-384"}
        or algo.startswith(("SHA-384-", "SHA384-"))
    ):
        return ("SHA-384", "HASH_FUNCTION")

    if (
        algo in {"SHA-512", "SHA512", "SHA-2-512", "SHA2-512"}
        or algo.startswith(("SHA-512-", "SHA512-"))
    ):
        return ("SHA-512", "HASH_FUNCTION")

    if (
        algo in {"SHA-3", "SHA3", "SHA-3-256", "SHA3-256", "SHA-3-384", "SHA3-384", "SHA-3-512", "SHA3-512", "SHAKE128", "SHAKE-128", "SHAKE256", "SHAKE-256"}
        or algo.startswith(("SHA-3-", "SHA3-", "SHAKE-", "SHAKE"))
    ):
        return ("SHA-3", "HASH_FUNCTION")

    if algo in {"SHA-2", "SHA2"} or algo.startswith(("SHA-2-", "SHA2-")):
        return ("SHA-2", "HASH_FUNCTION")

    # 5. Unknown or Unclassified mechanism
    return (algo, "UNKNOWN")


def get_cryptographic_category(family: str, role: Optional[str] = None) -> str:
    """Determine human-readable cryptographic category distinguishing mechanism type and role.

    Distinguishes:
    - Public-key key-establishment mechanisms (ECDH, DH, RSA key est)
    - Digital-signature mechanisms (ECDSA, DSA, RSA signing)
    - Symmetric encryption (AES, 3DES, ChaCha20)
    - Cryptographic hash functions (SHA-256, SHA-384, SHA-512, SHA-3)
    - Standardized post-quantum key establishment (ML-KEM)
    - Standardized post-quantum digital signature (ML-DSA, SLH-DSA)
    - Unknown or unsupported mechanisms
    """
    fam = family.upper()
    role_norm = (role or "").strip().lower()

    if fam in {"ML-KEM", "KYBER"}:
        return "Post-Quantum Key Establishment (KEM)"

    if fam in {"ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS+", "FALCON"}:
        return "Post-Quantum Digital Signature"

    if fam in {"ECDH", "DIFFIE-HELLMAN"}:
        return "Public-Key Key Establishment"

    if fam in {"ECDSA", "DSA"}:
        return "Public-Key Digital Signature"

    if fam == "RSA":
        if "key establishment" in role_norm or "key exchange" in role_norm or "encapsulation" in role_norm:
            return "Public-Key Key Establishment"
        if "signature" in role_norm or "authentication" in role_norm:
            return "Public-Key Digital Signature"
        return "Public-Key Dual-Use (Key Establishment / Digital Signature)"

    if fam in {"AES", "3DES", "CHACHA20"}:
        return "Symmetric Encryption"

    if fam in {"SHA-256", "SHA-384", "SHA-512", "SHA-3", "SHA-2"}:
        return "Cryptographic Hash Function"

    return "Unknown / Unsupported Mechanism"


def check_algorithm_role_compatibility(algorithm: str, role: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Verify whether a cryptographic algorithm is compatible with the specified operational role.

    Args:
        algorithm: Algorithm name.
        role: Cryptographic role string.

    Returns:
        Tuple of (is_compatible: bool, error_message: Optional[str]).
    """
    if not role or role in {"Unknown / Unclassified", "Unspecified"}:
        return (True, None)

    family, mechanism_type = classify_cryptographic_primitive(algorithm)
    if mechanism_type == "UNKNOWN":
        # Unrecognized algorithm cannot be deterministically ruled incompatible
        return (True, None)

    role_norm = role.strip()

    # Allowed role mappings by canonical family
    allowed_roles = {
        "RSA": {"Key Establishment", "Digital Signature", "Unknown / Unclassified"},
        "ECDSA": {"Digital Signature", "Unknown / Unclassified"},
        "ECDH": {"Key Establishment", "Unknown / Unclassified"},
        "DIFFIE-HELLMAN": {"Key Establishment", "Unknown / Unclassified"},
        "DSA": {"Digital Signature", "Unknown / Unclassified"},
        "AES": {"Symmetric Encryption", "Unknown / Unclassified"},
        "3DES": {"Symmetric Encryption", "Unknown / Unclassified"},
        "CHACHA20": {"Symmetric Encryption", "Unknown / Unclassified"},
        "SHA-256": {"Cryptographic Hash", "Unknown / Unclassified"},
        "SHA-384": {"Cryptographic Hash", "Unknown / Unclassified"},
        "SHA-512": {"Cryptographic Hash", "Unknown / Unclassified"},
        "SHA-3": {"Cryptographic Hash", "Unknown / Unclassified"},
        "SHA-2": {"Cryptographic Hash", "Unknown / Unclassified"},
        "ML-KEM": {"Key Establishment", "Unknown / Unclassified"},
        "ML-DSA": {"Digital Signature", "Unknown / Unclassified"},
        "SLH-DSA": {"Digital Signature", "Unknown / Unclassified"},
        "FALCON": {"Digital Signature", "Unknown / Unclassified"},
    }

    permitted = allowed_roles.get(family, {"Unknown / Unclassified"})
    if role_norm not in permitted:
        intended = [r for r in permitted if r != "Unknown / Unclassified"]
        intended_str = " or ".join(intended) if intended else "unclassified"
        return (
            False,
            f"Algorithm '{algorithm}' ({family}) is intended for {intended_str}, "
            f"which is incompatible with the specified role '{role}'.",
        )

    return (True, None)


def evaluate_quantum_risk(
    algorithm: str,
    key_size: int,
    data_shelf_life_years: int = 5,
    crypto_role: Optional[str] = None,
    raise_on_incompatible: bool = False,
) -> Dict[str, Any]:
    """Calculate deterministic and explainable quantum risk exposure for an asset.

    Input Validation:
    - Missing or non-string algorithm names raise ValueError.
    - Invalid key sizes (<= 0 or non-int) raise ValueError / TypeError.
    - Negative data shelf-life (< 0 or non-int) raises ValueError / TypeError.
    - Incompatible algorithm-role combinations return an INCOMPATIBLE_ROLE assessment
      with UNKNOWN risk level, or raise ValueError if raise_on_incompatible is True.

    Important Principles:
    - Unknown algorithms are NOT classified as quantum-vulnerable. Instead, an explicit
      UNKNOWN / INSUFFICIENT_DATA status is returned with a recommendation for manual audit.
    - Symmetric algorithms and hash functions are evaluated under Grover's algorithm
      rather than conflated with Shor-vulnerable public key algorithms.
    - Numerical risk scores represent a heuristic urgency priority index (0.0 to 10.0 scale)
      and NOT an empirical probability of compromise.
    - An algorithm-level assessment does not label an entire system quantum-safe.

    Args:
        algorithm: Name of the cryptographic algorithm.
        key_size: Key length in bits (must be a positive integer).
        data_shelf_life_years: Duration in years data must remain confidential (X >= 0).
        crypto_role: Optional role ('Key Establishment', 'Digital Signature', etc.).
        raise_on_incompatible: If True, raises ValueError on incompatible algorithm-role pairings.

    Returns:
        Structured dictionary containing risk_level, risk_score, quantum_vulnerable flag,
        assumptions, limitations, and explainable reasoning.
    """
    # 1. Parameter type and range validation
    if algorithm is None or not isinstance(algorithm, str) or not algorithm.strip():
        raise ValueError("Cryptographic algorithm name is required and must be a non-empty string.")

    if type(data_shelf_life_years) is bool or not isinstance(data_shelf_life_years, int):
        raise TypeError(f"Data shelf-life must be an integer, got {type(data_shelf_life_years).__name__}.")

    if data_shelf_life_years < 0:
        raise ValueError(f"Data shelf-life cannot be negative, got {data_shelf_life_years}.")

    family, mechanism_type = classify_cryptographic_primitive(algorithm)
    crypto_category = get_cryptographic_category(family, crypto_role)

    # Key size validation: distinguish keyed algorithms from unkeyed primitives (hashes)
    is_hash = (mechanism_type == "HASH_FUNCTION" or (crypto_role and crypto_role.strip() == "Cryptographic Hash"))
    if is_hash:
        if key_size is not None:
            if type(key_size) is bool or not isinstance(key_size, int):
                raise TypeError(f"Key size must be an integer, got {type(key_size).__name__}.")
            if key_size < 0:
                raise ValueError(f"Key size cannot be negative, got {key_size}.")
    else:
        if type(key_size) is bool or not isinstance(key_size, int):
            raise TypeError(f"Key size must be an integer, got {type(key_size).__name__}.")
        if key_size <= 0:
            raise ValueError(f"Key size must be a positive integer, got {key_size}.")

    TIMELINE_EXPOSURE_EXPLANATION = (
        "Cryptographic vulnerability is an intrinsic mathematical property of the algorithm under quantum cryptanalysis "
        "(such as Shor's polynomial-time attack). In contrast, timeline-based exposure (such as Mosca's planning margin "
        "Z - (X + Y)) is an organizational scheduling heuristic. A positive planning margin provides migration lead time "
        "but does NOT guarantee safety; conversely, a negative margin highlights migration urgency but does not itself "
        "prove that an asset has been empirically compromised today."
    )

    # 2. Algorithm and role compatibility check
    is_compat, compat_error = check_algorithm_role_compatibility(algorithm, crypto_role)
    if not is_compat:
        if raise_on_incompatible:
            raise ValueError(compat_error)
        return {
            "algorithm": algorithm,
            "canonical_family": family,
            "cryptographic_category": crypto_category,
            "mechanism_type": mechanism_type,
            "crypto_role": crypto_role,
            "key_size": key_size,
            "data_shelf_life_years": data_shelf_life_years,
            "quantum_vulnerable": None,
            "shor_vulnerable": None,
            "grover_affected": None,
            "risk_level": "UNKNOWN",
            "risk_score": None,
            "assessment_status": "INCOMPATIBLE_ROLE",
            "recommended_status": "Reclassify Cryptographic Role",
            "reasoning": compat_error,
            "explanation": compat_error,
            "threat_relevance": "Algorithm and specified role are incompatible; threat relevance cannot be evaluated for an invalid cryptographic deployment.",
            "confidentiality_impact": "Cannot evaluate confidentiality lifetime implications for an incompatible algorithm-role pairing.",
            "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
            "result_rigor": "Requires Additional Information (Incompatible Algorithm-Role Assignment)",
            "recommended_next_action": "Reclassify cryptographic role to align with algorithm specification.",
            "assumptions": [
                "The specified operational role is functionally incompatible with this algorithm.",
                "Refusing to generate misleading risk scores for impossible primitive-role assignments."
            ],
            "limitations": [
                "Cannot assess quantum cryptanalytic risk when the algorithm cannot perform the assigned function."
            ],
            "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
        }

    # Case 1: Standardized PQC Primitives (NIST FIPS 203 / 204 / 205)
    if mechanism_type == "STANDARDIZED_PQC":
        is_kem = family in {"ML-KEM", "KYBER"}
        target_role = "key establishment" if is_kem else "digital signature"
        
        if is_kem:
            pqc_rigor = "Confirmed (NIST Standardized Resilient Primitive — FIPS 203)"
            next_action = "Maintain implementation of ML-KEM (FIPS 203); monitor ongoing hybrid deployment recommendations."
            conf_impact = (
                f"Establishes quantum-resistant shared secrets to neutralize the Harvest Now, Decrypt Later (HNDL) threat "
                f"for data requiring {data_shelf_life_years} years of confidentiality. Intercepted ciphertext cannot be retroactively decrypted by a CRQC."
            )
        elif family in {"ML-DSA", "DILITHIUM"}:
            pqc_rigor = "Confirmed (NIST Standardized Resilient Primitive — FIPS 204)"
            next_action = "Maintain implementation of ML-DSA (FIPS 204); monitor ongoing post-quantum guidance."
            conf_impact = (
                f"Provides quantum-resilient authenticity and integrity, eliminating quantum signature forgery risks "
                f"over the asset's {data_shelf_life_years}-year operational lifetime. Signatures are not subject to HNDL decryption."
            )
        elif family in {"SLH-DSA", "SPHINCS+", "SPHINCS"}:
            pqc_rigor = "Confirmed (NIST Standardized Resilient Primitive — FIPS 205)"
            next_action = "Maintain implementation of SLH-DSA (FIPS 205); monitor ongoing post-quantum guidance."
            conf_impact = (
                f"Provides quantum-resilient authenticity and integrity, eliminating quantum signature forgery risks "
                f"over the asset's {data_shelf_life_years}-year operational lifetime. Signatures are not subject to HNDL decryption."
            )
        else:
            pqc_rigor = "Confirmed (Standardized Resilient Primitive)"
            next_action = "Maintain implementation; monitor ongoing post-quantum guidance."
            conf_impact = f"Provides quantum-resilient cryptographic protection over the asset's {data_shelf_life_years}-year operational lifetime."

        threat_rel = (
            f"{algorithm} is a standardized post-quantum cryptographic primitive ({target_role}) "
            "based on structured lattice or hash-based problems, proven resilient against both Shor's polynomial-time algorithm and Grover's search on a CRQC."
        )

        return {
            "algorithm": algorithm,
            "canonical_family": family,
            "cryptographic_category": crypto_category,
            "mechanism_type": mechanism_type,
            "crypto_role": crypto_role or ("Key Establishment" if is_kem else "Digital Signature"),
            "key_size": key_size,
            "data_shelf_life_years": data_shelf_life_years,
            "risk_level": "LOW",
            "risk_score": 1.0,
            "quantum_vulnerable": False,
            "shor_vulnerable": False,
            "grover_affected": False,
            "assessment_status": "COMPLETED",
            "recommended_status": "Maintain Implementation & Monitor Standards",
            "reasoning": (
                f"{algorithm} is a standardized post-quantum cryptographic primitive ({target_role}) "
                "designed to resist known classical and quantum cryptanalytic attacks (Shor's and Grover's). "
                "Note: Individual primitive resilience does not guarantee end-to-end system quantum safety."
            ),
            "explanation": (
                f"{algorithm} is a standardized post-quantum cryptographic primitive ({target_role}) "
                "designed to resist known classical and quantum cryptanalytic attacks (Shor's and Grover's). "
                "Note: Individual primitive resilience does not guarantee end-to-end system quantum safety."
            ),
            "threat_relevance": threat_rel,
            "confidentiality_impact": conf_impact,
            "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
            "result_rigor": pqc_rigor,
            "recommended_next_action": next_action,
            "assumptions": [
                "Algorithm implementation adheres to NIST FIPS specifications without implementation flaws.",
                "Side-channel analysis and fault-injection defenses are implemented in production.",
            ],
            "limitations": [
                "Assessing a single post-quantum primitive does not certify whole-system or network-channel quantum safety.",
            ],
            "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
        }

    # Case 2: Asymmetric Public-Key Cryptography (Broken by Shor's Algorithm)
    if mechanism_type == "ASYMMETRIC_PUBLIC_KEY":
        # Distinguish key establishment (HNDL exposure) from digital signatures
        is_key_est = family in {"ECDH", "DIFFIE-HELLMAN"} or (
            family == "RSA" and (crypto_role is None or "key establishment" in (crypto_role or "").lower() or "dual-use" in crypto_category.lower())
        )

        if is_key_est:
            if data_shelf_life_years >= 10:
                risk_level = "CRITICAL"
                risk_score = 9.5
                reasoning = (
                    f"{algorithm} ({key_size}-bit) is an asymmetric key-establishment primitive completely vulnerable to "
                    f"Shor's algorithm on a CRQC. With an extended {data_shelf_life_years}-year confidentiality "
                    "requirement, it presents severe immediate exposure to Harvest Now, Decrypt Later (HNDL) attacks."
                )
            else:
                risk_level = "HIGH"
                risk_score = 8.0
                reasoning = (
                    f"{algorithm} ({key_size}-bit) relies on mathematical problems (factoring or discrete logs) "
                    "solvable in polynomial time by Shor's algorithm on a Cryptanalytically Relevant Quantum Computer."
                )
            conf_impact = (
                f"High relevance to Harvest Now, Decrypt Later (HNDL). Adversaries can intercept and archive encrypted "
                f"network traffic or key exchanges today, storing ciphertext to decrypt retroactively once a CRQC becomes operational. "
                f"Because this asset has a data confidentiality lifetime of {data_shelf_life_years} years, immediate migration to "
                "post-quantum key establishment is essential to protect historical traffic confidentiality."
            )
            next_action = "Plan migration to standardized post-quantum key encapsulation mechanism ML-KEM (NIST FIPS 203) or hybrid post-quantum key exchange."
        else:
            # Digital Signatures (ECDSA, DSA, or RSA explicitly designated for signing)
            if data_shelf_life_years >= 10:
                risk_level = "HIGH"
                risk_score = 8.5
                reasoning = (
                    f"{algorithm} ({key_size}-bit) is a digital signature algorithm vulnerable to key recovery and forgery via "
                    f"Shor's algorithm on a CRQC. With an extended {data_shelf_life_years}-year validity/non-repudiation requirement, "
                    "long-lived identity trust anchors and historical digital signatures face high exposure."
                )
            else:
                risk_level = "HIGH"
                risk_score = 7.5
                reasoning = (
                    f"{algorithm} ({key_size}-bit) is vulnerable to Shor's algorithm on a CRQC. Adversaries can forge signatures "
                    "once a cryptanalytically relevant quantum computer emerges."
                )
            conf_impact = (
                "Digital signatures protect authenticity and non-repudiation rather than confidentiality; historical signatures "
                f"are not subject to HNDL decryption. However, CRQC emergence allows signature forgery, threatening identity certificates, "
                f"software updates, and historical non-repudiation over the {data_shelf_life_years}-year horizon."
            )
            next_action = "Plan migration to standardized post-quantum digital signature schemes: ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)."

        if family == "RSA":
            threat_rel = (
                f"RSA relies on the integer factorization problem, which is solvable in polynomial time by Shor's algorithm "
                f"on a Cryptanalytically Relevant Quantum Computer (CRQC). Key length scaling ({key_size} bits) does not mitigate "
                "polynomial-time quantum attacks."
            )
        elif family in {"ECDSA", "ECDH"}:
            threat_rel = (
                f"{algorithm} relies on the elliptic curve discrete logarithm problem (ECDLP), which is solvable in polynomial time "
                "by Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC)."
            )
        else:
            threat_rel = (
                f"{algorithm} relies on discrete logarithms over finite fields, which is solvable in polynomial time "
                "by Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC)."
            )

        return {
            "algorithm": algorithm,
            "canonical_family": family,
            "cryptographic_category": crypto_category,
            "mechanism_type": mechanism_type,
            "crypto_role": crypto_role,
            "key_size": key_size,
            "data_shelf_life_years": data_shelf_life_years,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "quantum_vulnerable": True,
            "shor_vulnerable": True,
            "grover_affected": False,
            "assessment_status": "COMPLETED",
            "recommended_status": "Prioritize Migration to Standardized PQC",
            "reasoning": reasoning,
            "explanation": reasoning,
            "threat_relevance": threat_rel,
            "confidentiality_impact": conf_impact,
            "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
            "result_rigor": "Heuristic Priority Index (Mathematically Confirmed Shor-Vulnerable Primitive)",
            "recommended_next_action": next_action,
            "assumptions": [
                "Assumes Shor's algorithm will run efficiently on a sufficiently capable fault-tolerant CRQC.",
                "Assumes adversaries may conduct Harvest Now, Decrypt Later (HNDL) operations against encrypted traffic.",
            ],
            "limitations": [
                "Does not forecast the exact calendar year of CRQC arrival.",
                "Risk score reflects planning urgency, not a statistical compromise probability.",
            ],
            "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
        }

    # Case 3: Symmetric Ciphers (Affected by Grover's Algorithm)
    if mechanism_type == "SYMMETRIC_CIPHER":
        if family == "3DES":
            reasoning = (
                "3DES has legacy 64-bit block size vulnerabilities and its effective key search "
                "is reduced to < 80 bits under Grover's algorithm. Should be decommissioned immediately."
            )
            return {
                "algorithm": algorithm,
                "canonical_family": family,
                "cryptographic_category": crypto_category,
                "mechanism_type": mechanism_type,
                "crypto_role": crypto_role or "Symmetric Encryption",
                "key_size": key_size,
                "data_shelf_life_years": data_shelf_life_years,
                "risk_level": "HIGH",
                "risk_score": 7.5,
                "quantum_vulnerable": True,
                "shor_vulnerable": False,
                "grover_affected": True,
                "assessment_status": "COMPLETED",
                "recommended_status": "Decommission Immediately (Migrate to AES-256-GCM)",
                "reasoning": reasoning,
                "explanation": reasoning,
                "threat_relevance": (
                    "Symmetric cipher NOT susceptible to Shor's algorithm, but affected by Grover's algorithm. "
                    "Grover's quadratic speedup reduces effective key search to below 80 bits, compounding classical 64-bit block Sweet32 collisions."
                ),
                "confidentiality_impact": (
                    f"3DES provides insufficient effective key length under Grover's algorithm (< 80 bits). "
                    f"Archived ciphertext with a {data_shelf_life_years}-year confidentiality requirement is at risk of retroactive decryption by advanced cryptanalysis."
                ),
                "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
                "result_rigor": "Heuristic Priority Index (Grover Key-Halving Bound)",
                "recommended_next_action": "Decommission immediately; migrate to AES-256-GCM authenticated symmetric encryption.",
                "assumptions": [
                    "Grover's algorithm provides quadratic speedup for brute-force symmetric key search.",
                ],
                "limitations": [
                    "3DES is primarily obsolete due to classical block collisions (Sweet32); Grover exacerbates this.",
                ],
                "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
            }

        effective_quantum_security = key_size // 2 if key_size > 0 else 0
        if effective_quantum_security < 112:
            risk_level = "MEDIUM"
            risk_score = 5.5
            quantum_vulnerable = True
            rec_status = "Upgrade Key Length to 256 Bits"
            reasoning = (
                f"{algorithm}-{key_size} provides ~{effective_quantum_security} bits of effective security "
                "under Grover's algorithm, falling below the 128-bit quantum security floor recommended by NIST."
            )
            next_action = "Upgrade key length to AES-256 to ensure >= 128 bits of security under Grover's algorithm."
            conf_impact = (
                f"With ~{effective_quantum_security} bits of effective security under Grover's algorithm, confidentiality lifetime "
                f"({data_shelf_life_years} years) may be exposed to brute-force decryption if sufficiently large quantum search hardware is realized. Upgrade to 256 bits recommended."
            )
        else:
            risk_level = "LOW"
            risk_score = 2.0
            quantum_vulnerable = False
            rec_status = "Maintain Implementation with Authenticated Modes (GCM)"
            reasoning = (
                f"{algorithm}-{key_size} maintains ~{effective_quantum_security} bits of security under Grover's algorithm, "
                "meeting current post-quantum guidelines (>= 128 bits). Not vulnerable to Shor's algorithm."
            )
            next_action = "Maintain implementation with authenticated encryption modes (e.g., AES-256-GCM)."
            conf_impact = (
                f"Confidentiality is protected against HNDL attacks because ~{effective_quantum_security} bits of effective security "
                f"under Grover's algorithm exceeds the NIST 128-bit post-quantum security floor for data with a {data_shelf_life_years}-year confidentiality requirement."
            )

        threat_rel = (
            f"Symmetric ciphers are NOT susceptible to Shor's algorithm. However, they are affected by Grover's algorithm, "
            f"which provides a quadratic search speedup (halving effective security bits: {key_size} -> {effective_quantum_security} bits). "
            "AES-256 maintains >= 128 bits of post-quantum security."
        )

        return {
            "algorithm": algorithm,
            "canonical_family": family,
            "cryptographic_category": crypto_category,
            "mechanism_type": mechanism_type,
            "crypto_role": crypto_role or "Symmetric Encryption",
            "key_size": key_size,
            "data_shelf_life_years": data_shelf_life_years,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "quantum_vulnerable": quantum_vulnerable,
            "shor_vulnerable": False,
            "grover_affected": True,
            "assessment_status": "COMPLETED",
            "recommended_status": rec_status,
            "reasoning": reasoning,
            "explanation": reasoning,
            "threat_relevance": threat_rel,
            "confidentiality_impact": conf_impact,
            "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
            "result_rigor": "Heuristic Priority Index (Grover Key-Halving Bound)",
            "recommended_next_action": next_action,
            "assumptions": [
                "Grover's algorithm provides quadratic speedup, halving effective symmetric security bits.",
            ],
            "limitations": [
                "Does not evaluate mode-of-operation weaknesses (e.g. CBC padding or IV reuse).",
            ],
            "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
        }

    # Case 4: Cryptographic Hash Functions
    if mechanism_type == "HASH_FUNCTION":
        score = 1.0 if (key_size is not None and key_size >= 384) or family in {"SHA-384", "SHA-512", "SHA-3"} else 1.5
        reasoning = (
            f"{algorithm} is a cryptographic hash function not broken by Shor's algorithm. "
            "Pre-image resistance under Grover's algorithm remains at >= 128 bits of security, "
            "conforming to current NIST post-quantum guidance."
        )
        return {
            "algorithm": algorithm,
            "canonical_family": family,
            "cryptographic_category": crypto_category,
            "mechanism_type": mechanism_type,
            "crypto_role": crypto_role or "Cryptographic Hash",
            "key_size": key_size,
            "data_shelf_life_years": data_shelf_life_years,
            "risk_level": "LOW",
            "risk_score": score,
            "quantum_vulnerable": False,
            "shor_vulnerable": False,
            "grover_affected": True,
            "assessment_status": "COMPLETED",
            "recommended_status": "Maintain Current Implementation",
            "reasoning": reasoning,
            "explanation": reasoning,
            "threat_relevance": (
                f"{algorithm} is a cryptographic hash function NOT susceptible to Shor's algorithm. "
                "Under Grover's and BHT quantum collision algorithms, pre-image and collision resistance remain at or above the 128-bit quantum security floor for modern hashes."
            ),
            "confidentiality_impact": (
                f"Hash functions provide data integrity, password verification, or pseudo-random derivation rather than "
                f"confidentiality encapsulation. Not directly subject to HNDL ciphertext harvesting over the {data_shelf_life_years}-year window."
            ),
            "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
            "result_rigor": "Confirmed (Standardized Grover-Resilient Primitive)",
            "recommended_next_action": "Maintain current implementation with SHA-256, SHA-384, SHA-512, or SHA-3.",
            "assumptions": [
                "Pre-image and collision resistance are bounded by Grover/BHT quantum query complexities.",
            ],
            "limitations": [
                "Hash primitive evaluated in isolation; application-layer usage (HMAC, KDF, signatures) not evaluated.",
            ],
            "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
        }

    # Case 5: Unknown or Unclassified Algorithms (DO NOT assume quantum vulnerable or safe)
    reasoning = (
        f"Algorithm '{algorithm}' is unrecognized or unclassified. Insufficient information to "
        "determine quantum vulnerability automatically. A manual cryptographic inventory and "
        "expert cryptanalytic assessment are recommended."
    )
    return {
        "algorithm": algorithm,
        "canonical_family": family,
        "cryptographic_category": crypto_category,
        "mechanism_type": "UNKNOWN",
        "crypto_role": crypto_role,
        "key_size": key_size,
        "data_shelf_life_years": data_shelf_life_years,
        "risk_level": "UNKNOWN",
        "risk_score": None,
        "quantum_vulnerable": None,  # Explicitly Insufficient information
        "shor_vulnerable": None,
        "grover_affected": None,
        "assessment_status": "INSUFFICIENT_INFORMATION",
        "recommended_status": "Manual Cryptographic Audit Required",
        "reasoning": reasoning,
        "explanation": reasoning,
        "threat_relevance": f"Algorithm '{algorithm}' is unrecognized or unclassified. Threat relevance cannot be determined without cryptographic specifications.",
        "confidentiality_impact": f"Confidentiality lifetime implications for the {data_shelf_life_years}-year requirement cannot be evaluated without knowing primitive specifications and operational role.",
        "timeline_exposure_distinction": TIMELINE_EXPOSURE_EXPLANATION,
        "result_rigor": "Requires Additional Information (Unclassified Cryptographic Mechanism)",
        "recommended_next_action": "Conduct a manual cryptographic inventory audit and cryptanalytic assessment to identify primitive specifications.",
        "assumptions": [
            "No security properties or vulnerabilities are assumed for unrecognized mechanisms.",
        ],
        "limitations": [
            "Cannot calculate algorithmic quantum risk without verifiable primitive specifications.",
        ],
        "scoring_methodology": "QShield Qualitative Quantum Urgency Index (0.0-10.0 Scale, Non-Probabilistic Heuristic)",
    }
