"""Post-Quantum Cryptography (PQC) migration recommendations engine.

Recommendations are tailored to specific cryptographic roles:
- Key Establishment / Encapsulation (FIPS 203 ML-KEM)
- Digital Signatures (FIPS 204 ML-DSA, FIPS 205 SLH-DSA)
- Symmetric Encryption (NIST SP 800-38D AES-256)
- Cryptographic Hashing (FIPS 180-4 / FIPS 202)
- Unknown / Unclassified Mechanisms (Audit & Inventory Required)
"""

from typing import Any, Dict, Optional
from core.risk_engine import classify_cryptographic_primitive


def get_pqc_recommendation(
    algorithm: str,
    key_size: Optional[int] = 0,
    crypto_role: Optional[str] = None,
) -> Dict[str, Any]:
    """Provide role-aware migration recommendations aligned with NIST PQC standards.

    Args:
        algorithm: Legacy or current algorithm name.
        key_size: Key length in bits (0 or None if not applicable).
        crypto_role: Cryptographic operational role:
            'Key Establishment', 'Digital Signature', 'Symmetric Encryption',
            'Cryptographic Hash', or 'Unknown / Unclassified'.

    Returns:
        Structured recommendation dictionary.
    """
    family, mechanism_type = classify_cryptographic_primitive(algorithm)
    role_norm = (crypto_role or "").strip().lower()
    eff_key_size = int(key_size) if (key_size is not None and isinstance(key_size, int)) else 0

    # 1. Standardized PQC Primitives (Already post-quantum resilient)
    if mechanism_type == "STANDARDIZED_PQC":
        return {
            "legacy_algorithm": algorithm,
            "crypto_role": crypto_role or "Post-Quantum Cryptography",
            "target_pqc_algorithm": algorithm,
            "nist_standard": "Standardized NIST PQC",
            "priority": "Maintain",
            "action": (
                f"{algorithm} is already a standardized post-quantum primitive. "
                "Maintain current implementation and monitor implementation validation (e.g., FIPS 140-3 CAVP)."
            ),
        }

    # 2. Key Establishment / Key Agreement / Encapsulation
    is_key_est = (
        "key establishment" in role_norm
        or "key exchange" in role_norm
        or "encapsulation" in role_norm
        or family in {"ECDH", "DIFFIE-HELLMAN"}
    )
    if is_key_est:
        return {
            "legacy_algorithm": algorithm,
            "crypto_role": "Key Establishment",
            "target_pqc_algorithm": "ML-KEM-768 (or Hybrid X25519 + ML-KEM-768)",
            "nist_standard": "FIPS 203 (ML-KEM)",
            "priority": "Immediate",
            "action": (
                f"Migrate key establishment from {algorithm} to ML-KEM-768 (NIST FIPS 203) "
                "or adopt a hybrid classical/post-quantum scheme (e.g., X25519 + ML-KEM-768) "
                "to mitigate Harvest Now, Decrypt Later (HNDL) risk."
            ),
        }

    # 3. Digital Signatures / Authentication
    is_signature = (
        "signature" in role_norm
        or "authentication" in role_norm
        or family in {"ECDSA", "DSA"}
    )
    if is_signature:
        return {
            "legacy_algorithm": algorithm,
            "crypto_role": "Digital Signature",
            "target_pqc_algorithm": "ML-DSA-65 (or SLH-DSA-128s)",
            "nist_standard": "FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
            "priority": "High",
            "action": (
                f"Transition digital signatures from {algorithm} to ML-DSA-65 (FIPS 204) "
                "for general signing or SLH-DSA (FIPS 205) where stateless hash-based security is preferred."
            ),
        }

    # 4. RSA with Unspecified Role (Differentiate between KEM and Signatures)
    if family == "RSA":
        return {
            "legacy_algorithm": algorithm,
            "crypto_role": "Unspecified (Dual-Use: Encapsulation or Signature)",
            "target_pqc_algorithm": "ML-KEM-768 (for Key Exchange) / ML-DSA-65 (for Signatures)",
            "nist_standard": "FIPS 203 / FIPS 204",
            "priority": "Immediate",
            "action": (
                "Identify the operational role of this RSA key: if used for key transport or encapsulation, "
                "replace with ML-KEM-768 (FIPS 203); if used for digital signatures, migrate to ML-DSA-65 (FIPS 204)."
            ),
        }

    # 5. Symmetric Ciphers
    if mechanism_type == "SYMMETRIC_CIPHER":
        if family == "3DES":
            return {
                "legacy_algorithm": algorithm,
                "crypto_role": "Symmetric Encryption",
                "target_pqc_algorithm": "AES-256-GCM",
                "nist_standard": "NIST SP 800-38D",
                "priority": "Critical",
                "action": (
                    "Decommission legacy 3DES immediately. Migrate directly to AES-256-GCM to resolve "
                    "both classical 64-bit block weaknesses and Grover's quantum key-search halving."
                ),
            }

        if eff_key_size < 256:
            return {
                "legacy_algorithm": algorithm,
                "crypto_role": "Symmetric Encryption",
                "target_pqc_algorithm": "AES-256-GCM",
                "nist_standard": "NIST SP 800-38D",
                "priority": "Medium",
                "action": (
                    f"Upgrade key length from {key_size if key_size is not None else 0} bits to AES-256 to guarantee a 128-bit security "
                    "margin against Grover's quantum search algorithm."
                ),
            }

        return {
            "legacy_algorithm": algorithm,
            "crypto_role": "Symmetric Encryption",
            "target_pqc_algorithm": "AES-256-GCM",
            "nist_standard": "NIST SP 800-38D",
            "priority": "Maintain",
            "action": (
                f"{algorithm}-{key_size} provides ~128 bits of quantum security under Grover's algorithm. "
                "Maintain implementation with modern authenticated modes (GCM)."
            ),
        }

    # 6. Cryptographic Hash Functions
    if mechanism_type == "HASH_FUNCTION":
        return {
            "legacy_algorithm": algorithm,
            "crypto_role": "Cryptographic Hash",
            "target_pqc_algorithm": f"{algorithm} (or SHA-384 / SHA-3)",
            "nist_standard": "FIPS 180-4 / FIPS 202",
            "priority": "Maintain",
            "action": (
                f"{algorithm} remains quantum-resistant for pre-image resistance. "
                "For extended collision safety in ultra-long-term security environments, "
                "consider upgrading to SHA-384 or SHA-3."
            ),
        }

    # 7. Unknown or Unclassified mechanism / role
    return {
        "legacy_algorithm": algorithm,
        "crypto_role": crypto_role or "Unknown / Unclassified",
        "target_pqc_algorithm": "Assessment Required (Role Undefined)",
        "nist_standard": "N/A",
        "priority": "Assessment Needed",
        "action": (
            f"Algorithm '{algorithm}' and its operational role are not recognized. "
            "Perform a detailed cryptographic inventory audit to confirm its usage context "
            "(key establishment, digital signature, symmetric encryption, or hashing) "
            "prior to selecting a replacement."
        ),
    }
