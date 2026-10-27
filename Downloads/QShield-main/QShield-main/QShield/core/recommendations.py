"""Post-Quantum Cryptography (PQC) migration recommendations engine.

This module provides explainable, rule-based recommendations that depend on actual
assessment results from the quantum risk engine.

Recommendations consider:
- Cryptographic mechanism type (Shor-vulnerable, Grover-affected, PQC, unknown)
- Cryptographic operational role (key establishment, signature, symmetric, hash)
- Confidentiality duration (data shelf-life X)
- Migration duration and planning margin
- Data sensitivity (critical/long-lived data)
- Missing or unknown information

Each recommendation includes:
- The recommended action
- Why it is relevant
- The assessment finding that triggered it
- A suggested next step
- Authoritative NIST references
"""

from typing import Any, Dict, List, Optional
from core.risk_engine import classify_cryptographic_primitive


def get_explainable_recommendations(
    algorithm: str,
    key_size: int = 0,
    crypto_role: Optional[str] = None,
    data_shelf_life_years: int = 5,
    risk_assessment: Optional[Dict[str, Any]] = None,
    planning_margin: Optional[int] = None,
    data_sensitivity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Generate explainable, context-aware recommendations based on assessment results.

    This function provides a list of recommendations where each recommendation:
    - Is triggered by specific assessment findings
    - Explains why it's relevant to the asset
    - Provides clear next steps
    - References authoritative NIST standards

    Args:
        algorithm: Legacy or current algorithm name.
        key_size: Key length in bits.
        crypto_role: Cryptographic operational role.
        data_shelf_life_years: Required confidentiality duration in years.
        risk_assessment: Optional pre-computed risk assessment from evaluate_quantum_risk.
        planning_margin: Optional planning margin from scenario engine (Z - (X + Y)).
        data_sensitivity: Optional data sensitivity level (e.g., 'Critical', 'High', 'Medium', 'Low').

    Returns:
        List of recommendation dictionaries, each containing:
        - action: The recommended action
        - relevance: Why this recommendation applies
        - trigger: The assessment finding that triggered it
        - next_step: Concrete next step to take
        - reference: NIST or authoritative standard reference
    """
    recommendations = []

    # Use provided risk assessment or compute it
    if risk_assessment is None:
        from core.risk_engine import evaluate_quantum_risk
        risk_assessment = evaluate_quantum_risk(
            algorithm=algorithm,
            key_size=key_size,
            data_shelf_life_years=data_shelf_life_years,
            crypto_role=crypto_role,
        )

    family, mechanism_type = classify_cryptographic_primitive(algorithm)
    role_norm = (crypto_role or "").strip().lower()
    risk_level = risk_assessment.get("risk_level", "UNKNOWN")
    shor_vulnerable = risk_assessment.get("shor_vulnerable")
    grover_affected = risk_assessment.get("grover_affected")
    quantum_vulnerable = risk_assessment.get("quantum_vulnerable")

    # 1. Handle unknown or unclassified mechanisms
    if mechanism_type == "UNKNOWN" or risk_level == "UNKNOWN":
        recommendations.append({
            "action": "Perform detailed cryptographic inventory audit",
            "relevance": (
                f"The algorithm '{algorithm}' is not recognized in the standardized cryptographic catalog. "
                "Without identifying the actual cryptographic primitive, an accurate quantum risk assessment "
                "and migration path cannot be determined."
            ),
            "trigger": "Unknown/unclassified cryptographic mechanism",
            "next_step": (
                "Conduct a manual audit to identify: (1) the actual algorithm family (RSA, ECC, symmetric, hash, etc.), "
                "(2) the operational role (key establishment, signature, encryption, hashing), and (3) key sizes and modes. "
                "Consult vendor documentation or cryptographic module specifications."
            ),
            "reference": "NIST SP 800-57 Part 1 Rev. 5 (Cryptographic Key Management)",
        })
        return recommendations

    # 2. Handle incompatible algorithm-role combinations
    if risk_assessment.get("assessment_status") == "INCOMPATIBLE_ROLE":
        recommendations.append({
            "action": "Reclassify the cryptographic role",
            "relevance": (
                f"The algorithm '{algorithm}' ({family}) is functionally incompatible with the specified role '{crypto_role}'. "
                "This misclassification prevents accurate risk assessment and appropriate PQC migration targeting."
            ),
            "trigger": "Incompatible algorithm-role assignment",
            "next_step": (
                "Verify the actual operational use of this cryptographic primitive. "
                f"If used for key establishment, update role to 'Key Establishment'. "
                f"If used for digital signatures, update role to 'Digital Signature'. "
                "Consult system architecture documentation or code analysis to confirm usage."
            ),
            "reference": "NIST SP 800-57 Part 1 Rev. 5 (Key Management - Algorithm Selection)",
        })
        return recommendations

    # 3. Recommendations for Shor-vulnerable public-key cryptography
    if shor_vulnerable:
        # Check if it's key establishment (HNDL-critical)
        is_key_est = (
            "key establishment" in role_norm
            or "key exchange" in role_norm
            or "encapsulation" in role_norm
            or family in {"ECDH", "DIFFIE-HELLMAN"}
        )

        if is_key_est:
            recommendations.append({
                "action": "Inventory affected cryptographic dependencies",
                "relevance": (
                    f"{algorithm} is vulnerable to Shor's algorithm on a CRQC. "
                    "As a key establishment mechanism, it protects data confidentiality. "
                    "Intercepted ciphertext can be harvested now and decrypted later (HNDL)."
                ),
                "trigger": f"Shor-vulnerable key establishment mechanism ({algorithm})",
                "next_step": (
                    "Map all systems, libraries, and protocols that depend on this key establishment mechanism. "
                    "Identify certificate authorities, TLS configurations, VPN tunnels, and encrypted storage systems "
                    "that use this algorithm. Document data flows and trust relationships."
                ),
                "reference": "NIST SP 800-208 (Post-Quantum PKI) / NIST SP 800-57 Part 1 Rev. 5",
            })

            recommendations.append({
                "action": "Assess migration requirements and complexity",
                "relevance": (
                    f"Migrating from {algorithm} to post-quantum key establishment requires understanding "
                    "system dependencies, performance constraints, and interoperability requirements."
                ),
                "trigger": "Shor-vulnerable key establishment with migration planning needs",
                "next_step": (
                    "Evaluate: (1) computational resources for PQC primitives, (2) network bandwidth for larger key sizes, "
                    "(3) protocol support for hybrid or pure PQC schemes, (4) hardware acceleration availability, "
                    "(5) legacy system compatibility constraints. Document estimated migration duration (Y)."
                ),
                "reference": "NIST IR 8414 (Migration to Post-Quantum Cryptography)",
            })

            recommendations.append({
                "action": "Review standardized post-quantum cryptographic alternatives",
                "relevance": (
                    f"NIST has standardized ML-KEM (FIPS 203) for post-quantum key establishment. "
                    "This provides a quantum-resistant replacement for {algorithm}."
                ),
                "trigger": "NIST PQC standards available for key establishment",
                "next_step": (
                    "Evaluate ML-KEM-768 (NIST FIPS 203) as the primary replacement. "
                    "Consider hybrid classical/post-quantum schemes (e.g., X25519 + ML-KEM-768) for transitional deployments "
                    "to maintain backward compatibility while adding quantum resistance. "
                    "Review performance characteristics and key sizes."
                ),
                "reference": "FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard)",
            })

            recommendations.append({
                "action": "Develop a phased migration plan",
                "relevance": (
                    f"Complete migration from {algorithm} to PQC cannot be completed instantaneously. "
                    "A phased approach minimizes disruption while addressing HNDL risk."
                ),
                "trigger": "Organizational migration planning requirement",
                "next_step": (
                    "Create a migration roadmap: (1) prioritize systems with longest data shelf-life (X), "
                    "(2) establish pilot deployments for testing, (3) plan hybrid transitional phases, "
                    "(4) schedule production rollout, (5) maintain monitoring and rollback procedures. "
                    "Ensure planning margin Z - (X + Y) remains positive."
                ),
                "reference": "NIST IR 8414 (Migration to Post-Quantum Cryptography) / NSA CNSA 2.0 Timeline",
            })

            recommendations.append({
                "action": "Test compatibility before production deployment",
                "relevance": (
                    f"Post-quantum key establishment has different performance characteristics and key sizes than {algorithm}. "
                    "Compatibility testing prevents production failures."
                ),
                "trigger": "Pre-deployment validation requirement",
                "next_step": (
                    "Conduct testing in a staging environment: (1) measure key generation and encapsulation performance, "
                    "(2) verify interop with existing protocol stacks (TLS 1.3, SSH, IPsec), (3) test hybrid mode support, "
                    "(4) validate certificate issuance workflows, (5) assess impact on existing infrastructure."
                ),
                "reference": "NIST SP 800-208 (Post-Quantum PKI Implementation Guidance)",
            })

            # Add urgency recommendation based on shelf-life
            if data_shelf_life_years >= 10:
                recommendations.append({
                    "action": "Prioritize immediate migration planning for long-lived data",
                    "relevance": (
                        f"This asset protects data requiring {data_shelf_life_years} years of confidentiality. "
                        "Long shelf-life significantly increases HNDL exposure. Adversaries can harvest encrypted data today "
                        "for future quantum decryption, making immediate action critical."
                    ),
                    "trigger": f"Long confidentiality duration ({data_shelf_life_years} years) with Shor-vulnerable key establishment",
                    "next_step": (
                        "Elevate this asset to the highest migration priority tier. "
                        "Allocate dedicated resources for migration planning and implementation. "
                        "Consider interim risk mitigations such as reducing data shelf-life where possible, "
                        "or implementing additional confidentiality layers."
                    ),
                    "reference": "NIST IR 8414 (HNDL Risk Prioritization) / NSA CNSA 2.0 Guidance",
                })

            # Add planning margin recommendation if available
            if planning_margin is not None and planning_margin < 0:
                recommendations.append({
                    "action": "Accelerate migration due to negative planning margin",
                    "relevance": (
                        f"Planning margin is {planning_margin} years (negative). "
                        "Combined confidentiality duration (X={data_shelf_life_years}) and migration duration (Y) "
                        "exceed the available threat horizon buffer. This indicates insufficient time for planned migration."
                    ),
                    "trigger": f"Negative planning margin ({planning_margin} years)",
                    "next_step": (
                        "Take immediate actions: (1) reduce migration duration (Y) through dedicated resources, "
                        "(2) reduce data shelf-life (X) where business-justified, (3) implement interim risk controls, "
                        "(4) escalate to executive leadership for resource allocation, (5) reassess threat horizon assumptions."
                    ),
                    "reference": "Mosca's Theorem / NIST IR 8414 (Timeline Planning)",
                })

        # RSA dual-use (could be key establishment or signature)
        elif family == "RSA":
            recommendations.append({
                "action": "Identify the operational role of RSA keys",
                "relevance": (
                    f"RSA can be used for key establishment (encryption/KEM) or digital signatures. "
                    "The PQC migration path differs: ML-KEM for key establishment, ML-DSA for signatures. "
                    "Identifying the role is essential for correct migration targeting."
                ),
                "trigger": "RSA algorithm with unspecified dual-use role",
                "next_step": (
                    "Audit the RSA key usage: (1) check if used in TLS key exchange (RSA key transport), "
                    "(2) check if used for code signing or authentication (RSA signatures), "
                    "(3) check certificate key usage extensions, (4) review application code and configuration. "
                    "Update the crypto_role field to 'Key Establishment' or 'Digital Signature' accordingly."
                ),
                "reference": "NIST SP 800-57 Part 1 Rev. 5 (Key Usage Identification)",
            })

        # Digital signatures (less HNDL-critical but still important)
        else:
            recommendations.append({
                "action": "Plan migration to post-quantum digital signatures",
                "relevance": (
                    f"{algorithm} digital signatures are vulnerable to Shor's algorithm. "
                    "While signatures are not subject to HNDL decryption, quantum computers could forge signatures "
                    "on long-lived trust anchors, compromising identity and non-repudiation."
                ),
                "trigger": f"Shor-vulnerable digital signature mechanism ({algorithm})",
                "next_step": (
                    "Evaluate ML-DSA-65 (FIPS 204) for general signing use cases. "
                    "For applications requiring stateless hash-based security with conservative assumptions, "
                    "consider SLH-DSA-128s (FIPS 205). Review signature sizes, verification performance, "
                    "and certificate authority compatibility. Plan certificate authority transition."
                ),
                "reference": "FIPS 204 (Module-Lattice-Based Digital Signature Standard) / FIPS 205 (Stateful Hash-Based Digital Signature Standard)",
            })

            # Add data sensitivity recommendation for critical assets
            if data_sensitivity in {"Critical", "High"}:
                recommendations.append({
                    "action": "Prioritize signature migration for high-sensitivity trust anchors",
                    "relevance": (
                        f"This digital signature protects {data_sensitivity.lower()}-sensitive data or systems. "
                        "Compromise of the signing key could allow quantum signature forgery, "
                        "undermining trust in critical infrastructure or long-lived certificates."
                    ),
                    "trigger": f"High data sensitivity ({data_sensitivity}) with Shor-vulnerable signatures",
                    "next_step": (
                        "Include this asset in the high-priority migration tier. "
                        "Consider shorter certificate validity periods to limit exposure window. "
                        "Plan for certificate authority migration and trust anchor updates. "
                        "Document signature verification dependencies."
                    ),
                    "reference": "NIST SP 800-57 Part 1 Rev. 5 (High-Sensitivity Key Management)",
                })

    # 4. Recommendations for Grover-affected symmetric encryption
    if grover_affected:
        if family == "3DES":
            recommendations.append({
                "action": "Decommission 3DES immediately",
                "relevance": (
                    "3DES has 64-bit block vulnerabilities that enable practical attacks (sweet32). "
                    "Additionally, Grover's algorithm would reduce its effective security further. "
                    "3DES should be replaced regardless of quantum threat considerations."
                ),
                "trigger": "Legacy 3DES with classical and quantum vulnerabilities",
                "next_step": (
                    "Replace 3DES with AES-256-GCM (NIST SP 800-38D). "
                    "Ensure application compatibility testing. Remove 3DES from all cipher suite configurations. "
                    "Update security policies to prohibit 3DES use."
                ),
                "reference": "NIST SP 800-38D (AES-GCM) / NIST SP 800-57 Part 1 Rev. 5 (3DES Deprecation)",
            })
        elif key_size < 256:
            recommendations.append({
                "action": "Upgrade symmetric key length to 256 bits",
                "relevance": (
                    f"Current key size is {key_size} bits. Under Grover's algorithm, effective security "
                    f"would be halved to approximately {key_size // 2} bits. This falls below the NIST "
                    "128-bit post-quantum security floor for long-term protection."
                ),
                "trigger": f"Symmetric key size ({key_size} bits) below post-quantum threshold",
                "next_step": (
                    "Upgrade to AES-256-GCM or ChaCha20 with appropriate key sizes. "
                    "This provides ~128 bits of quantum-resistant security under Grover's algorithm. "
                    "Verify application compatibility with larger key sizes. Update encryption configurations."
                ),
                "reference": "NIST SP 800-57 Part 1 Rev. 5 (Symmetric Key Security Levels)",
            })
        else:
            recommendations.append({
                "action": "Evaluate symmetric encryption implementation quality",
                "relevance": (
                    f"{algorithm}-{key_size} provides approximately 128 bits of quantum security under Grover's algorithm, "
                    "meeting the NIST post-quantum security floor. However, implementation vulnerabilities can "
                    "undermine algorithmic strength."
                ),
                "trigger": "Adequate symmetric key size but implementation quality unknown",
                "next_step": (
                    "Review the implementation: (1) ensure authenticated encryption mode (GCM, CCM, or authenticated wrapper), "
                    "(2) verify proper IV/nonce handling and uniqueness, (3) check for side-channel vulnerabilities, "
                    "(4) validate key derivation functions, (5) ensure cryptographic library is up-to-date. "
                    "Consider specialist assessment for high-sensitivity applications."
                ),
                "reference": "NIST SP 800-38D (Authenticated Encryption) / NIST SP 800-108 (Key Derivation)",
            })

            # Add data sensitivity recommendation for symmetric encryption
            if data_sensitivity in {"Critical", "High"} and data_shelf_life_years >= 10:
                recommendations.append({
                    "action": "Conduct specialist assessment for critical symmetric encryption",
                    "relevance": (
                        f"This symmetric encryption protects {data_sensitivity.lower()}-sensitive data "
                        f"with a {data_shelf_life_years}-year confidentiality requirement. "
                        "While AES-256 is quantum-resistant under Grover's algorithm, implementation flaws "
                        "or side-channel vulnerabilities could compromise security."
                    ),
                    "trigger": f"Critical/long-lived data with symmetric encryption ({data_sensitivity}, {data_shelf_life_years} years)",
                    "next_step": (
                        "Engage cryptographic specialists to conduct a comprehensive assessment: "
                        "(1) code review for cryptographic implementation, (2) penetration testing for side channels, "
                        "(3) validation of key management procedures, (4) review of entropy sources, "
                        "(5) assessment of operational security controls."
                    ),
                    "reference": "NIST SP 800-140 (Cryptographic Module Validation) / NIST SP 800-90 (Random Bit Generation)",
                })

    # 5. Recommendations for hash functions
    if mechanism_type == "HASH_FUNCTION":
        recommendations.append({
            "action": "Assess hash function usage context",
            "relevance": (
                f"{algorithm} remains quantum-resistant for pre-image resistance. "
                "However, collision resistance may be affected by quantum algorithms for some hash functions. "
                "The appropriate action depends on the specific use case."
            ),
            "trigger": "Hash function with context-dependent security requirements",
            "next_step": (
                "Identify how this hash function is used: (1) pre-image resistance (password hashing, commitment schemes) - "
                "current algorithms are generally adequate, (2) collision resistance (digital signatures, certificates) - "
                "consider SHA-384 or SHA-3 for additional margin, (3) extendable-output functions (KDFs) - "
                "evaluate SHAKE256. Do not apply the public-key migration formula indiscriminately."
            ),
            "reference": "FIPS 180-4 (Secure Hash Standard) / FIPS 202 (SHA-3 Standard)",
        })

        if data_shelf_life_years >= 15:
            recommendations.append({
                "action": "Consider upgrading to SHA-384 or SHA-3 for ultra-long-term security",
                "relevance": (
                    f"Data requires {data_shelf_life_years} years of protection. "
                    "For collision-sensitive applications with ultra-long security requirements, "
                    "SHA-384 or SHA-3 provide additional quantum-resistant margin."
                ),
                "trigger": f"Ultra-long confidentiality duration ({data_shelf_life_years} years) with hash function",
                "next_step": (
                    "For collision-sensitive use cases (signatures, Merkle trees, certificate fingerprinting), "
                    "evaluate migration to SHA-384 or SHA-3-256. For general pre-image resistance, "
                    "current SHA-2 functions remain adequate. Document specific use cases before deciding."
                ),
                "reference": "FIPS 202 (SHA-3 Standard) / NIST SP 800-57 Part 1 Rev. 5",
            })

    # 6. Recommendations for standardized PQC (already quantum-safe)
    if mechanism_type == "STANDARDIZED_PQC":
        recommendations.append({
            "action": "Maintain current PQC implementation",
            "relevance": (
                f"{algorithm} is a standardized post-quantum cryptographic primitive under NIST FIPS standards. "
                "It is designed to resist both classical and quantum cryptanalysis."
            ),
            "trigger": "Standardized NIST PQC primitive",
            "next_step": (
                "Maintain current implementation with: (1) regular security updates, "
                "(2) monitoring for NIST guidance updates, (3) FIPS 140-3 validation if applicable, "
                "(4) testing of future algorithm variants. Do not declare the entire system quantum-safe "
                "without evaluating all components (signatures, key exchange, symmetric encryption, hashes)."
            ),
            "reference": f"NIST FIPS standard for {family} (203/204/205)",
        })

        # Add implementation quality recommendation
        recommendations.append({
            "action": "Validate PQC implementation security",
            "relevance": (
                f"While {algorithm} is quantum-resistant by design, implementation vulnerabilities "
                "(side channels, weak randomness, improper key handling) can compromise security."
            ),
            "trigger": "PQC implementation security validation",
            "next_step": (
                "Conduct implementation validation: (1) review for side-channel vulnerabilities (timing, power analysis), "
                "(2) validate entropy sources for key generation, (3) ensure proper key storage and lifecycle management, "
                "(4) test for constant-time implementations, (5) consider FIPS 140-3 module validation."
            ),
            "reference": "NIST SP 800-140 (Cryptographic Module Validation) / NIST SP 800-90 (Random Bit Generation)",
        })

    # 7. Add general recommendation if no specific recommendations were generated
    if not recommendations:
        recommendations.append({
            "action": "Review asset for migration planning",
            "relevance": (
                f"Asset using {algorithm} requires review to determine appropriate migration path "
                "based on operational context and security requirements."
            ),
            "trigger": "General asset review required",
            "next_step": (
                "Review the asset's: (1) data sensitivity classification, (2) confidentiality requirements, "
                "(3) operational dependencies, (4) performance constraints. Update asset metadata "
                "and reassess if additional context becomes available."
            ),
            "reference": "NIST SP 800-57 Part 1 Rev. 5 (General Cryptographic Management)",
        })

    return recommendations


def get_pqc_recommendation(
    algorithm: str,
    key_size: int = 0,
    crypto_role: Optional[str] = None,
) -> Dict[str, Any]:
    """Provide role-aware migration recommendations aligned with NIST PQC standards.

    This is a simplified interface for backward compatibility. For full explainable
    recommendations with assessment context, use get_explainable_recommendations.

    Args:
        algorithm: Legacy or current algorithm name.
        key_size: Key length in bits.
        crypto_role: Cryptographic operational role:
            'Key Establishment', 'Digital Signature', 'Symmetric Encryption',
            'Cryptographic Hash', or 'Unknown / Unclassified'.

    Returns:
        Structured recommendation dictionary.
    """
    family, mechanism_type = classify_cryptographic_primitive(algorithm)
    role_norm = (crypto_role or "").strip().lower()

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

        if key_size < 256:
            return {
                "legacy_algorithm": algorithm,
                "crypto_role": "Symmetric Encryption",
                "target_pqc_algorithm": "AES-256-GCM",
                "nist_standard": "NIST SP 800-38D",
                "priority": "Medium",
                "action": (
                    f"Upgrade key length from {key_size} bits to AES-256 to guarantee a 128-bit security "
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
