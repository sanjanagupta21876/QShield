"""Validation module for QShield asset and cryptographic configuration inputs."""

from typing import Any, Dict, List, Optional, Tuple
from core.risk_engine import (
    CANONICAL_FAMILIES,
    check_algorithm_role_compatibility,
    classify_cryptographic_primitive,
)

# Supported cryptographic algorithm categories and names
KNOWN_ALGORITHMS = {
    "RSA",
    "ECDSA",
    "ECDH",
    "DSA",
    "Diffie-Hellman",
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
}

KNOWN_ROLES = {
    "Key Establishment",
    "Digital Signature",
    "Symmetric Encryption",
    "Cryptographic Hash",
    "Unknown / Unclassified",
}

VALID_MIGRATION_STATUSES = {
    "Not Started",
    "Planning",
    "In Progress",
    "Completed",
    "Decommissioned",
}

VALID_DATA_SENSITIVITY = {
    "Critical",
    "High",
    "Medium",
    "Low",
}


def is_key_size_applicable(algorithm: Optional[str], role: Optional[str] = None) -> bool:
    """Determine whether key size is applicable for a given algorithm and role.

    Cryptographic hash functions (SHA-256, SHA-384, SHA-512, SHA-3, etc.) and
    assets operating purely as 'Cryptographic Hash' do not use keys.
    """
    if not algorithm or not isinstance(algorithm, str):
        return True
    family, mech = classify_cryptographic_primitive(algorithm)
    if mech == "HASH_FUNCTION" or (role and role.strip() == "Cryptographic Hash"):
        return False
    return True


def validate_cryptographic_parameters(
    algorithm: Any,
    key_size: Any,
    data_shelf_life_years: Any = 5,
    crypto_role: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """Validate core cryptographic parameters independently of full asset dictionary.

    Args:
        algorithm: Algorithm name or identifier.
        key_size: Key length in bits (optional / N/A for unkeyed algorithms like hashes).
        data_shelf_life_years: Required confidentiality lifetime in years.
        crypto_role: Cryptographic operational role.

    Returns:
        Tuple of (is_valid: bool, error_messages: List[str]).
    """
    errors: List[str] = []

    # Algorithm validation
    norm_algo = ""
    if algorithm is None or not isinstance(algorithm, str) or not algorithm.strip():
        errors.append("Cryptographic algorithm is required and cannot be empty.")
    else:
        norm_algo = algorithm.strip()
        # Role compatibility check
        if crypto_role and crypto_role in KNOWN_ROLES:
            is_compat, compat_err = check_algorithm_role_compatibility(norm_algo, crypto_role)
            if not is_compat and compat_err:
                errors.append(compat_err)

    # Key size validation (distinguishes applicable vs non-applicable primitives)
    applicable = is_key_size_applicable(norm_algo if norm_algo else None, crypto_role)
    if applicable:
        if key_size is None:
            errors.append("Key size is required.")
        elif type(key_size) is bool or not isinstance(key_size, int):
            errors.append("Key size must be a valid integer.")
        elif key_size <= 0:
            errors.append("Key size must be a positive integer.")
    else:
        # For hash functions and unkeyed primitives, key size can be None, 0, or output length
        if key_size is not None and not (type(key_size) is bool) and isinstance(key_size, int):
            if key_size < 0:
                errors.append("Key size cannot be negative.")
        elif key_size is not None:
            if type(key_size) is bool or not isinstance(key_size, int):
                errors.append("Key size must be a valid integer.")

    # Shelf-life validation
    if data_shelf_life_years is None:
        errors.append("Data shelf-life is required.")
    elif type(data_shelf_life_years) is bool or not isinstance(data_shelf_life_years, int):
        errors.append("Data shelf-life years must be a valid integer.")
    elif data_shelf_life_years < 0:
        errors.append("Data shelf-life years cannot be negative.")

    # Role validation
    if crypto_role and crypto_role not in KNOWN_ROLES:
        errors.append(
            f"Invalid cryptographic role '{crypto_role}'. Must be one of: {', '.join(sorted(KNOWN_ROLES))}."
        )

    return (len(errors) == 0, errors)


def validate_asset_data(data: Any) -> Tuple[bool, List[str]]:
    """Validate asset fields before ingestion or storage.

    Args:
        data: Dictionary of asset attributes.

    Returns:
        Tuple of (is_valid: bool, error_messages: List[str]).
    """
    if not isinstance(data, dict):
        return (False, ["Asset input data must be a dictionary."])

    errors: List[str] = []

    # Required descriptive fields
    name = str(data.get("name", "")).strip() if data.get("name") is not None else ""
    if not name:
        errors.append("Asset name is required and cannot be empty.")

    system_name = str(data.get("system_name", "")).strip() if data.get("system_name") is not None else ""
    if not system_name:
        errors.append("System name is required and cannot be empty.")

    # Migration status validation
    status = data.get("migration_status", "Not Started")
    if status not in VALID_MIGRATION_STATUSES:
        errors.append(
            f"Invalid migration status '{status}'. Must be one of: {', '.join(sorted(VALID_MIGRATION_STATUSES))}."
        )

    # Data sensitivity validation
    sensitivity = data.get("data_sensitivity", "Medium")
    if sensitivity not in VALID_DATA_SENSITIVITY:
        errors.append(
            f"Invalid data sensitivity '{sensitivity}'. Must be one of: {', '.join(sorted(VALID_DATA_SENSITIVITY))}."
        )

    # Cryptographic parameter validation
    algo = data.get("crypto_algorithm")
    role = data.get("crypto_role")
    key_size = data.get("key_size")
    shelf_life = data.get("data_shelf_life_years", 5)

    # Sanitize string numeric values (e.g. from web forms or JSON input)
    if isinstance(key_size, str):
        cleaned_ks = key_size.strip().upper()
        if cleaned_ks in {"N/A", "NONE", ""}:
            key_size = None
        elif cleaned_ks.isdigit():
            key_size = int(cleaned_ks)
        else:
            try:
                key_size = int(cleaned_ks)
            except ValueError:
                pass

    if isinstance(shelf_life, str) and shelf_life.strip().lstrip("-").isdigit():
        try:
            shelf_life = int(shelf_life.strip())
        except ValueError:
            pass

    params_valid, param_errors = validate_cryptographic_parameters(
        algorithm=algo,
        key_size=key_size,
        data_shelf_life_years=shelf_life,
        crypto_role=role,
    )
    errors.extend(param_errors)

    return (len(errors) == 0, errors)
