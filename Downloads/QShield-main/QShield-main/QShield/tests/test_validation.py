"""Unit tests for core/validation.py."""

import pytest
from core.validation import validate_asset_data, validate_cryptographic_parameters


def test_validate_valid_asset():
    data = {
        "name": "Payment Gateway Private Key",
        "system_name": "Checkout Service",
        "crypto_algorithm": "RSA",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 7,
        "migration_status": "Planning",
    }
    is_valid, errors = validate_asset_data(data)
    assert is_valid is True
    assert len(errors) == 0


def test_validate_missing_name():
    data = {
        "name": "   ",
        "system_name": "Checkout Service",
        "crypto_algorithm": "RSA",
        "key_size": 2048,
        "data_shelf_life_years": 5,
    }
    is_valid, errors = validate_asset_data(data)
    assert is_valid is False
    assert any("name is required" in err.lower() for err in errors)


def test_validate_invalid_key_size():
    data = {
        "name": "Test Key",
        "system_name": "Test Service",
        "crypto_algorithm": "AES",
        "key_size": -128,
        "data_shelf_life_years": 3,
    }
    is_valid, errors = validate_asset_data(data)
    assert is_valid is False
    assert any("positive integer" in err.lower() for err in errors)


def test_validate_negative_shelf_life():
    data = {
        "name": "Test Key",
        "system_name": "Test Service",
        "crypto_algorithm": "AES",
        "key_size": 256,
        "data_shelf_life_years": -2,
    }
    is_valid, errors = validate_asset_data(data)
    assert is_valid is False
    assert any("cannot be negative" in err.lower() for err in errors)


def test_validate_invalid_migration_status():
    data = {
        "name": "Test Key",
        "system_name": "Test Service",
        "crypto_algorithm": "AES",
        "key_size": 256,
        "data_shelf_life_years": 5,
        "migration_status": "UnknownStatus",
    }
    is_valid, errors = validate_asset_data(data)
    assert is_valid is False
    assert any("invalid migration status" in err.lower() for err in errors)


def test_validate_invalid_crypto_role():
    data = {
        "name": "Test Key",
        "system_name": "Test Service",
        "crypto_algorithm": "AES",
        "crypto_role": "InvalidRoleName",
        "key_size": 256,
        "data_shelf_life_years": 5,
    }
    is_valid, errors = validate_asset_data(data)
    assert is_valid is False
    assert any("invalid cryptographic role" in err.lower() for err in errors)


# ==============================================================================
# Phase 2 New Validation Tests
# ==============================================================================

def test_validate_asset_data_non_dict_type():
    """Verify non-dictionary input is rejected cleanly."""
    is_valid, errors = validate_asset_data("not a dictionary")
    assert is_valid is False
    assert any("must be a dictionary" in err.lower() for err in errors)

    is_valid, errors = validate_asset_data(None)
    assert is_valid is False
    assert any("must be a dictionary" in err.lower() for err in errors)


def test_validate_incompatible_algorithm_and_role():
    """Verify that incompatible algorithm and role combinations produce validation errors."""
    # AES with Digital Signature
    data_aes_sig = {
        "name": "Web Token Key",
        "system_name": "Auth Service",
        "crypto_algorithm": "AES",
        "crypto_role": "Digital Signature",
        "key_size": 256,
        "data_shelf_life_years": 5,
    }
    is_valid, errors = validate_asset_data(data_aes_sig)
    assert is_valid is False
    assert any("incompatible" in err.lower() for err in errors)

    # ECDSA with Key Establishment
    data_ecdsa_kem = {
        "name": "TLS Session Key",
        "system_name": "Gateway",
        "crypto_algorithm": "ECDSA",
        "crypto_role": "Key Establishment",
        "key_size": 256,
        "data_shelf_life_years": 3,
    }
    is_valid, errors = validate_asset_data(data_ecdsa_kem)
    assert is_valid is False
    assert any("incompatible" in err.lower() for err in errors)

    # ML-KEM with Digital Signature
    data_mlkem_sig = {
        "name": "Document Signer",
        "system_name": "Legal Portal",
        "crypto_algorithm": "ML-KEM",
        "crypto_role": "Digital Signature",
        "key_size": 768,
        "data_shelf_life_years": 10,
    }
    is_valid, errors = validate_asset_data(data_mlkem_sig)
    assert is_valid is False
    assert any("incompatible" in err.lower() for err in errors)


def test_validate_cryptographic_parameters_function():
    """Verify the standalone validate_cryptographic_parameters function."""
    # Valid parameters
    is_valid, errors = validate_cryptographic_parameters(
        algorithm="ML-KEM",
        key_size=768,
        data_shelf_life_years=5,
        crypto_role="Key Establishment",
    )
    assert is_valid is True
    assert len(errors) == 0

    # Missing algorithm
    is_valid, errors = validate_cryptographic_parameters(
        algorithm="",
        key_size=256,
    )
    assert is_valid is False
    assert any("required" in err.lower() for err in errors)

    # Invalid key size (boolean / negative)
    is_valid, errors = validate_cryptographic_parameters(
        algorithm="AES",
        key_size=True,
    )
    assert is_valid is False
    assert any("valid integer" in err.lower() for err in errors)

    is_valid, errors = validate_cryptographic_parameters(
        algorithm="AES",
        key_size=-256,
    )
    assert is_valid is False
    assert any("positive integer" in err.lower() for err in errors)


def test_validate_hash_function_does_not_require_key_size():
    """Verify hash functions where key size is not applicable can be registered with None or 0."""
    # SHA-256 with key_size = None
    data_sha_none = {
        "name": "Audit Hash",
        "system_name": "Logging Service",
        "crypto_algorithm": "SHA-256",
        "crypto_role": "Cryptographic Hash",
        "key_size": None,
        "data_shelf_life_years": 5,
        "migration_status": "Completed",
    }
    is_valid, errors = validate_asset_data(data_sha_none)
    assert is_valid is True
    assert len(errors) == 0

    # SHA-3 with key_size = "0"
    data_sha3_zero = {
        "name": "Block Hash",
        "system_name": "Ledger",
        "crypto_algorithm": "SHA-3",
        "crypto_role": "Cryptographic Hash",
        "key_size": "0",
        "data_shelf_life_years": 10,
        "migration_status": "Planning",
    }
    is_valid, errors = validate_asset_data(data_sha3_zero)
    assert is_valid is True
    assert len(errors) == 0

    # Negative key size still rejected
    data_sha_neg = {
        "name": "Invalid Hash",
        "system_name": "Logging",
        "crypto_algorithm": "SHA-256",
        "crypto_role": "Cryptographic Hash",
        "key_size": -10,
        "data_shelf_life_years": 5,
    }
    is_valid, errors = validate_asset_data(data_sha_neg)
    assert is_valid is False
    assert any("cannot be negative" in err.lower() for err in errors)

