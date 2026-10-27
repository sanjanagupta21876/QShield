"""Synthetic demonstration dataset and loading utilities for QShield.

All demonstration assets are explicitly synthetic and clearly labeled with '[DEMO] Synthetic'.
Designed to safely load into the database without creating duplicate records or
overwriting existing data without explicit user confirmation.
"""

import sqlite3
from typing import Any, Dict, List, Optional
from core.database import (
    get_db_connection,
    get_all_assets,
    insert_asset,
    delete_asset,
)


SYNTHETIC_DEMO_ASSETS: List[Dict[str, Any]] = [
    {
        "name": "[DEMO] Synthetic Core Banking TLS Certificate",
        "system_name": "Synthetic Online Banking Portal",
        "crypto_algorithm": "RSA",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 12,
        "migration_status": "Not Started",
    },
    {
        "name": "[DEMO] Synthetic Mobile App Auth Token Signer",
        "system_name": "Synthetic Identity Provider (IdP)",
        "crypto_algorithm": "ECDSA",
        "crypto_role": "Digital Signature",
        "key_size": 256,
        "data_shelf_life_years": 2,
        "migration_status": "Planning",
    },
    {
        "name": "[DEMO] Synthetic Customer PII Database Encryption",
        "system_name": "Synthetic Customer Data Platform",
        "crypto_algorithm": "AES",
        "crypto_role": "Symmetric Encryption",
        "key_size": 128,
        "data_shelf_life_years": 15,
        "migration_status": "In Progress",
    },
    {
        "name": "[DEMO] Synthetic Inter-Bank Settlement Messaging",
        "system_name": "Synthetic Clearing House Gateway",
        "crypto_algorithm": "AES",
        "crypto_role": "Symmetric Encryption",
        "key_size": 256,
        "data_shelf_life_years": 10,
        "migration_status": "Completed",
    },
    {
        "name": "[DEMO] Synthetic Employee Credential Hasher",
        "system_name": "Synthetic Active Directory Service",
        "crypto_algorithm": "SHA-256",
        "crypto_role": "Cryptographic Hash",
        "key_size": None,
        "data_shelf_life_years": 20,
        "migration_status": "Completed",
    },
    {
        "name": "[DEMO] Synthetic Post-Quantum Backbone Transport KEM",
        "system_name": "Synthetic Cloud Interconnect WAN",
        "crypto_algorithm": "ML-KEM",
        "crypto_role": "Key Establishment",
        "key_size": 768,
        "data_shelf_life_years": 30,
        "migration_status": "Completed",
    },
    {
        "name": "[DEMO] Synthetic Code Signing & Firmware Anchor",
        "system_name": "Synthetic Build & Release Pipeline",
        "crypto_algorithm": "ML-DSA",
        "crypto_role": "Digital Signature",
        "key_size": 65,
        "data_shelf_life_years": 10,
        "migration_status": "In Progress",
    },
    {
        "name": "[DEMO] Synthetic Legacy VPN Gateway Exchange",
        "system_name": "Synthetic Remote Access VPN",
        "crypto_algorithm": "Diffie-Hellman",
        "crypto_role": "Key Establishment",
        "key_size": 2048,
        "data_shelf_life_years": 6,
        "migration_status": "Planning",
    },
    {
        "name": "[DEMO] Synthetic Legacy Tape Archive Cipher",
        "system_name": "Synthetic Cold Storage Archive",
        "crypto_algorithm": "3DES",
        "crypto_role": "Symmetric Encryption",
        "key_size": 168,
        "data_shelf_life_years": 8,
        "migration_status": "Decommissioned",
    },
    {
        "name": "[DEMO] Synthetic Proprietary Mainframe Middleware",
        "system_name": "Synthetic Legacy Mainframe Bus",
        "crypto_algorithm": "Custom_Obfuscation_Cipher_v2",
        "crypto_role": "Unknown / Unclassified",
        "key_size": 128,
        "data_shelf_life_years": 10,
        "migration_status": "Not Started",
    },
]


def load_demo_dataset(
    conn: sqlite3.Connection,
    clear_existing: bool = False,
) -> Dict[str, Any]:
    """Safely load the synthetic demonstration dataset into the database.

    Args:
        conn: Active SQLite database connection.
        clear_existing: If True, explicitly purges current assets before loading.
                        If False (default), preserves existing inventory and avoids duplicates.

    Returns:
        Summary dict containing counts of inserted, skipped, and total records.
    """
    cursor = conn.cursor()

    if clear_existing:
        cursor.execute("DELETE FROM assets")
        conn.commit()

    existing_assets = get_all_assets(conn)
    existing_names = {a["name"].strip().lower() for a in existing_assets}

    inserted_count = 0
    skipped_count = 0

    for asset in SYNTHETIC_DEMO_ASSETS:
        name_key = asset["name"].strip().lower()
        if not clear_existing and name_key in existing_names:
            skipped_count += 1
            continue

        insert_asset(conn, asset)
        inserted_count += 1
        existing_names.add(name_key)

    total_assets = len(get_all_assets(conn))

    return {
        "inserted": inserted_count,
        "skipped": skipped_count,
        "total": total_assets,
        "cleared_existing": clear_existing,
    }


if __name__ == "__main__":
    with get_db_connection() as c:
        result = load_demo_dataset(c, clear_existing=False)
        print(f"Demo data load complete: {result['inserted']} inserted, {result['skipped']} skipped (Total: {result['total']})")
