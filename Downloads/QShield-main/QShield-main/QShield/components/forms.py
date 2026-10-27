"""Input forms and collection components for Streamlit interface."""

from typing import Any, Dict, Optional
import streamlit as st
from core.validation import (
    KNOWN_ALGORITHMS,
    KNOWN_ROLES,
    VALID_MIGRATION_STATUSES,
    VALID_DATA_SENSITIVITY,
    is_key_size_applicable,
    validate_asset_data,
)


def render_asset_intake_form() -> Optional[Dict[str, Any]]:
    """Render the cryptographic asset intake form in Streamlit.

    Returns:
        Validated dictionary of asset attributes if successfully submitted, else None.
    """
    with st.form("new_asset_form", clear_on_submit=True):
        st.subheader("Register Cryptographic Asset")

        col1, col2 = st.columns(2)
        with col1:
            name = st.text_input("Asset Name*", placeholder="e.g., Customer DB Encryption Key")
            crypto_algo = st.selectbox(
                "Cryptographic Algorithm*",
                options=sorted(KNOWN_ALGORITHMS),
                index=sorted(KNOWN_ALGORITHMS).index("RSA") if "RSA" in KNOWN_ALGORITHMS else 0,
            )

            # Auto-suggest role based on algorithm
            algo_upper = crypto_algo.upper()
            if "ECDSA" in algo_upper or algo_upper in {"DSA", "ML-DSA", "SLH-DSA", "FALCON"}:
                def_role = "Digital Signature"
            elif "ECDH" in algo_upper or "DIFFIE" in algo_upper or algo_upper in {"ML-KEM", "KYBER"}:
                def_role = "Key Establishment"
            elif algo_upper in {"AES", "3DES", "CHACHA20"}:
                def_role = "Symmetric Encryption"
            elif "SHA" in algo_upper:
                def_role = "Cryptographic Hash"
            else:
                def_role = "Key Establishment"

            crypto_role = st.selectbox(
                "Cryptographic Role*",
                options=sorted(KNOWN_ROLES),
                index=sorted(KNOWN_ROLES).index(def_role) if def_role in KNOWN_ROLES else 0,
            )

            # Determine key size applicability
            key_applicable = is_key_size_applicable(crypto_algo, crypto_role)
            def_keysize = 2048 if crypto_algo in {"RSA", "Diffie-Hellman", "DSA"} else (
                768 if crypto_algo == "ML-KEM" else (
                    65 if crypto_algo == "ML-DSA" else (
                        128 if crypto_algo == "SLH-DSA" else (
                            168 if crypto_algo == "3DES" else (
                                0 if not key_applicable else 256
                            )
                        )
                    )
                )
            )

            key_size = st.number_input(
                "Key Size (bits, 0 = N/A for Hashes)",
                min_value=0,
                max_value=16384,
                value=def_keysize,
                step=16 if def_keysize < 512 else 64,
                help="Key length in bits. For hash functions (e.g. SHA-256), enter 0 or N/A.",
            )

        with col2:
            system_name = st.text_input("System / Application Name*", placeholder="e.g., Core Banking System")
            shelf_life = st.number_input(
                "Data Shelf-Life (Years, X)*",
                min_value=0,
                max_value=50,
                value=5,
                step=1,
                help="Duration (X) this data must remain strictly confidential.",
            )
            data_sensitivity = st.selectbox(
                "Data Sensitivity*",
                options=sorted(VALID_DATA_SENSITIVITY),
                index=sorted(VALID_DATA_SENSITIVITY).index("Medium"),
                help="Classification of data sensitivity for migration prioritization.",
            )
            migration_status = st.selectbox(
                "Migration Status*",
                options=sorted(VALID_MIGRATION_STATUSES),
                index=sorted(VALID_MIGRATION_STATUSES).index("Not Started"),
            )

        submitted = st.form_submit_button("Add Asset to Inventory", use_container_width=True)

        if submitted:
            # If 0 is entered for an unkeyed algorithm, store as None / N/A
            ks_val = None if (key_size == 0 and not key_applicable) else int(key_size)
            asset_data = {
                "name": name,
                "system_name": system_name,
                "crypto_algorithm": crypto_algo,
                "crypto_role": crypto_role,
                "key_size": ks_val,
                "data_shelf_life_years": int(shelf_life),
                "data_sensitivity": data_sensitivity,
                "migration_status": migration_status,
            }
            is_valid, errors = validate_asset_data(asset_data)
            if not is_valid:
                for err in errors:
                    st.error(f"❌ {err}")
                return None
            return asset_data

    return None


def render_asset_edit_form(asset: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Render the cryptographic asset edit form pre-populated with current asset values.

    Args:
        asset: Dictionary of the existing asset attributes.

    Returns:
        Validated dictionary of updated asset attributes if submitted, else None.
    """
    form_key = f"edit_asset_form_{asset['id']}"
    with st.form(form_key):
        st.markdown(f"**Editing Asset ID #{asset['id']}:** `{asset['name']}`")

        c1, c2 = st.columns(2)
        with c1:
            name = st.text_input("Asset Name*", value=asset.get("name", ""))

            curr_algo = asset.get("crypto_algorithm", "RSA")
            algo_options = sorted(KNOWN_ALGORITHMS)
            if curr_algo not in algo_options:
                algo_options.append(curr_algo)
            algo_idx = algo_options.index(curr_algo) if curr_algo in algo_options else 0
            crypto_algo = st.selectbox("Cryptographic Algorithm*", options=algo_options, index=algo_idx)

            curr_role = asset.get("crypto_role", "Unknown / Unclassified")
            role_options = sorted(KNOWN_ROLES)
            if curr_role not in role_options:
                role_options.append(curr_role)
            role_idx = role_options.index(curr_role) if curr_role in role_options else 0
            crypto_role = st.selectbox("Cryptographic Role*", options=role_options, index=role_idx)

            curr_ks = asset.get("key_size")
            ks_init = int(curr_ks) if (curr_ks is not None and curr_ks > 0) else 0
            key_applicable = is_key_size_applicable(crypto_algo, crypto_role)

            key_size = st.number_input(
                "Key Size (bits, 0 = N/A)",
                min_value=0,
                max_value=16384,
                value=ks_init,
                step=16 if ks_init < 512 else 64,
                help="Key length in bits. Set to 0 if not applicable.",
            )

        with c2:
            system_name = st.text_input("System / Application Name*", value=asset.get("system_name", ""))
            shelf_life = st.number_input(
                "Data Shelf-Life (Years, X)*",
                min_value=0,
                max_value=50,
                value=int(asset.get("data_shelf_life_years", 5)),
                step=1,
            )

            curr_sensitivity = asset.get("data_sensitivity", "Medium")
            sensitivity_options = sorted(VALID_DATA_SENSITIVITY)
            if curr_sensitivity not in sensitivity_options:
                sensitivity_options.append(curr_sensitivity)
            sensitivity_idx = sensitivity_options.index(curr_sensitivity) if curr_sensitivity in sensitivity_options else 0
            data_sensitivity = st.selectbox("Data Sensitivity*", options=sensitivity_options, index=sensitivity_idx)

            curr_status = asset.get("migration_status", "Not Started")
            status_options = sorted(VALID_MIGRATION_STATUSES)
            if curr_status not in status_options:
                status_options.append(curr_status)
            status_idx = status_options.index(curr_status) if curr_status in status_options else 0
            migration_status = st.selectbox("Migration Status*", options=status_options, index=status_idx)

        submitted = st.form_submit_button("💾 Save Asset Updates", use_container_width=True)

        if submitted:
            ks_val = None if (key_size == 0 and not key_applicable) else int(key_size)
            updated_data = {
                "name": name,
                "system_name": system_name,
                "crypto_algorithm": crypto_algo,
                "crypto_role": crypto_role,
                "key_size": ks_val,
                "data_shelf_life_years": int(shelf_life),
                "data_sensitivity": data_sensitivity,
                "migration_status": migration_status,
            }
            is_valid, errors = validate_asset_data(updated_data)
            if not is_valid:
                for err in errors:
                    st.error(f"❌ {err}")
                return None
            return updated_data

    return None
