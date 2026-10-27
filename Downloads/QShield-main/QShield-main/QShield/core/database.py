"""Database management module for QShield using SQLite."""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

# Default database location inside the data/ folder
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "qshield.db"


def get_db_connection(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Establish and return a connection to the SQLite database.

    Args:
        db_path: Path to SQLite database file or ':memory:'.

    Returns:
        sqlite3.Connection with row_factory set to sqlite3.Row.
    """
    path = str(db_path if db_path is not None else DEFAULT_DB_PATH)
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str | Path] = None) -> None:
    """Initialize database tables and ensure schema consistency.

    Preserves existing data while ensuring all required columns exist.

    Args:
        db_path: Optional database path.
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                system_name TEXT NOT NULL,
                crypto_algorithm TEXT NOT NULL,
                crypto_role TEXT NOT NULL DEFAULT 'Unknown / Unclassified',
                key_size INTEGER,
                data_shelf_life_years INTEGER NOT NULL DEFAULT 5,
                migration_status TEXT NOT NULL DEFAULT 'Not Started',
                data_sensitivity TEXT DEFAULT 'Medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Check existing columns to ensure backward-compatible schema migration
        cursor.execute("PRAGMA table_info(assets)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "crypto_role" not in columns:
            cursor.execute(
                "ALTER TABLE assets ADD COLUMN crypto_role TEXT NOT NULL DEFAULT 'Unknown / Unclassified'"
            )
        if "data_sensitivity" not in columns:
            cursor.execute(
                "ALTER TABLE assets ADD COLUMN data_sensitivity TEXT DEFAULT 'Medium'"
            )

        conn.commit()


def _sanitize_key_size(key_size_val: Any) -> Optional[int]:
    """Helper to sanitize key_size into an integer or None."""
    if key_size_val is None or str(key_size_val).strip().upper() in {"N/A", "NONE", ""}:
        return None
    try:
        val = int(key_size_val)
        return val if val > 0 else 0
    except (ValueError, TypeError):
        return None


def insert_asset(conn: sqlite3.Connection, asset_data: Dict[str, Any]) -> int:
    """Insert a cryptographic asset into the database using parameterized queries.

    Handles algorithms where key size is not applicable by storing None (or 0 for legacy NOT NULL schemas).

    Args:
        conn: SQLite connection.
        asset_data: Dictionary containing asset fields.

    Returns:
        The ID of the newly inserted row.
    """
    cursor = conn.cursor()
    name = str(asset_data.get("name", "")).strip()
    if not name:
        raise ValueError("Asset name is required and cannot be empty.")
    algo = str(asset_data.get("crypto_algorithm", "")).strip()
    if not algo:
        raise ValueError("Cryptographic algorithm is required and cannot be empty.")

    key_size = _sanitize_key_size(asset_data.get("key_size"))
    data_sensitivity = asset_data.get("data_sensitivity", "Medium").strip()

    try:
        cursor.execute(
            """
            INSERT INTO assets (
                name, system_name, crypto_algorithm, crypto_role, key_size, data_shelf_life_years, migration_status, data_sensitivity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                asset_data.get("system_name", "Default System").strip(),
                algo,
                asset_data.get("crypto_role", "Unknown / Unclassified").strip(),
                key_size,
                int(asset_data.get("data_shelf_life_years", 5)),
                asset_data.get("migration_status", "Not Started").strip(),
                data_sensitivity,
            ),
        )
    except sqlite3.IntegrityError as e:
        # Fallback for legacy tables created with NOT NULL on key_size
        if "key_size" in str(e).lower() and key_size is None:
            cursor.execute(
                """
                INSERT INTO assets (
                    name, system_name, crypto_algorithm, crypto_role, key_size, data_shelf_life_years, migration_status, data_sensitivity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    asset_data.get("system_name", "Default System").strip(),
                    algo,
                    asset_data.get("crypto_role", "Unknown / Unclassified").strip(),
                    0,  # Legacy integer sentinel for Not Applicable
                    int(asset_data.get("data_shelf_life_years", 5)),
                    asset_data.get("migration_status", "Not Started").strip(),
                    data_sensitivity,
                ),
            )
        else:
            raise

    conn.commit()
    return cursor.lastrowid or 0


def get_all_assets(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Retrieve all cryptographic assets as dictionaries.

    Args:
        conn: SQLite connection.

    Returns:
        List of asset dictionaries.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets ORDER BY id ASC")
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_asset_by_id(conn: sqlite3.Connection, asset_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single cryptographic asset by its primary key ID.

    Args:
        conn: SQLite connection.
        asset_id: The ID of the asset.

    Returns:
        Asset dictionary if found, else None.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def update_asset(conn: sqlite3.Connection, asset_id: int, asset_data: Dict[str, Any]) -> bool:
    """Update an existing cryptographic asset using parameterized queries.

    Args:
        conn: SQLite connection.
        asset_id: The primary key ID of the asset to update.
        asset_data: Dictionary containing updated fields.

    Returns:
        True if the asset was found and updated, False otherwise.
    """
    cursor = conn.cursor()
    name = str(asset_data.get("name", "")).strip()
    if not name:
        raise ValueError("Asset name is required and cannot be empty.")
    algo = str(asset_data.get("crypto_algorithm", "")).strip()
    if not algo:
        raise ValueError("Cryptographic algorithm is required and cannot be empty.")

    key_size = _sanitize_key_size(asset_data.get("key_size"))
    data_sensitivity = asset_data.get("data_sensitivity", "Medium").strip()

    try:
        cursor.execute(
            """
            UPDATE assets SET
                name = ?,
                system_name = ?,
                crypto_algorithm = ?,
                crypto_role = ?,
                key_size = ?,
                data_shelf_life_years = ?,
                migration_status = ?,
                data_sensitivity = ?
            WHERE id = ?
            """,
            (
                name,
                asset_data.get("system_name", "Default System").strip(),
                algo,
                asset_data.get("crypto_role", "Unknown / Unclassified").strip(),
                key_size,
                int(asset_data.get("data_shelf_life_years", 5)),
                asset_data.get("migration_status", "Not Started").strip(),
                data_sensitivity,
                asset_id,
            ),
        )
    except sqlite3.IntegrityError as e:
        if "key_size" in str(e).lower() and key_size is None:
            cursor.execute(
                """
                UPDATE assets SET
                    name = ?,
                    system_name = ?,
                    crypto_algorithm = ?,
                    crypto_role = ?,
                    key_size = ?,
                    data_shelf_life_years = ?,
                    migration_status = ?,
                    data_sensitivity = ?
                WHERE id = ?
                """,
                (
                    name,
                    asset_data.get("system_name", "Default System").strip(),
                    algo,
                    asset_data.get("crypto_role", "Unknown / Unclassified").strip(),
                    0,
                    int(asset_data.get("data_shelf_life_years", 5)),
                    asset_data.get("migration_status", "Not Started").strip(),
                    data_sensitivity,
                    asset_id,
                ),
            )
        else:
            raise

    conn.commit()
    return cursor.rowcount > 0


def update_asset_migration_status(conn: sqlite3.Connection, asset_id: int, new_status: str) -> bool:
    """Update only the migration status of an asset using a parameterized query.

    Args:
        conn: SQLite connection.
        asset_id: The ID of the asset to update.
        new_status: The new migration status string.

    Returns:
        True if the asset was found and updated, False otherwise.
    """
    valid_statuses = {"Not Started", "Planning", "In Progress", "Completed", "Decommissioned"}
    status_clean = str(new_status).strip()
    if status_clean not in valid_statuses:
        raise ValueError(
            f"Invalid migration status '{new_status}'. Must be one of: {', '.join(sorted(valid_statuses))}."
        )
    cursor = conn.cursor()
    cursor.execute("UPDATE assets SET migration_status = ? WHERE id = ?", (status_clean, asset_id))
    conn.commit()
    return cursor.rowcount > 0


def delete_asset(conn: sqlite3.Connection, asset_id: int) -> bool:
    """Delete a cryptographic asset by its primary key ID using parameterized queries.

    Args:
        conn: SQLite connection.
        asset_id: The ID of the asset to delete.

    Returns:
        True if the asset was found and deleted, False otherwise.
    """
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    return cursor.rowcount > 0


def search_assets(
    conn: sqlite3.Connection,
    search_term: Optional[str] = None,
    algorithm: Optional[str] = None,
    role: Optional[str] = None,
    migration_status: Optional[str] = None,
    data_sensitivity: Optional[str] = None,
    sort_by: str = "id",
    sort_asc: bool = True,
) -> List[Dict[str, Any]]:
    """Search, filter, and sort cryptographic assets using parameterized SQL queries.

    Args:
        conn: SQLite connection.
        search_term: Substring to search across name, system_name, and algorithm.
        algorithm: Filter by specific algorithm (exact or 'All').
        role: Filter by specific operational role (exact or 'All').
        migration_status: Filter by specific migration status (exact or 'All').
        data_sensitivity: Filter by data sensitivity (exact or 'All').
        sort_by: Column name to sort by ('id', 'name', 'system_name', 'crypto_algorithm', 'data_shelf_life_years', 'migration_status').
        sort_asc: If True, sort ascending; otherwise descending.

    Returns:
        Filtered list of asset dictionaries.
    """
    cursor = conn.cursor()
    conditions = []
    params: List[Any] = []

    if search_term and search_term.strip():
        term = f"%{search_term.strip()}%"
        conditions.append("(name LIKE ? OR system_name LIKE ? OR crypto_algorithm LIKE ? OR crypto_role LIKE ?)")
        params.extend([term, term, term, term])

    if algorithm and algorithm != "All":
        conditions.append("crypto_algorithm = ?")
        params.append(algorithm.strip())

    if role and role != "All":
        conditions.append("crypto_role = ?")
        params.append(role.strip())

    if migration_status and migration_status != "All":
        conditions.append("migration_status = ?")
        params.append(migration_status.strip())

    if data_sensitivity and data_sensitivity != "All":
        conditions.append("data_sensitivity = ?")
        params.append(data_sensitivity.strip())

    # Whitelist allowed sort columns to prevent SQL injection
    allowed_sort_cols = {
        "id": "id",
        "name": "name",
        "system_name": "system_name",
        "crypto_algorithm": "crypto_algorithm",
        "crypto_role": "crypto_role",
        "key_size": "key_size",
        "data_shelf_life_years": "data_shelf_life_years",
        "migration_status": "migration_status",
        "data_sensitivity": "data_sensitivity",
        "created_at": "created_at",
    }
    col = allowed_sort_cols.get(sort_by.lower(), "id")
    order = "ASC" if sort_asc else "DESC"

    query = "SELECT * FROM assets"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY {col} {order}"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]
