"""Backend Persistence Service for Completed Cases.

Supports Supabase PostgreSQL as primary production database via DATABASE_URL
and provides in-memory SQLite fallback for test execution.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

_sqlite_conn: sqlite3.Connection | None = None


def _get_db_url() -> str | None:
    if "DATABASE_URL" in os.environ:
        url = os.environ.get("DATABASE_URL", "")
    else:
        try:
            url = get_settings().database_url or ""
        except Exception:
            url = ""
    return url.strip() if url and url.strip() else None


def is_postgres() -> bool:
    db_url = _get_db_url()
    if not db_url or not HAS_PSYCOPG2:
        return False
    return db_url.startswith("postgresql://") or db_url.startswith("postgres://")


def _get_sqlite_connection() -> sqlite3.Connection:
    global _sqlite_conn
    if _sqlite_conn is None:
        _sqlite_conn = sqlite3.connect(":memory:", check_same_thread=False)
        _sqlite_conn.row_factory = sqlite3.Row
        _init_sqlite_schema(_sqlite_conn)
    return _sqlite_conn


def _get_pg_connection():
    db_url = _get_db_url()
    if not db_url or not HAS_PSYCOPG2:
        raise RuntimeError("PostgreSQL database URL is not configured or psycopg2 is not installed.")
    try:
        conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
        return conn
    except Exception as exc:
        logger.error("Failed to connect to PostgreSQL database: %s", exc)
        raise RuntimeError("Database connection error. Please verify database configuration.") from None


def _init_sqlite_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS completed_cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            severity TEXT NOT NULL,
            classification TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            analyst_notes TEXT,
            investigation_data TEXT NOT NULL
        )
        """
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_subject ON completed_cases(subject)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_sender ON completed_cases(sender)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_classif ON completed_cases(classification)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON completed_cases(status)")
    conn.commit()


def _init_pg_schema(conn) -> None:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS completed_cases (
                id VARCHAR(128) PRIMARY KEY,
                title VARCHAR(512) NOT NULL,
                subject VARCHAR(512) NOT NULL,
                sender VARCHAR(256) NOT NULL,
                recipient VARCHAR(256) NOT NULL,
                severity VARCHAR(64) NOT NULL,
                classification VARCHAR(64) NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence VARCHAR(64) NOT NULL,
                status VARCHAR(64) NOT NULL,
                created_at VARCHAR(128) NOT NULL,
                updated_at VARCHAR(128) NOT NULL,
                source_ip VARCHAR(128) NOT NULL,
                analyst_notes TEXT,
                investigation_data JSONB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_completed_cases_subject ON completed_cases (subject);
            CREATE INDEX IF NOT EXISTS idx_completed_cases_sender ON completed_cases (sender);
            CREATE INDEX IF NOT EXISTS idx_completed_cases_classification ON completed_cases (classification);
            CREATE INDEX IF NOT EXISTS idx_completed_cases_status ON completed_cases (status);
            CREATE INDEX IF NOT EXISTS idx_completed_cases_created_at ON completed_cases (created_at DESC);
            """
        )
        conn.commit()


def init_db() -> None:
    """Initialize database tables and indices."""
    if is_postgres():
        try:
            conn = _get_pg_connection()
            try:
                _init_pg_schema(conn)
            finally:
                conn.close()
        except Exception as exc:
            logger.error("Failed to initialize PostgreSQL schema: %s", exc)
    else:
        conn = _get_sqlite_connection()
        _init_sqlite_schema(conn)


# Initialize schema on module load if possible
try:
    init_db()
except Exception:
    pass


def reset_db_for_testing() -> None:
    """Helper method for unit tests to clear stored cases."""
    global _sqlite_conn
    if is_postgres():
        conn = _get_pg_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("TRUNCATE TABLE completed_cases;")
                conn.commit()
        finally:
            conn.close()
    else:
        if _sqlite_conn is not None:
            cursor = _sqlite_conn.cursor()
            cursor.execute("DELETE FROM completed_cases;")
            _sqlite_conn.commit()


def save_case(case_dict: dict[str, Any]) -> dict[str, Any]:
    """Insert or update a completed case in database."""
    case_id = case_dict["id"]
    title = case_dict.get("title", "")
    subject = case_dict.get("subject", "")
    sender = case_dict.get("sender", "")
    recipient = case_dict.get("recipient", "")
    severity = case_dict.get("severity", "LOW")
    classification = case_dict.get("classification", "unclassified")
    risk_score = int(case_dict.get("riskScore", 0))
    confidence = case_dict.get("confidence", "medium")
    status = case_dict.get("status", "OPEN")
    created_at = case_dict.get("createdAt", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    updated_at = case_dict.get("updatedAt", created_at)
    source_ip = case_dict.get("sourceIp", "Unavailable")
    analyst_notes = case_dict.get("analystNotes")
    
    inv_data = case_dict.get("investigationData")
    if isinstance(inv_data, dict):
        inv_data_str = json.dumps(inv_data)
    elif isinstance(inv_data, str):
        inv_data_str = inv_data
    else:
        inv_data_str = json.dumps({})

    if is_postgres():
        conn = _get_pg_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO completed_cases (
                        id, title, subject, sender, recipient, severity, classification,
                        risk_score, confidence, status, created_at, updated_at, source_ip,
                        analyst_notes, investigation_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (id) DO UPDATE SET
                        title = EXCLUDED.title,
                        subject = EXCLUDED.subject,
                        sender = EXCLUDED.sender,
                        recipient = EXCLUDED.recipient,
                        severity = EXCLUDED.severity,
                        classification = EXCLUDED.classification,
                        risk_score = EXCLUDED.risk_score,
                        confidence = EXCLUDED.confidence,
                        status = EXCLUDED.status,
                        created_at = EXCLUDED.created_at,
                        updated_at = EXCLUDED.updated_at,
                        source_ip = EXCLUDED.source_ip,
                        analyst_notes = EXCLUDED.analyst_notes,
                        investigation_data = EXCLUDED.investigation_data;
                    """,
                    (
                        case_id, title, subject, sender, recipient, severity, classification,
                        risk_score, confidence, status, created_at, updated_at, source_ip,
                        analyst_notes, inv_data_str,
                    ),
                )
                conn.commit()
        finally:
            conn.close()
    else:
        conn = _get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO completed_cases (
                id, title, subject, sender, recipient, severity, classification,
                risk_score, confidence, status, created_at, updated_at, source_ip,
                analyst_notes, investigation_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id, title, subject, sender, recipient, severity, classification,
                risk_score, confidence, status, created_at, updated_at, source_ip,
                analyst_notes, inv_data_str,
            ),
        )
        conn.commit()

    return get_case_by_id(case_id) or case_dict


def get_case_by_id(case_id: str) -> dict[str, Any] | None:
    """Retrieve a single completed case by ID."""
    if is_postgres():
        conn = _get_pg_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM completed_cases WHERE LOWER(id) = LOWER(%s)", (case_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return None
                row_dict = dict(row)
        finally:
            conn.close()
    else:
        conn = _get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM completed_cases WHERE LOWER(id) = LOWER(?)", (case_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        row_dict = dict(row)

    inv_raw = row_dict["investigation_data"]
    if isinstance(inv_raw, dict):
        inv_data = inv_raw
    elif isinstance(inv_raw, str):
        try:
            inv_data = json.loads(inv_raw)
        except Exception:
            inv_data = {}
    else:
        inv_data = {}

    return {
        "id": row_dict["id"],
        "title": row_dict["title"],
        "subject": row_dict["subject"],
        "sender": row_dict["sender"],
        "recipient": row_dict["recipient"],
        "severity": row_dict["severity"],
        "classification": row_dict["classification"],
        "riskScore": row_dict["risk_score"],
        "confidence": row_dict["confidence"],
        "status": row_dict["status"],
        "createdAt": row_dict["created_at"],
        "updatedAt": row_dict["updated_at"],
        "sourceIp": row_dict["source_ip"],
        "analystNotes": row_dict.get("analyst_notes"),
        "investigationData": inv_data,
    }


def list_cases(
    search: str | None = None,
    verdict: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """List completed cases with optional search and verdict filtering."""
    if is_postgres():
        conn = _get_pg_connection()
        try:
            with conn.cursor() as cursor:
                query = "SELECT * FROM completed_cases WHERE 1=1"
                params: list[Any] = []

                if verdict and verdict.lower() != "all":
                    query += " AND LOWER(classification) = LOWER(%s)"
                    params.append(verdict.strip())

                if status and status.lower() != "all":
                    query += " AND LOWER(status) = LOWER(%s)"
                    params.append(status.strip())

                if search and search.strip():
                    term = f"%{search.strip().lower()}%"
                    query += " AND (LOWER(subject) LIKE %s OR LOWER(sender) LIKE %s OR LOWER(title) LIKE %s OR LOWER(source_ip) LIKE %s OR investigation_data::text ILIKE %s)"
                    params.extend([term, term, term, term, term])

                query += " ORDER BY created_at DESC"
                cursor.execute(query, params)
                rows = cursor.fetchall() or []
                rows_dicts = [dict(r) for r in rows]
        finally:
            conn.close()
    else:
        conn = _get_sqlite_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM completed_cases WHERE 1=1"
        params: list[Any] = []

        if verdict and verdict.lower() != "all":
            query += " AND LOWER(classification) = LOWER(?)"
            params.append(verdict.strip())

        if status and status.lower() != "all":
            query += " AND LOWER(status) = LOWER(?)"
            params.append(status.strip())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query += " AND (LOWER(subject) LIKE ? OR LOWER(sender) LIKE ? OR LOWER(title) LIKE ? OR LOWER(source_ip) LIKE ? OR LOWER(investigation_data) LIKE ?)"
            params.extend([term, term, term, term, term])

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall() or []
        rows_dicts = [dict(r) for r in rows]

    result = []
    for r in rows_dicts:
        inv_raw = r["investigation_data"]
        if isinstance(inv_raw, dict):
            inv_data = inv_raw
        elif isinstance(inv_raw, str):
            try:
                inv_data = json.loads(inv_raw)
            except Exception:
                inv_data = {}
        else:
            inv_data = {}

        result.append({
            "id": r["id"],
            "title": r["title"],
            "subject": r["subject"],
            "sender": r["sender"],
            "recipient": r["recipient"],
            "severity": r["severity"],
            "classification": r["classification"],
            "riskScore": r["risk_score"],
            "confidence": r["confidence"],
            "status": r["status"],
            "createdAt": r["created_at"],
            "updatedAt": r["updated_at"],
            "sourceIp": r["source_ip"],
            "analystNotes": r.get("analyst_notes"),
            "investigationData": inv_data,
        })
    return result


def update_case_status(case_id: str, new_status: str) -> bool:
    """Update workflow status of a case."""
    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if is_postgres():
        conn = _get_pg_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE completed_cases SET status = %s, updated_at = %s WHERE LOWER(id) = LOWER(%s)",
                    (new_status, updated_at, case_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        finally:
            conn.close()
    else:
        conn = _get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE completed_cases SET status = ?, updated_at = ? WHERE LOWER(id) = LOWER(?)",
            (new_status, updated_at, case_id),
        )
        conn.commit()
        return cursor.rowcount > 0
