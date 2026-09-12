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
    source_ip = case_dict.get("sourceIp") or "Unavailable"
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


def _add_case_numbers(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deprecated: Sequence numbering removed per requirement."""
    return cases


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

    ai_inv = inv_data.get("ai_investigation")
    if isinstance(ai_inv, dict) and (
        ai_inv.get("source") == "deterministic_fallback"
        or ai_inv.get("provider") == "deterministic_fallback"
    ):
        inv_data["ai_investigation"] = None

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

        ai_inv = inv_data.get("ai_investigation")
        if isinstance(ai_inv, dict) and (
            ai_inv.get("source") == "deterministic_fallback"
            or ai_inv.get("provider") == "deterministic_fallback"
        ):
            inv_data["ai_investigation"] = None

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


def find_historical_matches(
    email_from: str | None = None,
    source_ip: str | None = None,
    urls: list[str] | None = None,
    domains: list[str] | None = None,
    attachment_hashes: list[str] | None = None,
    current_case_id: str | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """
    Search stored completed cases for historical indicator overlap:
    - sender email / sender domain
    - originating source IP
    - shared URLs / domains
    - shared attachment SHA-256 hashes
    """
    all_cases = list_cases()
    if not all_cases:
        return []

    curr_sender = (email_from or "").strip().lower()
    curr_domain = curr_sender.split("@")[-1] if "@" in curr_sender else ""
    curr_ip = (source_ip or "").strip()
    curr_urls = set(u.strip().lower() for u in (urls or []))
    curr_domains = set(d.strip().lower() for d in (domains or []))
    curr_hashes = set(h.strip().lower() for h in (attachment_hashes or []))
    generic_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"}

    matches = []
    for c in all_cases:
        cid = c.get("id")
        if current_case_id and cid and cid.lower() == current_case_id.lower():
            continue

        reasons = []
        matching_indicators = []

        # 1. Source IP match
        c_ip = (c.get("sourceIp") or "").strip()
        if curr_ip and c_ip and c_ip.lower() not in {"unavailable", "none", ""} and c_ip.lower() == curr_ip.lower():
            matching_indicators.append("source_ip")
            reasons.append(f"Shares originating source IP {curr_ip}")

        # 2. Sender match
        c_sender = (c.get("sender") or "").strip().lower()
        if curr_sender and c_sender and c_sender == curr_sender:
            matching_indicators.append("sender")
            reasons.append(f"Shares exact sender email address {curr_sender}")

        # 3. Sender domain match
        c_domain = c_sender.split("@")[-1] if "@" in c_sender else ""
        if curr_domain and c_domain and curr_domain not in generic_domains and curr_domain == c_domain and "sender" not in matching_indicators:
            matching_indicators.append("sender_domain")
            reasons.append(f"Shares sender domain {curr_domain}")

        # 4. Shared URL/domain match in investigationData
        inv_data = c.get("investigationData") or {}
        c_inv_urls = set()
        c_inv_domains = set()

        if isinstance(inv_data, dict):
            for obs in inv_data.get("observables", []):
                val = (obs.get("value") or "").strip().lower()
                otype = (obs.get("type") or "").lower()
                if otype == "url" and val:
                    c_inv_urls.add(val)
                elif otype == "domain" and val:
                    c_inv_domains.add(val)

        shared_urls = curr_urls.intersection(c_inv_urls)
        if shared_urls:
            matching_indicators.append("shared_url")
            reasons.append(f"Shares URL observable: {list(shared_urls)[0]}")

        shared_domains = curr_domains.intersection(c_inv_domains) - generic_domains
        if shared_domains and "sender_domain" not in matching_indicators:
            matching_indicators.append("shared_domain")
            reasons.append(f"Shares domain observable: {list(shared_domains)[0]}")

        # 5. Shared attachment hash
        if curr_hashes and isinstance(inv_data, dict):
            for att in inv_data.get("attachments", []):
                h = (att.get("sha256") or "").strip().lower()
                if h and h in curr_hashes:
                    matching_indicators.append("shared_attachment_hash")
                    reasons.append(f"Shares matching attachment SHA-256 hash ({h[:12]}...)")

        if matching_indicators:
            matches.append({
                "case_id": cid,
                "title": c.get("title") or c.get("subject") or "Historical Investigation",
                "classification": c.get("classification", "unknown"),
                "severity": c.get("severity", "LOW"),
                "date": c.get("createdAt"),
                "matching_indicators": matching_indicators,
                "explanation": "; ".join(reasons),
            })

        if len(matches) >= limit:
            break

    return matches
