"""
db.py — SQLite database layer for MailGuard AI.
Auto-initialises the schema on first import. No manual setup required.
"""

from __future__ import annotations
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
import shutil
import tempfile

def _get_db_path() -> Path:
    env_path = os.getenv("DB_PATH")
    if env_path:
        return Path(env_path).resolve()

    # Vercel and AWS Lambda serverless read-only filesystem check
    is_serverless = bool(
        os.getenv("VERCEL")
        or os.getenv("VERCEL_ENV")
        or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
    )

    bundled_db = Path(__file__).resolve().parent / "data" / "mailguard.db"

    if is_serverless:
        tmp_db = Path(tempfile.gettempdir()) / "mailguard.db"
        if not tmp_db.exists() and bundled_db.exists():
            try:
                shutil.copy2(bundled_db, tmp_db)
            except Exception:
                pass
        return tmp_db

    # Local environment
    try:
        bundled_db.parent.mkdir(parents=True, exist_ok=True)
        # Test if writable
        test_file = bundled_db.parent / ".write_test"
        test_file.touch()
        test_file.unlink()
        return bundled_db
    except (OSError, PermissionError):
        # Fallback to temp directory if project folder is read-only
        tmp_db = Path(tempfile.gettempdir()) / "mailguard.db"
        if not tmp_db.exists() and bundled_db.exists():
            try:
                shutil.copy2(bundled_db, tmp_db)
            except Exception:
                pass
        return tmp_db

DB_PATH = _get_db_path()

# Cache the serverless flag for use in _ensure_db_initialized
_IS_SERVERLESS = bool(
    os.getenv("VERCEL")
    or os.getenv("VERCEL_ENV")
    or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
)

# Thread-local storage for connections (safe under uvicorn workers)
_local = threading.local()
_init_lock = threading.Lock()
_is_initialized = False


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    subject     TEXT DEFAULT '',
    from_address TEXT DEFAULT '',
    reply_to    TEXT DEFAULT '',
    sender_ip   TEXT DEFAULT '',
    headers     TEXT DEFAULT '',
    body        TEXT DEFAULT '',
    score       INTEGER DEFAULT 0,
    verdict     TEXT DEFAULT 'SAFE',
    category    TEXT DEFAULT 'UNKNOWN',
    confidence  REAL DEFAULT 0.0,
    reasons     TEXT DEFAULT '[]',
    breakdown   TEXT DEFAULT '{}',
    checks      TEXT DEFAULT '[]',
    geo         TEXT DEFAULT '{}',
    forensics   TEXT DEFAULT '{}',
    recommended_action TEXT DEFAULT '',
    status      TEXT DEFAULT 'new',
    decision    TEXT DEFAULT '{}',
    timeline    TEXT DEFAULT '[]'
);
"""


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------
def _ensure_writable(path: Path) -> None:
    """Ensure directory and file have write permissions."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            import stat
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass


def _get_conn() -> sqlite3.Connection:
    """Return a per-thread SQLite connection, creating it if needed."""
    if not hasattr(_local, "conn") or _local.conn is None:
        db_path = _get_db_path()
        _ensure_writable(db_path)
        _ensure_db_initialized()
        conn = sqlite3.connect(str(db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return _local.conn


def _ensure_db_initialized() -> None:
    """One-time thread-safe database schema initialization."""
    global _is_initialized
    if _is_initialized:
        return
    with _init_lock:
        if _is_initialized:
            return
        db_path = _get_db_path()
        _ensure_writable(db_path)
        conn = sqlite3.connect(str(db_path), timeout=30.0, check_same_thread=False)
        try:
            try:
                # WAL mode requires shared-memory files (.db-shm/.db-wal) which
                # are unreliable on Vercel's ephemeral /tmp — force DELETE on serverless.
                if _IS_SERVERLESS:
                    conn.execute("PRAGMA journal_mode=DELETE")
                else:
                    conn.execute("PRAGMA journal_mode=WAL")
            except Exception:
                conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(_SCHEMA)
            for col, col_def in [("decision", "TEXT DEFAULT '{}'"), ("timeline", "TEXT DEFAULT '[]'")]:
                try:
                    conn.execute(f"ALTER TABLE emails ADD COLUMN {col} {col_def}")
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()
        _is_initialized = True


def init_db() -> None:
    """Create the schema if it does not already exist."""
    _ensure_db_initialized()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _j(val: Any) -> str:
    """Serialize to JSON string."""
    return json.dumps(val, ensure_ascii=False)


def _dj(val: str) -> Any:
    """Deserialize from JSON string, returning empty structure on failure."""
    try:
        return json.loads(val) if val else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for field in ("reasons", "breakdown", "checks", "geo", "forensics", "timeline"):
        raw = d.get(field)
        d[field] = json.loads(raw) if raw else ({} if field in ("breakdown", "geo", "forensics", "decision") else [])
    # Handle decision separately (dict)
    raw_dec = d.get("decision")
    d["decision"] = json.loads(raw_dec) if raw_dec else {}
    return d


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------
def insert_email(record: Dict[str, Any]) -> None:
    """Insert a fully-built analysis record."""
    conn = _get_conn()
    # Add new columns if they don't exist (migration for existing DB)
    try:
        conn.execute("ALTER TABLE emails ADD COLUMN decision TEXT DEFAULT '{}'")
        conn.commit()
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE emails ADD COLUMN timeline TEXT DEFAULT '[]'")
        conn.commit()
    except Exception:
        pass

    conn.execute(
        """
        INSERT INTO emails
            (id, timestamp, subject, from_address, reply_to, sender_ip, headers, body,
             score, verdict, category, confidence,
             reasons, breakdown, checks, geo, forensics,
             recommended_action, status, decision, timeline)
        VALUES
            (:id, :timestamp, :subject, :from_address, :reply_to, :sender_ip, :headers, :body,
             :score, :verdict, :category, :confidence,
             :reasons, :breakdown, :checks, :geo, :forensics,
             :recommended_action, :status, :decision, :timeline)
        """,
        {
            **record,
            "reasons":   _j(record.get("reasons",   [])),
            "breakdown": _j(record.get("breakdown",  {})),
            "checks":    _j(record.get("checks",     [])),
            "geo":       _j(record.get("geo",        {})),
            "forensics": _j(record.get("forensics",  {})),
            "decision":  _j(record.get("decision",   {})),
            "timeline":  _j(record.get("timeline",   [])),
        },
    )
    conn.commit()


def get_email(email_id: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM emails WHERE id = ?", (email_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_emails(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM emails ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_status(email_id: str, status: str) -> bool:
    conn = _get_conn()
    cur = conn.execute(
        "UPDATE emails SET status = ? WHERE id = ?",
        (status, email_id),
    )
    conn.commit()
    return cur.rowcount > 0


def count_emails() -> int:
    conn = _get_conn()
    return conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]


def dashboard_stats() -> Dict[str, Any]:
    conn = _get_conn()

    total     = conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
    safe      = conn.execute("SELECT COUNT(*) FROM emails WHERE verdict='SAFE'").fetchone()[0]
    susp      = conn.execute("SELECT COUNT(*) FROM emails WHERE verdict='SUSPICIOUS'").fetchone()[0]
    high      = conn.execute("SELECT COUNT(*) FROM emails WHERE verdict='HIGH_RISK'").fetchone()[0]
    critical  = conn.execute("SELECT COUNT(*) FROM emails WHERE verdict='CRITICAL'").fetchone()[0]
    quarantined = conn.execute(
        """SELECT COUNT(*) FROM emails 
           WHERE status='quarantined' 
              OR decision LIKE '%"action": "QUARANTINE"%' 
              OR decision LIKE '%"action":"QUARANTINE"%'"""
    ).fetchone()[0]
    blocked = conn.execute(
        """SELECT COUNT(*) FROM emails 
           WHERE score >= 80 
              OR decision LIKE '%"action": "BLOCK"%' 
              OR decision LIKE '%"action":"BLOCK"%'"""
    ).fetchone()[0]

    threat_pct = round(((susp + high + critical) / total * 100), 1) if total else 0.0

    # Recent 10
    recent_rows = conn.execute(
        """SELECT id, timestamp, subject, from_address, score, verdict,
                  category, confidence, status
           FROM emails ORDER BY timestamp DESC LIMIT 10"""
    ).fetchall()
    recent = [dict(r) for r in recent_rows]

    # By category
    cat_rows = conn.execute(
        "SELECT category, COUNT(*) as cnt FROM emails GROUP BY category"
    ).fetchall()
    by_category = {r["category"]: r["cnt"] for r in cat_rows}

    # By verdict
    verd_rows = conn.execute(
        "SELECT verdict, COUNT(*) as cnt FROM emails GROUP BY verdict"
    ).fetchall()
    by_verdict = {r["verdict"]: r["cnt"] for r in verd_rows}

    # By day (last 14 days)
    day_rows = conn.execute(
        """SELECT substr(timestamp,1,10) as day, COUNT(*) as cnt
           FROM emails
           WHERE timestamp >= datetime('now','-14 days')
           GROUP BY day ORDER BY day"""
    ).fetchall()
    by_day = {r["day"]: r["cnt"] for r in day_rows}

    # Top sender domains — cleanly extracted without < > " or whitespace
    domain_rows = conn.execute(
        """SELECT from_address, COUNT(*) as cnt
           FROM emails
           WHERE from_address IS NOT NULL AND from_address != ''
           GROUP BY from_address
           ORDER BY cnt DESC"""
    ).fetchall()

    import re
    domain_counts: Dict[str, int] = {}
    domain_re = re.compile(r"@([a-zA-Z0-9.\-]+)")
    for r in domain_rows:
        addr = r["from_address"] or ""
        match = domain_re.search(addr)
        domain = match.group(1).lower().strip(">\"' ") if match else addr.strip("<>\"' ")
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + r["cnt"]

    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_domains = [[d, count] for d, count in top_domains]

    return {
        "total": total,
        "safe": safe,
        "suspicious": susp,
        "high_risk": high,
        "critical": critical,
        "quarantined": quarantined,
        "blocked": blocked,
        "threat_percentage": threat_pct,
        "recent": recent,
        "by_category": by_category,
        "by_verdict": by_verdict,
        "by_day": by_day,
        "top_domains": top_domains,
    }
