"""
db.py — SQLite schema and query functions.

All external database access goes through this module.
All queries use parameterised statements — no string interpolation.

The database file lives at data/security_automation.db by default.
Override with the DB_PATH environment variable (useful for tests).

Thread safety: each function opens and closes its own connection.
SQLite WAL mode allows concurrent reads during a write.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(os.environ.get("DB_PATH", "data/security_automation.db"))


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


def _make_connection(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")  # wait up to 5s on lock
    return conn


@contextmanager
def get_conn(path: Path | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager: open a connection, commit on success, rollback on error."""
    conn = _make_connection(path or _DEFAULT_DB_PATH)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS news_items (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    url               TEXT    NOT NULL,
    url_hash          TEXT    NOT NULL UNIQUE,
    title             TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    published_at      TEXT,
    fetched_at        TEXT    NOT NULL,
    content           TEXT,
    summary           TEXT,
    category          TEXT,
    severity          TEXT,
    affected_products TEXT,
    tags              TEXT,
    cluster_id        TEXT,
    raw_entry         TEXT
);

CREATE INDEX IF NOT EXISTS idx_news_fetched   ON news_items(fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_category  ON news_items(category);
CREATE INDEX IF NOT EXISTS idx_news_severity  ON news_items(severity);
CREATE INDEX IF NOT EXISTS idx_news_cluster   ON news_items(cluster_id);
CREATE INDEX IF NOT EXISTS idx_news_source    ON news_items(source);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_full_name      TEXT    NOT NULL,
    cve_id              TEXT,
    ghsa_id             TEXT,
    package_name        TEXT    NOT NULL,
    package_ecosystem   TEXT    NOT NULL,
    installed_version   TEXT,
    fixed_version       TEXT,
    cvss_score          REAL,
    is_kev              INTEGER NOT NULL DEFAULT 0,
    patch_available     INTEGER NOT NULL DEFAULT 0,
    priority_score      REAL,
    state               TEXT    NOT NULL DEFAULT 'new',
    first_seen_at       TEXT    NOT NULL,
    last_seen_at        TEXT    NOT NULL,
    resolved_at         TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_repo   ON findings(repo_full_name);
CREATE INDEX IF NOT EXISTS idx_findings_state  ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_cve    ON findings(cve_id);

-- Expression index for deduplication — COALESCE is valid in indexes (SQLite 3.9+)
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique
    ON findings(repo_full_name, package_name, package_ecosystem,
                COALESCE(cve_id, ''), COALESCE(ghsa_id, ''));

CREATE TABLE IF NOT EXISTS run_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at        TEXT    NOT NULL,
    completed_at      TEXT,
    status            TEXT    NOT NULL DEFAULT 'running',
    items_collected   INTEGER NOT NULL DEFAULT 0,
    items_categorized INTEGER NOT NULL DEFAULT 0,
    findings_new      INTEGER NOT NULL DEFAULT 0,
    findings_total    INTEGER NOT NULL DEFAULT 0,
    error_message     TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def init(path: Path | None = None) -> None:
    """Create all tables and apply migrations. Safe to call on every startup."""
    db_path = path or _DEFAULT_DB_PATH
    with get_conn(db_path) as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)
    logger.info("Database ready at %s", db_path)


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced in later milestones. Each ALTER is idempotent."""
    existing = {
        row[1]
        for row in conn.execute("PRAGMA table_info(findings)").fetchall()
    }
    # M3 columns
    if "manifest_path" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN manifest_path TEXT")
    if "ai_next_steps" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN ai_next_steps TEXT")
    # M4 columns
    if "notified_at" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN notified_at TEXT")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def url_hash(url: str) -> str:
    """SHA-256 of the URL, hex-encoded. Used as the deduplication key."""
    return hashlib.sha256(url.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def _json_loads(value: str | None) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


# ---------------------------------------------------------------------------
# News items
# ---------------------------------------------------------------------------


def insert_news_item(conn: sqlite3.Connection, item: dict) -> bool:
    """Insert a news item. Returns True if inserted, False if already exists (dedup)."""
    h = url_hash(item["url"])
    existing = conn.execute(
        "SELECT id FROM news_items WHERE url_hash = ?", (h,)
    ).fetchone()
    if existing:
        return False

    conn.execute(
        """
        INSERT INTO news_items
            (url, url_hash, title, source, published_at, fetched_at,
             content, summary, category, severity,
             affected_products, tags, cluster_id, raw_entry)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item["url"],
            h,
            item["title"],
            item["source"],
            item.get("published_at"),
            item.get("fetched_at", _now()),
            item.get("content"),
            item.get("summary"),
            item.get("category"),
            item.get("severity"),
            _json_dumps(item.get("affected_products")),
            _json_dumps(item.get("tags")),
            item.get("cluster_id"),
            _json_dumps(item.get("raw_entry")),
        ),
    )
    return True


def get_uncategorized_items(
    conn: sqlite3.Connection, limit: int = 50
) -> list[sqlite3.Row]:
    """Return news items that have not yet been categorized (category IS NULL)."""
    return conn.execute(
        """
        SELECT id, title, content, source, url
        FROM news_items
        WHERE category IS NULL
        ORDER BY fetched_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def update_item_categorization(
    conn: sqlite3.Connection,
    item_id: int,
    *,
    summary: str,
    category: str,
    severity: str,
    affected_products: list[str],
    tags: list[str],
    cluster_id: str | None,
) -> None:
    """Write categorization results back to a news item."""
    conn.execute(
        """
        UPDATE news_items
        SET summary = ?, category = ?, severity = ?,
            affected_products = ?, tags = ?, cluster_id = ?
        WHERE id = ?
        """,
        (
            summary,
            category,
            severity,
            _json_dumps(affected_products),
            _json_dumps(tags),
            cluster_id,
            item_id,
        ),
    )


def get_recent_items(
    conn: sqlite3.Connection, *, hours: int = 24, limit: int = 200
) -> list[sqlite3.Row]:
    """Return recently fetched items for the dashboard feed view."""
    return conn.execute(
        """
        SELECT id, title, source, published_at, fetched_at,
               summary, category, severity, affected_products, tags, cluster_id, url
        FROM news_items
        WHERE fetched_at >= datetime('now', ? || ' hours')
        ORDER BY fetched_at DESC
        LIMIT ?
        """,
        (f"-{hours}", limit),
    ).fetchall()


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------


def start_run(conn: sqlite3.Connection) -> int:
    """Insert a run_log row with status='running'. Returns the new run id."""
    cur = conn.execute(
        "INSERT INTO run_log (started_at, status) VALUES (?, 'running')",
        (_now(),),
    )
    return cur.lastrowid  # type: ignore[return-value]


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str,
    items_collected: int = 0,
    items_categorized: int = 0,
    findings_new: int = 0,
    findings_total: int = 0,
    error_message: str | None = None,
) -> None:
    """Mark a run as complete with final statistics."""
    conn.execute(
        """
        UPDATE run_log
        SET completed_at = ?, status = ?,
            items_collected = ?, items_categorized = ?,
            findings_new = ?, findings_total = ?,
            error_message = ?
        WHERE id = ?
        """,
        (
            _now(),
            status,
            items_collected,
            items_categorized,
            findings_new,
            findings_total,
            error_message,
            run_id,
        ),
    )


def get_last_successful_run(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """Return the most recent successful run, or None if none exist."""
    return conn.execute(
        "SELECT * FROM run_log WHERE status = 'success' ORDER BY completed_at DESC LIMIT 1"
    ).fetchone()


# ---------------------------------------------------------------------------
# Settings (key/value preferences)
# ---------------------------------------------------------------------------


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    """Read a preference value from the settings table."""
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Write (upsert) a preference value."""
    conn.execute(
        """
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, _now()),
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def upsert_finding(conn: sqlite3.Connection, finding: dict) -> bool:
    """Insert a new finding or refresh an existing one.

    Returns True if this is a brand-new finding (triggers notification in M4).
    For existing findings the last_seen_at and vulnerability data are updated;
    the state is NOT changed here — lifecycle.py (M4) owns state transitions.
    """
    existing = conn.execute(
        """
        SELECT id, state FROM findings
        WHERE repo_full_name      = ?
          AND package_name        = ?
          AND package_ecosystem   = ?
          AND COALESCE(cve_id,  '') = COALESCE(?, '')
          AND COALESCE(ghsa_id, '') = COALESCE(?, '')
        """,
        (
            finding["repo_full_name"],
            finding["package_name"],
            finding["package_ecosystem"],
            finding.get("cve_id"),
            finding.get("ghsa_id"),
        ),
    ).fetchone()

    if existing is None:
        conn.execute(
            """
            INSERT INTO findings (
                repo_full_name, cve_id, ghsa_id,
                package_name, package_ecosystem,
                installed_version, fixed_version,
                cvss_score, is_kev, patch_available, priority_score,
                state, first_seen_at, last_seen_at,
                manifest_path, ai_next_steps
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                finding["repo_full_name"],
                finding.get("cve_id"),
                finding.get("ghsa_id"),
                finding["package_name"],
                finding["package_ecosystem"],
                finding.get("installed_version"),
                finding.get("fixed_version"),
                finding.get("cvss_score"),
                1 if finding.get("is_kev") else 0,
                1 if finding.get("patch_available") else 0,
                finding.get("priority_score"),
                "new",
                _now(),
                _now(),
                finding.get("manifest_path"),
                None,
            ),
        )
        return True

    # Refresh mutable fields; leave state and first_seen_at alone
    conn.execute(
        """
        UPDATE findings SET
            last_seen_at      = ?,
            installed_version = ?,
            fixed_version     = ?,
            cvss_score        = ?,
            is_kev            = ?,
            patch_available   = ?,
            priority_score    = ?,
            manifest_path     = ?
        WHERE id = ?
        """,
        (
            _now(),
            finding.get("installed_version"),
            finding.get("fixed_version"),
            finding.get("cvss_score"),
            1 if finding.get("is_kev") else 0,
            1 if finding.get("patch_available") else 0,
            finding.get("priority_score"),
            finding.get("manifest_path"),
            existing["id"],
        ),
    )
    return False


def update_finding_next_steps(
    conn: sqlite3.Connection, finding_id: int, next_steps: dict
) -> None:
    """Store AI-generated next steps JSON for a finding."""
    conn.execute(
        "UPDATE findings SET ai_next_steps = ? WHERE id = ?",
        (_json_dumps(next_steps), finding_id),
    )


def get_findings(
    conn: sqlite3.Connection,
    *,
    state: str | None = None,
    repo: str | None = None,
    limit: int = 500,
) -> list[sqlite3.Row]:
    """Return findings, optionally filtered by state and/or repo."""
    clauses = []
    params: list[Any] = []
    if state:
        clauses.append("state = ?")
        params.append(state)
    if repo:
        clauses.append("repo_full_name = ?")
        params.append(repo)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return conn.execute(
        f"SELECT * FROM findings {where} ORDER BY priority_score DESC NULLS LAST LIMIT ?",
        params,
    ).fetchall()


def get_new_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all findings currently in 'new' state."""
    return conn.execute(
        "SELECT * FROM findings WHERE state = 'new' ORDER BY priority_score DESC NULLS LAST"
    ).fetchall()


def get_kev_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of CVE IDs present in the CISA KEV (from news_items)."""
    rows = conn.execute(
        "SELECT url FROM news_items WHERE source = 'CISA KEV'"
    ).fetchall()
    result = set()
    for row in rows:
        url = row["url"] or ""
        if "#" in url:
            result.add(url.split("#")[-1].upper())
    return result


def get_unnotified_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return new findings that have not yet been notified (notified_at IS NULL).

    These are the delta — exactly the findings that should trigger an alert.
    After sending the alert, call mark_findings_notified() with these IDs.
    """
    return conn.execute(
        """
        SELECT * FROM findings
        WHERE state = 'new' AND notified_at IS NULL
        ORDER BY priority_score DESC NULLS LAST
        """
    ).fetchall()


def mark_findings_notified(
    conn: sqlite3.Connection, finding_ids: list[int]
) -> None:
    """Stamp notified_at on findings that were successfully delivered."""
    if not finding_ids:
        return
    placeholders = ",".join("?" * len(finding_ids))
    conn.execute(
        f"UPDATE findings SET notified_at = ? WHERE id IN ({placeholders})",
        [_now(), *finding_ids],
    )
