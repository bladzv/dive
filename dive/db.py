"""
db.py — SQLite schema and query functions.

All external database access goes through this module.
All queries use parameterised statements — no string interpolation.

The database file lives at data/dive.db by default.
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
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(os.environ.get("DB_PATH", "data/dive.db"))


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
-- Matches get_news()'s ORDER BY COALESCE(published_at, fetched_at) exactly —
-- an expression index only serves a query whose ORDER BY/WHERE expression
-- matches it verbatim, and this is DIVE's most-hit paginated list query.
CREATE INDEX IF NOT EXISTS idx_news_published_coalesce
    ON news_items(COALESCE(published_at, fetched_at));

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
-- Every findings list/export/get_new_findings query sorts by this; without
-- an index each paginated page is a full table scan + sort.
CREATE INDEX IF NOT EXISTS idx_findings_priority  ON findings(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_firstseen ON findings(first_seen_at);
-- idx_findings_notified is created in _migrate(), after the notified_at
-- column it indexes is added (that column isn't in the base schema).

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

CREATE TABLE IF NOT EXISTS log_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    level       TEXT    NOT NULL,
    logger_name TEXT    NOT NULL,
    message     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_ts    ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_log_level ON log_entries(level);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_full_name  TEXT    NOT NULL,
    file_path       TEXT    NOT NULL,
    line_number     INTEGER,
    commit_sha      TEXT    NOT NULL,
    secret_type     TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL,
    fingerprint     TEXT    NOT NULL UNIQUE,
    match_key       TEXT,
    state           TEXT    NOT NULL DEFAULT 'new',
    first_seen_at   TEXT    NOT NULL,
    last_seen_at    TEXT    NOT NULL,
    notified_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_secrets_repo  ON secret_findings(repo_full_name);
CREATE INDEX IF NOT EXISTS idx_secrets_state ON secret_findings(state);
-- Matches the default ORDER BY first_seen_at DESC on the secrets list.
CREATE INDEX IF NOT EXISTS idx_secrets_firstseen ON secret_findings(first_seen_at);

CREATE TABLE IF NOT EXISTS rss_feeds (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    url             TEXT    NOT NULL UNIQUE,
    enabled         INTEGER NOT NULL DEFAULT 1,
    is_default      INTEGER NOT NULL DEFAULT 0,
    last_fetched_at TEXT,
    item_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS keywords (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword    TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bookmarks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    news_item_id INTEGER NOT NULL UNIQUE REFERENCES news_items(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bookmarks_item ON bookmarks(news_item_id);

-- Persistent, retention-independent record of CISA KEV membership. Kept
-- separate from news_items so is_kev scoring never regresses when a user
-- prunes old news (news.retention_days) or clears news data.
CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id        TEXT PRIMARY KEY,
    added_at      TEXT,
    first_seen_at TEXT NOT NULL
);
"""


def init(path: Path | None = None) -> None:
    """Create all tables and apply migrations. Safe to call on every startup."""
    db_path = path or _DEFAULT_DB_PATH
    with get_conn(db_path) as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)
    logger.info("Database ready at %s", db_path)


# Bump when adding a new one-time DATA migration (a full-table dedup/backfill
# pass) — schema_version gates those so they run once ever, not on every
# startup. Idempotent structural changes (ALTER TABLE / CREATE INDEX IF NOT
# EXISTS) are cheap PRAGMA checks and always run regardless of this version.
_SCHEMA_VERSION = 1


def _get_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM settings WHERE key = 'schema_version'").fetchone()
    if not row:
        return 0
    try:
        return int(row["value"])
    except (TypeError, ValueError):
        return 0


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        """
        INSERT INTO settings (key, value, updated_at) VALUES ('schema_version', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (str(version), _now()),
    )


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced in later milestones. Each ALTER/CREATE INDEX
    guard below is a cheap, idempotent PRAGMA table_info check and always
    runs. One-time DATA migrations (full-table dedup/backfill passes) are
    gated by schema_version — see _SCHEMA_VERSION.
    """
    news_existing = {row[1] for row in conn.execute("PRAGMA table_info(news_items)").fetchall()}
    if "categorize_attempts" not in news_existing:
        conn.execute("ALTER TABLE news_items ADD COLUMN categorize_attempts INT NOT NULL DEFAULT 0")

    existing = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    # M3 columns
    if "manifest_path" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN manifest_path TEXT")
    if "ai_next_steps" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN ai_next_steps TEXT")
    # M4 columns
    if "notified_at" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN notified_at TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_notified ON findings(notified_at)")
    # M9 columns
    if "annotation" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN annotation TEXT")
    # M10 columns
    if "github_issue_url" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN github_issue_url TEXT")
    # Affected version range sourced directly from OSV/advisory data
    if "affected_versions" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN affected_versions TEXT")
    # Latest published version from package registry + OSV vulnerability count
    if "latest_version" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN latest_version TEXT")
    if "latest_version_vuln_count" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN latest_version_vuln_count INTEGER")

    _migrate_secret_findings_columns(conn)

    version = _get_schema_version(conn)
    if version < _SCHEMA_VERSION:
        _dedup_aliased_findings(conn)
        _migrate_secret_findings_backfill(conn)
        _migrate_default_feed_urls(conn)
        _set_schema_version(conn, _SCHEMA_VERSION)


def _migrate_secret_findings_columns(conn: sqlite3.Connection) -> None:
    """Add secret_findings.match_key if missing, and ensure its unique index
    exists. Always runs — cheap idempotent PRAGMA/CREATE INDEX checks, unlike
    the full-table backfill in _migrate_secret_findings_backfill().
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(secret_findings)").fetchall()}
    if "match_key" not in cols:
        conn.execute("ALTER TABLE secret_findings ADD COLUMN match_key TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_matchkey ON secret_findings(match_key)"
    )


def _migrate_secret_findings_backfill(conn: sqlite3.Connection) -> None:
    """One-time: backfill match_key on legacy rows and collapse duplicates
    that predate it (gated by schema_version — see _migrate()).

    gitleaks' Fingerprint embeds the commit SHA, which is unstable across
    shallow-clone runs (the boundary commit slides as new commits land), so
    the same real secret was previously re-inserted under a fresh
    fingerprint each run. match_key drops the commit so re-sightings update
    instead of duplicating. New rows always get match_key set at insert time
    (see upsert_secret_finding), so this never has work to do after the
    first run — hence gating it rather than re-scanning the table forever.
    """
    # Drop the uniqueness guard while reconciling so backfilling duplicate rows
    # to the same key doesn't trip it; it is recreated at the end.
    conn.execute("DROP INDEX IF EXISTS idx_secrets_matchkey")

    # Backfill any rows missing a match_key (new column or older rows).
    rows = conn.execute("""
        SELECT id, repo_full_name, file_path, rule_id, secret_type, line_number
        FROM secret_findings
        WHERE match_key IS NULL OR match_key = ''
        """).fetchall()
    for r in rows:
        conn.execute(
            "UPDATE secret_findings SET match_key = ? WHERE id = ?",
            (
                secret_match_key(
                    r["repo_full_name"],
                    r["file_path"],
                    r["rule_id"],
                    r["secret_type"],
                    r["line_number"],
                ),
                r["id"],
            ),
        )

    # Collapse pre-existing duplicates: keep the earliest row per match_key,
    # but never drop a row a user already triaged as false_positive.
    dupes = conn.execute("""
        SELECT id, match_key, state
        FROM secret_findings
        WHERE match_key IN (
            SELECT match_key FROM secret_findings
            GROUP BY match_key HAVING COUNT(*) > 1
        )
        ORDER BY match_key,
                 CASE WHEN state = 'false_positive' THEN 0 ELSE 1 END,
                 id
        """).fetchall()
    seen: set[str] = set()
    for r in dupes:
        if r["match_key"] in seen:
            conn.execute("DELETE FROM secret_findings WHERE id = ?", (r["id"],))
        else:
            seen.add(r["match_key"])

    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_matchkey " "ON secret_findings(match_key)"
    )


def _migrate_default_feed_urls(conn: sqlite3.Connection) -> None:
    """Repoint default feeds whose upstream RSS URL changed. Existing installs
    seeded the old (now dead) URLs into rss_feeds; fix them in place so users
    don't have to re-add feeds manually. Only touches is_default rows.
    """
    for old_url, new_url in _RENAMED_DEFAULT_FEEDS:
        # Skip if the new URL already exists (UNIQUE on url) to avoid a clash.
        clash = conn.execute(
            "SELECT 1 FROM rss_feeds WHERE url = ? AND is_default = 1", (new_url,)
        ).fetchone()
        if clash:
            continue
        conn.execute(
            "UPDATE rss_feeds SET url = ? WHERE url = ? AND is_default = 1",
            (new_url, old_url),
        )


# Old → new default feed URLs (upstream feeds that moved or died).
_RENAMED_DEFAULT_FEEDS: list[tuple[str, str]] = [
    (
        "https://www.darkreading.com/rss_simple.asp",
        "https://www.darkreading.com/rss.xml",
    ),
    (
        "https://cloud.google.com/blog/topics/threat-intelligence/rss/",
        "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
    ),
]


def _dedup_aliased_findings(conn: sqlite3.Connection) -> None:
    """Merge duplicate findings created when OSV returned the same vulnerability
    under both its GHSA primary ID and its aliased CVE ID (or vice versa).
    Keeps the row with both IDs populated; takes the earlier first_seen_at.
    Safe to run repeatedly — no-op when no duplicates exist.
    """
    for col_have, col_null in (("ghsa_id", "cve_id"), ("cve_id", "ghsa_id")):
        pairs = conn.execute(f"""
            SELECT a.id AS keep_id, b.id AS drop_id,
                   CASE WHEN a.first_seen_at < b.first_seen_at
                        THEN a.first_seen_at ELSE b.first_seen_at END AS oldest
            FROM findings a
            JOIN findings b
              ON  a.repo_full_name    = b.repo_full_name
              AND a.package_name      = b.package_name
              AND a.package_ecosystem = b.package_ecosystem
              AND a.{col_have}        = b.{col_have}
              AND a.{col_null} IS NOT NULL
              AND b.{col_null} IS NULL
            """).fetchall()
        for keep_id, drop_id, oldest in pairs:
            conn.execute("UPDATE findings SET first_seen_at = ? WHERE id = ?", (oldest, keep_id))
            conn.execute("DELETE FROM findings WHERE id = ?", (drop_id,))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def url_hash(url: str) -> str:
    """SHA-256 of the URL, hex-encoded. Used as the deduplication key."""
    return hashlib.sha256(url.encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


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
    existing = conn.execute("SELECT id FROM news_items WHERE url_hash = ?", (h,)).fetchone()
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


MAX_CATEGORIZE_ATTEMPTS = 3


def get_uncategorized_items(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    """Return news items that have not yet been categorized, or that previously
    fell back to 'Uncategorized' and have not yet exhausted retry attempts."""
    return conn.execute(
        """
        SELECT id, title, content, source, url
        FROM news_items
        WHERE (category IS NULL OR category = 'Uncategorized')
          AND categorize_attempts < ?
        ORDER BY fetched_at DESC
        LIMIT ?
        """,
        (MAX_CATEGORIZE_ATTEMPTS, limit),
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
    """Write categorization results back to a news item.

    Increments categorize_attempts only on fallback ('Uncategorized') so that
    successfully-categorized items are never retried and failed items stop being
    retried after MAX_CATEGORIZE_ATTEMPTS runs.
    """
    if category == "Uncategorized":
        conn.execute(
            """
            UPDATE news_items
            SET summary = ?, category = ?, severity = ?,
                affected_products = ?, tags = ?, cluster_id = ?,
                categorize_attempts = categorize_attempts + 1
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
    else:
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
    conn: sqlite3.Connection,
    *,
    hours: int = 24,
    limit: int = 200,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
) -> list[sqlite3.Row]:
    """Return recently fetched items with optional filters."""
    clauses: list[str] = ["fetched_at >= datetime('now', ? || ' hours')"]
    params: list[Any] = [f"-{hours}"]
    if category:
        clauses.append("category = ?")
        params.append(category)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if search:
        clauses.append("(title LIKE ? OR summary LIKE ?)")
        s = f"%{search}%"
        params.extend([s, s])
    where = "WHERE " + " AND ".join(clauses)
    params.append(limit)
    return conn.execute(
        f"""
        SELECT id, title, source, published_at, fetched_at,
               summary, category, severity, affected_products, tags, cluster_id, url
        FROM news_items
        {where}
        ORDER BY fetched_at DESC
        LIMIT ?
        """,
        params,
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


def reconcile_interrupted_runs(conn: sqlite3.Connection) -> int:
    """Close out any run_log rows left at status='running' by a process that
    died mid-run (e.g. a container restart). Without this a crashed run stays
    'running' forever and permanently hides real history behind it. Returns
    the number of rows reconciled."""
    cur = conn.execute("""
        UPDATE run_log
        SET status = 'error',
            completed_at = COALESCE(completed_at, started_at),
            error_message = 'Interrupted by application restart'
        WHERE status = 'running'
        """)
    return cur.rowcount


# ---------------------------------------------------------------------------
# Application log entries
# ---------------------------------------------------------------------------


def insert_log_entry(
    conn: sqlite3.Connection,
    timestamp: str,
    level: str,
    logger_name: str,
    message: str,
) -> None:
    conn.execute(
        "INSERT INTO log_entries (timestamp, level, logger_name, message) VALUES (?, ?, ?, ?)",
        (timestamp, level, logger_name, message),
    )


def get_log_entries(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 25,
    level: str = "",
    search: str = "",
) -> list[sqlite3.Row]:
    params: list[Any] = []
    where_clauses: list[str] = []
    if level:
        where_clauses.append("level = ?")
        params.append(level.upper())
    if search:
        where_clauses.append("(message LIKE ? OR logger_name LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    offset = (page - 1) * per_page
    params.extend([per_page, offset])
    return conn.execute(
        f"SELECT * FROM log_entries {where} ORDER BY id DESC LIMIT ? OFFSET ?",  # noqa: S608
        params,
    ).fetchall()


def count_log_entries(conn: sqlite3.Connection, level: str = "", search: str = "") -> int:
    params: list[Any] = []
    where_clauses: list[str] = []
    if level:
        where_clauses.append("level = ?")
        params.append(level.upper())
    if search:
        where_clauses.append("(message LIKE ? OR logger_name LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    row = conn.execute(
        f"SELECT COUNT(*) FROM log_entries {where}",  # noqa: S608
        params,
    ).fetchone()
    return int(row[0]) if row else 0


def delete_old_log_entries(conn: sqlite3.Connection, days: int) -> int:
    cutoff = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    cur = conn.execute("DELETE FROM log_entries WHERE timestamp < ?", (cutoff,))
    return cur.rowcount


# ---------------------------------------------------------------------------
# Settings (key/value preferences)
# ---------------------------------------------------------------------------


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    """Read a preference value from the settings table."""
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
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

    Stamps the row's database id onto finding["id"] (insert or update) so
    callers can act on the specific row afterward without a natural-key
    re-query — which is fragile when cve_id is NULL for more than one row.
    """
    cve_id = finding.get("cve_id")
    ghsa_id = finding.get("ghsa_id")

    # Match flexibly: a row with (None, 'GHSA-xxx') is the same finding as one with
    # ('CVE-yyy', 'GHSA-xxx'). Match on any non-null identifier that is present.
    if ghsa_id and cve_id:
        lookup_sql = """
            SELECT id, state FROM findings
            WHERE repo_full_name = ? AND package_name = ? AND package_ecosystem = ?
              AND (ghsa_id = ? OR cve_id = ?)
            LIMIT 1
        """
        lookup_params = (
            finding["repo_full_name"],
            finding["package_name"],
            finding["package_ecosystem"],
            ghsa_id,
            cve_id,
        )
    elif ghsa_id:
        lookup_sql = """
            SELECT id, state FROM findings
            WHERE repo_full_name = ? AND package_name = ? AND package_ecosystem = ?
              AND ghsa_id = ?
            LIMIT 1
        """
        lookup_params = (
            finding["repo_full_name"],
            finding["package_name"],
            finding["package_ecosystem"],
            ghsa_id,
        )
    elif cve_id:
        lookup_sql = """
            SELECT id, state FROM findings
            WHERE repo_full_name = ? AND package_name = ? AND package_ecosystem = ?
              AND cve_id = ?
            LIMIT 1
        """
        lookup_params = (
            finding["repo_full_name"],
            finding["package_name"],
            finding["package_ecosystem"],
            cve_id,
        )
    else:
        lookup_sql = """
            SELECT id, state FROM findings
            WHERE repo_full_name = ? AND package_name = ? AND package_ecosystem = ?
              AND cve_id IS NULL AND ghsa_id IS NULL
            LIMIT 1
        """
        lookup_params = (
            finding["repo_full_name"],
            finding["package_name"],
            finding["package_ecosystem"],
        )

    existing = conn.execute(lookup_sql, lookup_params).fetchone()

    if existing is None:
        cursor = conn.execute(
            """
            INSERT INTO findings (
                repo_full_name, cve_id, ghsa_id,
                package_name, package_ecosystem,
                installed_version, fixed_version, affected_versions,
                cvss_score, is_kev, patch_available, priority_score,
                state, first_seen_at, last_seen_at,
                manifest_path, ai_next_steps
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                finding["repo_full_name"],
                cve_id,
                ghsa_id,
                finding["package_name"],
                finding["package_ecosystem"],
                finding.get("installed_version"),
                finding.get("fixed_version"),
                finding.get("affected_versions"),
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
        finding["id"] = cursor.lastrowid
        return True

    # Refresh mutable fields; leave state and first_seen_at alone.
    # Also backfill cve_id/ghsa_id if the existing row was created before we had
    # full OSV detail (e.g. stored with cve_id=NULL, now we know the real CVE ID).
    conn.execute(
        """
        UPDATE findings SET
            cve_id            = COALESCE(cve_id,  ?),
            ghsa_id           = COALESCE(ghsa_id, ?),
            last_seen_at      = ?,
            installed_version = ?,
            fixed_version     = ?,
            affected_versions = ?,
            cvss_score        = ?,
            is_kev            = ?,
            patch_available   = ?,
            priority_score    = ?,
            manifest_path     = ?
        WHERE id = ?
        """,
        (
            cve_id,
            ghsa_id,
            _now(),
            finding.get("installed_version"),
            finding.get("fixed_version"),
            finding.get("affected_versions"),
            finding.get("cvss_score"),
            1 if finding.get("is_kev") else 0,
            1 if finding.get("patch_available") else 0,
            finding.get("priority_score"),
            finding.get("manifest_path"),
            existing["id"],
        ),
    )
    finding["id"] = existing["id"]
    return False


def update_finding_next_steps(conn: sqlite3.Connection, finding_id: int, next_steps: dict) -> None:
    """Store AI-generated next steps JSON for a finding."""
    conn.execute(
        "UPDATE findings SET ai_next_steps = ? WHERE id = ?",
        (_json_dumps(next_steps), finding_id),
    )


def update_latest_version_for_package(
    conn: sqlite3.Connection,
    package_name: str,
    ecosystem: str,
    latest_version: str,
    vuln_count: int,
) -> None:
    """Set latest_version and latest_version_vuln_count on every finding row for
    this (package, ecosystem). Used by github_scanner after each scan so the UI
    can show the current upstream release alongside the patched range."""
    conn.execute(
        """
        UPDATE findings SET
            latest_version = ?,
            latest_version_vuln_count = ?
        WHERE package_name = ?
          AND package_ecosystem = ?
        """,
        (latest_version, vuln_count, package_name, ecosystem),
    )


def _findings_where(
    state: str | None,
    repo: str | None,
    since: str | None = None,
    until: str | None = None,
) -> tuple[str, list[Any]]:
    """Build the shared WHERE clause for findings list/count/export queries.

    Pseudo-states: 'unresolved' expands to state IN ('new','acknowledged');
    'all' is treated as no state filter. since/until bound first_seen_at.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if state == "unresolved":
        clauses.append("state IN ('new', 'acknowledged')")
    elif state and state != "all":
        clauses.append("state = ?")
        params.append(state)
    if since:
        clauses.append("first_seen_at >= ?")
        params.append(since)
    if until:
        clauses.append("first_seen_at < ?")
        params.append(until)
    if repo:
        clauses.append("repo_full_name = ?")
        params.append(repo)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def get_findings(
    conn: sqlite3.Connection,
    *,
    state: str | None = None,
    repo: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """Return findings, optionally filtered by state and/or repo."""
    where, params = _findings_where(state, repo, since=since, until=until)
    params.extend([limit, offset])
    return conn.execute(
        f"SELECT * FROM findings {where} ORDER BY priority_score DESC NULLS LAST LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def get_findings_count(
    conn: sqlite3.Connection,
    *,
    state: str | None = None,
    repo: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> int:
    """Return total count of findings matching the given filters."""
    where, params = _findings_where(state, repo, since=since, until=until)
    row = conn.execute(f"SELECT COUNT(*) AS n FROM findings {where}", params).fetchone()
    return int(row["n"] or 0)


def get_new_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all findings currently in 'new' state."""
    return conn.execute(
        "SELECT * FROM findings WHERE state = 'new' ORDER BY priority_score DESC NULLS LAST"
    ).fetchall()


def get_kev_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of CVE IDs present in the CISA KEV.

    Reads from the persistent `kev_entries` table so `is_kev` scoring is
    unaffected by news retention/pruning. Falls back to deriving the set from
    `news_items` (the pre-kev_entries behaviour) when the table is empty —
    e.g. immediately after upgrading, before the next collector run has had a
    chance to populate it.
    """
    rows = conn.execute("SELECT cve_id FROM kev_entries").fetchall()
    if rows:
        return {row["cve_id"] for row in rows}

    rows = conn.execute("SELECT url FROM news_items WHERE source = 'CISA KEV'").fetchall()
    result = set()
    for row in rows:
        url = row["url"] or ""
        if "#" in url:
            result.add(url.split("#")[-1].upper())
    return result


def upsert_kev_entries(conn: sqlite3.Connection, entries: Iterable[tuple[str, str | None]]) -> None:
    """Upsert (cve_id, added_at) pairs into the persistent KEV table.

    Never touched by retention/clear-data operations, so `is_kev` scoring
    survives news pruning. Safe to call with the full current KEV catalog on
    every collector run — existing rows just get their `added_at` refreshed.
    """
    now = _now()
    for cve_id, added_at in entries:
        if not cve_id:
            continue
        conn.execute(
            """
            INSERT INTO kev_entries (cve_id, added_at, first_seen_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET added_at = excluded.added_at
            """,
            (cve_id.upper(), added_at, now),
        )


def get_unnotified_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return new findings that have not yet been notified (notified_at IS NULL).

    These are the delta — exactly the findings that should trigger an alert.
    After sending the alert, call mark_findings_notified() with these IDs.
    """
    return conn.execute("""
        SELECT * FROM findings
        WHERE state = 'new' AND notified_at IS NULL
        ORDER BY priority_score DESC NULLS LAST
        """).fetchall()


def mark_findings_notified(conn: sqlite3.Connection, finding_ids: list[int]) -> None:
    """Stamp notified_at on findings that were successfully delivered."""
    if not finding_ids:
        return
    placeholders = ",".join("?" * len(finding_ids))
    conn.execute(
        f"UPDATE findings SET notified_at = ? WHERE id IN ({placeholders})",
        [_now(), *finding_ids],
    )


# ---------------------------------------------------------------------------
# Secret findings
# ---------------------------------------------------------------------------


def secret_match_key(
    repo_full_name: str,
    file_path: str,
    rule_id: str,
    secret_type: str,
    line_number: int | None,
) -> str:
    """Commit-independent identity for a secret finding.

    Deliberately excludes the commit SHA — gitleaks' Fingerprint embeds it, and
    shallow clones make it unstable across runs (see _migrate_secret_findings).
    A secret that physically moves to a different line may re-report once; that
    is far cheaper than re-inserting the same secret on every scan.
    """
    return "|".join([repo_full_name, file_path, rule_id, secret_type, str(line_number or "")])


def upsert_secret_finding(conn: sqlite3.Connection, finding: dict) -> bool:
    """Upsert a secret finding by its commit-independent match_key.

    Returns True if this is a brand-new finding (triggers notification).
    For existing findings last_seen_at and the latest sighting's commit/line/
    fingerprint are refreshed; state is unchanged.
    """
    match_key = secret_match_key(
        finding["repo_full_name"],
        finding["file_path"],
        finding["rule_id"],
        finding["secret_type"],
        finding.get("line_number"),
    )
    existing = conn.execute(
        "SELECT id FROM secret_findings WHERE match_key = ?",
        (match_key,),
    ).fetchone()

    if existing is None:
        conn.execute(
            """
            INSERT INTO secret_findings
                (repo_full_name, file_path, line_number, commit_sha,
                 secret_type, rule_id, fingerprint, match_key, state,
                 first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)
            """,
            (
                finding["repo_full_name"],
                finding["file_path"],
                finding.get("line_number"),
                finding["commit_sha"],
                finding["secret_type"],
                finding["rule_id"],
                finding["fingerprint"],
                match_key,
                _now(),
                _now(),
            ),
        )
        return True

    conn.execute(
        """
        UPDATE secret_findings
        SET last_seen_at = ?, commit_sha = ?, line_number = ?, fingerprint = ?
        WHERE id = ?
        """,
        (
            _now(),
            finding["commit_sha"],
            finding.get("line_number"),
            finding["fingerprint"],
            existing["id"],
        ),
    )
    return False


def _secrets_where(
    state: str | None,
    repo: str | None,
    since: str | None = None,
    until: str | None = None,
) -> tuple[str, list[Any]]:
    """Build the shared WHERE clause for secret findings queries.

    Pseudo-states: 'unresolved' maps to state='new'; 'all' means no state filter.
    since/until bound first_seen_at (used by New and Unresolved tabs).
    """
    clauses: list[str] = []
    params: list[Any] = []
    if state == "unresolved":
        clauses.append("state = 'new'")
    elif state and state != "all":
        clauses.append("state = ?")
        params.append(state)
    if since:
        clauses.append("first_seen_at >= ?")
        params.append(since)
    if until:
        clauses.append("first_seen_at < ?")
        params.append(until)
    if repo:
        clauses.append("repo_full_name = ?")
        params.append(repo)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def get_secret_findings(
    conn: sqlite3.Connection,
    *,
    state: str | None = None,
    repo: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """Return secret findings, optionally filtered by state and/or repo."""
    where, params = _secrets_where(state, repo, since=since, until=until)
    params.extend([limit, offset])
    return conn.execute(
        f"SELECT * FROM secret_findings {where} ORDER BY first_seen_at DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def get_secret_findings_count(
    conn: sqlite3.Connection,
    *,
    state: str | None = None,
    repo: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> int:
    """Return total count of secret findings matching the given filters."""
    where, params = _secrets_where(state, repo, since=since, until=until)
    row = conn.execute(f"SELECT COUNT(*) AS n FROM secret_findings {where}", params).fetchone()
    return int(row["n"] or 0)


def get_unnotified_secret_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return new secret findings that have not yet been notified."""
    return conn.execute("""
        SELECT * FROM secret_findings
        WHERE state = 'new' AND notified_at IS NULL
        ORDER BY first_seen_at DESC
        """).fetchall()


def mark_secret_findings_notified(conn: sqlite3.Connection, finding_ids: list[int]) -> None:
    """Stamp notified_at on secret findings that were delivered."""
    if not finding_ids:
        return
    placeholders = ",".join("?" * len(finding_ids))
    conn.execute(
        f"UPDATE secret_findings SET notified_at = ? WHERE id IN ({placeholders})",
        [_now(), *finding_ids],
    )


def get_secret_finding(conn: sqlite3.Connection, finding_id: int) -> sqlite3.Row | None:
    """Return a single secret finding by primary key, or None."""
    return conn.execute("SELECT * FROM secret_findings WHERE id = ?", (finding_id,)).fetchone()


def mark_secret_finding_false_positive(conn: sqlite3.Connection, finding_id: int) -> bool:
    """Mark a secret finding as a false positive. Returns True if updated."""
    cur = conn.execute(
        "UPDATE secret_findings SET state = 'false_positive' WHERE id = ? AND state = 'new'",
        (finding_id,),
    )
    return cur.rowcount > 0


def unmark_secret_false_positive(conn: sqlite3.Connection, finding_id: int) -> bool:
    """Revert a false-positive secret finding back to 'new'. Returns True if updated."""
    cur = conn.execute(
        "UPDATE secret_findings SET state = 'new' WHERE id = ? AND state = 'false_positive'",
        (finding_id,),
    )
    return cur.rowcount > 0


def mark_secret_finding_resolved(conn: sqlite3.Connection, finding_id: int) -> bool:
    """Mark a secret finding as resolved. Returns True if updated."""
    cur = conn.execute(
        "UPDATE secret_findings SET state = 'resolved' WHERE id = ? AND state != 'resolved'",
        (finding_id,),
    )
    return cur.rowcount > 0


def bulk_update_finding_state(conn: sqlite3.Connection, ids: list[int], action: str) -> int:
    """Update state for multiple findings at once. Returns the count of rows changed."""
    if not ids:
        return 0
    ph = ",".join("?" * len(ids))
    now = _now()
    if action == "acknowledge":
        cur = conn.execute(
            f"UPDATE findings SET state = 'acknowledged' WHERE id IN ({ph}) AND state = 'new'",
            ids,
        )
    elif action == "resolve":
        cur = conn.execute(
            f"UPDATE findings SET state = 'resolved', resolved_at = ? WHERE id IN ({ph}) AND state IN ('new', 'acknowledged')",
            [now, *ids],
        )
    elif action == "reopen":
        cur = conn.execute(
            f"UPDATE findings SET state = 'new', notified_at = NULL, resolved_at = NULL WHERE id IN ({ph}) AND state IN ('resolved', 'acknowledged')",
            ids,
        )
    else:
        return 0
    return cur.rowcount


def bulk_update_secret_state(conn: sqlite3.Connection, ids: list[int], action: str) -> int:
    """Update state for multiple secret findings at once. Returns the count of rows changed."""
    if not ids:
        return 0
    ph = ",".join("?" * len(ids))
    if action == "false-positive":
        cur = conn.execute(
            f"UPDATE secret_findings SET state = 'false_positive' WHERE id IN ({ph}) AND state = 'new'",
            ids,
        )
    elif action == "resolve":
        cur = conn.execute(
            f"UPDATE secret_findings SET state = 'resolved' WHERE id IN ({ph}) AND state = 'new'",
            ids,
        )
    else:
        return 0
    return cur.rowcount


def get_false_positive_fingerprints(conn: sqlite3.Connection) -> set[str]:
    """Return all fingerprints the user has marked as false positives."""
    rows = conn.execute(
        "SELECT fingerprint FROM secret_findings WHERE state = 'false_positive'"
    ).fetchall()
    return {r["fingerprint"] for r in rows}


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------


def add_bookmark(conn: sqlite3.Connection, news_item_id: int) -> bool:
    """Bookmark a news item. Returns True if inserted, False if already bookmarked."""
    existing = conn.execute(
        "SELECT id FROM bookmarks WHERE news_item_id = ?", (news_item_id,)
    ).fetchone()
    if existing:
        return False
    conn.execute(
        "INSERT INTO bookmarks (news_item_id, created_at) VALUES (?, ?)",
        (news_item_id, _now()),
    )
    return True


def remove_bookmark(conn: sqlite3.Connection, news_item_id: int) -> bool:
    """Remove a bookmark. Returns True if it existed and was deleted."""
    cur = conn.execute("DELETE FROM bookmarks WHERE news_item_id = ?", (news_item_id,))
    return cur.rowcount > 0


def is_bookmarked(conn: sqlite3.Connection, news_item_id: int) -> bool:
    """Return True if the item is bookmarked."""
    return (
        conn.execute("SELECT 1 FROM bookmarks WHERE news_item_id = ?", (news_item_id,)).fetchone()
        is not None
    )


def get_bookmarks(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all bookmarked news items, newest bookmark first."""
    return conn.execute("""
        SELECT n.id, n.title, n.url, n.source, n.published_at, n.fetched_at,
               n.summary, n.category, n.severity, b.created_at AS bookmarked_at
        FROM bookmarks b
        JOIN news_items n ON n.id = b.news_item_id
        ORDER BY b.created_at DESC
        """).fetchall()


def get_bookmarked_ids(conn: sqlite3.Connection) -> set[int]:
    """Return the set of currently bookmarked news_item IDs (for rendering toggle state)."""
    rows = conn.execute("SELECT news_item_id FROM bookmarks").fetchall()
    return {r["news_item_id"] for r in rows}


# ---------------------------------------------------------------------------
# Annotations (findings)
# ---------------------------------------------------------------------------


def set_finding_annotation(conn: sqlite3.Connection, finding_id: int, text: str | None) -> bool:
    """Set or clear a personal annotation on a finding. Returns True if row updated."""
    cur = conn.execute(
        "UPDATE findings SET annotation = ? WHERE id = ?",
        (text or None, finding_id),
    )
    return cur.rowcount > 0


def get_annotated_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all findings that have a non-empty personal annotation."""
    return conn.execute("""
        SELECT * FROM findings
        WHERE annotation IS NOT NULL AND annotation != ''
        ORDER BY priority_score DESC NULLS LAST
        """).fetchall()


# ---------------------------------------------------------------------------
# History / analytics queries
# ---------------------------------------------------------------------------


def get_news_trend(conn: sqlite3.Connection, days: int = 30) -> list[sqlite3.Row]:
    """Items per day × severity for the last N days (for trend charts)."""
    return conn.execute(
        """
        SELECT date(fetched_at) AS day,
               COALESCE(severity, 'Unknown') AS severity,
               COUNT(*) AS count
        FROM news_items
        WHERE fetched_at >= date('now', ? || ' days')
        GROUP BY day, severity
        ORDER BY day ASC
        """,
        (f"-{days}",),
    ).fetchall()


def get_findings_by_day(conn: sqlite3.Connection, days: int = 30) -> list[sqlite3.Row]:
    """New findings per calendar day over the last N days."""
    return conn.execute(
        """
        SELECT date(first_seen_at) AS day, COUNT(*) AS count
        FROM findings
        WHERE first_seen_at >= date('now', ? || ' days')
        GROUP BY day
        ORDER BY day ASC
        """,
        (f"-{days}",),
    ).fetchall()


def get_source_stats(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Per-source item totals, last-7-day count, and last fetch timestamp."""
    return conn.execute("""
        SELECT
            f.name,
            f.last_fetched_at,
            f.enabled,
            f.is_default,
            COUNT(n.id)                                                           AS total_items,
            SUM(CASE WHEN n.fetched_at >= date('now','-7 days') THEN 1 ELSE 0 END) AS week_items
        FROM rss_feeds f
        LEFT JOIN news_items n ON n.source = f.name
        GROUP BY f.id
        ORDER BY week_items DESC, total_items DESC
        """).fetchall()


def get_run_history(conn: sqlite3.Connection, limit: int = 30) -> list[sqlite3.Row]:
    """Return recent pipeline runs from newest to oldest."""
    return conn.execute(
        "SELECT * FROM run_log ORDER BY started_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def get_weekly_digest(conn: sqlite3.Connection) -> dict | None:
    """Return the most recent stored weekly digest, or None."""
    raw = get_setting(conn, "weekly_digest.latest", "")
    if not raw:
        return None
    try:
        import json

        return json.loads(raw)
    except Exception:
        return None


def save_weekly_digest(conn: sqlite3.Connection, data: dict) -> None:
    """Store weekly digest JSON snapshot in the settings table."""
    import json

    set_setting(conn, "weekly_digest.latest", json.dumps(data, ensure_ascii=False))


def get_pipeline_snapshot(conn: sqlite3.Connection) -> dict | None:
    """Return the most recently persisted pipeline run snapshot, or None."""
    raw = get_setting(conn, "pipeline.last_snapshot", "")
    if not raw:
        return None
    try:
        import json

        return json.loads(raw)
    except Exception:
        return None


def save_pipeline_snapshot(conn: sqlite3.Connection, data: dict) -> None:
    """Store the last-completed-run pipeline status JSON snapshot in the
    settings table, so per-step detail survives a process restart."""
    import json

    set_setting(conn, "pipeline.last_snapshot", json.dumps(data, ensure_ascii=False))


def get_weekly_digest_top_findings(
    conn: sqlite3.Connection,
) -> list[sqlite3.Row]:
    """Top 10 active findings by priority score for the weekly digest."""
    return conn.execute("""
        SELECT repo_full_name, cve_id, ghsa_id, package_name, package_ecosystem,
               cvss_score, priority_score, is_kev, patch_available, state,
               first_seen_at
        FROM findings
        WHERE state IN ('new', 'acknowledged')
        ORDER BY priority_score DESC NULLS LAST
        LIMIT 10
        """).fetchall()


def get_weekly_resolved_count(conn: sqlite3.Connection) -> int:
    """Count findings resolved in the last 7 days."""
    row = conn.execute("""
        SELECT COUNT(*) AS n FROM findings
        WHERE state = 'resolved'
          AND resolved_at >= date('now', '-7 days')
        """).fetchone()
    return int(row["n"] or 0) if row else 0


def get_weekly_new_findings_count(conn: sqlite3.Connection) -> int:
    """Count findings first seen in the last 7 days."""
    row = conn.execute("""
        SELECT COUNT(*) AS n FROM findings
        WHERE first_seen_at >= date('now', '-7 days')
        """).fetchone()
    return int(row["n"] or 0) if row else 0


def get_weekly_items_collected(conn: sqlite3.Connection) -> int:
    """Count news items collected in the last 7 days."""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM news_items WHERE fetched_at >= date('now','-7 days')"
    ).fetchone()
    return int(row["n"] or 0) if row else 0


def get_top_affected_repos(conn: sqlite3.Connection, limit: int = 5) -> list[sqlite3.Row]:
    """Repos with most active (new/acknowledged) findings, sorted descending."""
    return conn.execute(
        """
        SELECT repo_full_name, COUNT(*) AS finding_count,
               MAX(priority_score) AS max_priority
        FROM findings
        WHERE state IN ('new', 'acknowledged')
        GROUP BY repo_full_name
        ORDER BY finding_count DESC, max_priority DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def _news_where(
    category: str | None,
    severity: str | None,
    source: str | None,
    search: str | None,
) -> tuple[str, list[Any]]:
    """Build the shared WHERE clause for news list/count/export queries."""
    clauses: list[str] = []
    params: list[Any] = []
    if category:
        clauses.append("category = ?")
        params.append(category)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if search:
        clauses.append("(title LIKE ? OR summary LIKE ?)")
        s = f"%{search}%"
        params.extend([s, s])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def get_news_items_paginated(
    conn: sqlite3.Connection,
    *,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
    sort: str = "published_desc",
    limit: int = 25,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """Return paginated news items with optional filters.

    sort: "published_desc" (default) | "published_asc"
    Items with no published_at fall back to fetched_at for ordering.
    """
    where, params = _news_where(category, severity, source, search)
    order = "ASC" if sort == "published_asc" else "DESC"
    params.extend([limit, offset])
    return conn.execute(
        f"""
        SELECT id, title, source, published_at, fetched_at,
               summary, category, severity, affected_products, tags, cluster_id, url
        FROM news_items {where}
        ORDER BY COALESCE(published_at, fetched_at) {order}
        LIMIT ? OFFSET ?
        """,
        params,
    ).fetchall()


def get_news_items_count(
    conn: sqlite3.Connection,
    *,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
) -> int:
    """Return total count of news items matching the given filters."""
    where, params = _news_where(category, severity, source, search)
    row = conn.execute(f"SELECT COUNT(*) AS n FROM news_items {where}", params).fetchone()
    return int(row["n"] or 0)


def get_feed_analytics(conn: sqlite3.Connection, days: int = 30) -> list[sqlite3.Row]:
    """Items per source per day over the last N days (for feed analytics chart)."""
    return conn.execute(
        """
        SELECT f.name AS source,
               date(n.fetched_at) AS day,
               COUNT(n.id) AS count
        FROM rss_feeds f
        LEFT JOIN news_items n
               ON n.source = f.name
              AND n.fetched_at >= date('now', ? || ' days')
        WHERE f.enabled = 1
        GROUP BY f.name, day
        ORDER BY day ASC, f.name ASC
        """,
        (f"-{days}",),
    ).fetchall()


def get_news_items_for_export(
    conn: sqlite3.Connection,
    *,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
) -> list[sqlite3.Row]:
    """Return news items for data export (JSON/CSV), honoring the same filters
    as the news list view so an export matches what the user is viewing."""
    where, params = _news_where(category, severity, source, search)
    return conn.execute(
        f"""
        SELECT id, title, url, source, published_at, fetched_at,
               summary, category, severity, affected_products, tags
        FROM news_items {where}
        ORDER BY fetched_at DESC
        """,
        params,
    ).fetchall()


def get_findings_for_issue_creation(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return new findings that don't have a GitHub issue URL yet."""
    return conn.execute("""
        SELECT * FROM findings
        WHERE state = 'new' AND github_issue_url IS NULL
        ORDER BY priority_score DESC NULLS LAST
        """).fetchall()


def set_finding_github_issue_url(conn: sqlite3.Connection, finding_id: int, url: str) -> None:
    """Store the GitHub issue URL on a finding."""
    conn.execute(
        "UPDATE findings SET github_issue_url = ? WHERE id = ?",
        (url, finding_id),
    )


def get_findings_for_export(
    conn: sqlite3.Connection,
    *,
    state: str | None = None,
    repo: str | None = None,
) -> list[sqlite3.Row]:
    """Return findings for data export (JSON/CSV), honoring the same filters
    as the findings list view so an export matches what the user is viewing."""
    where, params = _findings_where(state, repo)
    return conn.execute(
        f"""
        SELECT id, repo_full_name, cve_id, ghsa_id, package_name,
               package_ecosystem, installed_version, fixed_version,
               cvss_score, is_kev, patch_available, priority_score,
               state, first_seen_at, last_seen_at, resolved_at,
               manifest_path, annotation, github_issue_url
        FROM findings {where}
        ORDER BY priority_score DESC NULLS LAST
        """,
        params,
    ).fetchall()


def get_secret_findings_summary(conn: sqlite3.Connection) -> dict:
    """Return per-state counts for the dashboard."""
    try:
        row = conn.execute("""
            SELECT
                SUM(CASE WHEN state = 'new'            THEN 1 ELSE 0 END) AS new,
                SUM(CASE WHEN state = 'false_positive' THEN 1 ELSE 0 END) AS false_positive,
                SUM(CASE WHEN state = 'resolved'       THEN 1 ELSE 0 END) AS resolved
            FROM secret_findings
            """).fetchone()
        return {
            "new": int(row["new"] or 0),
            "false_positive": int(row["false_positive"] or 0),
            "resolved": int(row["resolved"] or 0),
        }
    except Exception:
        return {"new": 0, "false_positive": 0, "resolved": 0}


# ---------------------------------------------------------------------------
# Data management (clear / bulk delete)
# ---------------------------------------------------------------------------


def delete_old_news(conn: sqlite3.Connection, days: int, preserve_bookmarked: bool = True) -> int:
    """Delete news items older than `days` days (by fetched_at).

    Used by the scheduled retention job. When preserve_bookmarked is True,
    bookmarked items are kept regardless of age so the user never silently
    loses something they explicitly saved. Returns the number of rows deleted.
    A non-positive `days` is a no-op (retention disabled).
    """
    if days <= 0:
        return 0
    sql = "DELETE FROM news_items WHERE fetched_at < date('now', ? || ' days')"
    if preserve_bookmarked:
        sql += " AND id NOT IN (SELECT news_item_id FROM bookmarks)"
    cur = conn.execute(sql, (f"-{days}",))
    return cur.rowcount


def clear_news_items(conn: sqlite3.Connection, days_back: int | None = None) -> int:
    """Delete news items. If days_back is given, deletes only items older than that."""
    if days_back is not None:
        cur = conn.execute(
            "DELETE FROM news_items WHERE fetched_at < date('now', ? || ' days')",
            (f"-{days_back}",),
        )
    else:
        cur = conn.execute("DELETE FROM news_items")
    if cur.rowcount:
        conn.execute("UPDATE rss_feeds SET item_count = 0")
    return cur.rowcount


def clear_findings(conn: sqlite3.Connection, days_back: int | None = None) -> int:
    """Delete findings. If days_back is given, deletes only items older than that."""
    if days_back is not None:
        cur = conn.execute(
            "DELETE FROM findings WHERE first_seen_at < date('now', ? || ' days')",
            (f"-{days_back}",),
        )
    else:
        cur = conn.execute("DELETE FROM findings")
    return cur.rowcount


def clear_secret_findings(conn: sqlite3.Connection, days_back: int | None = None) -> int:
    """Delete secret findings. If days_back is given, deletes only items older than that."""
    if days_back is not None:
        cur = conn.execute(
            "DELETE FROM secret_findings WHERE first_seen_at < date('now', ? || ' days')",
            (f"-{days_back}",),
        )
    else:
        cur = conn.execute("DELETE FROM secret_findings")
    return cur.rowcount


def clear_run_history(conn: sqlite3.Connection, days_back: int | None = None) -> int:
    """Delete run log entries. If days_back is given, deletes only entries older than that."""
    if days_back is not None:
        cur = conn.execute(
            "DELETE FROM run_log WHERE started_at < date('now', ? || ' days')",
            (f"-{days_back}",),
        )
    else:
        cur = conn.execute("DELETE FROM run_log")
    return cur.rowcount
