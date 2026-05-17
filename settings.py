"""
settings.py — SQLite-backed user preferences.

Manages all non-secret runtime configuration:
  - RSS feeds        (rss_feeds table)
  - Keyword watchlist (keywords table)
  - Feature toggles  (settings table, key prefix 'toggle.')
  - Scanner settings: severity threshold, excluded repos (settings table)

Secrets (GitHub token, dashboard password, webhook URLs, SMTP credentials)
remain in config.yaml and are never read or written here.

Usage:
    import settings
    feeds = settings.get_feeds(conn)           # list of enabled feed rows
    settings.add_feed(conn, "My Blog", url)
    settings.is_feature_enabled(conn, "github_scanning")  # bool
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime

import db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature toggle registry
# ---------------------------------------------------------------------------

FEATURE_TOGGLES: dict[str, dict] = {
    "github_scanning":       {"label": "GitHub repository scanning",   "default": True},
    "secrets_scanning":      {"label": "Secrets scanning",             "default": True},
    "github_issue_creation": {"label": "GitHub issue auto-creation",   "default": False},
    "news_clustering":       {"label": "News clustering",              "default": True},
    "outdated_tracking":     {"label": "Outdated dependency tracking", "default": True},
    "weekly_digest":         {"label": "Weekly digest",                "default": True},
    "patch_alerts":          {"label": "Patch availability alerts",    "default": True},
}

# ---------------------------------------------------------------------------
# Scanner settings
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "all"]
DEFAULT_SEVERITY_THRESHOLD = "high"

# ---------------------------------------------------------------------------
# Default RSS feeds (mirrors collector.DEFAULT_RSS_FEEDS; bootstrapped on
# first call to get_feeds() when the rss_feeds table is empty)
# ---------------------------------------------------------------------------

DEFAULT_FEEDS: list[tuple[str, str]] = [
    ("Bleeping Computer",         "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security",         "https://krebsonsecurity.com/feed/"),
    ("The Hacker News",           "https://feeds.feedburner.com/TheHackersNews"),
    ("SANS ISC",                  "https://isc.sans.edu/rssfeed_full.xml"),
    ("Cisco Talos",               "https://blog.talosintelligence.com/rss/"),
    ("Palo Alto Unit 42",         "https://unit42.paloaltonetworks.com/feed/"),
    ("Google Mandiant",           "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("CrowdStrike Blog",          "https://www.crowdstrike.com/blog/feed/"),
    ("Dark Reading",              "https://www.darkreading.com/rss_simple.asp"),
]


# ---------------------------------------------------------------------------
# RSS feeds
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).isoformat()


def get_feeds(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all feeds, bootstrapping defaults if the table is empty."""
    rows = conn.execute(
        "SELECT * FROM rss_feeds ORDER BY is_default DESC, name ASC"
    ).fetchall()
    if not rows:
        _bootstrap_default_feeds(conn)
        conn.connection.commit() if hasattr(conn, "connection") else None
        rows = conn.execute(
            "SELECT * FROM rss_feeds ORDER BY is_default DESC, name ASC"
        ).fetchall()
    return rows


def get_enabled_feeds(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return only enabled feeds — used by the collector."""
    rows = conn.execute(
        "SELECT * FROM rss_feeds WHERE enabled = 1 ORDER BY is_default DESC, name ASC"
    ).fetchall()
    if not rows:
        # Bootstrap and retry once
        _bootstrap_default_feeds(conn)
        rows = conn.execute(
            "SELECT * FROM rss_feeds WHERE enabled = 1 ORDER BY is_default DESC, name ASC"
        ).fetchall()
    return rows


def _bootstrap_default_feeds(conn: sqlite3.Connection) -> None:
    """Populate rss_feeds with DEFAULT_FEEDS. Safe to call on an empty table only."""
    now = _now()
    for name, url in DEFAULT_FEEDS:
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO rss_feeds
                    (name, url, enabled, is_default, created_at)
                VALUES (?, ?, 1, 1, ?)
                """,
                (name, url, now),
            )
        except Exception as exc:
            logger.warning("Could not bootstrap feed %s: %s", name, exc)


def add_feed(conn: sqlite3.Connection, name: str, url: str) -> sqlite3.Row:
    """Insert a new user-defined feed. Raises ValueError on duplicate URL."""
    existing = conn.execute(
        "SELECT id FROM rss_feeds WHERE url = ?", (url,)
    ).fetchone()
    if existing:
        raise ValueError(f"A feed with URL '{url}' already exists.")

    conn.execute(
        """
        INSERT INTO rss_feeds (name, url, enabled, is_default, created_at)
        VALUES (?, ?, 1, 0, ?)
        """,
        (name, url, _now()),
    )
    return conn.execute(
        "SELECT * FROM rss_feeds WHERE url = ?", (url,)
    ).fetchone()


def set_feed_enabled(conn: sqlite3.Connection, feed_id: int, enabled: bool) -> bool:
    """Enable or disable a feed. Returns True if the row was found and updated."""
    cur = conn.execute(
        "UPDATE rss_feeds SET enabled = ? WHERE id = ?",
        (1 if enabled else 0, feed_id),
    )
    return cur.rowcount > 0


def remove_feed(conn: sqlite3.Connection, feed_id: int) -> bool:
    """Delete a feed. Raises ValueError if it is a default feed (those can only be disabled).
    Returns True if deleted."""
    row = conn.execute(
        "SELECT is_default FROM rss_feeds WHERE id = ?", (feed_id,)
    ).fetchone()
    if row is None:
        return False
    if row["is_default"]:
        raise ValueError("Default feeds cannot be deleted — disable them instead.")
    conn.execute("DELETE FROM rss_feeds WHERE id = ?", (feed_id,))
    return True


def update_feed_stats(
    conn: sqlite3.Connection, url: str, last_fetched_at: str, item_count: int
) -> None:
    """Record last-fetched timestamp and item count after a successful fetch."""
    conn.execute(
        """
        UPDATE rss_feeds
        SET last_fetched_at = ?, item_count = item_count + ?
        WHERE url = ?
        """,
        (last_fetched_at, item_count, url),
    )


# ---------------------------------------------------------------------------
# Keyword watchlist
# ---------------------------------------------------------------------------


def get_keywords(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all keywords ordered alphabetically."""
    return conn.execute(
        "SELECT * FROM keywords ORDER BY keyword ASC"
    ).fetchall()


def add_keyword(conn: sqlite3.Connection, keyword: str) -> sqlite3.Row:
    """Add a keyword. Raises ValueError on duplicate (case-insensitive)."""
    normalised = keyword.strip().lower()
    if not normalised:
        raise ValueError("Keyword cannot be empty.")

    existing = conn.execute(
        "SELECT id FROM keywords WHERE LOWER(keyword) = ?", (normalised,)
    ).fetchone()
    if existing:
        raise ValueError(f"Keyword '{keyword}' already exists.")

    conn.execute(
        "INSERT INTO keywords (keyword, created_at) VALUES (?, ?)",
        (keyword.strip(), _now()),
    )
    return conn.execute(
        "SELECT * FROM keywords WHERE keyword = ?", (keyword.strip(),)
    ).fetchone()


def remove_keyword(conn: sqlite3.Connection, keyword_id: int) -> bool:
    """Remove a keyword by ID. Returns True if deleted."""
    cur = conn.execute("DELETE FROM keywords WHERE id = ?", (keyword_id,))
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Feature toggles
# ---------------------------------------------------------------------------


def get_feature_toggles(conn: sqlite3.Connection) -> dict[str, bool]:
    """Return current state of all feature toggles (key → bool)."""
    result: dict[str, bool] = {}
    for key, meta in FEATURE_TOGGLES.items():
        stored = db.get_setting(conn, f"toggle.{key}", "")
        if stored == "":
            result[key] = meta["default"]
        else:
            result[key] = stored == "1"
    return result


def set_feature_toggle(conn: sqlite3.Connection, key: str, enabled: bool) -> None:
    """Set one feature toggle. Raises ValueError for unknown keys."""
    if key not in FEATURE_TOGGLES:
        raise ValueError(f"Unknown feature toggle: '{key}'")
    db.set_setting(conn, f"toggle.{key}", "1" if enabled else "0")


def is_feature_enabled(conn: sqlite3.Connection, key: str) -> bool:
    """Return whether a feature is currently enabled."""
    stored = db.get_setting(conn, f"toggle.{key}", "")
    if stored == "":
        return FEATURE_TOGGLES.get(key, {}).get("default", True)
    return stored == "1"


# ---------------------------------------------------------------------------
# Scanner settings
# ---------------------------------------------------------------------------


def get_severity_threshold(conn: sqlite3.Connection) -> str:
    """Return the configured severity threshold (default: 'high')."""
    val = db.get_setting(conn, "scanner.severity_threshold", DEFAULT_SEVERITY_THRESHOLD)
    return val if val in SEVERITY_LEVELS else DEFAULT_SEVERITY_THRESHOLD


def set_severity_threshold(conn: sqlite3.Connection, threshold: str) -> None:
    """Set the severity threshold. Raises ValueError for unknown levels."""
    if threshold not in SEVERITY_LEVELS:
        raise ValueError(f"Invalid threshold '{threshold}'. Must be one of: {SEVERITY_LEVELS}")
    db.set_setting(conn, "scanner.severity_threshold", threshold)


def get_excluded_repos(conn: sqlite3.Connection) -> list[str]:
    """Return the list of repos excluded from scanning."""
    raw = db.get_setting(conn, "scanner.excluded_repos", "[]")
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def set_excluded_repos(conn: sqlite3.Connection, repos: list[str]) -> None:
    """Replace the excluded repos list."""
    db.set_setting(conn, "scanner.excluded_repos", json.dumps(repos))
