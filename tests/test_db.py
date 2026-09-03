"""
Unit tests for db.py — schema creation, insert/dedup, queries, settings.

All tests use a temporary in-memory SQLite database; no file I/O.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import dive.db as db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a freshly initialised temporary database."""
    db_path = tmp_path / "test.db"
    db.init(db_path)
    return db_path


@pytest.fixture
def conn(tmp_db: Path):
    """Yield an open connection to the test database."""
    with db.get_conn(tmp_db) as c:
        yield c


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_init_creates_tables(tmp_db: Path):
    with db.get_conn(tmp_db) as c:
        tables = {
            row[0]
            for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    assert "news_items" in tables
    assert "findings" in tables
    assert "run_log" in tables
    assert "settings" in tables
    assert "kev_entries" in tables


def test_init_is_idempotent(tmp_db: Path):
    """Calling init() a second time must not raise."""
    db.init(tmp_db)
    db.init(tmp_db)


def test_init_creates_expected_indexes(tmp_db: Path):
    """Regression test for the missing-index audit: every findings/secrets/
    news list query sorts on one of these columns, so a full scan+sort on
    every paginated page is the failure mode if any of these disappear."""
    with db.get_conn(tmp_db) as c:
        indexes = {
            row[0]
            for row in c.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        }
    for expected in (
        "idx_findings_priority",
        "idx_findings_notified",
        "idx_findings_firstseen",
        "idx_secrets_firstseen",
        "idx_news_published_coalesce",
    ):
        assert expected in indexes, f"missing index: {expected}"


# ---------------------------------------------------------------------------
# url_hash
# ---------------------------------------------------------------------------


def test_url_hash_is_deterministic():
    h1 = db.url_hash("https://example.com/article")
    h2 = db.url_hash("https://example.com/article")
    assert h1 == h2


def test_url_hash_different_urls_differ():
    assert db.url_hash("https://a.com") != db.url_hash("https://b.com")


def test_url_hash_length():
    # SHA-256 hex = 64 chars
    assert len(db.url_hash("https://example.com")) == 64


# ---------------------------------------------------------------------------
# insert_news_item
# ---------------------------------------------------------------------------


def _make_item(**overrides) -> dict:
    base = {
        "url": "https://example.com/cve-2024-1234",
        "title": "CVE-2024-1234 in Example Library",
        "source": "Test Feed",
        "published_at": "2024-01-15T00:00:00+00:00",
        "fetched_at": "2024-01-15T06:00:00+00:00",
        "content": "An example vulnerability was discovered.",
    }
    base.update(overrides)
    return base


def test_insert_news_item_returns_true_on_new(conn):
    assert db.insert_news_item(conn, _make_item()) is True


def test_insert_news_item_returns_false_on_duplicate(conn):
    item = _make_item()
    db.insert_news_item(conn, item)
    assert db.insert_news_item(conn, item) is False


def test_insert_news_item_deduplicates_by_url(conn):
    item_a = _make_item(title="Title A")
    item_b = _make_item(title="Title B")  # same URL, different title
    db.insert_news_item(conn, item_a)
    assert db.insert_news_item(conn, item_b) is False


def test_insert_news_item_allows_different_urls(conn):
    db.insert_news_item(conn, _make_item(url="https://example.com/a"))
    assert db.insert_news_item(conn, _make_item(url="https://example.com/b")) is True


def test_inserted_item_stored_correctly(conn):
    item = _make_item(content="Some content here")
    db.insert_news_item(conn, item)
    row = conn.execute("SELECT * FROM news_items WHERE source = 'Test Feed'").fetchone()
    assert row is not None
    assert row["title"] == item["title"]
    assert row["source"] == item["source"]
    assert row["content"] == item["content"]
    assert row["category"] is None  # not yet categorized


# ---------------------------------------------------------------------------
# get_uncategorized_items
# ---------------------------------------------------------------------------


def test_get_uncategorized_returns_only_uncategorized(conn):
    db.insert_news_item(conn, _make_item(url="https://example.com/uncategorized"))
    db.insert_news_item(conn, _make_item(url="https://example.com/categorized"))
    # Manually categorize the second item
    conn.execute(
        "UPDATE news_items SET category = 'Vulnerability' WHERE url = ?",
        ("https://example.com/categorized",),
    )
    rows = db.get_uncategorized_items(conn)
    assert len(rows) == 1
    assert rows[0]["url"] == "https://example.com/uncategorized"


def test_get_uncategorized_respects_limit(conn):
    for i in range(5):
        db.insert_news_item(conn, _make_item(url=f"https://example.com/item{i}"))
    rows = db.get_uncategorized_items(conn, limit=3)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# update_item_categorization
# ---------------------------------------------------------------------------


def test_update_item_categorization_sets_all_fields(conn):
    db.insert_news_item(conn, _make_item())
    row_id = conn.execute("SELECT id FROM news_items").fetchone()["id"]

    db.update_item_categorization(
        conn,
        row_id,
        summary="A critical vulnerability in Example Library.",
        category="Vulnerability",
        severity="Critical",
        affected_products=["Example Library", "SomeVendor"],
        tags=["rce", "cve"],
        cluster_id="CVE-2024-1234",
    )

    row = conn.execute("SELECT * FROM news_items WHERE id = ?", (row_id,)).fetchone()
    assert row["category"] == "Vulnerability"
    assert row["severity"] == "Critical"
    assert row["summary"] == "A critical vulnerability in Example Library."
    assert row["cluster_id"] == "CVE-2024-1234"
    assert json.loads(row["affected_products"]) == ["Example Library", "SomeVendor"]
    assert json.loads(row["tags"]) == ["rce", "cve"]


# ---------------------------------------------------------------------------
# run_log
# ---------------------------------------------------------------------------


def test_start_run_returns_integer_id(conn):
    run_id = db.start_run(conn)
    assert isinstance(run_id, int)
    assert run_id > 0


def test_finish_run_records_stats(conn):
    run_id = db.start_run(conn)
    db.finish_run(
        conn,
        run_id,
        status="success",
        items_collected=42,
        items_categorized=40,
        findings_new=3,
        findings_total=10,
    )
    row = conn.execute("SELECT * FROM run_log WHERE id = ?", (run_id,)).fetchone()
    assert row["status"] == "success"
    assert row["items_collected"] == 42
    assert row["items_categorized"] == 40
    assert row["findings_new"] == 3
    assert row["completed_at"] is not None


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_get_setting_returns_default_when_missing(conn):
    assert db.get_setting(conn, "nonexistent_key", default="fallback") == "fallback"


def test_set_and_get_setting_roundtrip(conn):
    db.set_setting(conn, "schedule_hours", "12")
    assert db.get_setting(conn, "schedule_hours") == "12"


def test_set_setting_overwrites_existing(conn):
    db.set_setting(conn, "model", "qwen2.5:3b")
    db.set_setting(conn, "model", "gemma2:2b")
    assert db.get_setting(conn, "model") == "gemma2:2b"


# ---------------------------------------------------------------------------
# Secret findings — commit-independent dedup (A1)
# ---------------------------------------------------------------------------


def _make_secret(**overrides) -> dict:
    base = {
        "repo_full_name": "owner/repo",
        "file_path": "config/settings.py",
        "line_number": 12,
        "commit_sha": "abc1234",
        "secret_type": "GitHub PAT",
        "rule_id": "github-pat",
        "fingerprint": "abc1234:config/settings.py:github-pat:12",
    }
    base.update(overrides)
    return base


def _secret_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) AS n FROM secret_findings").fetchone()["n"]


def test_upsert_secret_finding_new_returns_true(conn):
    assert db.upsert_secret_finding(conn, _make_secret()) is True
    assert _secret_count(conn) == 1


def test_upsert_secret_finding_same_match_key_diff_commit_no_dup(conn):
    """The boundary commit slides across shallow-clone runs: same secret, new
    commit_sha and fingerprint. It must NOT create a second row."""
    db.upsert_secret_finding(conn, _make_secret())
    second = db.upsert_secret_finding(
        conn,
        _make_secret(
            commit_sha="def5678",
            fingerprint="def5678:config/settings.py:github-pat:12",
        ),
    )
    assert second is False
    assert _secret_count(conn) == 1
    # The latest sighting's commit/fingerprint are refreshed on the surviving row.
    row = conn.execute("SELECT commit_sha, fingerprint FROM secret_findings").fetchone()
    assert row["commit_sha"] == "def5678"
    assert row["fingerprint"] == "def5678:config/settings.py:github-pat:12"


def test_upsert_secret_finding_distinct_secrets_kept(conn):
    db.upsert_secret_finding(
        conn, _make_secret(line_number=12, fingerprint="abc1234:config/settings.py:github-pat:12")
    )
    db.upsert_secret_finding(
        conn, _make_secret(line_number=40, fingerprint="abc1234:config/settings.py:github-pat:40")
    )
    assert _secret_count(conn) == 2


def test_upsert_secret_finding_fingerprint_collision_across_match_keys_no_crash(conn):
    """Regression test for a live failure: gitleaks reported two findings at
    the identical commit/file/rule/line with different secret_type
    descriptions. Their match_keys differ (secret_type is part of the key)
    but gitleaks's Fingerprint — the column with the actual UNIQUE
    constraint — does not depend on secret_type, so it collided. The naive
    match_key-only lookup missed this and the second INSERT raised
    sqlite3.IntegrityError instead of updating the existing row.
    """
    same_fingerprint = "abc1234:config/settings.py:generic-api-key:12"
    assert (
        db.upsert_secret_finding(
            conn,
            _make_secret(
                secret_type="Generic API Key",
                rule_id="generic-api-key",
                fingerprint=same_fingerprint,
            ),
        )
        is True
    )

    # Must not raise, and must not be counted as a second brand-new finding.
    second = db.upsert_secret_finding(
        conn,
        _make_secret(
            secret_type="AWS Access Key",  # different description, same location
            rule_id="generic-api-key",
            fingerprint=same_fingerprint,
        ),
    )
    assert second is False
    assert _secret_count(conn) == 1

    # match_key and secret_type are both refreshed to the latest sighting, so
    # the row never stores a match_key that describes a different secret_type
    # than what's in the secret_type column.
    row = conn.execute("SELECT match_key, secret_type FROM secret_findings").fetchone()
    assert row["secret_type"] == "AWS Access Key"
    expected_key = db.secret_match_key(
        "owner/repo", "config/settings.py", "generic-api-key", "AWS Access Key", 12
    )
    assert row["match_key"] == expected_key


def test_migrate_dedupes_existing_secret_duplicates(conn):
    """Rows created before the match_key migration (same secret, different
    commit) must collapse to one when the backfill runs.

    Calls _migrate_secret_findings_backfill directly rather than _migrate()
    — the `conn` fixture already ran init() once, which stamps
    schema_version and makes _migrate() a no-op for this one-time data
    migration on subsequent calls (see _SCHEMA_VERSION). That gating is
    exactly the point of M4.7; this test is about the dedup logic itself.
    """
    now = "2024-01-01T00:00:00+00:00"
    for i, sha in enumerate(("c1", "c2", "c3")):
        conn.execute(
            """
            INSERT INTO secret_findings
                (repo_full_name, file_path, line_number, commit_sha,
                 secret_type, rule_id, fingerprint, match_key, state,
                 first_seen_at, last_seen_at)
            VALUES (?,?,?,?,?,?,?,NULL,'new',?,?)
            """,
            (
                "owner/repo",
                "a.py",
                5,
                sha,
                "PAT",
                "github-pat",
                f"{sha}:a.py:github-pat:5",
                now,
                now,
            ),
        )
    assert _secret_count(conn) == 3
    db._migrate_secret_findings_backfill(conn)
    assert _secret_count(conn) == 1
    row = conn.execute("SELECT match_key FROM secret_findings").fetchone()
    assert row["match_key"] == db.secret_match_key("owner/repo", "a.py", "github-pat", "PAT", 5)


def test_migrate_dedup_keeps_false_positive(conn):
    """A user-triaged false_positive must survive dedup over a plain 'new' dup."""
    now = "2024-01-01T00:00:00+00:00"
    rows = [("c1", "new"), ("c2", "false_positive")]
    for sha, state in rows:
        conn.execute(
            """
            INSERT INTO secret_findings
                (repo_full_name, file_path, line_number, commit_sha,
                 secret_type, rule_id, fingerprint, match_key, state,
                 first_seen_at, last_seen_at)
            VALUES (?,?,?,?,?,?,?,NULL,?,?,?)
            """,
            (
                "owner/repo",
                "a.py",
                5,
                sha,
                "PAT",
                "github-pat",
                f"{sha}:a.py:github-pat:5",
                state,
                now,
                now,
            ),
        )
    db._migrate_secret_findings_backfill(conn)
    assert _secret_count(conn) == 1
    assert conn.execute("SELECT state FROM secret_findings").fetchone()["state"] == "false_positive"


# ---------------------------------------------------------------------------
# Schema versioning (M4.7)
# ---------------------------------------------------------------------------


def test_migrate_stamps_schema_version_on_fresh_init(conn):
    """db.init() (via the `conn` fixture) already ran _migrate() once —
    schema_version must be at the current version afterward."""
    assert db._get_schema_version(conn) == db._SCHEMA_VERSION


def test_migrate_skips_one_time_dedup_when_version_current(conn, monkeypatch):
    """Once schema_version is current, _migrate() must not re-run the
    full-table dedup/backfill passes — that's the whole point of gating them.
    """
    calls = []
    monkeypatch.setattr(db, "_dedup_aliased_findings", lambda c: calls.append("dedup"))
    monkeypatch.setattr(db, "_migrate_secret_findings_backfill", lambda c: calls.append("backfill"))
    monkeypatch.setattr(db, "_migrate_default_feed_urls", lambda c: calls.append("feeds"))

    db._migrate(conn)  # schema_version is already current from the fixture's init()

    assert calls == []


def test_migrate_runs_one_time_dedup_when_version_stale(conn, monkeypatch):
    """Simulates upgrading from a pre-M4.7 install: schema_version absent/0
    must still trigger the one-time migrations exactly once."""
    conn.execute("DELETE FROM settings WHERE key = 'schema_version'")
    assert db._get_schema_version(conn) == 0

    calls = []
    monkeypatch.setattr(db, "_dedup_aliased_findings", lambda c: calls.append("dedup"))
    monkeypatch.setattr(db, "_migrate_secret_findings_backfill", lambda c: calls.append("backfill"))
    monkeypatch.setattr(db, "_migrate_default_feed_urls", lambda c: calls.append("feeds"))

    db._migrate(conn)

    assert set(calls) == {"dedup", "backfill", "feeds"}
    assert db._get_schema_version(conn) == db._SCHEMA_VERSION


def test_migrate_secret_findings_columns_always_runs(conn):
    """The match_key column + its index must exist even though the backfill
    pass that also touches this table is version-gated."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(secret_findings)").fetchall()}
    assert "match_key" in cols
    indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_secrets_matchkey" in indexes


# ---------------------------------------------------------------------------
# News retention (A3)
# ---------------------------------------------------------------------------


def test_delete_old_news_removes_old_keeps_recent(conn):
    db.insert_news_item(
        conn, _make_item(url="https://x/old", fetched_at="2020-01-01T00:00:00+00:00")
    )
    db.insert_news_item(conn, _make_item(url="https://x/new", fetched_at=db._now()))
    deleted = db.delete_old_news(conn, days=30)
    assert deleted == 1
    remaining = conn.execute("SELECT url FROM news_items").fetchall()
    assert [r["url"] for r in remaining] == ["https://x/new"]


def test_delete_old_news_preserves_bookmarked(conn):
    db.insert_news_item(
        conn, _make_item(url="https://x/old", fetched_at="2020-01-01T00:00:00+00:00")
    )
    item_id = conn.execute("SELECT id FROM news_items WHERE url = 'https://x/old'").fetchone()["id"]
    db.add_bookmark(conn, item_id)
    deleted = db.delete_old_news(conn, days=30, preserve_bookmarked=True)
    assert deleted == 0
    assert conn.execute("SELECT COUNT(*) AS n FROM news_items").fetchone()["n"] == 1


def test_delete_old_news_disabled_is_noop(conn):
    db.insert_news_item(
        conn, _make_item(url="https://x/old", fetched_at="2020-01-01T00:00:00+00:00")
    )
    assert db.delete_old_news(conn, days=0) == 0
    assert conn.execute("SELECT COUNT(*) AS n FROM news_items").fetchone()["n"] == 1


# ---------------------------------------------------------------------------
# Filtered export (A4)
# ---------------------------------------------------------------------------


def test_get_news_items_for_export_filters(conn):
    db.insert_news_item(conn, _make_item(url="https://x/a", source="Feed A"))
    db.insert_news_item(conn, _make_item(url="https://x/b", source="Feed B"))
    rows = db.get_news_items_for_export(conn, source="Feed A")
    assert [r["source"] for r in rows] == ["Feed A"]
    assert len(db.get_news_items_for_export(conn)) == 2


def test_get_findings_for_export_filters(conn):
    db.upsert_finding(
        conn,
        {
            "repo_full_name": "owner/a",
            "package_name": "requests",
            "package_ecosystem": "PyPI",
            "cve_id": "CVE-2024-1",
        },
    )
    db.upsert_finding(
        conn,
        {
            "repo_full_name": "owner/b",
            "package_name": "flask",
            "package_ecosystem": "PyPI",
            "cve_id": "CVE-2024-2",
        },
    )
    rows = db.get_findings_for_export(conn, repo="owner/a")
    assert [r["repo_full_name"] for r in rows] == ["owner/a"]
    assert len(db.get_findings_for_export(conn)) == 2


# ---------------------------------------------------------------------------
# Repo dropdown helpers (replaced a reach-in to db._findings_where from main)
# ---------------------------------------------------------------------------


def _insert_finding_row(conn, cve, first_seen_at, state="new", repo="owner/a"):
    conn.execute(
        """
        INSERT INTO findings
            (repo_full_name, package_name, package_ecosystem, cve_id,
             state, first_seen_at, last_seen_at)
        VALUES (?, 'pkg', 'PyPI', ?, ?, ?, ?)
        """,
        (repo, cve, state, first_seen_at, first_seen_at),
    )


def _insert_secret_row(conn, file_path, first_seen_at, state="new", repo="owner/a"):
    conn.execute(
        """
        INSERT INTO secret_findings
            (repo_full_name, file_path, line_number, commit_sha, secret_type,
             rule_id, fingerprint, state, first_seen_at, last_seen_at)
        VALUES (?, ?, 1, 'abc', 'AWS Key', 'aws-key', ?, ?, ?, ?)
        """,
        (repo, file_path, f"fp-{repo}-{file_path}", state, first_seen_at, first_seen_at),
    )


def test_get_finding_repos_is_sorted_and_deduped(conn):
    _insert_finding_row(conn, "CVE-1", "2026-01-01T00:00:00+00:00", repo="owner/b")
    _insert_finding_row(conn, "CVE-2", "2026-01-01T00:00:00+00:00", repo="owner/a")
    _insert_finding_row(conn, "CVE-3", "2026-01-01T00:00:00+00:00", repo="owner/a")
    assert db.get_finding_repos(conn) == ["owner/a", "owner/b"]


def test_get_finding_repos_excludes_repo_with_only_resolved_under_unresolved(conn):
    _insert_finding_row(conn, "CVE-1", "2026-01-01T00:00:00+00:00", state="new", repo="owner/open")
    _insert_finding_row(
        conn, "CVE-2", "2026-01-01T00:00:00+00:00", state="resolved", repo="owner/done"
    )
    assert db.get_finding_repos(conn, state="unresolved") == ["owner/open"]
    # ...but 'all' still offers both.
    assert db.get_finding_repos(conn, state=None) == ["owner/done", "owner/open"]


def test_get_finding_repos_honors_since(conn):
    _insert_finding_row(conn, "CVE-1", "2026-01-05T00:00:00+00:00", repo="owner/fresh")
    _insert_finding_row(conn, "CVE-2", "2025-01-01T00:00:00+00:00", repo="owner/stale")
    assert db.get_finding_repos(conn, since="2026-01-01T00:00:00+00:00") == ["owner/fresh"]


def test_get_secret_repos_honors_state_and_since(conn):
    _insert_secret_row(conn, "a.py", "2026-01-05T00:00:00+00:00", repo="owner/fresh")
    _insert_secret_row(conn, "b.py", "2025-01-01T00:00:00+00:00", repo="owner/stale")
    _insert_secret_row(
        conn, "c.py", "2026-01-05T00:00:00+00:00", state="resolved", repo="owner/done"
    )

    assert db.get_secret_repos(conn) == ["owner/done", "owner/fresh", "owner/stale"]
    assert db.get_secret_repos(conn, state="unresolved") == ["owner/fresh", "owner/stale"]
    assert db.get_secret_repos(conn, since="2026-01-01T00:00:00+00:00") == [
        "owner/done",
        "owner/fresh",
    ]


# ---------------------------------------------------------------------------
# Secrets state machine — bulk/single parity and reopen
# ---------------------------------------------------------------------------


def test_bulk_resolve_accepts_false_positive_rows(conn):
    """Bulk resolve guarded on state='new', so a false_positive row silently
    stayed put while the single-item route resolved it fine."""
    _insert_secret_row(conn, "fp.py", "2026-01-01T00:00:00+00:00", state="false_positive")
    _insert_secret_row(conn, "open.py", "2026-01-01T00:00:00+00:00", state="new")
    ids = [r["id"] for r in conn.execute("SELECT id FROM secret_findings").fetchall()]

    assert db.bulk_update_secret_state(conn, ids, "resolve") == 2
    states = {r["state"] for r in conn.execute("SELECT state FROM secret_findings").fetchall()}
    assert states == {"resolved"}


def test_bulk_resolve_skips_already_resolved(conn):
    _insert_secret_row(conn, "done.py", "2026-01-01T00:00:00+00:00", state="resolved")
    ids = [r["id"] for r in conn.execute("SELECT id FROM secret_findings").fetchall()]
    assert db.bulk_update_secret_state(conn, ids, "resolve") == 0


def test_reopen_secret_finding_clears_notified_at(conn):
    _insert_secret_row(conn, "leak.py", "2026-01-01T00:00:00+00:00", state="resolved")
    sid = conn.execute("SELECT id FROM secret_findings").fetchone()["id"]
    conn.execute("UPDATE secret_findings SET notified_at = ? WHERE id = ?", ("2026-01-01", sid))

    assert db.reopen_secret_finding(conn, sid) is True
    row = conn.execute(
        "SELECT state, notified_at FROM secret_findings WHERE id = ?", (sid,)
    ).fetchone()
    assert row["state"] == "new"
    # Cleared so the notifier re-alerts, matching findings' reopen.
    assert row["notified_at"] is None


def test_reopen_secret_finding_only_applies_to_resolved(conn):
    _insert_secret_row(conn, "leak.py", "2026-01-01T00:00:00+00:00", state="new")
    sid = conn.execute("SELECT id FROM secret_findings").fetchone()["id"]
    assert db.reopen_secret_finding(conn, sid) is False


# ---------------------------------------------------------------------------
# Export column contracts
# ---------------------------------------------------------------------------


def test_get_secret_findings_for_export_column_contract(conn):
    """Explicit column list — adding a secret_findings column must not
    silently widen the export, and the dedup keys must stay out."""
    _insert_secret_row(conn, "leak.py", "2026-01-01T00:00:00+00:00")
    rows = db.get_secret_findings_for_export(conn)
    assert len(rows) == 1
    assert sorted(rows[0].keys()) == sorted(
        [
            "id",
            "repo_full_name",
            "file_path",
            "line_number",
            "commit_sha",
            "secret_type",
            "rule_id",
            "state",
            "first_seen_at",
            "last_seen_at",
            "notified_at",
        ]
    )
    assert "fingerprint" not in rows[0].keys()
    assert "match_key" not in rows[0].keys()


def test_get_secret_findings_for_export_honors_filters(conn):
    _insert_secret_row(conn, "a.py", "2026-01-05T00:00:00+00:00", repo="owner/a")
    _insert_secret_row(conn, "b.py", "2026-01-05T00:00:00+00:00", repo="owner/b")
    _insert_secret_row(conn, "c.py", "2026-01-05T00:00:00+00:00", state="resolved", repo="owner/a")

    assert sorted(
        r["file_path"] for r in db.get_secret_findings_for_export(conn, repo="owner/a")
    ) == ["a.py", "c.py"]
    assert sorted(
        r["file_path"] for r in db.get_secret_findings_for_export(conn, state="unresolved")
    ) == ["a.py", "b.py"]


def test_get_secret_findings_for_export_order_is_newest_first(conn):
    """ORDER BY first_seen_at DESC, id DESC — the id tiebreak keeps the order
    stable when two rows share a timestamp."""
    _insert_secret_row(conn, "old.py", "2025-01-01T00:00:00+00:00")
    _insert_secret_row(conn, "tie-first.py", "2026-01-05T00:00:00+00:00")
    _insert_secret_row(conn, "tie-second.py", "2026-01-05T00:00:00+00:00")

    order = [r["file_path"] for r in db.get_secret_findings_for_export(conn)]
    assert order == ["tie-second.py", "tie-first.py", "old.py"]


def test_get_findings_for_export_honors_since(conn):
    _insert_finding_row(conn, "CVE-FRESH", "2026-01-05T00:00:00+00:00")
    _insert_finding_row(conn, "CVE-STALE", "2025-01-01T00:00:00+00:00")
    rows = db.get_findings_for_export(conn, since="2026-01-01T00:00:00+00:00")
    assert [r["cve_id"] for r in rows] == ["CVE-FRESH"]


def test_get_findings_for_export_annotated_filter(conn):
    _insert_finding_row(conn, "CVE-NOTED", "2026-01-05T00:00:00+00:00")
    _insert_finding_row(conn, "CVE-PLAIN", "2026-01-05T00:00:00+00:00")
    fid = conn.execute("SELECT id FROM findings WHERE cve_id = 'CVE-NOTED'").fetchone()["id"]
    db.set_finding_annotation(conn, fid, "note")

    rows = db.get_findings_for_export(conn, annotated=True)
    assert [r["cve_id"] for r in rows] == ["CVE-NOTED"]
    # An empty-string annotation counts as absent, matching set_finding_annotation's clear.
    conn.execute("UPDATE findings SET annotation = '' WHERE id = ?", (fid,))
    assert db.get_findings_for_export(conn, annotated=True) == []


def test_get_news_items_for_export_bookmarked_filter(conn):
    db.insert_news_item(conn, _make_item(url="https://x/a", source="Feed A"))
    db.insert_news_item(conn, _make_item(url="https://x/b", source="Feed B"))
    nid = conn.execute("SELECT id FROM news_items WHERE source = 'Feed A'").fetchone()["id"]
    db.add_bookmark(conn, nid)

    rows = db.get_news_items_for_export(conn, bookmarked=True)
    assert [r["source"] for r in rows] == ["Feed A"]
    # Composes with the other filters rather than replacing them.
    assert db.get_news_items_for_export(conn, bookmarked=True, source="Feed B") == []
