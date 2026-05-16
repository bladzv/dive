"""
Unit tests for db.py — schema creation, insert/dedup, queries, settings.

All tests use a temporary in-memory SQLite database; no file I/O.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import db


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
            for row in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "news_items" in tables
    assert "findings" in tables
    assert "run_log" in tables
    assert "settings" in tables


def test_init_is_idempotent(tmp_db: Path):
    """Calling init() a second time must not raise."""
    db.init(tmp_db)
    db.init(tmp_db)


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
