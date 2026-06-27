"""
Unit tests for settings.py — RSS feeds, keywords, feature toggles, scanner settings.

All tests use a temporary initialised SQLite database; no file I/O beyond that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import dive.db as db
import dive.settings as settings

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test.db"
    db.init(db_path)
    return db_path


@pytest.fixture
def conn(tmp_db: Path):
    with db.get_conn(tmp_db) as c:
        yield c


# ---------------------------------------------------------------------------
# RSS Feeds
# ---------------------------------------------------------------------------


class TestGetFeeds:
    def test_bootstraps_defaults_when_empty(self, conn):
        rows = settings.get_feeds(conn)
        assert len(rows) == len(settings.DEFAULT_FEEDS)

    def test_bootstrap_only_once(self, conn):
        settings.get_feeds(conn)
        settings.get_feeds(conn)
        rows = conn.execute("SELECT COUNT(*) FROM rss_feeds").fetchone()[0]
        assert rows == len(settings.DEFAULT_FEEDS)

    def test_default_feeds_are_marked_is_default(self, conn):
        rows = settings.get_feeds(conn)
        assert all(row["is_default"] == 1 for row in rows)

    def test_default_feeds_are_enabled(self, conn):
        rows = settings.get_feeds(conn)
        assert all(row["enabled"] == 1 for row in rows)


class TestGetEnabledFeeds:
    def test_returns_only_enabled(self, conn):
        settings.get_feeds(conn)
        first = conn.execute("SELECT id FROM rss_feeds LIMIT 1").fetchone()["id"]
        settings.set_feed_enabled(conn, first, False)
        enabled = settings.get_enabled_feeds(conn)
        ids = [r["id"] for r in enabled]
        assert first not in ids

    def test_bootstraps_when_empty(self, conn):
        rows = settings.get_enabled_feeds(conn)
        assert len(rows) == len(settings.DEFAULT_FEEDS)


class TestAddFeed:
    def test_add_user_feed(self, conn):
        row = settings.add_feed(conn, "My Blog", "https://example.com/feed.xml")
        assert row["name"] == "My Blog"
        assert row["url"] == "https://example.com/feed.xml"
        assert row["is_default"] == 0
        assert row["enabled"] == 1

    def test_duplicate_url_raises(self, conn):
        settings.add_feed(conn, "Blog", "https://example.com/feed.xml")
        with pytest.raises(ValueError, match="already exists"):
            settings.add_feed(conn, "Blog 2", "https://example.com/feed.xml")

    def test_added_feed_appears_in_get_feeds(self, conn):
        settings.add_feed(conn, "New", "https://new.example.com/rss")
        urls = [r["url"] for r in settings.get_feeds(conn)]
        assert "https://new.example.com/rss" in urls


class TestSetFeedEnabled:
    def test_disable_feed(self, conn):
        settings.get_feeds(conn)
        feed_id = conn.execute("SELECT id FROM rss_feeds LIMIT 1").fetchone()["id"]
        result = settings.set_feed_enabled(conn, feed_id, False)
        assert result is True
        row = conn.execute("SELECT enabled FROM rss_feeds WHERE id=?", (feed_id,)).fetchone()
        assert row["enabled"] == 0

    def test_enable_feed(self, conn):
        settings.get_feeds(conn)
        feed_id = conn.execute("SELECT id FROM rss_feeds LIMIT 1").fetchone()["id"]
        settings.set_feed_enabled(conn, feed_id, False)
        settings.set_feed_enabled(conn, feed_id, True)
        row = conn.execute("SELECT enabled FROM rss_feeds WHERE id=?", (feed_id,)).fetchone()
        assert row["enabled"] == 1

    def test_nonexistent_id_returns_false(self, conn):
        assert settings.set_feed_enabled(conn, 99999, True) is False


class TestRemoveFeed:
    def test_remove_user_feed(self, conn):
        settings.add_feed(conn, "Temp", "https://temp.example.com/rss")
        feed_id = conn.execute(
            "SELECT id FROM rss_feeds WHERE url=?", ("https://temp.example.com/rss",)
        ).fetchone()["id"]
        result = settings.remove_feed(conn, feed_id)
        assert result is True
        row = conn.execute("SELECT id FROM rss_feeds WHERE id=?", (feed_id,)).fetchone()
        assert row is None

    def test_remove_default_feed_raises(self, conn):
        settings.get_feeds(conn)
        default_id = conn.execute("SELECT id FROM rss_feeds WHERE is_default=1 LIMIT 1").fetchone()[
            "id"
        ]
        with pytest.raises(ValueError, match="Default feeds cannot be deleted"):
            settings.remove_feed(conn, default_id)

    def test_remove_nonexistent_returns_false(self, conn):
        assert settings.remove_feed(conn, 99999) is False


class TestSyncDefaultFeedUrls:
    def test_updates_changed_url(self, conn):
        settings.get_feeds(conn)
        old_url = "https://old.example.com/feed"
        name = settings.DEFAULT_FEEDS[0][0]
        conn.execute("UPDATE rss_feeds SET url = ? WHERE name = ?", (old_url, name))
        settings.sync_default_feed_urls(conn)
        row = conn.execute("SELECT url FROM rss_feeds WHERE name = ?", (name,)).fetchone()
        assert row["url"] == settings.DEFAULT_FEEDS[0][1]

    def test_skips_user_renamed_feed(self, conn):
        settings.get_feeds(conn)
        canonical_url = settings.DEFAULT_FEEDS[0][1]
        conn.execute(
            "UPDATE rss_feeds SET url = ?, name = 'My Custom Name' WHERE is_default = 1 AND name = ?",
            (canonical_url, settings.DEFAULT_FEEDS[0][0]),
        )
        conn.execute(
            "UPDATE rss_feeds SET url = 'https://stale.example.com' WHERE name = 'My Custom Name'"
        )
        settings.sync_default_feed_urls(conn)
        row = conn.execute("SELECT url FROM rss_feeds WHERE name = 'My Custom Name'").fetchone()
        assert row["url"] == "https://stale.example.com"

    def test_no_op_when_urls_match(self, conn):
        settings.get_feeds(conn)
        settings.sync_default_feed_urls(conn)
        urls = [r["url"] for r in settings.get_feeds(conn)]
        expected = [url for _, url in settings.DEFAULT_FEEDS]
        assert sorted(urls) == sorted(expected)


class TestUpdateFeed:
    def test_update_url(self, conn):
        row = settings.add_feed(conn, "My Feed", "https://a.example.com/rss")
        result = settings.update_feed(conn, row["id"], url="https://b.example.com/rss")
        assert result is True
        updated = conn.execute("SELECT url FROM rss_feeds WHERE id=?", (row["id"],)).fetchone()
        assert updated["url"] == "https://b.example.com/rss"

    def test_update_url_resets_stats(self, conn):
        row = settings.add_feed(conn, "Stats Feed", "https://c.example.com/rss")
        settings.update_feed_stats(conn, "https://c.example.com/rss", "2025-01-01T00:00:00", 42)
        settings.update_feed(conn, row["id"], url="https://d.example.com/rss")
        updated = conn.execute(
            "SELECT last_fetched_at, item_count FROM rss_feeds WHERE id=?", (row["id"],)
        ).fetchone()
        assert updated["last_fetched_at"] is None
        assert updated["item_count"] == 0

    def test_update_name_only(self, conn):
        row = settings.add_feed(conn, "Old Name", "https://e.example.com/rss")
        settings.update_feed(conn, row["id"], name="New Name")
        updated = conn.execute(
            "SELECT name, url FROM rss_feeds WHERE id=?", (row["id"],)
        ).fetchone()
        assert updated["name"] == "New Name"
        assert updated["url"] == "https://e.example.com/rss"

    def test_update_name_only_does_not_reset_stats(self, conn):
        row = settings.add_feed(conn, "Named Feed", "https://f.example.com/rss")
        settings.update_feed_stats(conn, "https://f.example.com/rss", "2025-01-01T00:00:00", 5)
        settings.update_feed(conn, row["id"], name="Renamed")
        updated = conn.execute(
            "SELECT item_count FROM rss_feeds WHERE id=?", (row["id"],)
        ).fetchone()
        assert updated["item_count"] == 5

    def test_duplicate_url_raises(self, conn):
        r1 = settings.add_feed(conn, "Feed 1", "https://g.example.com/rss")
        r2 = settings.add_feed(conn, "Feed 2", "https://h.example.com/rss")
        with pytest.raises(ValueError, match="already exists"):
            settings.update_feed(conn, r2["id"], url=r1["url"])

    def test_nonexistent_id_returns_false(self, conn):
        assert settings.update_feed(conn, 99999, name="X") is False

    def test_works_on_default_feed(self, conn):
        settings.get_feeds(conn)
        default_id = conn.execute("SELECT id FROM rss_feeds WHERE is_default=1 LIMIT 1").fetchone()[
            "id"
        ]
        result = settings.update_feed(conn, default_id, name="My Custom Name")
        assert result is True


class TestUpdateFeedStats:
    def test_updates_last_fetched_and_item_count(self, conn):
        settings.add_feed(conn, "Stats Feed", "https://stats.example.com/rss")
        settings.update_feed_stats(
            conn, "https://stats.example.com/rss", "2025-01-01T00:00:00+00:00", 10
        )
        row = conn.execute(
            "SELECT last_fetched_at, item_count FROM rss_feeds WHERE url=?",
            ("https://stats.example.com/rss",),
        ).fetchone()
        assert row["last_fetched_at"] == "2025-01-01T00:00:00+00:00"
        assert row["item_count"] == 10

    def test_item_count_accumulates(self, conn):
        settings.add_feed(conn, "Acc Feed", "https://acc.example.com/rss")
        settings.update_feed_stats(
            conn, "https://acc.example.com/rss", "2025-01-01T00:00:00+00:00", 5
        )
        settings.update_feed_stats(
            conn, "https://acc.example.com/rss", "2025-01-02T00:00:00+00:00", 3
        )
        row = conn.execute(
            "SELECT item_count FROM rss_feeds WHERE url=?",
            ("https://acc.example.com/rss",),
        ).fetchone()
        assert row["item_count"] == 8


# ---------------------------------------------------------------------------
# Keywords
# ---------------------------------------------------------------------------


class TestKeywords:
    def test_get_empty(self, conn):
        assert settings.get_keywords(conn) == []

    def test_add_keyword(self, conn):
        row = settings.add_keyword(conn, "nginx")
        assert row["keyword"] == "nginx"

    def test_keywords_ordered_alphabetically(self, conn):
        settings.add_keyword(conn, "zookeeper")
        settings.add_keyword(conn, "apache")
        settings.add_keyword(conn, "nginx")
        words = [r["keyword"] for r in settings.get_keywords(conn)]
        assert words == sorted(words)

    def test_duplicate_raises(self, conn):
        settings.add_keyword(conn, "log4j")
        with pytest.raises(ValueError, match="already exists"):
            settings.add_keyword(conn, "log4j")

    def test_duplicate_case_insensitive(self, conn):
        settings.add_keyword(conn, "Log4J")
        with pytest.raises(ValueError, match="already exists"):
            settings.add_keyword(conn, "log4j")

    def test_empty_keyword_raises(self, conn):
        with pytest.raises(ValueError, match="cannot be empty"):
            settings.add_keyword(conn, "   ")

    def test_remove_keyword(self, conn):
        row = settings.add_keyword(conn, "cve")
        assert settings.remove_keyword(conn, row["id"]) is True
        assert settings.get_keywords(conn) == []

    def test_remove_nonexistent_returns_false(self, conn):
        assert settings.remove_keyword(conn, 99999) is False


# ---------------------------------------------------------------------------
# Feature Toggles
# ---------------------------------------------------------------------------


class TestFeatureToggles:
    def test_all_toggles_returned(self, conn):
        result = settings.get_feature_toggles(conn)
        assert set(result.keys()) == set(settings.FEATURE_TOGGLES.keys())

    def test_defaults_applied_when_not_set(self, conn):
        result = settings.get_feature_toggles(conn)
        for key, meta in settings.FEATURE_TOGGLES.items():
            assert result[key] == meta["default"]

    def test_set_and_get_toggle(self, conn):
        settings.set_feature_toggle(conn, "github_scanning", False)
        result = settings.get_feature_toggles(conn)
        assert result["github_scanning"] is False

    def test_set_toggle_true(self, conn):
        settings.set_feature_toggle(conn, "github_issue_creation", True)
        result = settings.get_feature_toggles(conn)
        assert result["github_issue_creation"] is True

    def test_unknown_toggle_raises(self, conn):
        with pytest.raises(ValueError, match="Unknown feature toggle"):
            settings.set_feature_toggle(conn, "nonexistent_toggle", True)

    def test_is_feature_enabled_default(self, conn):
        assert settings.is_feature_enabled(conn, "github_scanning") is True
        assert settings.is_feature_enabled(conn, "github_issue_creation") is False

    def test_is_feature_enabled_after_set(self, conn):
        settings.set_feature_toggle(conn, "github_scanning", False)
        assert settings.is_feature_enabled(conn, "github_scanning") is False

    def test_unknown_feature_defaults_true(self, conn):
        assert settings.is_feature_enabled(conn, "completely_unknown") is True


# ---------------------------------------------------------------------------
# Scanner Settings
# ---------------------------------------------------------------------------


class TestSeverityThreshold:
    def test_default_is_high(self, conn):
        assert settings.get_severity_threshold(conn) == "high"

    def test_set_and_get(self, conn):
        settings.set_severity_threshold(conn, "critical")
        assert settings.get_severity_threshold(conn) == "critical"

    def test_all_valid_levels(self, conn):
        for level in settings.SEVERITY_LEVELS:
            settings.set_severity_threshold(conn, level)
            assert settings.get_severity_threshold(conn) == level

    def test_invalid_level_raises(self, conn):
        with pytest.raises(ValueError, match="Invalid threshold"):
            settings.set_severity_threshold(conn, "extreme")

    def test_corrupt_value_falls_back_to_default(self, conn):
        db.set_setting(conn, "scanner.severity_threshold", "bogus")
        assert settings.get_severity_threshold(conn) == "high"


class TestExcludedRepos:
    def test_default_is_empty(self, conn):
        assert settings.get_excluded_repos(conn) == []

    def test_set_and_get(self, conn):
        repos = ["owner/repo-a", "owner/repo-b"]
        settings.set_excluded_repos(conn, repos)
        assert settings.get_excluded_repos(conn) == repos

    def test_set_empty_list(self, conn):
        settings.set_excluded_repos(conn, ["x/y"])
        settings.set_excluded_repos(conn, [])
        assert settings.get_excluded_repos(conn) == []

    def test_corrupt_json_falls_back_to_empty(self, conn):
        db.set_setting(conn, "scanner.excluded_repos", "not-json")
        assert settings.get_excluded_repos(conn) == []

    def test_corrupt_non_list_falls_back_to_empty(self, conn):
        db.set_setting(conn, "scanner.excluded_repos", '{"a": 1}')
        assert settings.get_excluded_repos(conn) == []


class TestNewsRetention:
    def test_default_is_disabled(self, conn):
        assert settings.get_news_retention_days(conn) == 0

    def test_roundtrip(self, conn):
        settings.set_news_retention_days(conn, 90)
        assert settings.get_news_retention_days(conn) == 90

    def test_rejects_negative(self, conn):
        with pytest.raises(ValueError):
            settings.set_news_retention_days(conn, -1)

    def test_corrupt_value_falls_back_to_default(self, conn):
        db.set_setting(conn, "news.retention_days", "not-a-number")
        assert settings.get_news_retention_days(conn) == 0
