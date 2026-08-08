"""
Unit tests for the M5 web dashboard — HTML routes and new API endpoints.

Uses FastAPI's TestClient without triggering the lifespan (no scheduler,
no config.yaml needed). main._config and db._DEFAULT_DB_PATH are patched
directly so the route handlers work against a clean in-memory database.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import dive.db as db
import dive.main as main
from dive.main import _require_auth, app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _setup(tmp_path: Path, monkeypatch):
    """Patch DB path + _config before each test; restore after."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "_DEFAULT_DB_PATH", db_path)
    db.init(db_path)

    # Store a known run token so /api/run tests can use it
    with db.get_conn(db_path) as conn:
        db.set_setting(conn, "run_token", "test-token-abc")

    # Build a minimal mock config
    cfg = MagicMock()
    cfg.ollama.host = "http://localhost:11434"
    cfg.ollama.model = "qwen2.5:3b"
    cfg.dashboard.username = "admin"
    cfg.dashboard.password = "secret"
    cfg.notifications.has_any_notification_channel = False

    monkeypatch.setattr(main, "_config", cfg)

    # Bypass HTTP Basic Auth for all tests in this module
    app.dependency_overrides[_require_auth] = lambda: "admin"

    yield

    app.dependency_overrides.clear()
    monkeypatch.setattr(main, "_config", None)


@pytest.fixture
def client() -> TestClient:
    # Do NOT use `with TestClient(app)` — we skip the lifespan intentionally
    # so no real scheduler starts and no config.yaml is loaded.
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


def test_health_is_unauthenticated():
    """GET /api/health must be accessible without credentials."""
    # Remove the override so real auth runs
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=True)
    resp = c.get("/api/health")
    assert resp.status_code == 200
    app.dependency_overrides[_require_auth] = lambda: "admin"


def test_protected_routes_require_auth():
    """Unauthenticated requests: page routes redirect to /login; API routes return 401."""
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
    for path in ["/", "/findings", "/settings"]:
        resp = c.get(path)
        assert resp.status_code == 302, f"Expected 302 for {path}, got {resp.status_code}"
        assert "/login" in resp.headers.get(
            "location", ""
        ), f"Expected redirect to /login for {path}"
    for path in ["/api/findings", "/api/news"]:
        resp = c.get(path)
        assert resp.status_code == 401, f"Expected 401 for {path}, got {resp.status_code}"
    app.dependency_overrides[_require_auth] = lambda: "admin"


# ---------------------------------------------------------------------------
# _safe_next() — open redirect prevention
# ---------------------------------------------------------------------------


def test_safe_next_allows_relative_path():
    assert main._safe_next("/settings") == "/settings"


def test_safe_next_allows_root():
    assert main._safe_next("/") == "/"


def test_safe_next_rejects_absolute_url():
    assert main._safe_next("https://evil.tld") == "/"


def test_safe_next_rejects_protocol_relative_double_slash():
    """ "//evil.tld" starts with "/" but browsers treat it as protocol-relative
    and navigate off-site — a naive startswith("/") check lets it through."""
    assert main._safe_next("//evil.tld") == "/"


def test_safe_next_rejects_backslash_variant():
    """Some browsers normalize "/\\evil.tld" to "//evil.tld"."""
    assert main._safe_next("/\\evil.tld") == "/"


def test_login_get_redirect_is_sanitized_when_already_authenticated(monkeypatch):
    """GET /login?next=//evil.tld while already logged in must not redirect
    off-site. The GET handler previously had no sanitization at all (only
    the POST handler guarded next_url, with a weaker startswith("/") check).
    """
    from itsdangerous import URLSafeTimedSerializer

    monkeypatch.setattr(main, "_session_serializer", URLSafeTimedSerializer("test-secret"))
    token = main._make_session_token({"authenticated": True, "username": "admin"})

    c = TestClient(app, raise_server_exceptions=True, follow_redirects=False)
    c.cookies.set(main._SESSION_COOKIE, token)
    resp = c.get("/login?next=//evil.tld")

    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


# ---------------------------------------------------------------------------
# POST /login — credential check + rate limiting
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_login_rate_limit():
    """The rate limiter's state is module-level and in-memory — clear it
    between tests so one test's failed attempts don't bleed into another's."""
    main._login_attempts.clear()
    yield
    main._login_attempts.clear()


def test_login_post_succeeds_with_valid_credentials(client, monkeypatch):
    from itsdangerous import URLSafeTimedSerializer

    monkeypatch.setattr(main, "_session_serializer", URLSafeTimedSerializer("test-secret"))
    resp = client.post(
        "/login",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_login_post_fails_with_invalid_credentials(client):
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_rate_limit_blocks_after_max_failed_attempts(client):
    for _ in range(main._LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        resp = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) > 0


def test_login_rate_limit_does_not_count_successful_attempts(client, monkeypatch):
    """A user who logs in successfully several times must never be locked
    out — only failed attempts count toward the limit."""
    from itsdangerous import URLSafeTimedSerializer

    monkeypatch.setattr(main, "_session_serializer", URLSafeTimedSerializer("test-secret"))
    for _ in range(main._LOGIN_RATE_LIMIT_MAX_ATTEMPTS + 5):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "secret"},
            follow_redirects=False,
        )
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


def test_health_returns_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_health_does_not_leak_pipeline_state(client):
    """Regression test: /api/health is unauthenticated and used to return the
    full pipeline status, including step_stats.scan/secrets.failed_repos
    (private repo names) and last_error (raw exception text). That payload
    now lives behind auth at /api/status.
    """
    data = client.get("/api/health").json()
    assert "pipeline" not in data
    assert "pipeline_steps" not in data
    assert "active_model" not in data
    assert set(data.keys()) == {"status", "version"}


def test_health_is_accessible_without_auth():
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=True)
    resp = c.get("/api/health")
    assert resp.status_code == 200
    app.dependency_overrides[_require_auth] = lambda: "admin"


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------


def test_status_requires_auth():
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=True)
    resp = c.get("/api/status")
    assert resp.status_code == 401
    app.dependency_overrides[_require_auth] = lambda: "admin"


def test_status_returns_full_payload(client):
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "pipeline" in data
    assert "pipeline_steps" in data


def test_status_pipeline_shape(client):
    data = client.get("/api/status").json()
    pipeline = data["pipeline"]
    assert "running" in pipeline
    assert "last_status" in pipeline


def test_status_includes_log_drops_count(client):
    """log_drops surfaces _SQLiteLogHandler's internal drop counter, which
    previously had no consumer anywhere — a silently lost ERROR record (e.g.
    from a failed secrets scan) was invisible even to an operator checking
    /api/status."""
    data = client.get("/api/status").json()
    assert "log_drops" in data
    assert isinstance(data["log_drops"], int)


def test_health_still_excludes_log_drops():
    """log_drops must stay behind auth like the rest of the detailed status
    payload — it is not sensitive on its own, but /api/health is deliberately
    kept minimal and unauthenticated (Docker healthcheck target)."""
    data = TestClient(app, raise_server_exceptions=True).get("/api/health").json()
    assert "log_drops" not in data


# ---------------------------------------------------------------------------
# HTML routes — smoke tests (200, correct content-type)
# ---------------------------------------------------------------------------


def test_dashboard_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_dashboard_contains_brand(client):
    resp = client.get("/")
    assert "DIVE" in resp.text


def test_dashboard_nav_dashboard_active(client):
    resp = client.get("/")
    assert 'class="active"' in resp.text or "active" in resp.text


def test_findings_page_returns_html(client):
    resp = client.get("/findings")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_findings_page_contains_table_or_empty_state(client):
    resp = client.get("/findings")
    # Either a <table> for findings or the empty-state div
    assert "<table" in resp.text or "empty-state" in resp.text


def test_findings_page_state_filter(client):
    resp = client.get("/findings?state=new")
    assert resp.status_code == 200


def test_logs_page_returns_html(client):
    resp = client.get("/logs")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_logs_page_uses_shared_set_page_size(client):
    """Regression test: setPageSize() used to be redefined locally inside
    {% block content %}, so the pjax router (which only re-executes scripts
    after <script id="page-scripts-fence">) never ran it on in-app
    navigation. It's now the shared DIVE.setPageSize from static/app.js
    (loaded once, outside the pjax-swapped region), so there's no
    page-local script to lose on navigation at all.

    The rows-per-page <select> only renders once pagination.total_pages > 1,
    so this seeds enough log entries (default page size is 25) to trigger it.
    """
    with db.get_conn() as conn:
        for i in range(30):
            db.insert_log_entry(conn, db._now(), "INFO", "dive.test", f"entry {i}")

    resp = client.get("/logs")
    html = resp.text
    assert "DIVE.setPageSize(this.value)" in html
    assert "function setPageSize" not in html


def test_settings_page_returns_html(client):
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_settings_page_has_interval_select(client):
    resp = client.get("/settings")
    assert "interval-select" in resp.text


def test_settings_page_has_model_grid(client):
    resp = client.get("/settings")
    assert "model-grid" in resp.text


def test_settings_page_shows_current_model(client):
    resp = client.get("/settings")
    assert "qwen2.5:3b" in resp.text


def test_base_template_has_run_token_meta(client):
    resp = client.get("/")
    assert 'name="run-token"' in resp.text


def test_base_template_has_run_now_button(client):
    resp = client.get("/")
    assert "Run Now" in resp.text


def test_drawer_failed_list_uses_delegated_listener_not_inline_onclick(client):
    """Regression test: the drawer's failed-source/repo lists used to toggle
    via an inline onclick on each rebuilt button, so expand state lived only
    on DOM nodes that updatePipelineDrawer() destroys on every status poll —
    expanding a list and waiting a few seconds collapsed it again. State now
    lives in the _drawerExpanded Set and toggling goes through a single
    listener delegated from #drawer-steps, registered once outside
    updatePipelineDrawer(), keyed by a stable data-failkey attribute.
    """
    resp = client.get("/")
    html = resp.text
    assert "data-failkey" in html
    assert "aria-expanded" in html
    assert "_drawerExpanded" in html
    assert "this.closest('.drawer-failed-wrap').classList.toggle('open')" not in html


# ---------------------------------------------------------------------------
# GET /api/news
# ---------------------------------------------------------------------------


def test_api_news_returns_list(client):
    resp = client.get("/api/news")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_news_empty_when_no_items(client):
    resp = client.get("/api/news")
    assert resp.json() == []


def test_api_news_returns_inserted_item(client):
    # Insert into the DB that _setup already patched onto db._DEFAULT_DB_PATH.
    # Use the current time so get_recent_items(hours=24) picks it up.
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat()
    with db.get_conn() as conn:
        db.insert_news_item(
            conn,
            {
                "url": "https://example.com/cve-2024-test",
                "title": "Test CVE article",
                "source": "Test Source",
                "fetched_at": now,
            },
        )
    resp = client.get("/api/news")
    assert resp.status_code == 200
    items = resp.json()
    assert any(item["title"] == "Test CVE article" for item in items)


def test_api_news_hours_param(client):
    resp = client.get("/api/news?hours=48")
    assert resp.status_code == 200


def test_api_news_limit_param(client):
    resp = client.get("/api/news?limit=5")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/ollama/models
# ---------------------------------------------------------------------------


def test_api_ollama_models_shape(client):
    with patch("httpx.Client") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"models": [{"name": "qwen2.5:3b"}, {"name": "llama3.2:3b"}]}
        mock_client.get.return_value = mock_resp

        resp = client.get("/api/ollama/models")

    assert resp.status_code == 200
    data = resp.json()
    assert "installed" in data
    assert "suggested" in data
    assert "current" in data


def test_api_ollama_models_installed_list(client):
    with patch("httpx.Client") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"models": [{"name": "qwen2.5:3b"}]}
        mock_client.get.return_value = mock_resp

        data = client.get("/api/ollama/models").json()

    assert "qwen2.5:3b" in data["installed"]


def test_api_ollama_models_graceful_on_ollama_unreachable(client):
    """When Ollama is down, installed should be [] — not a 500."""
    with patch("httpx.Client") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = Exception("connection refused")

        resp = client.get("/api/ollama/models")

    assert resp.status_code == 200
    assert resp.json()["installed"] == []


def test_api_ollama_models_current_reflects_config(client):
    data = client.get("/api/ollama/models").json()
    # current should come from _config.ollama.model (mocked as qwen2.5:3b)
    # OR from the active_model setting (not set in this test)
    assert data["current"] == "qwen2.5:3b"


def test_api_ollama_models_suggested_list_not_empty(client):
    data = client.get("/api/ollama/models").json()
    assert len(data["suggested"]) > 0
    for m in data["suggested"]:
        assert "name" in m
        assert "description" in m


# ---------------------------------------------------------------------------
# GET /api/settings
# ---------------------------------------------------------------------------


def test_get_settings_returns_interval(client):
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "run_interval_hours" in data


def test_get_settings_returns_model(client):
    data = client.get("/api/settings").json()
    assert "active_model" in data


# ---------------------------------------------------------------------------
# POST /api/settings
# ---------------------------------------------------------------------------


def test_post_settings_interval(client):
    resp = client.post(
        "/api/settings", json={"run_interval_hours": 12}, headers={"X-Run-Token": "test-token-abc"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"


def test_post_settings_active_model(client):
    resp = client.post(
        "/api/settings",
        json={"active_model": "llama3.2:3b"},
        headers={"X-Run-Token": "test-token-abc"},
    )
    assert resp.status_code == 200

    # Re-reading settings should reflect the change
    data = client.get("/api/settings").json()
    assert data["active_model"] == "llama3.2:3b"


def test_post_settings_invalid_interval_returns_400(client):
    resp = client.post(
        "/api/settings", json={"run_interval_hours": -1}, headers={"X-Run-Token": "test-token-abc"}
    )
    assert resp.status_code == 400


def test_post_settings_zero_interval_returns_400(client):
    resp = client.post(
        "/api/settings", json={"run_interval_hours": 0}, headers={"X-Run-Token": "test-token-abc"}
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Template helpers (unit-tested directly)
# ---------------------------------------------------------------------------


def test_cvss_severity_critical():
    label, cls = main._cvss_severity(9.5)
    assert label == "Critical"
    assert cls == "critical"


def test_cvss_severity_high():
    label, cls = main._cvss_severity(7.0)
    assert label == "High"
    assert cls == "high"


def test_cvss_severity_none():
    label, cls = main._cvss_severity(None)
    assert label == "Unknown"
    assert cls == "unknown"


def test_time_ago_minutes():
    from datetime import UTC, datetime, timedelta

    recent = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
    result = main._time_ago(recent)
    assert "m ago" in result


def test_time_ago_hours():
    from datetime import UTC, datetime, timedelta

    recent = (datetime.now(UTC) - timedelta(hours=3)).isoformat()
    result = main._time_ago(recent)
    assert "h ago" in result


def test_time_ago_none_returns_dash():
    assert main._time_ago(None) == "—"


# ---------------------------------------------------------------------------
# News retention setting (A3)
# ---------------------------------------------------------------------------


def test_scanner_settings_includes_retention(client):
    data = client.get("/api/config/scanner").json()
    assert "news_retention_days" in data
    assert data["news_retention_days"] == 0


def test_scanner_settings_saves_retention(client):
    resp = client.post(
        "/api/config/scanner",
        json={"news_retention_days": 45},
        headers={"X-Run-Token": "test-token-abc"},
    )
    assert resp.status_code == 200
    assert client.get("/api/config/scanner").json()["news_retention_days"] == 45


def test_scanner_settings_rejects_negative_retention(client):
    resp = client.post(
        "/api/config/scanner",
        json={"news_retention_days": -5},
        headers={"X-Run-Token": "test-token-abc"},
    )
    assert resp.status_code == 400


def test_settings_page_shows_retention_field(client):
    html = client.get("/settings").text
    assert "news-retention-days" in html


# ---------------------------------------------------------------------------
# Filtered export (A4)
# ---------------------------------------------------------------------------


def _seed_news(source: str, url: str):
    from datetime import UTC, datetime

    with db.get_conn() as conn:
        db.insert_news_item(
            conn,
            {
                "url": url,
                "title": f"Item from {source}",
                "source": source,
                "fetched_at": datetime.now(UTC).isoformat(),
            },
        )


def test_export_news_honors_source_filter(client):
    _seed_news("Feed A", "https://x/a")
    _seed_news("Feed B", "https://x/b")
    resp = client.get("/api/export/news?format=csv&source=Feed A")
    assert resp.status_code == 200
    body = resp.text
    assert "Feed A" in body
    assert "Feed B" not in body


def test_export_news_unfiltered_returns_all(client):
    _seed_news("Feed A", "https://x/a")
    _seed_news("Feed B", "https://x/b")
    body = client.get("/api/export/news?format=csv").text
    assert "Feed A" in body and "Feed B" in body


def test_export_findings_honors_repo_filter(client):
    with db.get_conn() as conn:
        for repo in ("owner/a", "owner/b"):
            db.upsert_finding(
                conn,
                {
                    "repo_full_name": repo,
                    "package_name": "pkg",
                    "package_ecosystem": "PyPI",
                    "cve_id": f"CVE-{repo[-1]}",
                },
            )
    body = client.get("/api/export/findings?format=csv&repo=owner/a").text
    assert "owner/a" in body
    assert "owner/b" not in body


def test_news_page_export_link_carries_filter(client):
    html = client.get("/news?source=Feed%20A").text
    assert "/api/export/news?format=csv&source=Feed" in html.replace("&amp;", "&")


# ---------------------------------------------------------------------------
# Feed PATCH — name/url editing
# ---------------------------------------------------------------------------


def _add_feed(client, name="Test Feed", url="https://test.example.com/rss"):
    """Helper: insert a feed row directly via the DB (bypasses URL validation)."""
    import dive.settings as st

    with db.get_conn() as conn:
        return st.add_feed(conn, name, url)


def test_patch_feed_name_only(client):
    feed = _add_feed(client)
    resp = client.patch(
        f"/api/config/feeds/{feed['id']}",
        json={"name": "Renamed Feed"},
        headers={"X-Run-Token": "test-token-abc"},
    )
    assert resp.status_code == 200
    with db.get_conn() as conn:
        row = conn.execute("SELECT name FROM rss_feeds WHERE id=?", (feed["id"],)).fetchone()
    assert row["name"] == "Renamed Feed"


def test_patch_feed_url_valid(client):
    feed = _add_feed(client)
    with patch("dive.main._validate_feed_url", return_value=True):
        resp = client.patch(
            f"/api/config/feeds/{feed['id']}",
            json={"url": "https://new.example.com/rss"},
            headers={"X-Run-Token": "test-token-abc"},
        )
    assert resp.status_code == 200
    with db.get_conn() as conn:
        row = conn.execute("SELECT url FROM rss_feeds WHERE id=?", (feed["id"],)).fetchone()
    assert row["url"] == "https://new.example.com/rss"


def test_patch_feed_url_invalid(client):
    feed = _add_feed(client)
    with patch("dive.main._validate_feed_url", return_value=False):
        resp = client.patch(
            f"/api/config/feeds/{feed['id']}",
            json={"url": "https://broken.example.com/rss"},
            headers={"X-Run-Token": "test-token-abc"},
        )
    assert resp.status_code == 422


def test_patch_feed_url_duplicate(client):
    _add_feed(client, "Feed A", "https://a.example.com/rss")
    feed_b = _add_feed(client, "Feed B", "https://b.example.com/rss")
    with patch("dive.main._validate_feed_url", return_value=True):
        resp = client.patch(
            f"/api/config/feeds/{feed_b['id']}",
            json={"url": "https://a.example.com/rss"},
            headers={"X-Run-Token": "test-token-abc"},
        )
    assert resp.status_code == 409


def test_patch_feed_not_found(client):
    resp = client.patch(
        "/api/config/feeds/99999",
        json={"name": "Ghost"},
        headers={"X-Run-Token": "test-token-abc"},
    )
    assert resp.status_code == 404


def test_patch_default_feed_name_and_url(client):
    import dive.settings as st

    with db.get_conn() as conn:
        st.get_feeds(conn)
        default_id = conn.execute("SELECT id FROM rss_feeds WHERE is_default=1 LIMIT 1").fetchone()[
            "id"
        ]

    with patch("dive.main._validate_feed_url", return_value=True):
        resp = client.patch(
            f"/api/config/feeds/{default_id}",
            json={"name": "Custom Name", "url": "https://custom.example.com/rss"},
            headers={"X-Run-Token": "test-token-abc"},
        )
    assert resp.status_code == 200
