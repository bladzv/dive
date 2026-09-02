"""
Unit tests for the M5 web dashboard — HTML routes and new API endpoints.

Uses FastAPI's TestClient without triggering the lifespan (no scheduler,
no config.yaml needed). main._config and db._DEFAULT_DB_PATH are patched
directly so the route handlers work against a clean in-memory database.
"""

from __future__ import annotations

import json
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
    resp = client.post(
        "/login",
        data={"username": "admin", "password": "wrong", "next_url": "/findings"},
    )
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.text
    # next_url must round-trip into the re-rendered form's hidden field so a
    # retry still lands where the user was headed.
    assert 'value="/findings"' in resp.text


def test_login_rate_limit_blocks_after_max_failed_attempts(client):
    for _ in range(main._LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        resp = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) > 0
    # Must be the styled login page, not a raw FastAPI JSON error body —
    # this is the exact moment the user is already locked out and confused.
    assert resp.headers["content-type"].startswith("text/html")
    assert "Too many attempts" in resp.text
    assert '{"detail"' not in resp.text


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


# ---------------------------------------------------------------------------
# New ⊂ Open — the state-window superset invariant
#
# "New this run" used to carry a lower bound on first_seen_at while "Open"
# carried an *upper* bound of the same timestamp, which made the two tabs
# disjoint: a finding first seen in the latest run appeared under New and was
# invisible under Open. These tests pin the superset relationship.
# ---------------------------------------------------------------------------


def _seed_successful_run(started_at: str, completed_at: str = "2026-01-02T00:00:00+00:00") -> None:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO run_log (started_at, completed_at, status) VALUES (?, ?, 'success')",
            (started_at, completed_at),
        )


def _seed_finding_at(cve: str, first_seen_at: str, state: str = "new") -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO findings
                (repo_full_name, package_name, package_ecosystem, cve_id,
                 state, first_seen_at, last_seen_at)
            VALUES ('owner/repo', 'pkg', 'PyPI', ?, ?, ?, ?)
            """,
            (cve, state, first_seen_at, first_seen_at),
        )


def _seed_secret_at(file_path: str, first_seen_at: str, state: str = "new") -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO secret_findings
                (repo_full_name, file_path, line_number, commit_sha, secret_type,
                 rule_id, fingerprint, state, first_seen_at, last_seen_at)
            VALUES ('owner/repo', ?, 1, 'abc123', 'AWS Key', 'aws-key', ?, ?, ?, ?)
            """,
            (file_path, f"fp-{file_path}", state, first_seen_at, first_seen_at),
        )


def test_findings_new_is_subset_of_open(client):
    """A finding first seen in the latest run must appear under BOTH tabs."""
    _seed_successful_run("2026-01-02T00:00:00+00:00")
    _seed_finding_at("CVE-NEW-0001", "2026-01-02T06:00:00+00:00")  # during latest run
    _seed_finding_at("CVE-OLD-0002", "2025-12-01T00:00:00+00:00")  # carried over

    new_html = client.get("/findings?state=new").text
    open_html = client.get("/findings?state=unresolved").text

    # New shows only the fresh one.
    assert "CVE-NEW-0001" in new_html
    assert "CVE-OLD-0002" not in new_html
    # Open is a superset: it shows the fresh one too, not just the carried-over.
    assert "CVE-NEW-0001" in open_html
    assert "CVE-OLD-0002" in open_html


def test_secrets_new_is_subset_of_open(client):
    _seed_successful_run("2026-01-02T00:00:00+00:00")
    _seed_secret_at("fresh.py", "2026-01-02T06:00:00+00:00")
    _seed_secret_at("stale.py", "2025-12-01T00:00:00+00:00")

    new_html = client.get("/secrets?state=new").text
    open_html = client.get("/secrets?state=unresolved").text

    assert "fresh.py" in new_html
    assert "stale.py" not in new_html
    assert "fresh.py" in open_html
    assert "stale.py" in open_html


def test_open_total_is_never_less_than_new_total(client):
    """Count invariant that must hold for any seed, not just the one above."""
    _seed_successful_run("2026-01-02T00:00:00+00:00")
    _seed_finding_at("CVE-A", "2026-01-02T06:00:00+00:00")
    _seed_finding_at("CVE-B", "2025-12-01T00:00:00+00:00")
    _seed_finding_at("CVE-C", "2026-01-02T07:00:00+00:00", state="acknowledged")

    with db.get_conn() as conn:
        since = main._state_window(conn, "new")
        new_total = db.get_findings_count(conn, state="new", since=since)
        open_total = db.get_findings_count(conn, state="unresolved", since=None)
    assert open_total >= new_total
    assert new_total == 1  # only CVE-A is state='new' AND in-window
    assert open_total == 3  # every new/acknowledged row, regardless of age


def test_state_window_with_no_successful_run_shows_nothing(client):
    """No run has ever completed → New must be empty, not everything."""
    _seed_finding_at("CVE-ORPHAN", "2026-01-02T06:00:00+00:00")

    assert "CVE-ORPHAN" not in client.get("/findings?state=new").text
    assert "CVE-ORPHAN" not in client.get("/api/export/findings?format=csv&state=new").text
    # ...but it is still visible as an open finding.
    assert "CVE-ORPHAN" in client.get("/findings?state=unresolved").text


def test_export_matches_view_for_new_tab(client):
    """The export used to ignore the window and return all-time state='new'."""
    _seed_successful_run("2026-01-02T00:00:00+00:00")
    _seed_finding_at("CVE-NEW-0001", "2026-01-02T06:00:00+00:00")
    _seed_finding_at("CVE-OLD-0002", "2025-12-01T00:00:00+00:00")

    body = client.get("/api/export/findings?format=csv&state=new").text
    assert "CVE-NEW-0001" in body
    assert "CVE-OLD-0002" not in body

    open_body = client.get("/api/export/findings?format=csv&state=unresolved").text
    assert "CVE-NEW-0001" in open_body and "CVE-OLD-0002" in open_body


def test_logs_page_returns_html(client):
    resp = client.get("/logs")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_logs_page_per_page_control_is_a_link_menu(client):
    """Regression test: setPageSize() used to be redefined locally inside
    {% block content %}, so the pjax router (which only re-executes scripts
    after <script id="page-scripts-fence">) never ran it on in-app
    navigation — and later, once centralized, DIVE.setPageSize() still
    changed pages via `window.location`, defeating pjax entirely.

    The rows-per-page control is now a ui.page_size_menu: real <a href>
    links built server-side, navigated by the pjax router like any other
    link. There is no per-page JS behavior left to lose on navigation.

    The control only renders once pagination.total_pages > 1, so this seeds
    enough log entries (default page size is 25) to trigger it.
    """
    with db.get_conn() as conn:
        for i in range(30):
            db.insert_log_entry(conn, db._now(), "INFO", "dive.test", f"entry {i}")

    resp = client.get("/logs")
    html = resp.text.replace("&amp;", "&")
    assert "<select" not in html
    assert "DIVE.setPageSize" not in html
    assert "function setPageSize" not in html
    assert 'href="/logs?per_page=50"' in html


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


def test_export_findings_json_branch_returns_json(client):
    """The JSON branch of every export was previously untested — only CSV."""
    with db.get_conn() as conn:
        db.upsert_finding(
            conn,
            {
                "repo_full_name": "owner/a",
                "package_name": "pkg",
                "package_ecosystem": "PyPI",
                "cve_id": "CVE-2024-0001",
            },
        )
    resp = client.get("/api/export/findings?format=json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    rows = json.loads(resp.text)
    assert [r["cve_id"] for r in rows] == ["CVE-2024-0001"]


def test_export_findings_annotated_narrows_to_notes(client):
    """The /personal 'Findings with notes' export must not dump every row."""
    with db.get_conn() as conn:
        # upsert_finding stamps the row id onto the dict it is handed.
        noted = {
            "repo_full_name": "owner/a",
            "package_name": "noted-pkg",
            "package_ecosystem": "PyPI",
            "cve_id": "CVE-2024-1111",
        }
        db.upsert_finding(conn, noted)
        db.upsert_finding(
            conn,
            {
                "repo_full_name": "owner/a",
                "package_name": "plain-pkg",
                "package_ecosystem": "PyPI",
                "cve_id": "CVE-2024-2222",
            },
        )
        db.set_finding_annotation(conn, noted["id"], "look at this")

    body = client.get("/api/export/findings?format=csv&annotated=1").text
    assert "noted-pkg" in body
    assert "plain-pkg" not in body
    # Unscoped export still returns both.
    both = client.get("/api/export/findings?format=csv").text
    assert "noted-pkg" in both and "plain-pkg" in both


def test_export_news_bookmarked_narrows_to_saved(client):
    """The /personal 'Bookmarks' export must not dump the whole news table."""
    _seed_news("Feed A", "https://x/a")
    _seed_news("Feed B", "https://x/b")
    with db.get_conn() as conn:
        row = conn.execute("SELECT id FROM news_items WHERE source = 'Feed A'").fetchone()
        db.add_bookmark(conn, row["id"])

    body = client.get("/api/export/news?format=csv&bookmarked=1").text
    assert "Feed A" in body
    assert "Feed B" not in body


# ---------------------------------------------------------------------------
# Secrets routes and export
#
# Nothing covered /secrets or /api/secrets* before this.
# ---------------------------------------------------------------------------

_SECRETS_EXPORT_FIELDS = [
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


def test_secrets_page_returns_html(client):
    resp = client.get("/secrets")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_secrets_page_has_export_menu(client):
    """Guards against the export menu being dropped from the template."""
    assert "/api/export/secrets" in client.get("/secrets").text


def test_export_secrets_csv_header_is_exact(client):
    """Structural guard: a new secret_findings column must never silently
    join the export, and fingerprint/match_key must stay out."""
    _seed_secret_at("leak.py", "2026-01-02T06:00:00+00:00")
    body = client.get("/api/export/secrets?format=csv").text
    header = body.splitlines()[0].strip()
    assert header.split(",") == _SECRETS_EXPORT_FIELDS
    assert "fingerprint" not in header
    assert "match_key" not in header


def test_export_secrets_json_branch(client):
    _seed_secret_at("leak.py", "2026-01-02T06:00:00+00:00")
    resp = client.get("/api/export/secrets?format=json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    rows = json.loads(resp.text)
    assert len(rows) == 1
    assert sorted(rows[0].keys()) == sorted(_SECRETS_EXPORT_FIELDS)


def test_export_secrets_honors_state_filter(client):
    # `state=new` is time-windowed, so it needs a successful run to bound
    # against — without one the sentinel correctly returns nothing (see
    # test_state_window_with_no_successful_run_shows_nothing).
    _seed_successful_run("2026-01-02T00:00:00+00:00")
    _seed_secret_at("open.py", "2026-01-02T06:00:00+00:00", state="new")
    _seed_secret_at("dismissed.py", "2026-01-02T06:00:00+00:00", state="false_positive")

    body = client.get("/api/export/secrets?format=csv&state=new").text
    assert "open.py" in body
    assert "dismissed.py" not in body

    # false_positive is an exact state match, not windowed.
    fp_body = client.get("/api/export/secrets?format=csv&state=false_positive").text
    assert "dismissed.py" in fp_body
    assert "open.py" not in fp_body


def test_export_secrets_honors_repo_filter(client):
    _seed_secret_at("a.py", "2026-01-02T06:00:00+00:00")
    with db.get_conn() as conn:
        conn.execute("""
            INSERT INTO secret_findings
                (repo_full_name, file_path, line_number, commit_sha, secret_type,
                 rule_id, fingerprint, state, first_seen_at, last_seen_at)
            VALUES ('other/repo', 'b.py', 1, 'def456', 'AWS Key', 'aws-key',
                    'fp-b', 'new', '2026-01-02T06:00:00+00:00', '2026-01-02T06:00:00+00:00')
            """)
    body = client.get("/api/export/secrets?format=csv&repo=owner/repo").text
    assert "a.py" in body
    assert "b.py" not in body


def _secret_id(file_path: str) -> int:
    with db.get_conn() as conn:
        return conn.execute(
            "SELECT id FROM secret_findings WHERE file_path = ?", (file_path,)
        ).fetchone()["id"]


def test_secret_reopen_moves_resolved_back_to_new(client):
    _seed_secret_at("leak.py", "2026-01-02T06:00:00+00:00", state="resolved")
    sid = _secret_id("leak.py")

    resp = client.post(f"/api/secrets/{sid}/reopen", headers={"X-Run-Token": "test-token-abc"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "new"
    with db.get_conn() as conn:
        row = conn.execute("SELECT state FROM secret_findings WHERE id = ?", (sid,)).fetchone()
    assert row["state"] == "new"


def test_secret_reopen_on_non_resolved_returns_404(client):
    _seed_secret_at("leak.py", "2026-01-02T06:00:00+00:00", state="new")
    sid = _secret_id("leak.py")
    resp = client.post(f"/api/secrets/{sid}/reopen", headers={"X-Run-Token": "test-token-abc"})
    assert resp.status_code == 404


def test_secret_reopen_requires_csrf_token(client):
    _seed_secret_at("leak.py", "2026-01-02T06:00:00+00:00", state="resolved")
    sid = _secret_id("leak.py")
    assert client.post(f"/api/secrets/{sid}/reopen").status_code == 403


def test_bulk_resolve_moves_false_positive_rows(client):
    """Bulk resolve guarded on state='new', so selecting a false_positive
    silently reported 0 updated while the single-item route worked."""
    _seed_secret_at("fp.py", "2026-01-02T06:00:00+00:00", state="false_positive")
    _seed_secret_at("open.py", "2026-01-02T06:00:00+00:00", state="new")
    ids = [_secret_id("fp.py"), _secret_id("open.py")]

    resp = client.post(
        "/api/secrets/bulk",
        json={"ids": ids, "action": "resolve"},
        headers={"X-Run-Token": "test-token-abc"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 2
    with db.get_conn() as conn:
        states = {
            r["file_path"]: r["state"]
            for r in conn.execute("SELECT file_path, state FROM secret_findings").fetchall()
        }
    assert states == {"fp.py": "resolved", "open.py": "resolved"}


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


# ---------------------------------------------------------------------------
# Filter controls — with_params preservation, the table-tools contract, chips
#
# These pin the SERVER half of contracts that have no JS test runner to guard
# them. The client half (syncMenuField, the data-field mirror dispatch, and
# table-tools' _filterOptions('repo') scrape) is manual-verification only.
# ---------------------------------------------------------------------------


def test_with_params_preserves_siblings_and_drops_page():
    assert (
        main._with_params("/findings?state=new&severity=critical&page=3", state="all")
        == "/findings?state=all&severity=critical"
    )


def test_with_params_deletes_on_empty_value():
    assert main._with_params("/findings?state=new&repo=a/b", repo=None) == "/findings?state=new"
    assert main._with_params("/findings?state=new&repo=a/b", repo="") == "/findings?state=new"


def test_with_params_returns_relative_path_not_absolute():
    """Must stay origin-agnostic behind a reverse proxy, and same-origin so
    base.html's pjax router intercepts it."""
    out = main._with_params("http://example.tld/findings?state=new", state="all")
    assert out.startswith("/findings")
    assert "example.tld" not in out


def test_findings_state_menu_preserves_every_other_filter(client):
    """The state links used to carry only `repo`, silently dropping
    severity/sort/direction/per_page."""
    resp = client.get(
        "/findings?state=all&severity=critical&sort=repo&direction=asc&per_page=50&page=2"
    )
    html = resp.text.replace("&amp;", "&")
    assert (
        'href="/findings?state=new&severity=critical&sort=repo&direction=asc&per_page=50"' in html
    )
    # page is always reset by a filter change.
    assert "state=new&severity=critical&sort=repo&direction=asc&per_page=50&page=" not in html


def test_findings_repo_menu_declares_table_tools_contract(client):
    """static/table-tools.js scrapes [data-filter-source="repo"] to build the
    Repo column-header filter. If this attribute disappears that menu loses
    its filter section silently — no error, no other failing test."""
    _seed_finding_at("CVE-2026-AAAA", "2026-01-05T00:00:00+00:00")
    html = client.get("/findings").text
    assert 'data-filter-source="repo"' in html


def test_conditional_attributes_are_not_html_escaped(client):
    """Jinja autoescapes {{ 'attr="v"' if cond }}, which renders
    attr=&#34;v&#34; and makes every selector miss it. Attributes must be
    emitted from {% if %} blocks instead."""
    _seed_finding_at("CVE-2026-BBBB", "2026-01-05T00:00:00+00:00")
    for path in ("/findings", "/secrets", "/news", "/settings", "/logs"):
        html = client.get(path).text
        assert "&#34;" not in html, f"escaped attribute quotes in {path}"
    assert 'aria-current="true"' in client.get("/findings").text


def test_findings_chips_appear_only_when_filtered(client):
    _seed_finding_at("CVE-2026-CCCC", "2026-01-05T00:00:00+00:00")
    filtered = client.get("/findings?severity=critical").text
    assert "filter-chips" in filtered
    assert "Clear filters" in filtered

    # The default state is not a filter, so no chip row on a bare view.
    assert "filter-chips" not in client.get("/findings").text


def test_settings_selects_are_field_menus_with_focusable_labels(client):
    """A hidden <input> mirror is not focusable, so <label for=…> must target
    the trigger or it is inert."""
    html = client.get("/settings").text
    assert "<select" not in html
    for ident in ("interval-select", "severity-select"):
        assert f'<input type="hidden" id="{ident}"' in html
        assert f'data-field="{ident}"' in html
        assert f'id="{ident}-trigger"' in html
        assert f'for="{ident}-trigger"' in html
        assert f'for="{ident}">' not in html


def test_converted_pages_have_no_native_select(client):
    """Native <select> popups cover their own control — that is the whole
    reason for param_menu/field_menu. Guards against one creeping back in."""
    _seed_finding_at("CVE-2026-DDDD", "2026-01-05T00:00:00+00:00")
    for path in ("/findings", "/news", "/settings"):
        assert "<select" not in client.get(path).text, f"native <select> back in {path}"


# ---------------------------------------------------------------------------
# Phase 4 — remaining conversions (secrets, logs, history)
# ---------------------------------------------------------------------------


def test_secrets_state_menu_preserves_every_other_filter(client):
    """Same fix as findings: the old hand-built href carried only `repo`.
    The exact-string match below already proves `page` is dropped — if it
    weren't, this href would carry it too and the match would fail."""
    _seed_secret_at("leak.py", "2026-01-05T00:00:00+00:00")
    resp = client.get("/secrets?state=all&sort=repo&direction=asc&per_page=50&page=2")
    html = resp.text.replace("&amp;", "&")
    assert 'href="/secrets?state=new&sort=repo&direction=asc&per_page=50"' in html


def test_secrets_repo_menu_declares_table_tools_contract(client):
    _seed_secret_at("leak.py", "2026-01-05T00:00:00+00:00")
    html = client.get("/secrets").text
    assert 'data-filter-source="repo"' in html


def test_secrets_chips_appear_only_when_filtered(client):
    _seed_secret_at("leak.py", "2026-01-05T00:00:00+00:00")
    filtered = client.get("/secrets?state=resolved").text
    assert "filter-chips" in filtered
    assert "Clear filters" in filtered
    assert "filter-chips" not in client.get("/secrets").text


def test_history_page_days_select_is_field_menu(client):
    html = client.get("/history").text
    assert "<select" not in html
    assert 'id="days-select"' in html
    assert 'data-field="days-select"' in html
    assert 'id="days-select-trigger"' in html
    assert 'for="days-select-trigger"' in html
    assert 'onchange="loadAll()"' in html


def test_logs_page_has_no_native_select(client):
    with db.get_conn() as conn:
        for i in range(30):
            db.insert_log_entry(conn, db._now(), "INFO", "dive.test", f"entry {i}")
    html = client.get("/logs").text
    assert "<select" not in html
    assert 'data-field="per_page"' not in html  # per-page is a param_menu, not a field_menu


# ---------------------------------------------------------------------------
# Phase 5 — row/bulk mutation endpoints: CSRF guard + action/undo round-trip
#
# These had no HTTP-level coverage before (only the Phase 2 secrets/reopen
# endpoint did) — the client-side Undo Snackbar work only makes sense if the
# server-side undo target (reopen / unmark-false-positive) is itself proven
# to round-trip correctly.
# ---------------------------------------------------------------------------


def _finding_id(cve: str) -> int:
    with db.get_conn() as conn:
        return conn.execute("SELECT id FROM findings WHERE cve_id = ?", (cve,)).fetchone()["id"]


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/findings/1/acknowledge", None),
        ("/api/findings/1/resolve", None),
        ("/api/findings/1/reopen", None),
        ("/api/findings/bulk", {"ids": [1], "action": "acknowledge"}),
        ("/api/secrets/1/false-positive", None),
        ("/api/secrets/1/unmark-false-positive", None),
        ("/api/secrets/1/resolve", None),
        ("/api/secrets/bulk", {"ids": [1], "action": "resolve"}),
    ],
)
def test_mutation_endpoints_reject_missing_csrf_token(client, path, body):
    resp = client.post(path, json=body) if body is not None else client.post(path)
    assert resp.status_code == 403


def test_finding_acknowledge_then_reopen_round_trips(client):
    _seed_finding_at("CVE-2026-ACK1", "2026-01-05T00:00:00+00:00")
    fid = _finding_id("CVE-2026-ACK1")
    headers = {"X-Run-Token": "test-token-abc"}

    ack = client.post(f"/api/findings/{fid}/acknowledge", headers=headers)
    assert ack.status_code == 200
    assert ack.json()["status"] == "acknowledged"

    reopened = client.post(f"/api/findings/{fid}/reopen", headers=headers)
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "new"


def test_finding_resolve_then_reopen_round_trips(client):
    _seed_finding_at("CVE-2026-RES1", "2026-01-05T00:00:00+00:00")
    fid = _finding_id("CVE-2026-RES1")
    headers = {"X-Run-Token": "test-token-abc"}

    resolved = client.post(f"/api/findings/{fid}/resolve", headers=headers)
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"

    reopened = client.post(f"/api/findings/{fid}/reopen", headers=headers)
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "new"


def test_finding_double_acknowledge_returns_404(client):
    """The non-idempotency the client's 404 handling exists for: acting on a
    finding whose state already moved returns 404, not a silent success."""
    _seed_finding_at("CVE-2026-DBL1", "2026-01-05T00:00:00+00:00")
    fid = _finding_id("CVE-2026-DBL1")
    headers = {"X-Run-Token": "test-token-abc"}

    first = client.post(f"/api/findings/{fid}/acknowledge", headers=headers)
    assert first.status_code == 200
    second = client.post(f"/api/findings/{fid}/acknowledge", headers=headers)
    assert second.status_code == 404


def test_finding_bulk_acknowledge_then_bulk_reopen_round_trips(client):
    _seed_finding_at("CVE-2026-BULK1", "2026-01-05T00:00:00+00:00")
    _seed_finding_at("CVE-2026-BULK2", "2026-01-05T00:00:00+00:00")
    ids = [_finding_id("CVE-2026-BULK1"), _finding_id("CVE-2026-BULK2")]
    headers = {"X-Run-Token": "test-token-abc"}

    ack = client.post(
        "/api/findings/bulk", json={"ids": ids, "action": "acknowledge"}, headers=headers
    )
    assert ack.status_code == 200
    assert ack.json()["updated"] == 2

    reopened = client.post(
        "/api/findings/bulk", json={"ids": ids, "action": "reopen"}, headers=headers
    )
    assert reopened.status_code == 200
    assert reopened.json()["updated"] == 2


def test_secret_mark_fp_then_unmark_round_trips(client):
    _seed_secret_at("undo-fp.py", "2026-01-05T00:00:00+00:00", state="new")
    sid = _secret_id("undo-fp.py")
    headers = {"X-Run-Token": "test-token-abc"}

    fp = client.post(f"/api/secrets/{sid}/false-positive", headers=headers)
    assert fp.status_code == 200

    unmarked = client.post(f"/api/secrets/{sid}/unmark-false-positive", headers=headers)
    assert unmarked.status_code == 200
    with db.get_conn() as conn:
        state = conn.execute("SELECT state FROM secret_findings WHERE id = ?", (sid,)).fetchone()[
            "state"
        ]
    assert state == "new"


def test_secret_resolve_then_reopen_round_trips(client):
    _seed_secret_at("undo-resolve.py", "2026-01-05T00:00:00+00:00", state="new")
    sid = _secret_id("undo-resolve.py")
    headers = {"X-Run-Token": "test-token-abc"}

    resolved = client.post(f"/api/secrets/{sid}/resolve", headers=headers)
    assert resolved.status_code == 200

    reopened = client.post(f"/api/secrets/{sid}/reopen", headers=headers)
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "new"


# ---------------------------------------------------------------------------
# Phase 6 — ⌘K command palette
#
# The palette is pure client-side (static/app.js), so only its markup
# contract is checkable here; behavior is manual-verification only, as there
# is no JS test runner in this repo.
# ---------------------------------------------------------------------------


def test_command_palette_markup_present_on_every_page(client):
    """Lives in base.html outside .page-main so a pjax swap never removes it."""
    for path in ("/", "/findings", "/secrets", "/news", "/settings"):
        html = client.get(path).text
        assert 'id="command-palette"' in html, f"palette missing on {path}"
        assert 'id="command-input"' in html
        assert 'id="command-list"' in html


def test_command_palette_uses_combobox_listbox_not_menu(client):
    """Focus stays on the input with aria-activedescendant pointing at the
    highlighted option — the pattern screen readers expect for a
    filter-as-you-type list, not role=menu."""
    html = client.get("/findings").text
    assert 'role="combobox"' in html
    assert 'aria-controls="command-list"' in html
    assert 'aria-autocomplete="list"' in html
    assert 'role="listbox"' in html
    # The live region that announces the result count.
    assert 'id="command-status"' in html
    assert 'aria-live="polite"' in html


def test_command_palette_is_not_a_modal_backdrop(client):
    """It must not reuse .modal-backdrop: the global modal Escape/backdrop
    handlers would then also fire on it, double-handling every dismissal."""
    html = client.get("/findings").text
    start = html.index('id="command-palette"')
    end = html.index("</body>", start)
    assert "modal-backdrop" not in html[start:end]


# ---------------------------------------------------------------------------
# Phase 7 — accessibility bundle, bulk secrets remediation modal, polish motion
# ---------------------------------------------------------------------------


def test_skip_link_present_and_targets_main(client):
    html = client.get("/findings").text
    assert 'class="skip-link' in html
    assert 'href="#page-main"' in html
    assert 'id="page-main"' in html
    assert 'tabindex="-1"' in html


def test_drawer_triggers_have_aria_expanded_and_haspopup(client):
    html = client.get("/").text
    assert 'aria-controls="pipeline-drawer"' in html
    # Both the desktop chip and the mobile trigger declare the relationship.
    assert html.count('aria-controls="pipeline-drawer"') == 2
    assert 'aria-haspopup="true"' in html


def test_nav_toggle_and_theme_toggle_have_aria_state(client):
    html = client.get("/").text
    assert 'id="nav-toggle"' in html and 'aria-expanded="false"' in html
    assert 'id="theme-btn"' in html and "aria-pressed=" in html


def test_run_status_live_region_is_separate_from_status_text(client):
    """Must NOT be aria-live itself — that node is rewritten by
    DIVE.timeAgo() on every 5-60s poll even while idle, which would spam
    'Xm ago' announcements forever. The dedicated node is only ever touched
    once, at the running-to-finished edge."""
    html = client.get("/").text
    assert 'id="run-status-live"' in html
    assert 'aria-live="polite"' in html
    status_text_tag = html[
        html.index('id="status-text"') - 40 : html.index('id="status-text"') + 60
    ]
    assert "aria-live" not in status_text_tag


def test_secrets_rows_carry_repo_and_file_for_bulk_resolve_modal(client):
    """openBulkResolveModal() reads these off each selected row to build the
    per-repo git-filter-repo commands — without them a bulk Resolve modal
    would render with no remediation commands at all."""
    _seed_secret_at("bulk-modal.py", "2026-01-05T00:00:00+00:00")
    html = client.get("/secrets").text
    assert 'data-repo="' in html
    assert 'data-file="' in html


def test_secrets_bulk_resolve_routes_through_modal_not_direct_api_call(client):
    """The per-row Resolve… deliberately walks the user through the
    git-filter-repo steps first; bulk used to skip straight past that."""
    html = client.get("/secrets").text
    assert "function openBulkResolveModal" in html
    assert "openBulkResolveModal(ids)" in html


def test_dashboard_and_settings_call_stagger_in(client):
    assert "DIVE.staggerIn('.exposure-pill')" in client.get("/").text
    assert "DIVE.staggerIn('.settings-section')" in client.get("/settings").text
