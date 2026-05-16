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

import db
import main
from main import app, _require_auth


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
    """Dashboard pages must return 401 without the dependency override."""
    app.dependency_overrides.clear()
    c = TestClient(app, raise_server_exceptions=False)
    for path in ["/", "/findings", "/settings", "/api/findings", "/api/news"]:
        resp = c.get(path)
        assert resp.status_code == 401, f"Expected 401 for {path}, got {resp.status_code}"
    app.dependency_overrides[_require_auth] = lambda: "admin"


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


def test_health_returns_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "pipeline" in data


def test_health_pipeline_shape(client):
    data = client.get("/api/health").json()
    pipeline = data["pipeline"]
    assert "running" in pipeline
    assert "last_status" in pipeline


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
    from datetime import datetime, timezone as tz
    now = datetime.now(tz.utc).isoformat()
    with db.get_conn() as conn:
        db.insert_news_item(conn, {
            "url": "https://example.com/cve-2024-test",
            "title": "Test CVE article",
            "source": "Test Source",
            "fetched_at": now,
        })
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
    resp = client.post("/api/settings", json={"run_interval_hours": 12})
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"


def test_post_settings_active_model(client):
    resp = client.post("/api/settings", json={"active_model": "llama3.2:3b"})
    assert resp.status_code == 200

    # Re-reading settings should reflect the change
    data = client.get("/api/settings").json()
    assert data["active_model"] == "llama3.2:3b"


def test_post_settings_invalid_interval_returns_400(client):
    resp = client.post("/api/settings", json={"run_interval_hours": -1})
    assert resp.status_code == 400


def test_post_settings_zero_interval_returns_400(client):
    resp = client.post("/api/settings", json={"run_interval_hours": 0})
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
    from datetime import datetime, timedelta, timezone as tz
    recent = (datetime.now(tz.utc) - timedelta(minutes=15)).isoformat()
    result = main._time_ago(recent)
    assert "m ago" in result


def test_time_ago_hours():
    from datetime import datetime, timedelta, timezone as tz
    recent = (datetime.now(tz.utc) - timedelta(hours=3)).isoformat()
    result = main._time_ago(recent)
    assert "h ago" in result


def test_time_ago_none_returns_dash():
    assert main._time_ago(None) == "—"
