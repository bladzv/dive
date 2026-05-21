"""
Unit tests for pipeline pause and cancel controls.

Tests the _enter_step() internals and the /api/run/pause + /api/run/cancel
endpoints without starting a real pipeline run.
"""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import dive.db as db
import dive.main as main
from dive.main import _require_auth, app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_pipeline_globals(tmp_path: Path, monkeypatch):
    """Reset all pipeline globals to clean state before each test."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "_DEFAULT_DB_PATH", db_path)
    db.init(db_path)

    with db.get_conn(db_path) as conn:
        db.set_setting(conn, "run_token", "test-token")

    app.dependency_overrides[_require_auth] = lambda: "admin"

    # Reset all pipeline control state
    main._pipeline_control["cancel_requested"] = False
    main._pipeline_control["pause_requested"] = False
    main._pipeline_pause_event.set()
    with main._pipeline_lock:
        main._pipeline_status["running"] = False
        main._pipeline_status["current_step"] = None
        main._pipeline_status["step_history"] = []
        main._pipeline_status["paused"] = False

    yield

    app.dependency_overrides.clear()
    # Restore clean state so other test modules are unaffected
    main._pipeline_control["cancel_requested"] = False
    main._pipeline_control["pause_requested"] = False
    main._pipeline_pause_event.set()
    with main._pipeline_lock:
        main._pipeline_status["running"] = False
        main._pipeline_status["current_step"] = None
        main._pipeline_status["step_history"] = []
        main._pipeline_status["paused"] = False


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def running_client(client) -> TestClient:
    """Client with pipeline marked as running."""
    with main._pipeline_lock:
        main._pipeline_status["running"] = True
    yield client
    with main._pipeline_lock:
        main._pipeline_status["running"] = False


# ---------------------------------------------------------------------------
# POST /api/run/cancel
# ---------------------------------------------------------------------------


def test_cancel_when_not_running_returns_409(client):
    resp = client.post("/api/run/cancel", headers={"X-Run-Token": "test-token"})
    assert resp.status_code == 409


def test_cancel_when_running_returns_200(running_client):
    resp = running_client.post("/api/run/cancel", headers={"X-Run-Token": "test-token"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancel_requested"


def test_cancel_sets_flag(running_client):
    running_client.post("/api/run/cancel", headers={"X-Run-Token": "test-token"})
    assert main._pipeline_control["cancel_requested"] is True


def test_cancel_releases_pause_event(running_client):
    """Cancel must unblock a paused pipeline by setting the event."""
    main._pipeline_pause_event.clear()  # simulate paused state

    running_client.post("/api/run/cancel", headers={"X-Run-Token": "test-token"})

    assert main._pipeline_pause_event.is_set()


# ---------------------------------------------------------------------------
# POST /api/run/pause
# ---------------------------------------------------------------------------


def test_pause_when_not_running_returns_409(client):
    resp = client.post(
        "/api/run/pause", json={"pause": True}, headers={"X-Run-Token": "test-token"}
    )
    assert resp.status_code == 409


def test_resume_when_not_running_returns_409(client):
    resp = client.post(
        "/api/run/pause", json={"pause": False}, headers={"X-Run-Token": "test-token"}
    )
    assert resp.status_code == 409


def test_pause_clears_event(running_client):
    resp = running_client.post(
        "/api/run/pause", json={"pause": True}, headers={"X-Run-Token": "test-token"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "paused"
    assert not main._pipeline_pause_event.is_set()
    assert main._pipeline_control["pause_requested"] is True


def test_resume_sets_event(running_client):
    main._pipeline_pause_event.clear()
    main._pipeline_control["pause_requested"] = True

    resp = running_client.post(
        "/api/run/pause", json={"pause": False}, headers={"X-Run-Token": "test-token"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "resumed"
    assert main._pipeline_pause_event.is_set()
    assert main._pipeline_control["pause_requested"] is False


# ---------------------------------------------------------------------------
# _enter_step() internals
# ---------------------------------------------------------------------------


def test_enter_step_returns_true_when_clear():
    """Normal path: event set, no cancel → step proceeds."""
    result = main._enter_step("collect")
    assert result is True
    assert main._pipeline_status["current_step"] == "collect"


def test_enter_step_returns_false_when_cancel_requested():
    """Cancel flag set → step must not proceed."""
    main._pipeline_control["cancel_requested"] = True
    result = main._enter_step("collect")
    assert result is False
    assert main._pipeline_status["current_step"] is None


def test_enter_step_blocks_while_paused_then_proceeds():
    """Paused pipeline unblocks and proceeds once resumed."""
    main._pipeline_pause_event.clear()

    results = []

    def _runner():
        results.append(main._enter_step("scan"))

    t = threading.Thread(target=_runner, daemon=True)
    t.start()

    # Give the thread a moment to block on the event
    t.join(timeout=0.1)
    assert not results, "should be blocked"

    # Resume
    main._pipeline_pause_event.set()
    t.join(timeout=2)

    assert results == [True]
    assert main._pipeline_status["current_step"] == "scan"


def test_enter_step_cancel_during_pause_returns_false():
    """Cancel while paused: step must return False (not proceed)."""
    main._pipeline_pause_event.clear()

    results = []

    def _runner():
        results.append(main._enter_step("scan"))

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout=0.1)
    assert not results

    # Cancel (which also sets the event)
    main._pipeline_control["cancel_requested"] = True
    main._pipeline_pause_event.set()
    t.join(timeout=2)

    assert results == [False]


def test_enter_step_timeout_self_resumes_subsequent_steps():
    """After the pause auto-timeout, subsequent steps must not re-pause.

    This is the regression test for the bug where _pipeline_pause_event remained
    cleared after the timeout, causing every following step to wait again.
    """
    # Simulate a very short timeout so the test doesn't take 30 minutes
    with patch.object(main, "_MAX_PAUSE_SECONDS", 0.05):
        main._pipeline_pause_event.clear()

        # First step — times out after 50 ms
        result1 = main._enter_step("collect")

    # After the timeout the event must have been re-set so subsequent steps
    # don't block.
    assert result1 is True
    assert (
        main._pipeline_pause_event.is_set()
    ), "event should be set after timeout so subsequent steps don't re-pause"
    assert main._pipeline_control["pause_requested"] is False

    # Second step must return immediately without blocking
    result2 = main._enter_step("categorize")
    assert result2 is True
