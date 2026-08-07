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


# ---------------------------------------------------------------------------
# POST /api/run
# ---------------------------------------------------------------------------


def test_run_starts_pipeline_and_returns_200(client, monkeypatch):
    monkeypatch.setattr(main, "_run_pipeline", lambda: None)
    resp = client.post("/api/run", headers={"X-Run-Token": "test-token"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "started"


def test_run_marks_running_before_returning(client, monkeypatch):
    """The route itself must claim `running` synchronously, not leave it to
    the spawned thread — otherwise two near-simultaneous requests can both
    observe running=False and both report "started"."""
    started = threading.Event()
    release = threading.Event()

    def _slow_pipeline():
        started.set()
        release.wait(timeout=2)

    monkeypatch.setattr(main, "_run_pipeline", _slow_pipeline)

    resp = client.post("/api/run", headers={"X-Run-Token": "test-token"})
    assert resp.status_code == 200
    # By the time the HTTP response comes back, running must already be True
    # — the route sets it under the lock before starting the thread.
    assert main._pipeline_status["running"] is True

    release.set()
    started.wait(timeout=2)


def test_run_returns_409_when_already_running(running_client):
    resp = running_client.post("/api/run", headers={"X-Run-Token": "test-token"})
    assert resp.status_code == 409
    assert resp.json()["status"] == "already_running"


def test_run_rejects_missing_csrf_token(client, monkeypatch):
    monkeypatch.setattr(main, "_run_pipeline", lambda: None)
    resp = client.post("/api/run")
    assert resp.status_code == 403


def test_run_pipeline_resets_running_flag_when_file_lock_unavailable(tmp_path, monkeypatch):
    """Exercises _run_pipeline()'s own early-exit path: if another process
    already holds data/.pipeline.lock, FileLock.acquire() raises Timeout
    before the function's main try/finally is even entered. The route now
    sets running=True before starting the thread (see test_run_marks_running_
    before_returning above), so _run_pipeline must undo that itself here —
    otherwise the status stays stuck reporting a run that never started.
    """
    from filelock import FileLock

    lock_path = tmp_path / "pipeline.lock"
    monkeypatch.setattr(main, "_LOCK_FILE", lock_path)

    # Simulate the route having already claimed "running" before spawning
    # the thread that calls _run_pipeline().
    with main._pipeline_lock:
        main._pipeline_status["running"] = True

    holder = FileLock(str(lock_path), timeout=0)
    holder.acquire()
    try:
        main._run_pipeline()
    finally:
        holder.release()

    assert main._pipeline_status["running"] is False
