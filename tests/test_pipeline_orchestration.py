"""
End-to-end tests for _run_pipeline() orchestration.

_run_pipeline() previously had no test coverage at all — these tests exercise
the real step-sequencing logic (with all external I/O mocked) rather than
just the pause/cancel primitives covered by test_pipeline_controls.py.

Regression coverage for the bug where a secrets-scanner failure raised
UnboundLocalError (sec_stats read after an except that skipped its
assignment), which aborted lifecycle reconciliation and notification for
the rest of the run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import dive.db as db
import dive.main as main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class _FakeCollectorStats:
    items_fetched: int = 0
    items_new: int = 0
    failed_sources: list = field(default_factory=list)


@dataclass
class _FakeCategorizerStats:
    categorized: int = 0
    uncategorized: int = 0
    uncategorized_rate: float = 0.0


@dataclass
class _FakeScannerStats:
    findings_new: int = 0
    finding_keys: set = field(default_factory=set)
    scanned_repos: set = field(default_factory=set)
    repos_scanned: int = 0
    packages_checked: int = 0
    failed_repos: list = field(default_factory=list)
    skipped_repos: list = field(default_factory=list)


@dataclass
class _FakeSecretsStats:
    repos_scanned: int = 0
    secrets_new: int = 0
    failed_repos: list = field(default_factory=list)


@pytest.fixture(autouse=True)
def _reset_pipeline_globals(tmp_path: Path, monkeypatch):
    """Point the DB and pipeline lock at tmp_path, reset all module globals."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "_DEFAULT_DB_PATH", db_path)
    db.init(db_path)

    monkeypatch.setattr(main, "_LOCK_FILE", tmp_path / "pipeline.lock")
    monkeypatch.setattr(main, "_config", None)

    # Every alert path is mocked so tests never depend on notifier internals
    # (which would otherwise raise on a None config) or attempt real I/O.
    for name in (
        "send_pipeline_start_alert",
        "send_failure_alert",
        "send_pipeline_summary_alert",
        "send_findings_alert",
        "send_secrets_alert",
    ):
        monkeypatch.setattr(main.notifier, name, MagicMock())

    main._pipeline_control["cancel_requested"] = False
    main._pipeline_control["pause_requested"] = False
    main._pipeline_pause_event.set()
    with main._pipeline_lock:
        main._pipeline_status["running"] = False
        main._pipeline_status["current_step"] = None
        main._pipeline_status["step_history"] = []
        main._pipeline_status["step_stats"] = {}
        main._pipeline_status["paused"] = False

    yield

    main._pipeline_control["cancel_requested"] = False
    main._pipeline_control["pause_requested"] = False
    main._pipeline_pause_event.set()
    with main._pipeline_lock:
        main._pipeline_status["running"] = False
        main._pipeline_status["current_step"] = None
        main._pipeline_status["step_history"] = []
        main._pipeline_status["step_stats"] = {}
        main._pipeline_status["paused"] = False


def _step_statuses() -> dict[str, str]:
    return {h["key"]: h["status"] for h in main._pipeline_status["step_history"]}


# ---------------------------------------------------------------------------
# The regression test
# ---------------------------------------------------------------------------


def test_secrets_scanner_failure_does_not_abort_lifecycle_and_notify(monkeypatch):
    """A secrets-scanner exception must not prevent lifecycle/notify from running.

    Before the fix, ss.run() raising left `sec_stats` unbound; the
    unconditional `_set_step_stats("secrets", repos_scanned=sec_stats...)`
    call right after raised UnboundLocalError, which escaped to the pipeline's
    outer exception handler and skipped steps 5 (lifecycle) and 6 (notify)
    entirely — silently suppressing vulnerability alerts.
    """
    monkeypatch.setattr(main.collector_module, "run", MagicMock(return_value=_FakeCollectorStats()))
    monkeypatch.setattr(
        main.categorizer_module, "run", MagicMock(return_value=_FakeCategorizerStats())
    )
    monkeypatch.setattr(main.gs, "run", MagicMock(return_value=_FakeScannerStats()))
    monkeypatch.setattr(main.ss, "run", MagicMock(side_effect=RuntimeError("gitleaks exploded")))

    main._run_pipeline()

    statuses = _step_statuses()
    assert statuses["secrets"] == "error"
    assert statuses["lifecycle"] == "ok", "lifecycle must still run after a secrets-step failure"
    assert statuses["notify"] == "ok", "notify must still run after a secrets-step failure"

    # The pipeline as a whole must not be marked as a hard error just because
    # one step failed — each step owns its own error state independently.
    assert main._pipeline_status["last_status"] == "success"
    assert main._pipeline_status["running"] is False


def test_secrets_scanner_success_records_stats(monkeypatch):
    """Sanity check: the happy path still records step stats as before."""
    monkeypatch.setattr(main.collector_module, "run", MagicMock(return_value=_FakeCollectorStats()))
    monkeypatch.setattr(
        main.categorizer_module, "run", MagicMock(return_value=_FakeCategorizerStats())
    )
    monkeypatch.setattr(main.gs, "run", MagicMock(return_value=_FakeScannerStats()))
    monkeypatch.setattr(
        main.ss, "run", MagicMock(return_value=_FakeSecretsStats(repos_scanned=3, secrets_new=1))
    )

    main._run_pipeline()

    statuses = _step_statuses()
    assert statuses["secrets"] == "ok"
    assert statuses["lifecycle"] == "ok"
    assert statuses["notify"] == "ok"
    assert main._pipeline_status["step_stats"]["secrets"]["repos_scanned"] == 3
    assert main._pipeline_status["last_status"] == "success"


def test_full_pipeline_runs_all_steps_in_order(monkeypatch):
    monkeypatch.setattr(main.collector_module, "run", MagicMock(return_value=_FakeCollectorStats()))
    monkeypatch.setattr(
        main.categorizer_module, "run", MagicMock(return_value=_FakeCategorizerStats())
    )
    monkeypatch.setattr(main.gs, "run", MagicMock(return_value=_FakeScannerStats()))
    monkeypatch.setattr(main.ss, "run", MagicMock(return_value=_FakeSecretsStats()))

    main._run_pipeline()

    ordered_keys = [h["key"] for h in main._pipeline_status["step_history"]]
    assert ordered_keys == [
        "collect",
        "categorize",
        "scan",
        "issues",
        "secrets",
        "lifecycle",
        "notify",
    ]
    assert all(status != "error" for status in _step_statuses().values())
