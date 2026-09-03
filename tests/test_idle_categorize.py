"""
Unit tests for main._run_idle_categorize() — the background job that
categorizes one batch of pending news items between pipeline runs.

Ollama itself is never hit here: categorizer_module.run is mocked out, so
these tests only verify the guard conditions (config missing, pipeline
running, both feature toggles) and that a real run wires the batch size
through correctly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import dive.db as db
import dive.main as main
import dive.settings as settings


@pytest.fixture(autouse=True)
def _reset_globals(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "_DEFAULT_DB_PATH", db_path)
    db.init(db_path)

    monkeypatch.setattr(main, "_LOCK_FILE", tmp_path / "pipeline.lock")
    monkeypatch.setattr(main, "_IDLE_CATEGORIZE_LOCK_FILE", tmp_path / "idle_categorize.lock")

    with main._pipeline_lock:
        main._pipeline_status["running"] = False

    yield

    with main._pipeline_lock:
        main._pipeline_status["running"] = False


def _enable_both_toggles():
    with db.get_conn() as conn:
        settings.set_feature_toggle(conn, "llm_categorizer", True)
        settings.set_feature_toggle(conn, "idle_categorization", True)


def test_noop_when_config_missing(monkeypatch):
    monkeypatch.setattr(main, "_config", None)
    fake_run = MagicMock()
    monkeypatch.setattr(main.categorizer_module, "run", fake_run)

    main._run_idle_categorize()

    fake_run.assert_not_called()


def test_noop_when_pipeline_running(monkeypatch):
    monkeypatch.setattr(main, "_config", MagicMock())
    _enable_both_toggles()
    fake_run = MagicMock()
    monkeypatch.setattr(main.categorizer_module, "run", fake_run)

    with main._pipeline_lock:
        main._pipeline_status["running"] = True

    main._run_idle_categorize()

    fake_run.assert_not_called()


def test_noop_when_idle_toggle_disabled(monkeypatch):
    monkeypatch.setattr(main, "_config", MagicMock())
    with db.get_conn() as conn:
        settings.set_feature_toggle(conn, "llm_categorizer", True)
        settings.set_feature_toggle(conn, "idle_categorization", False)
    fake_run = MagicMock()
    monkeypatch.setattr(main.categorizer_module, "run", fake_run)

    main._run_idle_categorize()

    fake_run.assert_not_called()


def test_noop_when_llm_categorizer_toggle_disabled(monkeypatch):
    monkeypatch.setattr(main, "_config", MagicMock())
    with db.get_conn() as conn:
        settings.set_feature_toggle(conn, "llm_categorizer", False)
        settings.set_feature_toggle(conn, "idle_categorization", True)
    fake_run = MagicMock()
    monkeypatch.setattr(main.categorizer_module, "run", fake_run)

    main._run_idle_categorize()

    fake_run.assert_not_called()


def test_runs_one_batch_when_enabled_and_idle(monkeypatch):
    fake_config = MagicMock()
    monkeypatch.setattr(main, "_config", fake_config)
    _enable_both_toggles()
    with db.get_conn() as conn:
        settings.set_categorize_batch_size(conn, 7)

    fake_stats = MagicMock(total_processed=3, categorized=3, uncategorized=0)
    fake_run = MagicMock(return_value=fake_stats)
    monkeypatch.setattr(main.categorizer_module, "run", fake_run)

    main._run_idle_categorize()

    fake_run.assert_called_once()
    _, kwargs = fake_run.call_args
    assert kwargs["max_items"] == 7
    assert fake_run.call_args[0][1] is fake_config
