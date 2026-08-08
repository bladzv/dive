"""
Unit tests for _SQLiteLogHandler — reuses one connection across emit() calls
instead of opening a fresh one per log record.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

import dive.db as db
import dive.main as main


@pytest.fixture
def tmp_db(tmp_path: Path, monkeypatch) -> Path:
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "_DEFAULT_DB_PATH", db_path)
    db.init(db_path)
    return db_path


def _make_record(msg: str, level: int = logging.INFO) -> logging.LogRecord:
    return logging.LogRecord(
        name="dive.test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )


def test_emit_writes_log_entry(tmp_db: Path):
    handler = main._SQLiteLogHandler()
    handler.emit(_make_record("hello"))

    with db.get_conn(tmp_db) as conn:
        rows = conn.execute("SELECT message FROM log_entries").fetchall()
    assert [r["message"] for r in rows] == ["hello"]


def test_emit_reuses_the_same_connection_across_calls(tmp_db: Path):
    handler = main._SQLiteLogHandler()
    handler.emit(_make_record("first"))
    conn_after_first = handler._conn
    handler.emit(_make_record("second"))

    assert handler._conn is conn_after_first  # no new connection opened

    with db.get_conn(tmp_db) as conn:
        rows = conn.execute("SELECT message FROM log_entries ORDER BY id").fetchall()
    assert [r["message"] for r in rows] == ["first", "second"]


def test_emit_never_raises_on_failure(tmp_db: Path, monkeypatch):
    handler = main._SQLiteLogHandler()
    monkeypatch.setattr(
        db, "insert_log_entry", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    handler.emit(_make_record("this will fail"))  # must not raise
    assert handler._dropped == 1


def test_emit_drops_broken_connection_and_recovers(tmp_db: Path, monkeypatch):
    """After a failure the handler must not keep retrying against a
    possibly-broken connection forever — it should get a fresh one."""
    handler = main._SQLiteLogHandler()
    handler.emit(_make_record("first"))
    assert handler._conn is not None

    original_insert = db.insert_log_entry
    monkeypatch.setattr(
        db, "insert_log_entry", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    handler.emit(_make_record("will fail"))
    assert handler._conn is None

    # Restore only insert_log_entry — monkeypatch.undo() would also revert
    # the tmp_db fixture's _DEFAULT_DB_PATH patch, silently redirecting the
    # next write to the real database file.
    monkeypatch.setattr(db, "insert_log_entry", original_insert)
    handler.emit(_make_record("recovered"))
    assert handler._conn is not None

    with db.get_conn(tmp_db) as conn:
        messages = {r["message"] for r in conn.execute("SELECT message FROM log_entries")}
    assert messages == {"first", "recovered"}


# ---------------------------------------------------------------------------
# emit() — retry on transient lock contention (sqlite3.OperationalError)
#
# The pipeline holds a write transaction open across a whole scan step, so
# the log handler's separate connection can hit "database is locked" for a
# genuinely transient reason — this must not be treated the same as a
# permanently broken connection (RuntimeError, covered above).
# ---------------------------------------------------------------------------


def test_emit_retries_on_operational_error_then_succeeds(tmp_db: Path, monkeypatch):
    monkeypatch.setattr(main, "_LOG_INSERT_BACKOFF_S", 0)  # keep the test fast
    handler = main._SQLiteLogHandler()

    original_insert = db.insert_log_entry
    call_count = 0

    def flaky_insert(*a, **k):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise sqlite3.OperationalError("database is locked")
        return original_insert(*a, **k)

    with patch("dive.main.db.insert_log_entry", side_effect=flaky_insert):
        handler.emit(_make_record("locked-then-ok"))

    assert call_count == 2
    assert handler._dropped == 0
    with db.get_conn(tmp_db) as conn:
        rows = conn.execute("SELECT message FROM log_entries").fetchall()
    assert [r["message"] for r in rows] == ["locked-then-ok"]


def test_emit_drops_after_exhausting_retries_on_persistent_lock(tmp_db: Path, monkeypatch):
    monkeypatch.setattr(main, "_LOG_INSERT_BACKOFF_S", 0)
    handler = main._SQLiteLogHandler()

    with patch(
        "dive.main.db.insert_log_entry",
        side_effect=sqlite3.OperationalError("database is locked"),
    ):
        handler.emit(_make_record("always-locked"))

    assert handler._dropped == 1
    assert handler._conn is None  # connection reset for the next record

    with db.get_conn(tmp_db) as conn:
        rows = conn.execute("SELECT message FROM log_entries").fetchall()
    assert rows == []


def test_emit_does_not_retry_non_operational_errors(tmp_db: Path, monkeypatch):
    """A genuinely broken connection (e.g. RuntimeError) must fail fast, not
    pay the retry backoff meant for transient lock contention."""
    monkeypatch.setattr(main, "_LOG_INSERT_BACKOFF_S", 1)  # would make the test slow if hit
    handler = main._SQLiteLogHandler()

    call_count = 0

    def always_broken(*a, **k):
        nonlocal call_count
        call_count += 1
        raise RuntimeError("boom")

    with patch("dive.main.db.insert_log_entry", side_effect=always_broken):
        handler.emit(_make_record("broken"))  # must not raise, must not hang

    assert call_count == 1
    assert handler._dropped == 1


def test_get_conn_sets_a_long_busy_timeout(tmp_db: Path):
    """Regression test: a live run measured a pipeline step holding its write
    transaction open for 48.9s, well past the 5s default busy_timeout on
    request/pipeline connections — this handler's dedicated connection needs
    a much longer budget since it has nothing else to do but wait."""
    handler = main._SQLiteLogHandler()
    conn = handler._get_conn()
    (timeout_ms,) = conn.execute("PRAGMA busy_timeout").fetchone()
    assert timeout_ms == main._LOG_CONN_BUSY_TIMEOUT_MS
    assert timeout_ms >= 30_000  # comfortably longer than the 5s request default


def test_get_dropped_log_count_reflects_handler_state(tmp_db: Path, monkeypatch):
    monkeypatch.setattr(main, "_sqlite_log_handler", None)
    assert main._get_dropped_log_count() == 0

    handler = main._SQLiteLogHandler()
    handler._dropped = 3
    monkeypatch.setattr(main, "_sqlite_log_handler", handler)
    assert main._get_dropped_log_count() == 3
