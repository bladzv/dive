"""
Unit tests for _SQLiteLogHandler — reuses one connection across emit() calls
instead of opening a fresh one per log record.
"""

from __future__ import annotations

import logging
from pathlib import Path

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
