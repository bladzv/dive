"""
Shared pytest fixtures.

Existing test files that already define their own `tmp_db`/`conn` fixtures are
left as-is — this file only adds fixtures for new tests so they don't need to
repeat the boilerplate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import dive.db as db


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test.db"
    db.init(db_path)
    return db_path


@pytest.fixture
def conn(tmp_db: Path):
    with db.get_conn(tmp_db) as c:
        yield c
