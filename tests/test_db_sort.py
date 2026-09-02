"""
Unit tests for the server-side sort whitelists (_FINDINGS_SORTS, _SECRETS_SORTS,
_LOGS_SORTS / _order_by) and the findings `severity` filter added alongside the
interactive-tables UI work.

SQLite can't bind an ORDER BY expression as a query parameter, so every sort
key must be resolved through a whitelist dict before it ever reaches the SQL
string — these tests exist to catch a future change that bypasses that and
interpolates the raw `sort`/`direction` query param instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import dive.db as db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test.db"
    db.init(db_path)
    return db_path


@pytest.fixture
def conn(tmp_db: Path):
    with db.get_conn(tmp_db) as c:
        yield c


def _finding(repo, package, cvss_score=None, priority_score=None, **extra):
    row = {
        "repo_full_name": repo,
        "package_name": package,
        "package_ecosystem": "PyPI",
        "cvss_score": cvss_score,
        "priority_score": priority_score,
    }
    row.update(extra)
    return row


def _secret(repo, file_path, rule_id, secret_type="Generic API Key", fingerprint=None, **extra):
    row = {
        "repo_full_name": repo,
        "file_path": file_path,
        "commit_sha": "abc123",
        "secret_type": secret_type,
        "rule_id": rule_id,
        "fingerprint": fingerprint or f"abc123:{file_path}:{rule_id}:1",
    }
    row.update(extra)
    return row


# ---------------------------------------------------------------------------
# Findings sort whitelist
# ---------------------------------------------------------------------------


def test_findings_sort_every_whitelisted_key_executes(conn):
    """Every public sort key must produce a query that runs, in both directions."""
    db.upsert_finding(conn, _finding("owner/a", "requests", cvss_score=5.0, priority_score=10))
    db.upsert_finding(conn, _finding("owner/b", "flask", cvss_score=8.0, priority_score=20))

    for key in db._FINDINGS_SORTS:
        for direction in ("asc", "desc"):
            rows = db.get_findings(conn, sort=key, direction=direction)
            assert len(rows) == 2


def test_findings_sort_unknown_key_falls_back_to_default(conn):
    db.upsert_finding(conn, _finding("owner/a", "requests", cvss_score=5.0, priority_score=10))
    db.upsert_finding(conn, _finding("owner/b", "flask", cvss_score=8.0, priority_score=20))

    default_rows = db.get_findings(conn, sort=None, direction=None)
    unknown_rows = db.get_findings(conn, sort="nope", direction="desc")
    assert [r["id"] for r in default_rows] == [r["id"] for r in unknown_rows]


def test_findings_sort_injection_attempt_falls_back_and_table_survives(conn):
    db.upsert_finding(conn, _finding("owner/a", "requests", cvss_score=5.0, priority_score=10))
    db.upsert_finding(conn, _finding("owner/b", "flask", cvss_score=8.0, priority_score=20))

    # Must not raise, must not affect the table, must behave like an unknown key.
    rows = db.get_findings(conn, sort="id; DROP TABLE findings--", direction="asc")
    assert len(rows) == 2

    # The table must still exist and be fully queryable afterward.
    still_there = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
    assert still_there == 2


def test_findings_sort_by_cvss_desc(conn):
    db.upsert_finding(conn, _finding("owner/a", "low", cvss_score=2.0))
    db.upsert_finding(conn, _finding("owner/b", "high", cvss_score=9.5))
    db.upsert_finding(conn, _finding("owner/c", "mid", cvss_score=5.5))

    rows = db.get_findings(conn, sort="cvss", direction="desc")
    assert [r["package_name"] for r in rows] == ["high", "mid", "low"]


def test_findings_sort_by_repo_asc(conn):
    db.upsert_finding(conn, _finding("owner/zeta", "z"))
    db.upsert_finding(conn, _finding("owner/alpha", "a"))
    db.upsert_finding(conn, _finding("owner/mid", "m"))

    rows = db.get_findings(conn, sort="repo", direction="asc")
    assert [r["repo_full_name"] for r in rows] == ["owner/alpha", "owner/mid", "owner/zeta"]


def test_findings_sort_tiebreak_is_stable(conn):
    """Equal-value rows must come back in a deterministic (id DESC) order —
    without the tiebreak, pagination could repeat or drop rows across pages."""
    db.upsert_finding(conn, _finding("owner/a", "first", cvss_score=5.0))
    db.upsert_finding(conn, _finding("owner/b", "second", cvss_score=5.0))

    rows_1 = db.get_findings(conn, sort="cvss", direction="desc")
    rows_2 = db.get_findings(conn, sort="cvss", direction="desc")
    assert [r["id"] for r in rows_1] == [r["id"] for r in rows_2]
    # Higher id (inserted later) sorts first under the id DESC tiebreak.
    assert rows_1[0]["package_name"] == "second"


# ---------------------------------------------------------------------------
# Secrets sort whitelist
# ---------------------------------------------------------------------------


def test_secrets_sort_every_whitelisted_key_executes(conn):
    db.upsert_secret_finding(conn, _secret("owner/a", "a.py", "generic-api-key"))
    db.upsert_secret_finding(conn, _secret("owner/b", "b.py", "aws-key"))

    for key in db._SECRETS_SORTS:
        for direction in ("asc", "desc"):
            rows = db.get_secret_findings(conn, sort=key, direction=direction)
            assert len(rows) == 2


def test_secrets_sort_unknown_key_falls_back_to_default(conn):
    db.upsert_secret_finding(conn, _secret("owner/a", "a.py", "generic-api-key"))
    db.upsert_secret_finding(conn, _secret("owner/b", "b.py", "aws-key"))

    default_rows = db.get_secret_findings(conn, sort=None, direction=None)
    unknown_rows = db.get_secret_findings(conn, sort="nope", direction="desc")
    assert [r["id"] for r in default_rows] == [r["id"] for r in unknown_rows]


def test_secrets_sort_injection_attempt_falls_back_and_table_survives(conn):
    db.upsert_secret_finding(conn, _secret("owner/a", "a.py", "generic-api-key"))

    rows = db.get_secret_findings(conn, sort="id; DROP TABLE secret_findings--", direction="asc")
    assert len(rows) == 1
    still_there = conn.execute("SELECT COUNT(*) AS n FROM secret_findings").fetchone()["n"]
    assert still_there == 1


def test_secrets_sort_by_repo_asc(conn):
    db.upsert_secret_finding(conn, _secret("owner/zeta", "a.py", "rule-1"))
    db.upsert_secret_finding(conn, _secret("owner/alpha", "b.py", "rule-2"))

    rows = db.get_secret_findings(conn, sort="repo", direction="asc")
    assert [r["repo_full_name"] for r in rows] == ["owner/alpha", "owner/zeta"]


# ---------------------------------------------------------------------------
# Logs sort whitelist
# ---------------------------------------------------------------------------


def test_logs_sort_every_whitelisted_key_executes(conn):
    db.insert_log_entry(conn, "2026-01-01T00:00:00", "INFO", "dive.main", "first")
    db.insert_log_entry(conn, "2026-01-01T00:00:01", "ERROR", "dive.scanner", "second")

    for key in db._LOGS_SORTS:
        for direction in ("asc", "desc"):
            rows = db.get_log_entries(conn, sort=key, direction=direction)
            assert len(rows) == 2


def test_logs_sort_unknown_key_falls_back_to_default(conn):
    db.insert_log_entry(conn, "2026-01-01T00:00:00", "INFO", "dive.main", "first")
    db.insert_log_entry(conn, "2026-01-01T00:00:01", "ERROR", "dive.scanner", "second")

    default_rows = db.get_log_entries(conn, sort=None, direction=None)
    unknown_rows = db.get_log_entries(conn, sort="nope", direction="desc")
    assert [r["id"] for r in default_rows] == [r["id"] for r in unknown_rows]


def test_logs_sort_injection_attempt_falls_back_and_table_survives(conn):
    db.insert_log_entry(conn, "2026-01-01T00:00:00", "INFO", "dive.main", "first")

    rows = db.get_log_entries(conn, sort="id; DROP TABLE log_entries--", direction="asc")
    assert len(rows) == 1
    still_there = conn.execute("SELECT COUNT(*) AS n FROM log_entries").fetchone()[0]
    assert still_there == 1


def test_logs_sort_by_level_asc(conn):
    db.insert_log_entry(conn, "2026-01-01T00:00:00", "WARNING", "dive.main", "w")
    db.insert_log_entry(conn, "2026-01-01T00:00:01", "ERROR", "dive.main", "e")
    db.insert_log_entry(conn, "2026-01-01T00:00:02", "INFO", "dive.main", "i")

    rows = db.get_log_entries(conn, sort="level", direction="asc")
    assert [r["level"] for r in rows] == ["ERROR", "INFO", "WARNING"]


# ---------------------------------------------------------------------------
# Findings severity filter (_SEVERITY_RANGES) — mirrors main._cvss_severity()
# ---------------------------------------------------------------------------


def test_findings_severity_filter_critical(conn):
    db.upsert_finding(conn, _finding("owner/a", "crit", cvss_score=9.0))
    db.upsert_finding(conn, _finding("owner/b", "high", cvss_score=8.9))

    rows = db.get_findings(conn, severity="critical")
    assert [r["package_name"] for r in rows] == ["crit"]


def test_findings_severity_filter_high(conn):
    db.upsert_finding(conn, _finding("owner/a", "high", cvss_score=7.0))
    db.upsert_finding(conn, _finding("owner/b", "high2", cvss_score=8.9))
    db.upsert_finding(conn, _finding("owner/c", "crit", cvss_score=9.0))
    db.upsert_finding(conn, _finding("owner/d", "mid", cvss_score=6.9))

    rows = db.get_findings(conn, severity="high")
    assert {r["package_name"] for r in rows} == {"high", "high2"}


def test_findings_severity_filter_medium(conn):
    db.upsert_finding(conn, _finding("owner/a", "mid", cvss_score=4.0))
    db.upsert_finding(conn, _finding("owner/b", "mid2", cvss_score=6.9))
    db.upsert_finding(conn, _finding("owner/c", "high", cvss_score=7.0))
    db.upsert_finding(conn, _finding("owner/d", "low", cvss_score=3.9))

    rows = db.get_findings(conn, severity="medium")
    assert {r["package_name"] for r in rows} == {"mid", "mid2"}


def test_findings_severity_filter_low(conn):
    db.upsert_finding(conn, _finding("owner/a", "low", cvss_score=0.1))
    db.upsert_finding(conn, _finding("owner/b", "low2", cvss_score=3.9))
    db.upsert_finding(conn, _finding("owner/c", "mid", cvss_score=4.0))

    rows = db.get_findings(conn, severity="low")
    assert {r["package_name"] for r in rows} == {"low", "low2"}


def test_findings_severity_filter_unknown_matches_null_cvss(conn):
    db.upsert_finding(conn, _finding("owner/a", "no-score", cvss_score=None))
    db.upsert_finding(conn, _finding("owner/b", "has-score", cvss_score=5.0))

    rows = db.get_findings(conn, severity="unknown")
    assert [r["package_name"] for r in rows] == ["no-score"]


def test_findings_severity_filter_unrecognised_key_is_ignored(conn):
    """An invalid severity key must not raise and must not filter anything —
    mirrors how an unrecognised state/repo value behaves in _findings_where."""
    db.upsert_finding(conn, _finding("owner/a", "one", cvss_score=5.0))
    db.upsert_finding(conn, _finding("owner/b", "two", cvss_score=None))

    rows = db.get_findings(conn, severity="not-a-real-severity")
    assert len(rows) == 2


def test_findings_severity_filter_composes_with_state_and_repo(conn):
    db.upsert_finding(conn, _finding("owner/a", "match", cvss_score=9.5))
    db.upsert_finding(conn, _finding("owner/a", "wrong-severity", cvss_score=1.0))
    db.upsert_finding(conn, _finding("owner/b", "wrong-repo", cvss_score=9.5))

    rows = db.get_findings(conn, repo="owner/a", severity="critical")
    assert [r["package_name"] for r in rows] == ["match"]


def test_get_findings_count_honors_severity(conn):
    db.upsert_finding(conn, _finding("owner/a", "crit", cvss_score=9.5))
    db.upsert_finding(conn, _finding("owner/b", "low", cvss_score=1.0))

    assert db.get_findings_count(conn, severity="critical") == 1
    assert db.get_findings_count(conn) == 2


def test_get_findings_for_export_honors_severity(conn):
    db.upsert_finding(conn, _finding("owner/a", "crit", cvss_score=9.5))
    db.upsert_finding(conn, _finding("owner/b", "low", cvss_score=1.0))

    rows = db.get_findings_for_export(conn, severity="critical")
    assert [r["package_name"] for r in rows] == ["crit"]


# ---------------------------------------------------------------------------
# The state window — `since` only, no upper bound
#
# _findings_where/_secrets_where used to also accept `until`, which the page
# routes set for the 'unresolved' tab and which made Open and New disjoint.
# `until` is gone; these pin the remaining one-sided clause.
# ---------------------------------------------------------------------------


def test_findings_where_no_longer_accepts_until(conn):
    """A resurrected upper bound is how the disjoint-tabs bug would come back."""
    with pytest.raises(TypeError):
        db.get_findings(conn, until="2026-01-01T00:00:00+00:00")
    with pytest.raises(TypeError):
        db.get_findings_count(conn, until="2026-01-01T00:00:00+00:00")


def test_secrets_where_no_longer_accepts_until(conn):
    with pytest.raises(TypeError):
        db.get_secret_findings(conn, until="2026-01-01T00:00:00+00:00")
    with pytest.raises(TypeError):
        db.get_secret_findings_count(conn, until="2026-01-01T00:00:00+00:00")


def test_findings_since_is_inclusive_lower_bound(conn):
    """`since` uses >=, so a finding first seen exactly at the run's start
    timestamp counts as part of that run rather than falling through."""
    boundary = "2026-01-02T00:00:00+00:00"
    conn.execute(
        """
        INSERT INTO findings
            (repo_full_name, package_name, package_ecosystem, cve_id,
             state, first_seen_at, last_seen_at)
        VALUES ('owner/a', 'exactly-at-boundary', 'PyPI', 'CVE-1', 'new', ?, ?)
        """,
        (boundary, boundary),
    )
    rows = db.get_findings(conn, state="new", since=boundary)
    assert [r["package_name"] for r in rows] == ["exactly-at-boundary"]


def test_unresolved_ignores_since_window_in_the_route_contract(conn):
    """state='unresolved' has no time bound of its own: passing since=None
    (what main._state_window returns for it) returns every open row."""
    for pkg, first_seen in (
        ("fresh", "2026-01-05T00:00:00+00:00"),
        ("stale", "2020-01-01T00:00:00+00:00"),
    ):
        conn.execute(
            """
            INSERT INTO findings
                (repo_full_name, package_name, package_ecosystem, cve_id,
                 state, first_seen_at, last_seen_at)
            VALUES ('owner/a', ?, 'PyPI', ?, 'new', ?, ?)
            """,
            (pkg, f"CVE-{pkg}", first_seen, first_seen),
        )
    rows = db.get_findings(conn, state="unresolved", since=None)
    assert sorted(r["package_name"] for r in rows) == ["fresh", "stale"]
