"""
Unit tests for lifecycle.py — state machine transitions and reconciliation.

No external calls are made — everything runs against an in-memory SQLite DB.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import dive.db as db
import dive.lifecycle as lifecycle

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def conn(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init(db_path)
    with db.get_conn(db_path) as c:
        yield c


def _insert(conn, **overrides) -> int:
    """Insert a minimal finding and return its id."""
    base = {
        "repo_full_name": "user/repo",
        "cve_id": "CVE-2024-0001",
        "ghsa_id": None,
        "package_name": "requests",
        "package_ecosystem": "PyPI",
        "installed_version": "2.28.0",
        "fixed_version": "2.32.0",
        "cvss_score": 9.0,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 54.0,
        "manifest_path": "requirements.txt",
    }
    base.update(overrides)
    db.upsert_finding(conn, base)
    row = conn.execute(
        "SELECT id FROM findings WHERE repo_full_name=? AND package_name=?",
        (base["repo_full_name"], base["package_name"]),
    ).fetchone()
    return row["id"]


def _key(repo, pkg, eco, cve="", ghsa=""):
    return (repo, pkg, eco, cve, ghsa)


# ---------------------------------------------------------------------------
# acknowledge()
# ---------------------------------------------------------------------------


def test_acknowledge_new_finding(conn):
    fid = _insert(conn)
    assert lifecycle.acknowledge(conn, fid) is True
    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "acknowledged"


def test_acknowledge_returns_false_if_not_new(conn):
    fid = _insert(conn)
    lifecycle.acknowledge(conn, fid)  # now acknowledged
    assert lifecycle.acknowledge(conn, fid) is False


def test_acknowledge_nonexistent_returns_false(conn):
    assert lifecycle.acknowledge(conn, 99999) is False


# ---------------------------------------------------------------------------
# resolve()
# ---------------------------------------------------------------------------


def test_resolve_new_finding(conn):
    fid = _insert(conn)
    assert lifecycle.resolve(conn, fid) is True
    row = conn.execute("SELECT state, resolved_at FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "resolved"
    assert row["resolved_at"] is not None


def test_resolve_acknowledged_finding(conn):
    fid = _insert(conn)
    lifecycle.acknowledge(conn, fid)
    assert lifecycle.resolve(conn, fid) is True


def test_resolve_already_resolved_returns_false(conn):
    fid = _insert(conn)
    lifecycle.resolve(conn, fid)
    assert lifecycle.resolve(conn, fid) is False


def test_resolve_nonexistent_returns_false(conn):
    assert lifecycle.resolve(conn, 99999) is False


# ---------------------------------------------------------------------------
# reopen()
# ---------------------------------------------------------------------------


def test_reopen_resolved_finding(conn):
    fid = _insert(conn)
    lifecycle.resolve(conn, fid)
    assert lifecycle.reopen(conn, fid) is True
    row = conn.execute(
        "SELECT state, notified_at, resolved_at FROM findings WHERE id=?", (fid,)
    ).fetchone()
    assert row["state"] == "new"
    assert row["notified_at"] is None
    assert row["resolved_at"] is None


def test_reopen_acknowledged_finding(conn):
    fid = _insert(conn)
    lifecycle.acknowledge(conn, fid)
    assert lifecycle.reopen(conn, fid) is True
    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "new"


def test_reopen_new_finding_returns_false(conn):
    fid = _insert(conn)
    assert lifecycle.reopen(conn, fid) is False


# ---------------------------------------------------------------------------
# recheck_resolved()
# ---------------------------------------------------------------------------


def test_recheck_resolved_reverts_when_still_present(conn):
    fid = _insert(conn)
    lifecycle.resolve(conn, fid)

    key = _key("user/repo", "requests", "PyPI", "CVE-2024-0001")
    reverted = lifecycle.recheck_resolved(conn, {key})
    assert reverted == 1

    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "new"


def test_recheck_resolved_does_not_revert_when_gone(conn):
    fid = _insert(conn)
    lifecycle.resolve(conn, fid)

    reverted = lifecycle.recheck_resolved(conn, set())
    assert reverted == 0

    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "resolved"


def test_recheck_resolved_clears_notified_at(conn):
    fid = _insert(conn)
    lifecycle.resolve(conn, fid)
    conn.execute("UPDATE findings SET notified_at = '2024-01-01' WHERE id=?", (fid,))

    key = _key("user/repo", "requests", "PyPI", "CVE-2024-0001")
    lifecycle.recheck_resolved(conn, {key})

    row = conn.execute("SELECT notified_at FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["notified_at"] is None


def test_recheck_resolved_returns_count(conn):
    _insert(conn, cve_id="CVE-2024-0001", package_name="pkgA")
    _insert(conn, cve_id="CVE-2024-0002", package_name="pkgB")

    # Resolve both
    rows = conn.execute("SELECT id FROM findings").fetchall()
    for row in rows:
        lifecycle.resolve(conn, row["id"])

    # Only pkgA is still present
    key_a = _key("user/repo", "pkgA", "PyPI", "CVE-2024-0001")
    reverted = lifecycle.recheck_resolved(conn, {key_a})
    assert reverted == 1


# ---------------------------------------------------------------------------
# auto_resolve_gone()
# ---------------------------------------------------------------------------


def test_auto_resolve_gone_resolves_missing_finding(conn):
    fid = _insert(conn)

    # Simulate a scan run that found no vulnerabilities in user/repo
    scanned_key = _key("user/repo", "SOME-OTHER-PKG", "PyPI", "CVE-X")
    resolved = lifecycle.auto_resolve_gone(conn, {scanned_key})
    assert resolved == 1

    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "resolved"


def test_auto_resolve_does_not_resolve_unscanned_repos(conn):
    _insert(conn, repo_full_name="user/other-repo")
    # current run only scanned user/repo — NOT user/other-repo
    scanned_key = _key("user/repo", "anything", "PyPI", "CVE-X")
    resolved = lifecycle.auto_resolve_gone(conn, {scanned_key})
    assert resolved == 0


def test_auto_resolve_does_not_touch_resolved_findings(conn):
    fid = _insert(conn)
    lifecycle.resolve(conn, fid)

    # Even if resolved finding is absent from scan, count should be 0
    scanned_key = _key("user/repo", "OTHER", "PyPI")
    resolved = lifecycle.auto_resolve_gone(conn, {scanned_key})
    assert resolved == 0


def test_auto_resolve_empty_keys_returns_zero(conn):
    _insert(conn)
    assert lifecycle.auto_resolve_gone(conn, set()) == 0


def test_auto_resolve_acknowledged_finding_gets_resolved(conn):
    fid = _insert(conn)
    lifecycle.acknowledge(conn, fid)

    scanned_key = _key("user/repo", "OTHER", "PyPI")
    resolved = lifecycle.auto_resolve_gone(conn, {scanned_key})
    assert resolved == 1


def test_auto_resolve_clean_scan_resolves_via_scanned_repos(conn):
    """Regression: repo scans clean (zero findings) — explicit scanned_repos triggers resolution.

    Before the fix, scanned_repos was derived from current_finding_keys, so a repo
    with no findings this run would never appear in scanned_repos and its stale
    findings would remain 'new' forever.
    """
    fid = _insert(conn)
    # No finding keys at all — the repo produced zero vulnerabilities this scan.
    resolved = lifecycle.auto_resolve_gone(conn, set(), scanned_repos={"user/repo"})
    assert resolved == 1
    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "resolved"


def test_auto_resolve_scanned_repos_does_not_touch_unscanned_repo(conn):
    """Explicit scanned_repos must still exclude repos not in the set."""
    _insert(conn, repo_full_name="user/other-repo")
    # Only user/repo was scanned — user/other-repo findings must not be touched.
    resolved = lifecycle.auto_resolve_gone(conn, set(), scanned_repos={"user/repo"})
    assert resolved == 0


def test_auto_resolve_clean_scan_acknowledged_finding(conn):
    """Acknowledged findings in a cleanly-scanned repo are also auto-resolved."""
    fid = _insert(conn)
    lifecycle.acknowledge(conn, fid)
    resolved = lifecycle.auto_resolve_gone(conn, set(), scanned_repos={"user/repo"})
    assert resolved == 1
    row = conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["state"] == "resolved"


# ---------------------------------------------------------------------------
# db.get_unnotified_findings / db.mark_findings_notified
# ---------------------------------------------------------------------------


def test_get_unnotified_findings_returns_new_without_notified_at(conn):
    fid = _insert(conn)
    rows = db.get_unnotified_findings(conn)
    assert any(r["id"] == fid for r in rows)


def test_get_unnotified_findings_excludes_already_notified(conn):
    fid = _insert(conn)
    db.mark_findings_notified(conn, [fid])
    rows = db.get_unnotified_findings(conn)
    assert not any(r["id"] == fid for r in rows)


def test_get_unnotified_findings_excludes_acknowledged(conn):
    fid = _insert(conn)
    lifecycle.acknowledge(conn, fid)
    rows = db.get_unnotified_findings(conn)
    assert not any(r["id"] == fid for r in rows)


def test_mark_findings_notified_sets_timestamp(conn):
    fid = _insert(conn)
    db.mark_findings_notified(conn, [fid])
    row = conn.execute("SELECT notified_at FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["notified_at"] is not None


def test_mark_findings_notified_empty_list_is_noop(conn):
    # Should not raise
    db.mark_findings_notified(conn, [])
