"""
Unit tests for github_issue_creator.py.

All GitHub API calls and DB writes are mocked.
No network access or real tokens required.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import db as db_module
import github_issue_creator as gic
from github_issue_creator import (
    _build_issue_body,
    _issue_title,
    _severity_label,
    _vuln_id,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db_module.init(db_path)
    with db_module.get_conn(db_path) as conn:
        yield conn


def _make_config(token: str = "fake-token", username: str = "testuser"):
    from config import AppConfig, DashboardConfig, GitHubConfig

    return AppConfig(
        github=GitHubConfig(token=token, username=username),
        dashboard=DashboardConfig(username="admin", password="secret"),
    )


def _make_finding_row(**overrides) -> sqlite3.Row:
    """Return a sqlite3.Row-like object for a finding."""
    base = {
        "id": 1,
        "repo_full_name": "testuser/myrepo",
        "cve_id": "CVE-2024-1234",
        "ghsa_id": None,
        "package_name": "requests",
        "package_ecosystem": "PyPI",
        "installed_version": "2.28.0",
        "fixed_version": "2.31.0",
        "cvss_score": 9.1,
        "is_kev": 0,
        "patch_available": 1,
        "priority_score": 95.0,
        "state": "new",
        "ai_next_steps": None,
        "github_issue_url": None,
        "annotation": None,
    }
    base.update(overrides)
    # Build a real sqlite3.Row from an in-memory connection for type fidelity
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cols = ", ".join(f"? AS {k}" for k in base.keys())
    row = conn.execute(f"SELECT {cols}", list(base.values())).fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# _vuln_id
# ---------------------------------------------------------------------------


def test_vuln_id_prefers_cve():
    row = _make_finding_row(cve_id="CVE-2024-0001", ghsa_id="GHSA-xxxx-xxxx-xxxx")
    assert _vuln_id(row) == "CVE-2024-0001"


def test_vuln_id_falls_back_to_ghsa():
    row = _make_finding_row(cve_id=None, ghsa_id="GHSA-xxxx-xxxx-xxxx")
    assert _vuln_id(row) == "GHSA-xxxx-xxxx-xxxx"


def test_vuln_id_no_id():
    row = _make_finding_row(cve_id=None, ghsa_id=None)
    assert _vuln_id(row) == "no-id"


# ---------------------------------------------------------------------------
# _severity_label
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score, expected",
    [
        (None, "Unknown"),
        (9.0, "Critical"),
        (9.5, "Critical"),
        (7.0, "High"),
        (8.9, "High"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (3.9, "Low"),
        (0.0, "Low"),
    ],
)
def test_severity_label(score, expected):
    assert _severity_label(score) == expected


# ---------------------------------------------------------------------------
# _issue_title
# ---------------------------------------------------------------------------


def test_issue_title_with_cve():
    row = _make_finding_row(cve_id="CVE-2024-1234", package_name="requests")
    assert _issue_title(row) == "[Security] CVE-2024-1234 in requests"


def test_issue_title_with_ghsa():
    row = _make_finding_row(cve_id=None, ghsa_id="GHSA-abcd-efgh-ijkl", package_name="flask")
    assert _issue_title(row) == "[Security] GHSA-abcd-efgh-ijkl in flask"


# ---------------------------------------------------------------------------
# _build_issue_body
# ---------------------------------------------------------------------------


def test_build_issue_body_contains_key_fields():
    row = _make_finding_row(
        cve_id="CVE-2024-1234",
        package_name="requests",
        package_ecosystem="PyPI",
        installed_version="2.28.0",
        fixed_version="2.31.0",
        cvss_score=9.1,
        is_kev=1,
    )
    body = _build_issue_body(row)
    assert "CVE-2024-1234" in body
    assert "requests" in body
    assert "PyPI" in body
    assert "2.28.0" in body
    assert "2.31.0" in body
    assert "9.1" in body
    assert "Critical" in body
    assert "KEV" in body


def test_build_issue_body_includes_ai_next_steps():
    ns = {"impact": "Remote code execution", "fix": "pip install requests>=2.31.0", "effort": "Low"}
    row = _make_finding_row(ai_next_steps=json.dumps(ns))
    body = _build_issue_body(row)
    assert "Remote code execution" in body
    assert "pip install" in body
    assert "Low" in body


def test_build_issue_body_nvd_link():
    row = _make_finding_row(cve_id="CVE-2024-5678")
    body = _build_issue_body(row)
    assert "nvd.nist.gov" in body


def test_build_issue_body_ghsa_link():
    row = _make_finding_row(cve_id=None, ghsa_id="GHSA-abcd-1234-efgh")
    body = _build_issue_body(row)
    assert "github.com/advisories" in body


def test_build_issue_body_no_kev_when_false():
    row = _make_finding_row(is_kev=0)
    body = _build_issue_body(row)
    assert "KEV" not in body


# ---------------------------------------------------------------------------
# run() — integration with mocked GitHub + DB
# ---------------------------------------------------------------------------


def test_run_creates_issue(in_memory_db):
    # Seed a finding that needs an issue
    in_memory_db.execute("""
        INSERT INTO findings
            (repo_full_name, cve_id, package_name, package_ecosystem,
             state, first_seen_at, last_seen_at)
        VALUES ('user/repo', 'CVE-2024-0001', 'requests', 'PyPI',
                'new', '2026-01-01', '2026-01-01')
        """)
    (
        in_memory_db.connection.commit()
        if hasattr(in_memory_db, "connection")
        else in_memory_db.commit()
    )

    mock_issue = MagicMock()
    mock_issue.html_url = "https://github.com/user/repo/issues/42"

    mock_repo = MagicMock()
    mock_repo.get_issues.return_value = []
    mock_repo.create_issue.return_value = mock_issue

    with patch("github_issue_creator.Github") as mock_gh_cls:
        mock_gh_cls.return_value.get_repo.return_value = mock_repo
        config = _make_config()
        stats = gic.run(in_memory_db, config)

    assert stats.issues_created == 1
    assert stats.issues_skipped == 0
    assert stats.issues_failed == 0

    row = in_memory_db.execute(
        "SELECT github_issue_url FROM findings WHERE cve_id = 'CVE-2024-0001'"
    ).fetchone()
    assert row["github_issue_url"] == "https://github.com/user/repo/issues/42"


def test_run_skips_duplicate_open_issue(in_memory_db):
    in_memory_db.execute("""
        INSERT INTO findings
            (repo_full_name, cve_id, package_name, package_ecosystem,
             state, first_seen_at, last_seen_at)
        VALUES ('user/repo', 'CVE-2024-9999', 'flask', 'PyPI',
                'new', '2026-01-01', '2026-01-01')
        """)
    (
        in_memory_db.connection.commit()
        if hasattr(in_memory_db, "connection")
        else in_memory_db.commit()
    )

    existing_issue = MagicMock()
    existing_issue.title = "[Security] CVE-2024-9999 in flask"
    existing_issue.html_url = "https://github.com/user/repo/issues/7"

    mock_repo = MagicMock()
    mock_repo.get_issues.return_value = [existing_issue]

    with patch("github_issue_creator.Github") as mock_gh_cls:
        mock_gh_cls.return_value.get_repo.return_value = mock_repo
        stats = gic.run(in_memory_db, _make_config())

    assert stats.issues_created == 0
    assert stats.issues_skipped == 1
    mock_repo.create_issue.assert_not_called()

    # The existing issue URL must be stamped so the finding is never rechecked
    row = in_memory_db.execute(
        "SELECT github_issue_url FROM findings WHERE cve_id = 'CVE-2024-9999'"
    ).fetchone()
    assert row["github_issue_url"] == "https://github.com/user/repo/issues/7"


def test_run_no_findings_returns_empty_stats(in_memory_db):
    with patch("github_issue_creator.Github"):
        stats = gic.run(in_memory_db, _make_config())
    assert stats.issues_created == 0
    assert stats.issues_skipped == 0
    assert stats.issues_failed == 0


def test_run_handles_github_exception(in_memory_db):
    from github import GithubException

    in_memory_db.execute("""
        INSERT INTO findings
            (repo_full_name, cve_id, package_name, package_ecosystem,
             state, first_seen_at, last_seen_at)
        VALUES ('user/repo', 'CVE-2024-5555', 'numpy', 'PyPI',
                'new', '2026-01-01', '2026-01-01')
        """)
    (
        in_memory_db.connection.commit()
        if hasattr(in_memory_db, "connection")
        else in_memory_db.commit()
    )

    mock_repo = MagicMock()
    mock_repo.get_issues.side_effect = GithubException(403, "Forbidden", None)

    with patch("github_issue_creator.Github") as mock_gh_cls:
        mock_gh_cls.return_value.get_repo.return_value = mock_repo
        stats = gic.run(in_memory_db, _make_config())

    assert stats.issues_failed == 1
    assert "user/repo" in stats.failed_repos


def test_run_skips_already_issued_findings(in_memory_db):
    # Finding already has a github_issue_url — should not be returned by DB query
    in_memory_db.execute("""
        INSERT INTO findings
            (repo_full_name, cve_id, package_name, package_ecosystem,
             state, first_seen_at, last_seen_at, github_issue_url)
        VALUES ('user/repo', 'CVE-2024-3333', 'boto3', 'PyPI',
                'new', '2026-01-01', '2026-01-01',
                'https://github.com/user/repo/issues/10')
        """)
    (
        in_memory_db.connection.commit()
        if hasattr(in_memory_db, "connection")
        else in_memory_db.commit()
    )

    with patch("github_issue_creator.Github") as mock_gh_cls:
        stats = gic.run(in_memory_db, _make_config())

    # get_repo should never be called — no eligible findings
    mock_gh_cls.return_value.get_repo.assert_not_called()
    assert stats.issues_created == 0
