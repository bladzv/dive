"""
Unit tests for secrets_scanner.py.

All external I/O (subprocess, GitHub API, DB) is mocked.
No gitleaks binary or network access required.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import dive.secrets_scanner as ss

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_db():
    """Return an initialised in-memory SQLite connection."""
    import dive.db as db_module

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(db_module._SCHEMA)
    db_module._migrate(conn)
    conn.commit()
    yield conn
    conn.close()


def _make_config(token: str = "fake-token", username: str = "testuser"):
    from dive.config import AppConfig, DashboardConfig, GitHubConfig

    return AppConfig(
        github=GitHubConfig(token=token, username=username),
        dashboard=DashboardConfig(username="admin", password="secret"),
    )


def _gitleaks_finding(**overrides) -> dict:
    base = {
        "Description": "GitHub Personal Access Token",
        "StartLine": 12,
        "EndLine": 12,
        "File": "config/settings.py",
        "Commit": "abc1234567890",
        "RuleID": "github-pat",
        "Fingerprint": "abc1234567890:config/settings.py:github-pat:12",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _run_gitleaks
# ---------------------------------------------------------------------------


def test_run_gitleaks_returns_findings(tmp_path):
    findings = [_gitleaks_finding()]

    def fake_run(cmd, **kwargs):
        # Write findings to the report path supplied in the command
        for i, arg in enumerate(cmd):
            if arg == "--report-path" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(json.dumps(findings))
        result = MagicMock()
        result.returncode = 1  # gitleaks exits 1 when leaks found
        return result

    with patch("dive.secrets_scanner.subprocess.run", side_effect=fake_run):
        result = ss._run_gitleaks(str(tmp_path))

    assert len(result) == 1
    assert result[0]["RuleID"] == "github-pat"


def test_run_gitleaks_no_leaks(tmp_path):
    def fake_run(cmd, **kwargs):
        for i, arg in enumerate(cmd):
            if arg == "--report-path" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("[]")
        result = MagicMock()
        result.returncode = 0
        return result

    with patch("dive.secrets_scanner.subprocess.run", side_effect=fake_run):
        result = ss._run_gitleaks(str(tmp_path))

    assert result == []


def test_run_gitleaks_error_exit_code(tmp_path):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 2  # unexpected error
        result.stderr = b"fatal: not a git repository"
        return result

    with patch("dive.secrets_scanner.subprocess.run", side_effect=fake_run):
        result = ss._run_gitleaks(str(tmp_path))

    assert result == []


def test_run_gitleaks_empty_report(tmp_path):
    def fake_run(cmd, **kwargs):
        for i, arg in enumerate(cmd):
            if arg == "--report-path" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("")
        result = MagicMock()
        result.returncode = 0
        return result

    with patch("dive.secrets_scanner.subprocess.run", side_effect=fake_run):
        result = ss._run_gitleaks(str(tmp_path))

    assert result == []


# ---------------------------------------------------------------------------
# _scan_repo — DB upsert and false-positive filtering
# ---------------------------------------------------------------------------


def test_scan_repo_inserts_new_finding(in_memory_db):
    finding = _gitleaks_finding()
    mock_repo = MagicMock()
    mock_repo.full_name = "user/myrepo"

    with (
        patch("dive.secrets_scanner._clone", return_value=(True, "")),
        patch("dive.secrets_scanner._run_gitleaks", return_value=[finding]),
    ):
        count = ss._scan_repo(in_memory_db, mock_repo, "token", 30, set())

    assert count == 1
    row = in_memory_db.execute("SELECT * FROM secret_findings").fetchone()
    assert row["repo_full_name"] == "user/myrepo"
    assert row["rule_id"] == "github-pat"
    assert row["state"] == "new"


def test_scan_repo_deduplicates_same_fingerprint(in_memory_db):
    finding = _gitleaks_finding()
    mock_repo = MagicMock()
    mock_repo.full_name = "user/myrepo"

    with (
        patch("dive.secrets_scanner._clone", return_value=(True, "")),
        patch("dive.secrets_scanner._run_gitleaks", return_value=[finding]),
    ):
        first = ss._scan_repo(in_memory_db, mock_repo, "token", 30, set())
        second = ss._scan_repo(in_memory_db, mock_repo, "token", 30, set())

    assert first == 1
    assert second == 0  # same fingerprint — not new
    assert in_memory_db.execute("SELECT COUNT(*) FROM secret_findings").fetchone()[0] == 1


def test_scan_repo_skips_false_positive_fingerprints(in_memory_db):
    finding = _gitleaks_finding()
    fp_fingerprints = {finding["Fingerprint"]}
    mock_repo = MagicMock()
    mock_repo.full_name = "user/myrepo"

    with (
        patch("dive.secrets_scanner._clone", return_value=(True, "")),
        patch("dive.secrets_scanner._run_gitleaks", return_value=[finding]),
    ):
        count = ss._scan_repo(in_memory_db, mock_repo, "token", 30, fp_fingerprints)

    assert count == 0
    assert in_memory_db.execute("SELECT COUNT(*) FROM secret_findings").fetchone()[0] == 0


def test_scan_repo_skips_finding_without_fingerprint(in_memory_db):
    finding = _gitleaks_finding(Fingerprint="")
    mock_repo = MagicMock()
    mock_repo.full_name = "user/myrepo"

    with (
        patch("dive.secrets_scanner._clone", return_value=(True, "")),
        patch("dive.secrets_scanner._run_gitleaks", return_value=[finding]),
    ):
        count = ss._scan_repo(in_memory_db, mock_repo, "token", 30, set())

    assert count == 0


def test_scan_repo_raises_on_clone_failure(in_memory_db):
    mock_repo = MagicMock()
    mock_repo.full_name = "user/myrepo"

    with (
        patch("dive.secrets_scanner._clone", return_value=(False, "fatal: repository not found")),
        pytest.raises(RuntimeError, match="git clone failed"),
    ):
        ss._scan_repo(in_memory_db, mock_repo, "token", 30, set())


def test_clone_redacts_token_from_stderr(tmp_path):
    token = "ghp_supersecrettoken1234567890"
    fake_result = MagicMock()
    fake_result.returncode = 128
    fake_result.stderr = (
        f"fatal: unable to access 'https://x-access-token:{token}@github.com/u/r.git/': "
        "The requested URL returned error: 403"
    ).encode()

    with patch("dive.secrets_scanner.subprocess.run", return_value=fake_result):
        ok, detail = ss._clone(
            f"https://x-access-token:{token}@github.com/u/r.git", str(tmp_path), 30, token
        )

    assert ok is False
    assert token not in detail
    assert "<TOKEN>" in detail
    assert "403" in detail


def test_clone_succeeds_returns_empty_detail(tmp_path):
    fake_result = MagicMock()
    fake_result.returncode = 0

    with patch("dive.secrets_scanner.subprocess.run", return_value=fake_result):
        ok, detail = ss._clone(
            "https://x-access-token:tok@github.com/u/r.git", str(tmp_path), 30, "tok"
        )

    assert ok is True
    assert detail == ""


def test_scan_repo_clone_failure_message_excludes_token(in_memory_db):
    mock_repo = MagicMock()
    mock_repo.full_name = "user/myrepo"

    with (
        patch(
            "dive.secrets_scanner._clone",
            return_value=(False, "remote: Write access to repository not granted."),
        ),
        pytest.raises(RuntimeError) as exc_info,
    ):
        ss._scan_repo(in_memory_db, mock_repo, "super-secret-token", 30, set())

    assert "super-secret-token" not in str(exc_info.value)
    assert "Write access to repository not granted" in str(exc_info.value)


# ---------------------------------------------------------------------------
# run() — top-level entry point
# ---------------------------------------------------------------------------


def test_run_returns_missing_when_no_gitleaks(in_memory_db):
    config = _make_config()
    with patch("dive.secrets_scanner.shutil.which", return_value=None):
        stats = ss.run(in_memory_db, config)

    assert stats.gitleaks_missing is True
    assert stats.repos_scanned == 0


def test_run_returns_stats_on_success(in_memory_db):
    config = _make_config()
    finding = _gitleaks_finding()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/repo1"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch("dive.secrets_scanner._clone", return_value=(True, "")),
        patch("dive.secrets_scanner._run_gitleaks", return_value=[finding]),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert stats.repos_scanned == 1
    assert stats.secrets_new == 1
    assert stats.failed_repos == []
    assert stats.gitleaks_missing is False


def test_run_lists_repos_via_authenticated_user_not_named_user(in_memory_db):
    """Regression test: gh.get_user(username) (NamedUser) only returns public
    repos even with a valid token. Must call gh.get_user() with NO arguments
    (AuthenticatedUser → GET /user/repos) and pass type="all", matching
    github_scanner.py's repo listing — otherwise private repos are silently
    skipped by the secrets scanner while still being covered by the
    dependency scanner, which is the more dangerous direction to get wrong.
    """
    config = _make_config()
    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = []

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        ss.run(in_memory_db, config)

    MockGithub.return_value.get_user.assert_called_once_with()
    mock_gh_user.get_repos.assert_called_once_with(type="all")


def test_run_records_failed_repo(in_memory_db):
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/broken"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch("dive.secrets_scanner._clone", side_effect=RuntimeError("git clone failed")),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert stats.repos_scanned == 0
    assert "user/broken" in stats.failed_repos


def test_run_sets_token_permission_warning_from_probe(in_memory_db):
    config = _make_config()
    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = []

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch(
            "dive.secrets_scanner.probe_private_repo_access",
            return_value="GitHub token cannot read private repository contents (403 on org/x).",
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert stats.token_permission_warning is not None
    assert "403" in stats.token_permission_warning


# ---------------------------------------------------------------------------
# _get_scan_depth
# ---------------------------------------------------------------------------


def test_get_scan_depth_default(in_memory_db):
    assert ss._get_scan_depth(in_memory_db) == 30


def test_get_scan_depth_from_settings(in_memory_db):
    import dive.db as db_module

    db_module.set_setting(in_memory_db, "secrets_scan_depth", "50")
    in_memory_db.commit()
    assert ss._get_scan_depth(in_memory_db) == 50


def test_get_scan_depth_invalid_falls_back(in_memory_db):
    import dive.db as db_module

    db_module.set_setting(in_memory_db, "secrets_scan_depth", "not-a-number")
    in_memory_db.commit()
    assert ss._get_scan_depth(in_memory_db) == 30
