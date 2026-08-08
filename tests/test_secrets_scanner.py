"""
Unit tests for secrets_scanner.py.

All external I/O (subprocess, GitHub API, DB) is mocked.
No gitleaks binary or network access required.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
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


def test_run_gitleaks_error_exit_code_raises_gitleaks_failed(tmp_path):
    """A non-0/1 exit code is a real gitleaks crash, not "no findings" — it
    must raise so the caller can distinguish it from a clean scan, rather than
    silently returning an empty list (which previously made a crashed scan
    indistinguishable from a repo with zero secrets)."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 2  # unexpected error
        result.stderr = b"fatal: not a git repository"
        return result

    with (
        patch("dive.secrets_scanner.subprocess.run", side_effect=fake_run),
        pytest.raises(ss._GitleaksFailed, match="exited 2"),
    ):
        ss._run_gitleaks(str(tmp_path))


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
    assert len(stats.failed_repos) == 1
    assert "user/broken" in stats.failed_repos[0]
    assert "RuntimeError" in stats.failed_repos[0]


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


# ---------------------------------------------------------------------------
# _explain_clone_failure / clone-failure remediation surfacing
# ---------------------------------------------------------------------------


def test_explain_clone_failure_maps_write_access_403_to_read_access_fix():
    msg = ss._explain_clone_failure("remote: Write access to repository not granted.")
    assert msg is not None
    assert "Contents: Read-only" in msg
    assert "does NOT require write access" in msg


def test_explain_clone_failure_returns_none_for_unrecognised_error():
    assert ss._explain_clone_failure("fatal: early EOF") is None


def test_run_surfaces_clone_permission_failure_inline_and_as_warning(in_memory_db):
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/broken"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch(
            "dive.secrets_scanner._clone",
            return_value=(False, "remote: Write access to repository not granted."),
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert len(stats.failed_repos) == 1
    assert "user/broken" in stats.failed_repos[0]
    assert "Contents" in stats.failed_repos[0]
    assert stats.token_permission_warning is not None
    assert "user/broken" in stats.token_permission_warning
    assert "Contents" in stats.token_permission_warning


def test_run_does_not_overwrite_probe_warning_with_clone_failure_warning(in_memory_db):
    """probe_private_repo_access's warning is set before the scan loop runs and
    is strictly more informative (it names the exact repo the probe checked) —
    a later clone failure must not clobber it."""
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/broken"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    sentinel = "GitHub token cannot read private repository contents (403 on org/x)."

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch("dive.secrets_scanner.probe_private_repo_access", return_value=sentinel),
        patch(
            "dive.secrets_scanner._clone",
            return_value=(False, "remote: Write access to repository not granted."),
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert stats.token_permission_warning == sentinel
    # the per-repo entry still carries its own remediation
    assert "Contents" in stats.failed_repos[0]


def test_run_records_timeout_with_actionable_message(in_memory_db):
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/slow"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch(
            "dive.secrets_scanner._scan_repo",
            side_effect=subprocess.TimeoutExpired(cmd="git clone", timeout=120),
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert stats.repos_scanned == 0
    assert len(stats.failed_repos) == 1
    assert "user/slow" in stats.failed_repos[0]
    assert "secrets_scan_depth" in stats.failed_repos[0]


def test_run_sets_warning_when_gitleaks_missing(in_memory_db):
    config = _make_config()
    with patch("dive.secrets_scanner.shutil.which", return_value=None):
        stats = ss.run(in_memory_db, config)

    assert stats.gitleaks_missing is True
    assert stats.token_permission_warning is not None
    assert "gitleaks" in stats.token_permission_warning.lower()


# ---------------------------------------------------------------------------
# _condense_detail
# ---------------------------------------------------------------------------


def test_condense_detail_prefers_fatal_line():
    detail = (
        "remote: Write access to repository not granted.\n"
        "fatal: unable to access 'https://github.com/u/r.git/': "
        "The requested URL returned error: 403\n"
    )
    result = ss._condense_detail(detail)
    assert result.startswith("fatal:")
    assert "403" in result


def test_condense_detail_falls_back_to_first_line_without_fatal():
    result = ss._condense_detail("remote: something went wrong\nmore detail here")
    assert result == "remote: something went wrong"


def test_condense_detail_handles_empty_string():
    result = ss._condense_detail("")
    assert result == "no error output from git"


# ---------------------------------------------------------------------------
# run() — no failed_repos entry is ever a bare repo name
# ---------------------------------------------------------------------------


def test_run_unmatched_clone_failure_still_carries_a_reason(in_memory_db):
    """Regression test for the reported symptom: a clone failure whose stderr
    matches none of _explain_clone_failure's three patterns previously
    produced a bare repo name in failed_repos with no indication of cause."""
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/broken"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch(
            "dive.secrets_scanner._clone",
            return_value=(False, "fatal: the remote end hung up unexpectedly"),
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert len(stats.failed_repos) == 1
    assert stats.failed_repos[0] != "user/broken"
    assert "user/broken" in stats.failed_repos[0]
    assert "remote end hung up" in stats.failed_repos[0]
    # unrecognised failures are not actionable enough for the aggregate banner
    assert stats.token_permission_warning is None


def test_run_gitleaks_failure_recorded_as_failed_not_scanned(in_memory_db):
    """A crashed gitleaks run must not be indistinguishable from a clean scan
    — the repo must land in failed_repos, not repos_scanned."""
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/crashy"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch("dive.secrets_scanner._clone", return_value=(True, "")),
        patch(
            "dive.secrets_scanner._run_gitleaks",
            side_effect=ss._GitleaksFailed("exited 2: fatal: not a git repository"),
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert stats.repos_scanned == 0
    assert len(stats.failed_repos) == 1
    assert "user/crashy" in stats.failed_repos[0]
    assert "not a git repository" in stats.failed_repos[0]


def test_run_gitleaks_malformed_json_raises_gitleaks_failed(tmp_path):
    def fake_run(cmd, **kwargs):
        for i, arg in enumerate(cmd):
            if arg == "--report-path" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("{not valid json")
        result = MagicMock()
        result.returncode = 0
        return result

    with (
        patch("dive.secrets_scanner.subprocess.run", side_effect=fake_run),
        pytest.raises(ss._GitleaksFailed, match="unreadable report"),
    ):
        ss._run_gitleaks(str(tmp_path))


def test_run_generic_exception_carries_exception_type_and_message(in_memory_db):
    """The catch-all handler previously discarded the exception entirely,
    leaving only a bare repo name."""
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/weird"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch("dive.secrets_scanner._scan_repo", side_effect=ValueError("unexpected shape")),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert len(stats.failed_repos) == 1
    assert "user/weird" in stats.failed_repos[0]
    assert "ValueError" in stats.failed_repos[0]
    assert "unexpected shape" in stats.failed_repos[0]


# ---------------------------------------------------------------------------
# run() — timeout does not leak the embedded access token
# ---------------------------------------------------------------------------


def test_run_clone_timeout_does_not_leak_token(in_memory_db, caplog):
    """TimeoutExpired.cmd for a clone timeout is the real argv, which embeds a
    live access token in the clone URL. Neither the failed_repos entry nor
    the log message may contain it — only the binary name may be extracted
    from exc.cmd."""
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/slow-clone"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    real_argv = [
        "git",
        "clone",
        "--depth",
        "31",
        "--quiet",
        "https://x-access-token:SUPERSECRETTOKEN@github.com/user/slow-clone.git",
        "/tmp/whatever",
    ]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch(
            "dive.secrets_scanner._scan_repo",
            side_effect=subprocess.TimeoutExpired(cmd=real_argv, timeout=120),
        ),
        caplog.at_level("ERROR"),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert len(stats.failed_repos) == 1
    assert "SUPERSECRETTOKEN" not in stats.failed_repos[0]
    assert "x-access-token" not in stats.failed_repos[0]
    assert "git clone timed out" in stats.failed_repos[0]
    for record in caplog.records:
        assert "SUPERSECRETTOKEN" not in record.getMessage()
        assert "x-access-token" not in record.getMessage()


def test_run_gitleaks_timeout_message_differs_from_clone_timeout(in_memory_db):
    config = _make_config()

    mock_repo = MagicMock()
    mock_repo.full_name = "user/slow-scan"

    mock_gh_user = MagicMock()
    mock_gh_user.get_repos.return_value = [mock_repo]

    with (
        patch("dive.secrets_scanner.shutil.which", return_value="/usr/local/bin/gitleaks"),
        patch("dive.secrets_scanner.Github") as MockGithub,
        patch(
            "dive.secrets_scanner._scan_repo",
            side_effect=subprocess.TimeoutExpired(
                cmd=["gitleaks", "detect", "--source", "/tmp/x"], timeout=180
            ),
        ),
    ):
        MockGithub.return_value.get_user.return_value = mock_gh_user
        stats = ss.run(in_memory_db, config)

    assert "gitleaks scan timed out" in stats.failed_repos[0]
    assert "exclude this repo" in stats.failed_repos[0]
