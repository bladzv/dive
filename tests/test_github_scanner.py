"""
Unit tests for github_scanner.py — manifest parsers, version extraction,
severity/CVSS helpers, priority scoring, OSV response parsing, AI next steps.

No GitHub API or OSV.dev calls are made — everything is tested with fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

import dive.db as db
import dive.github_scanner as gs
from dive.config import AppConfig, DashboardConfig, GitHubConfig
from dive.github_scanner import (
    _LATEST_VERSION_REGISTRIES,
    Package,
    ScannerStats,
    _cvss_to_severity_text,
    _extract_fixed_version,
    _extract_severity,
    _extract_version,
    _lookup_latest_maven,
    _lookup_latest_nuget,
    _lookup_latest_packagist,
    _parse_build_gradle,
    _parse_cargo_lock,
    _parse_cargo_toml,
    _parse_composer_json,
    _parse_composer_lock,
    _parse_csproj,
    _parse_gemfile,
    _parse_gemfile_lock,
    _parse_github_actions,
    _parse_go_mod,
    _parse_next_steps,
    _parse_package_json,
    _parse_package_lock,
    _parse_packages_lock_json,
    _parse_pipfile,
    _parse_pnpm_lock,
    _parse_poetry_lock,
    _parse_pom_xml,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    _parse_uv_lock,
    _parse_yarn_lock,
    _priority_score,
    _query_and_store_batch,
    _RepoTreeUnavailable,
    _store_osv_finding,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_conn(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init(db_path)
    with db.get_conn(db_path) as conn:
        yield conn


# ---------------------------------------------------------------------------
# _extract_version
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("4.18.2", "4.18.2"),
        ("^4.18.0", "4.18.0"),
        ("~4.18.0", "4.18.0"),
        (">=1.0.0", "1.0.0"),
        (">=1.0,<2.0", "1.0"),
        ("==2.28.0", "2.28.0"),
        ("*", None),
        ("latest", None),
        ("", None),
        ("v3", "3"),  # v-prefixed
        ("1.0.0-beta.1", "1.0.0-beta.1"),
    ],
)
def test_extract_version(spec, expected):
    assert _extract_version(spec) == expected


# ---------------------------------------------------------------------------
# _parse_package_lock
# ---------------------------------------------------------------------------


def test_parse_package_lock_v3():
    content = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app"},  # root entry — should be skipped
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/lodash": {"version": "4.17.20"},
            },
        }
    )
    pkgs = _parse_package_lock(content, "package-lock.json")
    names = {p.name: p.version for p in pkgs}
    assert names.get("express") == "4.18.2"
    assert names.get("lodash") == "4.17.20"
    assert "" not in names  # root skipped


def test_parse_package_lock_returns_npm_ecosystem():
    content = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/react": {"version": "18.0.0"}},
        }
    )
    pkgs = _parse_package_lock(content, "package-lock.json")
    assert all(p.ecosystem == "npm" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_package_json
# ---------------------------------------------------------------------------


def test_parse_package_json_extracts_dependencies():
    content = json.dumps(
        {
            "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }
    )
    pkgs = _parse_package_json(content, "package.json")
    names = {p.name for p in pkgs}
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names


def test_parse_package_json_strips_semver_range():
    content = json.dumps({"dependencies": {"express": "^4.18.0"}})
    pkgs = _parse_package_json(content, "package.json")
    assert pkgs[0].version == "4.18.0"


# ---------------------------------------------------------------------------
# _parse_requirements_txt
# ---------------------------------------------------------------------------


_REQUIREMENTS = """\
# This is a comment
requests==2.28.0
flask>=2.0,<3.0
django~=4.2
cryptography  # pinned elsewhere
-r other.txt
numpy
"""


def test_parse_requirements_txt_extracts_names():
    pkgs = _parse_requirements_txt(_REQUIREMENTS, "requirements.txt")
    names = {p.name for p in pkgs}
    assert "requests" in names
    assert "flask" in names
    assert "django" in names


def test_parse_requirements_txt_extracts_pinned_version():
    pkgs = _parse_requirements_txt(_REQUIREMENTS, "requirements.txt")
    req = next(p for p in pkgs if p.name == "requests")
    assert req.version == "2.28.0"


def test_parse_requirements_txt_extracts_lower_bound():
    pkgs = _parse_requirements_txt(_REQUIREMENTS, "requirements.txt")
    flask = next(p for p in pkgs if p.name == "flask")
    assert flask.version == "2.0"


def test_parse_requirements_txt_skips_r_includes():
    pkgs = _parse_requirements_txt(_REQUIREMENTS, "requirements.txt")
    names = {p.name for p in pkgs}
    assert "other.txt" not in names


def test_parse_requirements_txt_skips_comments():
    pkgs = _parse_requirements_txt("# just a comment\n", "requirements.txt")
    assert len(pkgs) == 0


def test_parse_requirements_txt_pypi_ecosystem():
    pkgs = _parse_requirements_txt("flask==2.0.0\n", "requirements.txt")
    assert all(p.ecosystem == "PyPI" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_pipfile
# ---------------------------------------------------------------------------


_PIPFILE = """\
[packages]
requests = ">=2.28"
flask = "*"

[dev-packages]
pytest = ">=7.0"
"""


def test_parse_pipfile_extracts_packages():
    pkgs = _parse_pipfile(_PIPFILE, "Pipfile")
    names = {p.name for p in pkgs}
    assert "requests" in names
    assert "flask" in names


def test_parse_pipfile_extracts_dev_packages():
    pkgs = _parse_pipfile(_PIPFILE, "Pipfile")
    names = {p.name for p in pkgs}
    assert "pytest" in names


def test_parse_pipfile_star_version_is_none():
    pkgs = _parse_pipfile(_PIPFILE, "Pipfile")
    flask = next(p for p in pkgs if p.name == "flask")
    assert flask.version is None


# ---------------------------------------------------------------------------
# _parse_pyproject_toml
# ---------------------------------------------------------------------------


_PYPROJECT = """\
[project]
name = "my-project"
dependencies = [
    "requests>=2.28",
    "flask~=2.0",
    "click",
]
"""


def test_parse_pyproject_toml_extracts_deps():
    pkgs = _parse_pyproject_toml(_PYPROJECT, "pyproject.toml")
    names = {p.name for p in pkgs}
    assert "requests" in names
    assert "flask" in names
    assert "click" in names


def test_parse_pyproject_toml_extracts_version():
    pkgs = _parse_pyproject_toml(_PYPROJECT, "pyproject.toml")
    req = next(p for p in pkgs if p.name == "requests")
    assert req.version == "2.28"


def test_parse_pyproject_toml_no_version_is_none():
    pkgs = _parse_pyproject_toml(_PYPROJECT, "pyproject.toml")
    click = next(p for p in pkgs if p.name == "click")
    assert click.version is None


# ---------------------------------------------------------------------------
# _parse_github_actions
# ---------------------------------------------------------------------------


_WORKFLOW = """\
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4.6.1
      - uses: ./.github/actions/local-action   # local — should be skipped
      - run: echo hello
"""


def test_parse_github_actions_extracts_uses():
    pkgs = _parse_github_actions(_WORKFLOW, ".github/workflows/ci.yml")
    names = {p.name for p in pkgs}
    assert "actions/checkout" in names
    assert "actions/setup-python" in names


def test_parse_github_actions_skips_local():
    pkgs = _parse_github_actions(_WORKFLOW, ".github/workflows/ci.yml")
    names = {p.name for p in pkgs}
    assert not any(n.startswith(".") for n in names)


def test_parse_github_actions_extracts_version():
    pkgs = _parse_github_actions(_WORKFLOW, ".github/workflows/ci.yml")
    checkout = next(p for p in pkgs if p.name == "actions/checkout")
    assert checkout.version == "v4"


def test_parse_github_actions_ecosystem():
    pkgs = _parse_github_actions(_WORKFLOW, ".github/workflows/ci.yml")
    assert all(p.ecosystem == "GitHub Actions" for p in pkgs)


# ---------------------------------------------------------------------------
# _extract_severity
# ---------------------------------------------------------------------------


def test_extract_severity_from_database_specific():
    vuln = {"database_specific": {"severity": "HIGH"}}
    text, score = _extract_severity(vuln)
    assert text == "High"
    assert score == 7.5


def test_extract_severity_critical():
    vuln = {"database_specific": {"severity": "CRITICAL"}}
    text, score = _extract_severity(vuln)
    assert text == "Critical"
    assert score == 9.0


def test_extract_severity_unknown_fallback():
    vuln = {}
    text, score = _extract_severity(vuln)
    assert text == "Unknown"
    assert score is None


# ---------------------------------------------------------------------------
# _extract_fixed_version
# ---------------------------------------------------------------------------


def _make_osv_vuln(ecosystem: str, pkg_name: str, fixed: str) -> dict:
    return {
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ]
    }


def test_extract_fixed_version_found():
    vuln = _make_osv_vuln("PyPI", "requests", "2.32.0")
    assert _extract_fixed_version(vuln, "PyPI", "requests") == "2.32.0"


def test_extract_fixed_version_case_insensitive():
    vuln = _make_osv_vuln("PyPI", "Requests", "2.32.0")
    assert _extract_fixed_version(vuln, "PyPI", "requests") == "2.32.0"


def test_extract_fixed_version_wrong_ecosystem():
    vuln = _make_osv_vuln("npm", "requests", "2.32.0")
    assert _extract_fixed_version(vuln, "PyPI", "requests") is None


def test_extract_fixed_version_no_fix():
    vuln = {
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ]
    }
    assert _extract_fixed_version(vuln, "PyPI", "requests") is None


# ---------------------------------------------------------------------------
# _priority_score
# ---------------------------------------------------------------------------


def test_priority_score_critical_kev_no_patch():
    score = _priority_score(cvss_score=9.0, is_kev=True, patch_available=False)
    # 9*6=54 + 25 - 5 = 74
    assert score == 74.0


def test_priority_score_high_no_kev_patch():
    score = _priority_score(cvss_score=7.5, is_kev=False, patch_available=True)
    # 7.5*6=45
    assert score == 45.0


def test_priority_score_minimum_zero():
    score = _priority_score(cvss_score=0.0, is_kev=False, patch_available=True)
    assert score >= 0.0


def test_priority_score_maximum_100():
    score = _priority_score(cvss_score=10.0, is_kev=True, patch_available=False)
    assert score <= 100.0


def test_priority_score_none_cvss():
    score = _priority_score(cvss_score=None, is_kev=False, patch_available=True)
    assert score == 0.0


# ---------------------------------------------------------------------------
# _cvss_to_severity_text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score, expected",
    [
        (10.0, "Critical"),
        (9.0, "Critical"),
        (8.9, "High"),
        (7.0, "High"),
        (6.9, "Medium"),
        (4.0, "Medium"),
        (3.9, "Low"),
        (0.0, "Low"),
    ],
)
def test_cvss_to_severity_text(score, expected):
    assert _cvss_to_severity_text(score) == expected


# ---------------------------------------------------------------------------
# _parse_next_steps
# ---------------------------------------------------------------------------


def test_parse_next_steps_valid():
    raw = json.dumps(
        {
            "impact": "Attacker can execute arbitrary code.",
            "fix": "Upgrade to requests>=2.32.0",
            "effort": "Low",
        }
    )
    result = _parse_next_steps(raw)
    assert result is not None
    assert result["effort"] == "Low"
    assert "2.32.0" in result["fix"]


def test_parse_next_steps_invalid_json():
    assert _parse_next_steps("not json") is None


def test_parse_next_steps_missing_field():
    raw = json.dumps({"impact": "bad", "fix": "something"})  # missing effort
    result = _parse_next_steps(raw)
    # effort defaults to Medium when missing/invalid
    assert result is None or result["effort"] == "Medium"


def test_parse_next_steps_invalid_effort_defaults_medium():
    raw = json.dumps(
        {
            "impact": "Something bad.",
            "fix": "Upgrade it.",
            "effort": "Very Hard",  # invalid
        }
    )
    result = _parse_next_steps(raw)
    assert result is not None
    assert result["effort"] == "Medium"


# ---------------------------------------------------------------------------
# db.upsert_finding
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> dict:
    base = {
        "repo_full_name": "user/my-repo",
        "cve_id": "CVE-2024-1234",
        "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
        "package_name": "requests",
        "package_ecosystem": "PyPI",
        "installed_version": "2.28.0",
        "fixed_version": "2.32.0",
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 45.0,
        "manifest_path": "requirements.txt",
    }
    base.update(overrides)
    return base


def test_upsert_finding_returns_true_on_new(db_conn):
    assert db.upsert_finding(db_conn, _make_finding()) is True


def test_upsert_finding_returns_false_on_duplicate(db_conn):
    db.upsert_finding(db_conn, _make_finding())
    assert db.upsert_finding(db_conn, _make_finding()) is False


def test_upsert_finding_state_defaults_to_new(db_conn):
    db.upsert_finding(db_conn, _make_finding())
    row = db_conn.execute("SELECT state FROM findings").fetchone()
    assert row["state"] == "new"


def test_upsert_finding_does_not_change_state_on_update(db_conn):
    db.upsert_finding(db_conn, _make_finding())
    db_conn.execute("UPDATE findings SET state = 'acknowledged'")
    # Second upsert should NOT revert state to 'new'
    db.upsert_finding(db_conn, _make_finding(installed_version="2.28.1"))
    row = db_conn.execute("SELECT state FROM findings").fetchone()
    assert row["state"] == "acknowledged"


def test_upsert_finding_stamps_id_on_insert(db_conn):
    finding = _make_finding()
    assert "id" not in finding
    db.upsert_finding(db_conn, finding)
    row = db_conn.execute(
        "SELECT id FROM findings WHERE cve_id = ?", (finding["cve_id"],)
    ).fetchone()
    assert finding["id"] == row["id"]


def test_upsert_finding_stamps_id_on_update(db_conn):
    first = _make_finding()
    db.upsert_finding(db_conn, first)
    inserted_id = first["id"]

    second = _make_finding(installed_version="2.28.1")
    db.upsert_finding(db_conn, second)
    assert second["id"] == inserted_id


def test_upsert_finding_id_disambiguates_rows_sharing_null_cve_id(db_conn):
    """Two findings for the same package with cve_id=NULL but different
    ghsa_id are distinct rows. Threading finding["id"] through (rather than
    re-querying by natural key on cve_id alone) must resolve to the correct
    one for each — this is the scenario the old
    _generate_next_steps_for_finding lookup got wrong.
    """
    first = _make_finding(cve_id=None, ghsa_id="GHSA-aaaa-aaaa-aaaa")
    second = _make_finding(cve_id=None, ghsa_id="GHSA-bbbb-bbbb-bbbb")
    db.upsert_finding(db_conn, first)
    db.upsert_finding(db_conn, second)

    assert first["id"] != second["id"]
    row1 = db_conn.execute("SELECT ghsa_id FROM findings WHERE id = ?", (first["id"],)).fetchone()
    row2 = db_conn.execute("SELECT ghsa_id FROM findings WHERE id = ?", (second["id"],)).fetchone()
    assert row1["ghsa_id"] == "GHSA-aaaa-aaaa-aaaa"
    assert row2["ghsa_id"] == "GHSA-bbbb-bbbb-bbbb"


def test_get_kev_cve_ids_from_news_items(db_conn):
    db.insert_news_item(
        db_conn,
        {
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#CVE-2024-9999",
            "title": "CVE-2024-9999 — KEV entry",
            "source": "CISA KEV",
            "fetched_at": "2024-01-15T00:00:00+00:00",
        },
    )
    kev_ids = db.get_kev_cve_ids(db_conn)
    assert "CVE-2024-9999" in kev_ids


def test_get_kev_cve_ids_empty_when_no_kev(db_conn):
    assert db.get_kev_cve_ids(db_conn) == set()


def test_kev_survives_news_pruning(db_conn):
    """is_kev must not regress when news.retention_days prunes the KEV news item."""
    db.insert_news_item(
        db_conn,
        {
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#CVE-2024-9999",
            "title": "CVE-2024-9999 — KEV entry",
            "source": "CISA KEV",
            "fetched_at": "2024-01-15T00:00:00+00:00",
        },
    )
    db.upsert_kev_entries(db_conn, [("CVE-2024-9999", "2024-01-10")])

    # Simulate retention pruning away the news item entirely.
    db.clear_news_items(db_conn)
    assert db_conn.execute("SELECT COUNT(*) FROM news_items").fetchone()[0] == 0

    kev_ids = db.get_kev_cve_ids(db_conn)
    assert "CVE-2024-9999" in kev_ids


def test_upsert_kev_entries_is_idempotent_and_updates_added_at(db_conn):
    db.upsert_kev_entries(db_conn, [("CVE-2024-1111", "2024-01-01")])
    db.upsert_kev_entries(db_conn, [("CVE-2024-1111", "2024-02-01")])
    row = db_conn.execute(
        "SELECT added_at FROM kev_entries WHERE cve_id = ?", ("CVE-2024-1111",)
    ).fetchone()
    assert row["added_at"] == "2024-02-01"
    count = db_conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0]
    assert count == 1


def test_upsert_kev_entries_uppercases_cve_id(db_conn):
    db.upsert_kev_entries(db_conn, [("cve-2024-2222", None)])
    kev_ids = db.get_kev_cve_ids(db_conn)
    assert "CVE-2024-2222" in kev_ids


# ---------------------------------------------------------------------------
# run() — repo listing must cover private repos
# ---------------------------------------------------------------------------


def test_run_lists_repos_via_authenticated_user_with_type_all(db_conn):
    """gs.run() must list repos via the AuthenticatedUser (GET /user/repos,
    type="all") so private repos are included — this is the behaviour
    secrets_scanner.py was missing (it called gh.get_user(username), a
    NamedUser, which only returns public repos). Locking this in here so the
    dependency scanner can't regress to the same bug.
    """
    from unittest.mock import patch

    config = AppConfig(
        github=GitHubConfig(token="tok", username="someuser"),
        dashboard=DashboardConfig(username="admin", password="secret"),
    )
    mock_user = MagicMock()
    mock_user.get_repos.return_value = []

    with patch("dive.github_scanner.Github") as MockGithub:
        MockGithub.return_value.get_user.return_value = mock_user
        MockGithub.return_value.rate_limiting = (5000, 5000)
        gs.run(db_conn, config)

    MockGithub.return_value.get_user.assert_called_once_with()
    mock_user.get_repos.assert_called_once_with(type="all")


# ---------------------------------------------------------------------------
# run() / _scan_repo — skipped vs. failed repos must be visible, not silent
# ---------------------------------------------------------------------------


def test_fetch_manifest_content_uses_contents_api_for_small_file():
    mock_repo = MagicMock()
    mock_repo.full_name = "user/repo"
    mock_content = MagicMock()
    mock_content.decoded_content = b'{"name": "pkg"}'
    mock_repo.get_contents.return_value = mock_content

    raw = gs._fetch_manifest_content(mock_repo, "package.json", "sha123", 500)

    assert raw == '{"name": "pkg"}'
    mock_repo.get_contents.assert_called_once_with("package.json")
    mock_repo.get_git_blob.assert_not_called()


def test_fetch_manifest_content_uses_blob_api_above_contents_size_limit():
    """Regression test: files over ~1MB return encoding="none" from the
    Contents API and previously yielded zero packages with only a DEBUG log.
    """
    import base64

    mock_repo = MagicMock()
    mock_repo.full_name = "user/repo"
    mock_blob = MagicMock()
    mock_blob.content = base64.b64encode(b'{"name": "big-pkg"}').decode()
    mock_repo.get_git_blob.return_value = mock_blob

    raw = gs._fetch_manifest_content(mock_repo, "package-lock.json", "sha456", 2_000_000)

    assert raw == '{"name": "big-pkg"}'
    mock_repo.get_git_blob.assert_called_once_with("sha456")
    mock_repo.get_contents.assert_not_called()


def test_fetch_manifest_content_skips_absurdly_large_file():
    mock_repo = MagicMock()
    mock_repo.full_name = "user/repo"

    raw = gs._fetch_manifest_content(mock_repo, "huge.json", "sha789", 50_000_000)

    assert raw is None
    mock_repo.get_git_blob.assert_not_called()
    mock_repo.get_contents.assert_not_called()


def test_fetch_manifest_content_handles_directory_response():
    mock_repo = MagicMock()
    mock_repo.full_name = "user/repo"
    mock_repo.get_contents.return_value = [MagicMock(), MagicMock()]

    raw = gs._fetch_manifest_content(mock_repo, "some/path", "sha000", 100)

    assert raw is None


def test_scan_repo_raises_when_tree_unavailable():
    from github import GithubException

    mock_repo = MagicMock()
    mock_repo.full_name = "user/no-tree"
    mock_repo.default_branch = "main"
    mock_repo.get_git_tree.side_effect = GithubException(404, "Not Found", None)

    with pytest.raises(_RepoTreeUnavailable):
        gs._scan_repo(mock_repo)


def _tree_element(path, size=100):
    el = MagicMock()
    el.type = "blob"
    el.path = path
    el.sha = f"sha-{path}"
    el.size = size
    return el


def test_scan_repo_picks_one_npm_lockfile_when_multiple_present():
    """A repo mid-migration from Yarn to npm can have both package-lock.json
    and yarn.lock (plus the loose package.json) — only one should be fetched
    so packages aren't double-counted."""
    mock_repo = MagicMock()
    mock_repo.full_name = "user/multi-lock"
    mock_repo.default_branch = "main"

    tree = MagicMock()
    tree.truncated = False
    tree.tree = [
        _tree_element("package.json"),
        _tree_element("package-lock.json"),
        _tree_element("yarn.lock"),
    ]
    mock_repo.get_git_tree.return_value = tree

    fetched_paths = []

    def _fake_get_contents(path):
        fetched_paths.append(path)
        content = MagicMock()
        content.decoded_content = b'{"packages": {}}'
        return content

    mock_repo.get_contents.side_effect = _fake_get_contents

    gs._scan_repo(mock_repo)

    assert fetched_paths == ["package-lock.json"]


def test_run_records_repo_in_skipped_repos_when_tree_unavailable(db_conn):
    from unittest.mock import patch

    from github import GithubException

    config = AppConfig(
        github=GitHubConfig(token="tok", username="someuser"),
        dashboard=DashboardConfig(username="admin", password="secret"),
    )
    mock_repo = MagicMock()
    mock_repo.full_name = "user/no-tree"
    mock_repo.default_branch = "main"
    mock_repo.get_git_tree.side_effect = GithubException(404, "Not Found", None)

    mock_user = MagicMock()
    mock_user.get_repos.return_value = [mock_repo]

    with patch("dive.github_scanner.Github") as MockGithub:
        MockGithub.return_value.get_user.return_value = mock_user
        MockGithub.return_value.rate_limiting = (5000, 5000)
        stats = gs.run(db_conn, config)

    assert stats.skipped_repos == ["user/no-tree"]
    assert stats.failed_repos == []
    assert stats.repos_scanned == 0


def test_run_records_repo_in_failed_repos_on_unexpected_error(db_conn):
    """Previously a bare Exception during a repo scan was logged but counted
    in neither failed_repos nor repos_scanned — a silent gap where a repo
    just vanished from the run's accounting."""
    from unittest.mock import patch

    config = AppConfig(
        github=GitHubConfig(token="tok", username="someuser"),
        dashboard=DashboardConfig(username="admin", password="secret"),
    )
    mock_repo = MagicMock()
    mock_repo.full_name = "user/weird"
    mock_repo.default_branch = "main"
    mock_repo.get_git_tree.side_effect = RuntimeError("boom")

    mock_user = MagicMock()
    mock_user.get_repos.return_value = [mock_repo]

    with patch("dive.github_scanner.Github") as MockGithub:
        MockGithub.return_value.get_user.return_value = mock_user
        MockGithub.return_value.rate_limiting = (5000, 5000)
        stats = gs.run(db_conn, config)

    assert "user/weird" in stats.failed_repos
    assert stats.repos_scanned == 0


# ---------------------------------------------------------------------------
# _parse_go_mod
# ---------------------------------------------------------------------------

_GO_MOD = """\
module github.com/user/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/net v0.20.0 // indirect
)

require github.com/user/pkg v1.2.3
"""


def test_parse_go_mod_extracts_block_deps():
    pkgs = _parse_go_mod(_GO_MOD, "go.mod")
    names = {p.name: p.version for p in pkgs}
    assert names.get("github.com/gin-gonic/gin") == "1.9.1"
    assert names.get("golang.org/x/net") == "0.20.0"


def test_parse_go_mod_extracts_single_line_dep():
    pkgs = _parse_go_mod(_GO_MOD, "go.mod")
    names = {p.name for p in pkgs}
    assert "github.com/user/pkg" in names


def test_parse_go_mod_strips_v_prefix():
    pkgs = _parse_go_mod(_GO_MOD, "go.mod")
    gin = next(p for p in pkgs if p.name == "github.com/gin-gonic/gin")
    assert gin.version == "1.9.1"


def test_parse_go_mod_ecosystem():
    pkgs = _parse_go_mod(_GO_MOD, "go.mod")
    assert all(p.ecosystem == "Go" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_cargo_toml
# ---------------------------------------------------------------------------

_CARGO_TOML = """\
[package]
name = "my-app"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
local-dep = { path = "../other" }
git-dep = { git = "https://github.com/foo/bar" }

[dev-dependencies]
rand = "0.8"
"""


def test_parse_cargo_toml_extracts_deps():
    pkgs = _parse_cargo_toml(_CARGO_TOML, "Cargo.toml")
    names = {p.name for p in pkgs}
    assert "serde" in names
    assert "tokio" in names


def test_parse_cargo_toml_extracts_dev_deps():
    pkgs = _parse_cargo_toml(_CARGO_TOML, "Cargo.toml")
    names = {p.name for p in pkgs}
    assert "rand" in names


def test_parse_cargo_toml_skips_path_deps():
    pkgs = _parse_cargo_toml(_CARGO_TOML, "Cargo.toml")
    names = {p.name for p in pkgs}
    assert "local-dep" not in names


def test_parse_cargo_toml_skips_git_deps():
    pkgs = _parse_cargo_toml(_CARGO_TOML, "Cargo.toml")
    names = {p.name for p in pkgs}
    assert "git-dep" not in names


def test_parse_cargo_toml_extracts_version():
    pkgs = _parse_cargo_toml(_CARGO_TOML, "Cargo.toml")
    serde = next(p for p in pkgs if p.name == "serde")
    assert serde.version == "1.0"


def test_parse_cargo_toml_ecosystem():
    pkgs = _parse_cargo_toml(_CARGO_TOML, "Cargo.toml")
    assert all(p.ecosystem == "crates.io" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_cargo_lock
# ---------------------------------------------------------------------------

_CARGO_LOCK = """\
[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"

[[package]]
name = "tokio"
version = "1.35.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


def test_parse_cargo_lock_extracts_registry_crates():
    pkgs = _parse_cargo_lock(_CARGO_LOCK, "Cargo.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("serde") == "1.0.193"
    assert names.get("tokio") == "1.35.1"


def test_parse_cargo_lock_skips_local_crates():
    pkgs = _parse_cargo_lock(_CARGO_LOCK, "Cargo.lock")
    names = {p.name for p in pkgs}
    assert "local-crate" not in names


def test_parse_cargo_lock_ecosystem():
    pkgs = _parse_cargo_lock(_CARGO_LOCK, "Cargo.lock")
    assert all(p.ecosystem == "crates.io" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_pom_xml
# ---------------------------------------------------------------------------

_POM_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.21</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
"""


def test_parse_pom_xml_extracts_deps():
    pkgs = _parse_pom_xml(_POM_XML, "pom.xml")
    names = {p.name for p in pkgs}
    assert "org.springframework:spring-core" in names


def test_parse_pom_xml_name_is_group_artifact():
    pkgs = _parse_pom_xml(_POM_XML, "pom.xml")
    dep = next(p for p in pkgs if "spring-core" in p.name)
    assert dep.name == "org.springframework:spring-core"
    assert dep.version == "5.3.21"


def test_parse_pom_xml_skips_property_version():
    pkgs = _parse_pom_xml(_POM_XML, "pom.xml")
    junit = next((p for p in pkgs if "junit" in p.name), None)
    assert junit is not None
    assert junit.version is None


def test_parse_pom_xml_no_version_is_none():
    pkgs = _parse_pom_xml(_POM_XML, "pom.xml")
    jackson = next(p for p in pkgs if "jackson-databind" in p.name)
    assert jackson.version is None


def test_parse_pom_xml_ecosystem():
    pkgs = _parse_pom_xml(_POM_XML, "pom.xml")
    assert all(p.ecosystem == "Maven" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_build_gradle
# ---------------------------------------------------------------------------

_BUILD_GRADLE = """\
dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation "junit:junit:4.13.2"
    api 'com.google.guava:guava:32.0.0-jre'
    implementation group: 'org.apache.commons', name: 'commons-lang3', version: '3.12.0'
}
"""


def test_parse_build_gradle_string_notation():
    pkgs = _parse_build_gradle(_BUILD_GRADLE, "build.gradle")
    names = {p.name for p in pkgs}
    assert "org.springframework:spring-core" in names
    assert "junit:junit" in names


def test_parse_build_gradle_map_notation():
    pkgs = _parse_build_gradle(_BUILD_GRADLE, "build.gradle")
    names = {p.name for p in pkgs}
    assert "org.apache.commons:commons-lang3" in names


def test_parse_build_gradle_extracts_version():
    pkgs = _parse_build_gradle(_BUILD_GRADLE, "build.gradle")
    spring = next(p for p in pkgs if p.name == "org.springframework:spring-core")
    assert spring.version == "5.3.21"


def test_parse_build_gradle_ecosystem():
    pkgs = _parse_build_gradle(_BUILD_GRADLE, "build.gradle")
    assert all(p.ecosystem == "Maven" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_gemfile
# ---------------------------------------------------------------------------

_GEMFILE = """\
source 'https://rubygems.org'

gem 'rails', '~> 7.0.4'
gem 'puma', '>= 5.0'
gem 'nokogiri'

group :development do
  gem 'byebug', '1.1.0'
end
"""


def test_parse_gemfile_extracts_gems():
    pkgs = _parse_gemfile(_GEMFILE, "Gemfile")
    names = {p.name for p in pkgs}
    assert "rails" in names
    assert "puma" in names
    assert "nokogiri" in names


def test_parse_gemfile_extracts_group_gems():
    pkgs = _parse_gemfile(_GEMFILE, "Gemfile")
    names = {p.name for p in pkgs}
    assert "byebug" in names


def test_parse_gemfile_extracts_version():
    pkgs = _parse_gemfile(_GEMFILE, "Gemfile")
    rails = next(p for p in pkgs if p.name == "rails")
    assert rails.version == "7.0.4"


def test_parse_gemfile_no_version_is_none():
    pkgs = _parse_gemfile(_GEMFILE, "Gemfile")
    noko = next(p for p in pkgs if p.name == "nokogiri")
    assert noko.version is None


def test_parse_gemfile_ecosystem():
    pkgs = _parse_gemfile(_GEMFILE, "Gemfile")
    assert all(p.ecosystem == "RubyGems" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_gemfile_lock
# ---------------------------------------------------------------------------

_GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
      actioncable (= 7.0.8)
      activesupport (= 7.0.8)
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)

GIT
  remote: https://github.com/foo/bar.git
  specs:
    bar (1.0.0)

BUNDLED WITH
   2.4.10
"""


def test_parse_gemfile_lock_extracts_gems():
    pkgs = _parse_gemfile_lock(_GEMFILE_LOCK, "Gemfile.lock")
    names = {p.name for p in pkgs}
    assert "rails" in names
    assert "nokogiri" in names


def test_parse_gemfile_lock_skips_git_section():
    pkgs = _parse_gemfile_lock(_GEMFILE_LOCK, "Gemfile.lock")
    names = {p.name for p in pkgs}
    assert "bar" not in names


def test_parse_gemfile_lock_strips_platform_suffix():
    pkgs = _parse_gemfile_lock(_GEMFILE_LOCK, "Gemfile.lock")
    noko = next(p for p in pkgs if p.name == "nokogiri")
    assert noko.version == "1.15.4"


def test_parse_gemfile_lock_extracts_version():
    pkgs = _parse_gemfile_lock(_GEMFILE_LOCK, "Gemfile.lock")
    rails = next(p for p in pkgs if p.name == "rails")
    assert rails.version == "7.0.8"


def test_parse_gemfile_lock_ecosystem():
    pkgs = _parse_gemfile_lock(_GEMFILE_LOCK, "Gemfile.lock")
    assert all(p.ecosystem == "RubyGems" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_yarn_lock — v1 (classic)
# ---------------------------------------------------------------------------

_YARN_LOCK_V1 = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.10.4", "@babel/code-frame@^7.12.11":
  version "7.16.7"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.16.7.tgz"
  dependencies:
    "@babel/highlight" "^7.16.7"

lodash@^4.17.0, lodash@^4.17.20:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"""


def test_parse_yarn_lock_v1_extracts_scoped_package():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V1, "yarn.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("@babel/code-frame") == "7.16.7"


def test_parse_yarn_lock_v1_extracts_unscoped_package():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V1, "yarn.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("lodash") == "4.17.21"


def test_parse_yarn_lock_v1_ecosystem():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V1, "yarn.lock")
    assert all(p.ecosystem == "npm" for p in pkgs)


def test_parse_yarn_lock_v1_does_not_pick_up_dependencies_subblock_version():
    """The `dependencies:` sub-block under @babel/code-frame has no
    "version" line at that indent, so only two packages total are found."""
    pkgs = _parse_yarn_lock(_YARN_LOCK_V1, "yarn.lock")
    assert len(pkgs) == 2


# ---------------------------------------------------------------------------
# _parse_yarn_lock — v2+ (Berry)
# ---------------------------------------------------------------------------

_YARN_LOCK_V2 = """\
# This file is generated by running "yarn install" inside your project.
__metadata:
  version: 8
  cacheKey: 10

"@babel/core@npm:^7.20.0, @babel/core@npm:^7.12.3":
  version: 7.20.0
  resolution: "@babel/core@npm:7.20.0"
  checksum: abc123
  languageName: node
  linkType: hard

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: def456
  languageName: node
  linkType: hard
"""


def test_parse_yarn_lock_v2_detected_and_extracts_scoped_package():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V2, "yarn.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("@babel/core") == "7.20.0"


def test_parse_yarn_lock_v2_extracts_unscoped_package():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V2, "yarn.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("lodash") == "4.17.21"


def test_parse_yarn_lock_v2_skips_metadata_key():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V2, "yarn.lock")
    names = {p.name for p in pkgs}
    assert "__metadata" not in names


def test_parse_yarn_lock_v2_ecosystem():
    pkgs = _parse_yarn_lock(_YARN_LOCK_V2, "yarn.lock")
    assert all(p.ecosystem == "npm" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_pnpm_lock
# ---------------------------------------------------------------------------

_PNPM_LOCK_OLD_FORMAT = """\
lockfileVersion: '6.0'

dependencies:
  express:
    specifier: ^4.18.0
    version: 4.18.2

packages:
  /express/4.18.2:
    resolution: {integrity: sha512-fake}
  /@babel/core/7.20.0:
    resolution: {integrity: sha512-fake}
"""

_PNPM_LOCK_NEW_FORMAT = """\
lockfileVersion: '9.0'

packages:
  express@4.18.2:
    resolution: {integrity: sha512-fake}
  '@babel/core@7.20.0':
    resolution: {integrity: sha512-fake}
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-fake}
"""


def test_parse_pnpm_lock_old_format_unscoped():
    pkgs = _parse_pnpm_lock(_PNPM_LOCK_OLD_FORMAT, "pnpm-lock.yaml")
    names = {p.name: p.version for p in pkgs}
    assert names.get("express") == "4.18.2"


def test_parse_pnpm_lock_old_format_scoped():
    pkgs = _parse_pnpm_lock(_PNPM_LOCK_OLD_FORMAT, "pnpm-lock.yaml")
    names = {p.name: p.version for p in pkgs}
    assert names.get("@babel/core") == "7.20.0"


def test_parse_pnpm_lock_new_format_unscoped():
    pkgs = _parse_pnpm_lock(_PNPM_LOCK_NEW_FORMAT, "pnpm-lock.yaml")
    names = {p.name: p.version for p in pkgs}
    assert names.get("express") == "4.18.2"


def test_parse_pnpm_lock_new_format_scoped():
    pkgs = _parse_pnpm_lock(_PNPM_LOCK_NEW_FORMAT, "pnpm-lock.yaml")
    names = {p.name: p.version for p in pkgs}
    assert names.get("@babel/core") == "7.20.0"


def test_parse_pnpm_lock_strips_peer_dependency_suffix():
    pkgs = _parse_pnpm_lock(_PNPM_LOCK_NEW_FORMAT, "pnpm-lock.yaml")
    names = {p.name: p.version for p in pkgs}
    assert names.get("react-dom") == "18.2.0"


def test_parse_pnpm_lock_ecosystem():
    pkgs = _parse_pnpm_lock(_PNPM_LOCK_OLD_FORMAT, "pnpm-lock.yaml")
    assert all(p.ecosystem == "npm" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_poetry_lock / _parse_uv_lock
# ---------------------------------------------------------------------------

_POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.28.0"
description = "Python HTTP for Humans."

[[package]]
name = "flask"
version = "2.0.0"
description = "A simple framework."
"""

_UV_LOCK = """\
version = 1
requires-python = ">=3.9"

[[package]]
name = "requests"
version = "2.28.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "click"
version = "8.1.3"
source = { registry = "https://pypi.org/simple" }
"""


def test_parse_poetry_lock_extracts_packages():
    pkgs = _parse_poetry_lock(_POETRY_LOCK, "poetry.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("requests") == "2.28.0"
    assert names.get("flask") == "2.0.0"


def test_parse_poetry_lock_ecosystem():
    pkgs = _parse_poetry_lock(_POETRY_LOCK, "poetry.lock")
    assert all(p.ecosystem == "PyPI" for p in pkgs)


def test_parse_uv_lock_extracts_packages():
    pkgs = _parse_uv_lock(_UV_LOCK, "uv.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("requests") == "2.28.0"
    assert names.get("click") == "8.1.3"


def test_parse_uv_lock_ecosystem():
    pkgs = _parse_uv_lock(_UV_LOCK, "uv.lock")
    assert all(p.ecosystem == "PyPI" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_composer_json / _parse_composer_lock
# ---------------------------------------------------------------------------

_COMPOSER_JSON = json.dumps(
    {
        "require": {
            "php": ">=8.0",
            "monolog/monolog": "^2.0",
        },
        "require-dev": {
            "phpunit/phpunit": "^9.0",
        },
    }
)

_COMPOSER_LOCK = json.dumps(
    {
        "packages": [
            {"name": "monolog/monolog", "version": "v2.5.0"},
        ],
        "packages-dev": [
            {"name": "phpunit/phpunit", "version": "v9.5.0"},
        ],
    }
)


def test_parse_composer_json_extracts_packages():
    pkgs = _parse_composer_json(_COMPOSER_JSON, "composer.json")
    names = {p.name for p in pkgs}
    assert "monolog/monolog" in names
    assert "phpunit/phpunit" in names


def test_parse_composer_json_skips_platform_requirements():
    pkgs = _parse_composer_json(_COMPOSER_JSON, "composer.json")
    names = {p.name for p in pkgs}
    assert "php" not in names


def test_parse_composer_json_ecosystem():
    pkgs = _parse_composer_json(_COMPOSER_JSON, "composer.json")
    assert all(p.ecosystem == "Packagist" for p in pkgs)


def test_parse_composer_lock_extracts_packages_and_dev_packages():
    pkgs = _parse_composer_lock(_COMPOSER_LOCK, "composer.lock")
    names = {p.name: p.version for p in pkgs}
    assert names.get("monolog/monolog") == "2.5.0"
    assert names.get("phpunit/phpunit") == "9.5.0"


def test_parse_composer_lock_ecosystem():
    pkgs = _parse_composer_lock(_COMPOSER_LOCK, "composer.lock")
    assert all(p.ecosystem == "Packagist" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_packages_lock_json (NuGet)
# ---------------------------------------------------------------------------

_PACKAGES_LOCK_JSON = json.dumps(
    {
        "version": 1,
        "dependencies": {
            "net6.0": {
                "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
                "Some.Transitive": {"type": "Transitive", "resolved": "1.2.3"},
            },
            "net8.0": {
                "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
            },
        },
    }
)


def test_parse_packages_lock_json_extracts_packages():
    pkgs = _parse_packages_lock_json(_PACKAGES_LOCK_JSON, "packages.lock.json")
    names = {p.name: p.version for p in pkgs}
    assert names.get("Newtonsoft.Json") == "13.0.1"
    assert names.get("Some.Transitive") == "1.2.3"


def test_parse_packages_lock_json_dedupes_across_frameworks():
    pkgs = _parse_packages_lock_json(_PACKAGES_LOCK_JSON, "packages.lock.json")
    newtonsoft = [p for p in pkgs if p.name == "Newtonsoft.Json"]
    assert len(newtonsoft) == 1


def test_parse_packages_lock_json_ecosystem():
    pkgs = _parse_packages_lock_json(_PACKAGES_LOCK_JSON, "packages.lock.json")
    assert all(p.ecosystem == "NuGet" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_csproj (NuGet)
# ---------------------------------------------------------------------------

_CSPROJ_SDK_STYLE = """\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="2.12.0" />
  </ItemGroup>
</Project>
"""

_CSPROJ_NAMESPACED = """\
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003" ToolsVersion="4.0">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json">
      <Version>13.0.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>
"""


def test_parse_csproj_sdk_style_extracts_packages():
    pkgs = _parse_csproj(_CSPROJ_SDK_STYLE, "MyProject.csproj")
    names = {p.name: p.version for p in pkgs}
    assert names.get("Newtonsoft.Json") == "13.0.1"
    assert names.get("Serilog") == "2.12.0"


def test_parse_csproj_sdk_style_ecosystem():
    pkgs = _parse_csproj(_CSPROJ_SDK_STYLE, "MyProject.csproj")
    assert all(p.ecosystem == "NuGet" for p in pkgs)


def test_parse_csproj_namespaced_with_child_version_element():
    pkgs = _parse_csproj(_CSPROJ_NAMESPACED, "Legacy.csproj")
    names = {p.name: p.version for p in pkgs}
    assert names.get("Newtonsoft.Json") == "13.0.1"


# ---------------------------------------------------------------------------
# _parse_manifest dispatcher — new formats routed correctly
# ---------------------------------------------------------------------------


def test_parse_manifest_routes_pnpm_lock_not_github_actions():
    """pnpm-lock.yaml ends in .yaml — must not fall through to the generic
    GitHub Actions workflow parser, which would silently yield zero packages."""
    pkgs = gs._parse_manifest("pnpm-lock.yaml", _PNPM_LOCK_OLD_FORMAT, "npm")
    assert len(pkgs) > 0


def test_parse_manifest_routes_yarn_lock():
    pkgs = gs._parse_manifest("yarn.lock", _YARN_LOCK_V1, "npm")
    assert len(pkgs) > 0


def test_parse_manifest_routes_csproj_by_suffix():
    pkgs = gs._parse_manifest("src/MyProject.csproj", _CSPROJ_SDK_STYLE, "NuGet")
    assert len(pkgs) > 0


def test_parse_manifest_routes_composer_files():
    assert len(gs._parse_manifest("composer.json", _COMPOSER_JSON, "Packagist")) > 0
    assert len(gs._parse_manifest("composer.lock", _COMPOSER_LOCK, "Packagist")) > 0


def test_parse_manifest_routes_packages_lock_json():
    pkgs = gs._parse_manifest("packages.lock.json", _PACKAGES_LOCK_JSON, "NuGet")
    assert len(pkgs) > 0


# ---------------------------------------------------------------------------
# _query_and_store_batch — OSV full-detail fetch
# ---------------------------------------------------------------------------

# The /v1/querybatch endpoint only returns {id, modified}. The scanner must
# fetch full details via GET /v1/vulns/{id} so that CVSS scores are available.


def _make_batch_response(vuln_id: str) -> dict:
    return {"results": [{"vulns": [{"id": vuln_id, "modified": "2024-01-01T00:00:00Z"}]}]}


def _make_full_vuln(vuln_id: str) -> dict:
    return {
        "id": vuln_id,
        "aliases": ["CVE-2024-9999"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}
                ],
            }
        ],
    }


def test_query_and_store_batch_fetches_full_vuln_details(db_conn, tmp_path):
    """Batch results carry only {id, modified}; full details must be fetched."""
    from dive.config import AppConfig, DashboardConfig, GitHubConfig

    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )

    vuln_id = "GHSA-test-1234-abcd"
    pkg = Package(
        name="requests",
        version="2.28.0",
        ecosystem="PyPI",
        repo_full_name="user/repo",
        manifest_path="requirements.txt",
    )
    stats = ScannerStats()

    batch_resp = MagicMock()
    batch_resp.raise_for_status = MagicMock()
    batch_resp.json.return_value = _make_batch_response(vuln_id)

    detail_resp = MagicMock()
    detail_resp.raise_for_status = MagicMock()
    detail_resp.json.return_value = _make_full_vuln(vuln_id)

    client = MagicMock()
    client.post.return_value = batch_resp
    client.get.return_value = detail_resp

    _query_and_store_batch(db_conn, client, config, [pkg], set(), stats)

    # Full-detail GET must have been called with the vuln ID
    client.get.assert_called_once()
    assert vuln_id in client.get.call_args[0][0]

    # Finding must be stored with a real CVSS score (not NULL)
    row = db_conn.execute("SELECT cvss_score FROM findings").fetchone()
    assert row is not None
    assert row["cvss_score"] is not None
    assert row["cvss_score"] > 0


def test_query_and_store_batch_deduplicates_vuln_detail_requests(db_conn):
    """Same vuln in two packages → only one GET /v1/vulns/{id} call."""
    from dive.config import AppConfig, DashboardConfig, GitHubConfig

    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )

    vuln_id = "GHSA-test-dedup-0001"
    pkgs = [
        Package("requests", "2.28.0", "PyPI", "requirements.txt", "user/repo-a"),
        Package("requests", "2.28.0", "PyPI", "requirements.txt", "user/repo-b"),
    ]
    stats = ScannerStats()

    batch_resp = MagicMock()
    batch_resp.raise_for_status = MagicMock()
    batch_resp.json.return_value = {
        "results": [
            {"vulns": [{"id": vuln_id, "modified": "2024-01-01T00:00:00Z"}]},
            {"vulns": [{"id": vuln_id, "modified": "2024-01-01T00:00:00Z"}]},
        ]
    }

    detail_resp = MagicMock()
    detail_resp.raise_for_status = MagicMock()
    detail_resp.json.return_value = _make_full_vuln(vuln_id)

    client = MagicMock()
    client.post.return_value = batch_resp
    client.get.return_value = detail_resp

    _query_and_store_batch(db_conn, client, config, pkgs, set(), stats)

    # Only one detail fetch despite two packages matching the same vuln
    assert client.get.call_count == 1


def test_query_and_store_batch_detail_fetch_failure_stores_with_null_cvss(db_conn):
    """If the detail GET fails, the finding is still stored (not silently dropped)
    but with a NULL cvss_score so it isn't lost."""
    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )

    pkg = Package("requests", "2.28.0", "PyPI", "requirements.txt", "user/repo")
    stats = ScannerStats()

    batch_resp = MagicMock()
    batch_resp.raise_for_status = MagicMock()
    batch_resp.json.return_value = _make_batch_response("GHSA-fail-0000-0000")

    client = MagicMock()
    client.post.return_value = batch_resp
    client.get.side_effect = httpx.RequestError("timeout")

    # Must not raise
    _query_and_store_batch(db_conn, client, config, [pkg], set(), stats)

    # Finding is stored but with NULL cvss_score (unknown severity)
    row = db_conn.execute("SELECT cvss_score FROM findings").fetchone()
    assert row is not None
    assert row["cvss_score"] is None


def test_query_and_store_batch_follows_next_page_token(db_conn):
    """A package with many advisories pages via next_page_token on its own
    result entry — the batch must be re-queried (carrying page_token
    forward) until no token remains, or vulns beyond the first page are lost.
    """
    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )
    pkg = Package("requests", "2.28.0", "PyPI", "requirements.txt", "user/repo")
    stats = ScannerStats()

    page1 = MagicMock()
    page1.raise_for_status = MagicMock()
    page1.json.return_value = {
        "results": [
            {
                "vulns": [{"id": "GHSA-page1-0001", "modified": "2024-01-01T00:00:00Z"}],
                "next_page_token": "tok-page-2",
            }
        ]
    }
    page2 = MagicMock()
    page2.raise_for_status = MagicMock()
    page2.json.return_value = {
        "results": [{"vulns": [{"id": "GHSA-page2-0001", "modified": "2024-01-01T00:00:00Z"}]}]
    }

    def _fake_get(url, **kwargs):
        # Distinct, alias-free detail responses — _make_full_vuln hardcodes
        # the same CVE alias for every vuln, which would make the dedup
        # logic (correctly) treat these two different vulns as duplicates.
        vuln_id = url.rsplit("/", 1)[-1]
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"id": vuln_id, "aliases": []}
        return resp

    client = MagicMock()
    client.post.side_effect = [page1, page2]
    client.get.side_effect = _fake_get

    _query_and_store_batch(db_conn, client, config, [pkg], set(), stats)

    assert client.post.call_count == 2
    second_call_payload = client.post.call_args_list[1].kwargs["json"]
    assert second_call_payload["queries"][0]["page_token"] == "tok-page-2"

    findings = db_conn.execute("SELECT ghsa_id FROM findings").fetchall()
    assert {r["ghsa_id"] for r in findings} == {"GHSA-page1-0001", "GHSA-page2-0001"}


def test_query_and_store_batch_respects_page_cap(db_conn):
    """A next_page_token that never ends must not paginate forever."""
    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )
    pkg = Package("requests", "2.28.0", "PyPI", "requirements.txt", "user/repo")
    stats = ScannerStats()

    looping_resp = MagicMock()
    looping_resp.raise_for_status = MagicMock()
    looping_resp.json.return_value = {"results": [{"vulns": [], "next_page_token": "always-more"}]}
    client = MagicMock()
    client.post.return_value = looping_resp

    from dive.github_scanner import _OSV_BATCH_MAX_PAGES

    _query_and_store_batch(db_conn, client, config, [pkg], set(), stats)

    assert client.post.call_count == _OSV_BATCH_MAX_PAGES


# ---------------------------------------------------------------------------
# _store_osv_finding — lifecycle key tracking with severity threshold
# ---------------------------------------------------------------------------


def _make_osv_vuln_with_cvss(ghsa_id: str, cvss_vector: str, pkg_name: str, ecosystem: str) -> dict:
    return {
        "id": ghsa_id,
        "aliases": [],
        "severity": [{"type": "CVSS_V3", "score": cvss_vector}],
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}],
                    }
                ],
            }
        ],
    }


def test_below_threshold_finding_is_stored_but_not_notified(db_conn):
    """A finding below the notification threshold must still be stored so the
    Vulnerabilities page shows the complete inventory. The threshold is a
    notification-time gate only — it never suppresses storage."""
    from dive.config import AppConfig, DashboardConfig, GitHubConfig

    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )
    pkg = Package("astro", "4.0.0", "npm", "package.json", "user/repo")
    stats = ScannerStats()
    # CVSS 6.1 → Medium; threshold is "high" → would previously have been
    # dropped from storage. Now it must be stored regardless of threshold.
    vuln = _make_osv_vuln_with_cvss(
        "GHSA-test-med-0001",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "astro",
        "npm",
    )

    _store_osv_finding(db_conn, config, pkg, vuln, set(), stats)

    # Row is stored despite being below the high threshold.
    count = db_conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert count == 1
    row = db_conn.execute("SELECT cvss_score, ghsa_id, repo_full_name FROM findings").fetchone()
    assert row["ghsa_id"] == "GHSA-test-med-0001"
    assert row["repo_full_name"] == "user/repo"
    assert 4.0 <= row["cvss_score"] < 7.0  # medium band

    # Key still recorded so lifecycle does not auto-resolve this finding.
    expected_key = ("user/repo", "astro", "npm", "", "GHSA-test-med-0001")
    assert expected_key in stats.finding_keys


# ---------------------------------------------------------------------------
# Latest-version registry adapters: Maven / NuGet / Packagist
# ---------------------------------------------------------------------------


def _mock_client_response(json_body=None, raise_for_status_exc=None, status_code=200):
    """Build a MagicMock httpx.Client that returns one canned response."""
    response = MagicMock()
    response.status_code = status_code
    if raise_for_status_exc is not None:
        response.raise_for_status.side_effect = raise_for_status_exc
    else:
        response.raise_for_status.return_value = None
    response.json.return_value = json_body if json_body is not None else {}
    client = MagicMock()
    client.get.return_value = response
    return client


# --- Maven ----------------------------------------------------------------


def test_lookup_latest_maven_happy_path():
    client = _mock_client_response({"response": {"docs": [{"latestVersion": "3.2.1"}]}})
    assert _lookup_latest_maven("org.example:widget", client) == "3.2.1"


def test_lookup_latest_maven_requires_group_artifact_form():
    client = MagicMock()
    assert _lookup_latest_maven("not-a-coordinate", client) is None
    client.get.assert_not_called()


def test_lookup_latest_maven_handles_empty_docs():
    client = _mock_client_response({"response": {"docs": []}})
    assert _lookup_latest_maven("org.example:nonexistent", client) is None


def test_lookup_latest_maven_handles_malformed_json():
    client = _mock_client_response({"response": "garbage"})
    assert _lookup_latest_maven("org.example:widget", client) is None


def test_lookup_latest_maven_swallows_http_errors():
    client = _mock_client_response(raise_for_status_exc=httpx.HTTPError("boom"))
    assert _lookup_latest_maven("org.example:widget", client) is None


# --- NuGet ----------------------------------------------------------------


def test_lookup_latest_nuget_prefers_stable_releases():
    """When stable and prerelease versions coexist, the latest *stable* wins."""
    client = _mock_client_response(
        {"versions": ["1.0.0", "1.1.0", "2.0.0-preview1", "2.0.0-preview2"]}
    )
    assert _lookup_latest_nuget("Newtonsoft.Json", client) == "1.1.0"


def test_lookup_latest_nuget_falls_back_to_prerelease_if_only_pre():
    client = _mock_client_response({"versions": ["0.1.0-alpha", "0.2.0-alpha"]})
    assert _lookup_latest_nuget("Newtonsoft.Json", client) == "0.2.0-alpha"


def test_lookup_latest_nuget_lowercases_package_id_in_url():
    client = _mock_client_response({"versions": ["1.0.0"]})
    _lookup_latest_nuget("Newtonsoft.Json", client)
    called_url = client.get.call_args[0][0]
    assert "newtonsoft.json" in called_url
    assert "Newtonsoft.Json" not in called_url


def test_lookup_latest_nuget_handles_missing_versions_key():
    client = _mock_client_response({})
    assert _lookup_latest_nuget("Newtonsoft.Json", client) is None


def test_lookup_latest_nuget_swallows_404():
    client = _mock_client_response(
        raise_for_status_exc=httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock(status_code=404)
        )
    )
    assert _lookup_latest_nuget("does.not.exist", client) is None


# --- Packagist ------------------------------------------------------------


def test_lookup_latest_packagist_returns_first_stable():
    client = _mock_client_response(
        {
            "packages": {
                "vendor/pkg": [
                    {"version": "2.4.0"},
                    {"version": "2.3.5"},
                    {"version": "2.3.4"},
                ]
            }
        }
    )
    assert _lookup_latest_packagist("vendor/pkg", client) == "2.4.0"


def test_lookup_latest_packagist_skips_dev_branches():
    client = _mock_client_response(
        {
            "packages": {
                "vendor/pkg": [
                    {"version": "dev-main"},
                    {"version": "dev-master"},
                    {"version": "1.5.0"},
                ]
            }
        }
    )
    assert _lookup_latest_packagist("vendor/pkg", client) == "1.5.0"


def test_lookup_latest_packagist_requires_vendor_package_form():
    client = MagicMock()
    assert _lookup_latest_packagist("not-a-coordinate", client) is None
    client.get.assert_not_called()


def test_lookup_latest_packagist_handles_missing_package_entry():
    client = _mock_client_response({"packages": {}})
    assert _lookup_latest_packagist("vendor/pkg", client) is None


def test_lookup_latest_packagist_swallows_network_errors():
    client = MagicMock()
    client.get.side_effect = httpx.RequestError("connection refused")
    assert _lookup_latest_packagist("vendor/pkg", client) is None


# --- Registry registration ------------------------------------------------


def test_new_ecosystems_registered():
    """Maven / NuGet / Packagist must be present in the registry dispatch table
    so _enrich_latest_versions actually calls them."""
    assert _LATEST_VERSION_REGISTRIES["Maven"] is _lookup_latest_maven
    assert _LATEST_VERSION_REGISTRIES["NuGet"] is _lookup_latest_nuget
    assert _LATEST_VERSION_REGISTRIES["Packagist"] is _lookup_latest_packagist


# ---------------------------------------------------------------------------
# _enrich_latest_versions — parallel lookup, serialized DB writes
# ---------------------------------------------------------------------------


def test_enrich_latest_versions_updates_db_for_each_package(db_conn, monkeypatch):
    """Network lookups now run on a thread pool; the DB write for each
    successful lookup must still land, and only on the calling thread."""

    def _fake_lookup(package, ecosystem, client):
        return (package, ecosystem, "9.9.9", 0)

    monkeypatch.setattr(gs, "_lookup_one_latest_version", _fake_lookup)

    updates: list[tuple] = []
    monkeypatch.setattr(
        db, "update_latest_version_for_package", lambda conn, *args: updates.append(args)
    )

    gs._enrich_latest_versions(db_conn, {("lodash", "npm"), ("requests", "PyPI")})

    assert set(updates) == {
        ("lodash", "npm", "9.9.9", 0),
        ("requests", "PyPI", "9.9.9", 0),
    }


def test_enrich_latest_versions_skips_unknown_ecosystem(db_conn, monkeypatch):
    called = []
    monkeypatch.setattr(
        gs,
        "_lookup_one_latest_version",
        lambda package, ecosystem, client: called.append((package, ecosystem)) or None,
    )
    gs._enrich_latest_versions(db_conn, {("mystery-pkg", "TotallyUnknownEcosystem")})
    assert called == [("mystery-pkg", "TotallyUnknownEcosystem")]


def test_lookup_one_latest_version_returns_none_for_unregistered_ecosystem():
    client = MagicMock()
    assert gs._lookup_one_latest_version("pkg", "NotARealEcosystem", client) is None
