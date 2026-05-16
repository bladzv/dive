"""
Unit tests for github_scanner.py — manifest parsers, version extraction,
severity/CVSS helpers, priority scoring, OSV response parsing, AI next steps.

No GitHub API or OSV.dev calls are made — everything is tested with fixtures.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import db
import github_scanner as gs
from github_scanner import (
    Package,
    _cvss_to_severity_text,
    _extract_fixed_version,
    _extract_severity,
    _extract_version,
    _parse_github_actions,
    _parse_next_steps,
    _parse_package_json,
    _parse_package_lock,
    _parse_pipfile,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    _priority_score,
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
        ("v3", "3"),           # v-prefixed
        ("1.0.0-beta.1", "1.0.0-beta.1"),
    ],
)
def test_extract_version(spec, expected):
    assert _extract_version(spec) == expected


# ---------------------------------------------------------------------------
# _parse_package_lock
# ---------------------------------------------------------------------------


def test_parse_package_lock_v3():
    content = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "my-app"},          # root entry — should be skipped
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.20"},
        },
    })
    pkgs = _parse_package_lock(content, "package-lock.json")
    names = {p.name: p.version for p in pkgs}
    assert names.get("express") == "4.18.2"
    assert names.get("lodash") == "4.17.20"
    assert "" not in names  # root skipped


def test_parse_package_lock_returns_npm_ecosystem():
    content = json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/react": {"version": "18.0.0"}},
    })
    pkgs = _parse_package_lock(content, "package-lock.json")
    assert all(p.ecosystem == "npm" for p in pkgs)


# ---------------------------------------------------------------------------
# _parse_package_json
# ---------------------------------------------------------------------------


def test_parse_package_json_extracts_dependencies():
    content = json.dumps({
        "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
        "devDependencies": {"jest": "^29.0.0"},
    })
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
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}
                ],
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
    raw = json.dumps({
        "impact": "Attacker can execute arbitrary code.",
        "fix": "Upgrade to requests>=2.32.0",
        "effort": "Low",
    })
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
    raw = json.dumps({
        "impact": "Something bad.",
        "fix": "Upgrade it.",
        "effort": "Very Hard",  # invalid
    })
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


def test_get_kev_cve_ids_from_news_items(db_conn):
    db.insert_news_item(db_conn, {
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#CVE-2024-9999",
        "title": "CVE-2024-9999 — KEV entry",
        "source": "CISA KEV",
        "fetched_at": "2024-01-15T00:00:00+00:00",
    })
    kev_ids = db.get_kev_cve_ids(db_conn)
    assert "CVE-2024-9999" in kev_ids


def test_get_kev_cve_ids_empty_when_no_kev(db_conn):
    assert db.get_kev_cve_ids(db_conn) == set()
