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

import db
from config import AppConfig, DashboardConfig, GitHubConfig
from github_scanner import (
    Package,
    ScannerStats,
    _cvss_to_severity_text,
    _extract_fixed_version,
    _extract_severity,
    _extract_version,
    _parse_build_gradle,
    _parse_cargo_lock,
    _parse_cargo_toml,
    _parse_gemfile,
    _parse_gemfile_lock,
    _parse_github_actions,
    _parse_go_mod,
    _parse_next_steps,
    _parse_package_json,
    _parse_package_lock,
    _parse_pipfile,
    _parse_pom_xml,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    _priority_score,
    _query_and_store_batch,
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
    from config import AppConfig, DashboardConfig, GitHubConfig

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

    _query_and_store_batch(db_conn, client, config, [pkg], set(), stats, "high")

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
    from config import AppConfig, DashboardConfig, GitHubConfig

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

    _query_and_store_batch(db_conn, client, config, pkgs, set(), stats, "high")

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
    _query_and_store_batch(db_conn, client, config, [pkg], set(), stats, "high")

    # Finding is stored but with NULL cvss_score (unknown severity)
    row = db_conn.execute("SELECT cvss_score FROM findings").fetchone()
    assert row is not None
    assert row["cvss_score"] is None


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


def test_below_threshold_finding_still_tracked_in_finding_keys(db_conn):
    """A Medium finding filtered by 'high' threshold must still appear in
    finding_keys so auto_resolve_gone() does not mark it resolved."""
    from config import AppConfig, DashboardConfig, GitHubConfig

    config = AppConfig(
        github=GitHubConfig(token="tok", username="u"),
        dashboard=DashboardConfig(username="admin", password="pw"),
    )
    pkg = Package("astro", "4.0.0", "npm", "package.json", "user/repo")
    stats = ScannerStats()
    # CVSS 6.1 → Medium; threshold is "high" → should be filtered from storage
    vuln = _make_osv_vuln_with_cvss(
        "GHSA-test-med-0001",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "astro",
        "npm",
    )

    _store_osv_finding(db_conn, config, pkg, vuln, set(), stats, severity_threshold="high")

    # Below threshold — nothing stored in DB
    count = db_conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert count == 0

    # But the key IS recorded so lifecycle does not auto-resolve this finding
    expected_key = ("user/repo", "astro", "npm", "", "GHSA-test-med-0001")
    assert expected_key in stats.finding_keys
