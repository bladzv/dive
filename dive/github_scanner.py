"""
github_scanner.py — Scan GitHub repositories for vulnerable dependencies.

Pipeline per run:
  1. List all repos for the authenticated user via PyGithub.
  2. For each repo, get the full file tree (1 API call) then fetch only the
     manifest files that exist — minimising GitHub API usage.
  3. Parse installed package versions from those manifests.
  4. Query OSV.dev in batches of 500 to find known vulnerabilities.
  5. Cross-reference with CISA KEV (from the local DB) and NIST NVD data.
  6. Compute priority scores and upsert findings.
  7. For each brand-new Critical/High finding, call Ollama for plain-English
     next steps.

Manifest formats (npm and Python first, as the most common; Actions workflows):
  npm:     package.json (semver ranges), package-lock.json (exact pins, preferred)
  Python:  requirements.txt, Pipfile (TOML), pyproject.toml [project.dependencies]
  Actions: .github/workflows/*.yml  (uses: owner/action@version)

GitHub API rate limit: checked before each repo. Once remaining budget drops
below 10% of the hourly limit (or a RateLimitExceededException is raised
mid-scan), the run stops early — any repos not yet reached ARE skipped this
run (picked up on the next scheduled run). This isn't silent: a warning is
logged and `ScannerStats.rate_limit_warning` is set, so the gap is visible
in the pipeline drawer rather than looking like a clean, complete scan.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import sqlite3
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import httpx
import yaml
from github import Github, GithubException, RateLimitExceededException

try:
    from cvss import CVSS2 as _CVSS2
    from cvss import CVSS3 as _CVSS3
    from cvss import CVSS4 as _CVSS4

    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False

from . import db
from . import settings as st
from .config import AppConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
_OSV_BATCH_SIZE = 500  # max queries per OSV.dev batch request
_OSV_BATCH_MAX_PAGES = 5  # safety cap on next_page_token pagination per query
_OSV_DETAIL_FETCH_WORKERS = 8  # bounded concurrency for per-vuln detail fetches
_LATEST_VERSION_WORKERS = 8  # bounded concurrency for latest-version enrichment
_HTTP_TIMEOUT = 30.0
_MAX_MANIFESTS_PER_REPO = 25  # guard against monorepos with hundreds of lockfiles
_RATE_LIMIT_WARN_PCT = 0.10  # warn when < 10% of requests remain
_CONTENTS_API_SIZE_LIMIT = 1_000_000  # Contents API returns encoding="none" above ~1MB
_MAX_MANIFEST_BYTES = 20_000_000  # sanity cap on files fetched via the Git Blobs API

# Filename → ecosystem mapping (exact filenames only; paths checked separately)
_MANIFEST_FILENAMES: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "poetry.lock": "PyPI",
    "uv.lock": "PyPI",
    "go.mod": "Go",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "composer.json": "Packagist",
    "composer.lock": "Packagist",
    "packages.lock.json": "NuGet",
}

# Filename SUFFIX → ecosystem mapping, checked when the exact filename isn't
# in _MANIFEST_FILENAMES (e.g. a .csproj can be named anything).
_MANIFEST_SUFFIXES: dict[str, str] = {
    ".csproj": "NuGet",
}

# (loose manifest, lockfiles in priority order — first present wins) — used
# to drop the loose manifest, and all but one lockfile, when both exist.
_LOCKFILE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("package.json", ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")),
    ("pyproject.toml", ("poetry.lock", "uv.lock")),
    ("composer.json", ("composer.lock",)),
    ("Cargo.toml", ("Cargo.lock",)),
    ("Gemfile", ("Gemfile.lock",)),
)

# Severities that trigger AI next-steps generation
_HIGH_SEVERITY = {"Critical", "High"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Package:
    name: str
    version: str | None
    ecosystem: str
    manifest_path: str
    repo_full_name: str


@dataclass
class ScannerStats:
    repos_scanned: int = 0
    packages_checked: int = 0
    findings_new: int = 0
    findings_updated: int = 0
    api_requests_start: int = 0
    api_requests_end: int = 0
    failed_repos: list[str] = field(default_factory=list)
    skipped_repos: list[str] = field(default_factory=list)
    rate_limit_warning: bool = False
    token_permission_warning: str | None = None
    finding_keys: set = field(default_factory=set)
    scanned_repos: set[str] = field(default_factory=set)
    _enrich_queue: set = field(
        default_factory=set
    )  # (package_name, ecosystem) needing latest-version check

    @property
    def api_requests_used(self) -> int:
        return self.api_requests_start - self.api_requests_end


class _RepoTreeUnavailable(Exception):
    """Raised by _scan_repo when a repo's file tree can't be fetched at all,
    so the caller can distinguish "skipped entirely" from "scanned but
    genuinely has no manifests" — both previously looked identical (an empty
    package list) and the failure was only ever logged at DEBUG."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(
    conn: sqlite3.Connection,
    config: AppConfig,
    excluded_repos: list[str] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> ScannerStats:
    """Scan all repos and store vulnerability findings. Never raises.

    on_progress(done, total_repos) is called after each repo so callers can
    track real-time progress (e.g. to update the pipeline drawer).
    """
    stats = ScannerStats()
    kev_cves = db.get_kev_cve_ids(conn)
    _excluded = set(excluded_repos or [])

    g = Github(config.github.token)

    # Record rate limit at start
    try:
        remaining, limit = g.rate_limiting
        stats.api_requests_start = remaining
        logger.info("GitHub API rate limit: %d/%d remaining", remaining, limit)
    except GithubException as exc:
        logger.warning("Could not read rate limit: %s", exc)

    # Collect all packages across all repos first, then batch-query OSV
    all_packages: list[Package] = []

    try:
        user = g.get_user()
        repos = list(user.get_repos(type="all"))
    except GithubException as exc:
        logger.error("Failed to list repositories: %s", exc)
        return stats

    stats.token_permission_warning = probe_private_repo_access(repos)
    if stats.token_permission_warning:
        logger.warning(stats.token_permission_warning)

    scannable = [r for r in repos if r.full_name not in _excluded]
    total_repos = len(scannable)
    logger.info("Scanning %d repositories (%d excluded)", total_repos, len(repos) - total_repos)
    if on_progress:
        on_progress(0, total_repos)

    for repo in scannable:
        # Check rate limit before each repo
        try:
            remaining, limit = g.rate_limiting
            if remaining < limit * _RATE_LIMIT_WARN_PCT:
                logger.warning(
                    "GitHub API rate limit low: %d/%d remaining. "
                    "Repos scanned so far: %d/%d. "
                    "Remaining repos will be scanned on the next run.",
                    remaining,
                    limit,
                    stats.repos_scanned,
                    total_repos,
                )
                stats.rate_limit_warning = True
                break
        except GithubException:
            pass

        try:
            packages = _scan_repo(repo)
            all_packages.extend(packages)
            stats.repos_scanned += 1
            stats.scanned_repos.add(repo.full_name)
        except RateLimitExceededException:
            logger.warning("Rate limit exceeded mid-scan — stopping early")
            stats.rate_limit_warning = True
            break
        except _RepoTreeUnavailable as exc:
            logger.warning("Could not get file tree for %s — skipping: %s", repo.full_name, exc)
            stats.skipped_repos.append(repo.full_name)
        except GithubException as exc:
            logger.warning("Failed to scan %s: %s", repo.full_name, exc)
            stats.failed_repos.append(repo.full_name)
        except Exception as exc:
            logger.exception("Unexpected error scanning %s: %s", repo.full_name, exc)
            stats.failed_repos.append(repo.full_name)
        if on_progress:
            on_progress(
                stats.repos_scanned + len(stats.failed_repos) + len(stats.skipped_repos),
                total_repos,
            )

    # Record rate limit at end
    try:
        stats.api_requests_end, _ = g.rate_limiting
        logger.info("API requests used this scan: %d", stats.api_requests_used)
    except GithubException:
        pass

    if not all_packages:
        logger.info("No packages found to check")
        return stats

    stats.packages_checked = len(all_packages)
    logger.info(
        "Querying OSV.dev for %d packages across %d repos", len(all_packages), stats.repos_scanned
    )

    # Query OSV.dev and process findings
    with _make_http_client() as client:
        _process_all_packages(conn, client, config, all_packages, kev_cves, stats)

    # For findings with no known fix, look up the latest package version and
    # check whether it is clean so the UI can suggest an upgrade path.
    if stats._enrich_queue:
        _enrich_latest_versions(conn, stats._enrich_queue)

    logger.info(
        "Scan complete: %d repos, %d packages, %d new findings, %d updated",
        stats.repos_scanned,
        stats.packages_checked,
        stats.findings_new,
        stats.findings_updated,
    )
    return stats


# ---------------------------------------------------------------------------
# Repo scanning
# ---------------------------------------------------------------------------


def probe_private_repo_access(repos: list) -> str | None:
    """Return an actionable warning if the token can't read private repos, else None.

    A fine-grained PAT can read a private repo's metadata (200 on the repos
    list) while lacking the separate Contents: Read-only scope needed to read
    its file tree — that gap surfaces as a 403 on every private repo in both
    scanners, with no indication of why. This costs at most one extra API
    call (skipped entirely when the account has no private repos) so the
    cause is reported once, up front, instead of once per private repo.
    """
    private_repo = next((r for r in repos if getattr(r, "private", False)), None)
    if private_repo is None:
        return None

    try:
        private_repo.get_git_tree(private_repo.default_branch or "HEAD", recursive=True)
    except GithubException as exc:
        if exc.status != 403:
            return None
        return (
            "GitHub token cannot read private repository contents "
            f"(403 on {private_repo.full_name}). Private repos will be skipped by "
            "both scanners. Fix: fine-grained PAT → Repository permissions → "
            "Contents: Read-only, and ensure those repos are in the token's "
            "repository access."
        )
    except Exception as exc:
        # This probe is a diagnostic nicety, not core scanning logic — it must
        # never take down the whole run over an unrelated transient error.
        # Genuine per-repo failures are still caught and reported by the
        # real scan loop below.
        logger.debug("Private-repo access probe failed non-fatally: %s", exc)
        return None
    return None


def _scan_repo(repo) -> list[Package]:
    """Return all packages found in dependency manifests for one repo.

    Raises _RepoTreeUnavailable if the repo's tree itself can't be fetched
    (e.g. an empty repo or a token-permission gap), so the caller can tell
    that apart from a repo that was scanned but genuinely has no manifests.
    """
    packages: list[Package] = []

    try:
        # One API call to get the full file tree
        tree = repo.get_git_tree(repo.default_branch or "HEAD", recursive=True)
    except GithubException as exc:
        raise _RepoTreeUnavailable(str(exc)) from exc

    manifest_paths: list[tuple[str, str, str, int]] = []  # (path, ecosystem, sha, size)
    workflow_paths: list[tuple[str, str, int]] = []  # (path, sha, size)

    for element in tree.tree:
        if element.type != "blob":
            continue
        path: str = element.path
        filename = path.rsplit("/", 1)[-1]
        size = element.size or 0

        if filename in _MANIFEST_FILENAMES:
            manifest_paths.append((path, _MANIFEST_FILENAMES[filename], element.sha, size))
        elif path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            workflow_paths.append((path, element.sha, size))
        else:
            for suffix, ecosystem in _MANIFEST_SUFFIXES.items():
                if filename.endswith(suffix):
                    manifest_paths.append((path, ecosystem, element.sha, size))
                    break

    # Prefer lock files over loose manifests (exact pinned versions are more
    # reliable). When multiple lockfiles for the same ecosystem are present
    # (e.g. a repo mid-migration from Yarn to pnpm), pick exactly one in
    # priority order so packages aren't double-counted, and log the choice.
    for loose, lockfile_priority in _LOCKFILE_GROUPS:
        present = [
            lf for lf in lockfile_priority if any(p.endswith(lf) for p, _, _, _ in manifest_paths)
        ]
        if not present:
            continue
        chosen = present[0]
        if len(present) > 1:
            logger.info(
                "%s: multiple %s lockfiles present (%s) — using %s",
                repo.full_name,
                loose,
                ", ".join(present),
                chosen,
            )
        drop = {loose} | (set(lockfile_priority) - {chosen})
        manifest_paths = [
            (p, e, sha, sz)
            for p, e, sha, sz in manifest_paths
            if not any(p.endswith(d) for d in drop)
        ]

    all_paths = manifest_paths[:_MAX_MANIFESTS_PER_REPO]
    if len(manifest_paths) > _MAX_MANIFESTS_PER_REPO:
        logger.warning(
            "%s: %d manifests found, capped at %d — some may be skipped this run",
            repo.full_name,
            len(manifest_paths),
            _MAX_MANIFESTS_PER_REPO,
        )
    all_paths += [(p, "Actions", sha, sz) for p, sha, sz in workflow_paths[:5]]

    if tree.truncated:
        logger.debug("%s: file tree truncated — may miss some manifests", repo.full_name)

    for path, ecosystem, sha, size in all_paths:
        try:
            raw = _fetch_manifest_content(repo, path, sha, size)
            if raw is None:
                continue
            parsed = _parse_manifest(path, raw, ecosystem)
            for pkg in parsed:
                pkg.repo_full_name = repo.full_name
            packages.extend(parsed)
        except GithubException as exc:
            logger.warning("Could not fetch %s/%s: %s", repo.full_name, path, exc)
        except Exception as exc:
            logger.warning("Error parsing %s/%s: %s", repo.full_name, path, exc)

    return packages


def _fetch_manifest_content(repo, path: str, sha: str, size: int) -> str | None:
    """Fetch a manifest file's text content.

    The Contents API silently returns encoding="none" with empty content for
    blobs over ~1 MB — previously this tripped an assertion deep in PyGithub
    that was swallowed by a blanket except, so large package-lock.json /
    Gemfile.lock files (exactly the highest-value manifests) yielded zero
    packages with nothing but a DEBUG log line. Route anything over that
    threshold through the Git Blobs API instead, which serves up to 100 MB.
    """
    if size > _MAX_MANIFEST_BYTES:
        logger.warning(
            "%s: %s is %d bytes — skipping (exceeds %d byte sanity cap)",
            repo.full_name,
            path,
            size,
            _MAX_MANIFEST_BYTES,
        )
        return None

    if size > _CONTENTS_API_SIZE_LIMIT:
        blob = repo.get_git_blob(sha)
        return base64.b64decode(blob.content).decode("utf-8", errors="replace")

    content_obj = repo.get_contents(path)
    if isinstance(content_obj, list):
        # A directory landed at this path — shouldn't happen for a blob from
        # the tree walk, but the Contents API can still surprise us.
        logger.warning("%s: %s resolved to a directory, not a file", repo.full_name, path)
        return None
    return content_obj.decoded_content.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------


def _parse_manifest(path: str, content: str, ecosystem: str) -> list[Package]:
    """Dispatch to the correct parser based on filename."""
    filename = path.rsplit("/", 1)[-1]
    try:
        if filename == "package-lock.json":
            return _parse_package_lock(content, path)
        if filename == "package.json":
            return _parse_package_json(content, path)
        if filename == "yarn.lock":
            return _parse_yarn_lock(content, path)
        if filename == "pnpm-lock.yaml":
            return _parse_pnpm_lock(content, path)
        if filename == "requirements.txt":
            return _parse_requirements_txt(content, path)
        if filename == "Pipfile":
            return _parse_pipfile(content, path)
        if filename == "pyproject.toml":
            return _parse_pyproject_toml(content, path)
        if filename == "poetry.lock":
            return _parse_poetry_lock(content, path)
        if filename == "uv.lock":
            return _parse_uv_lock(content, path)
        # Must come after the specific "*.yaml" manifest checks above (e.g.
        # pnpm-lock.yaml), which would otherwise never be reached.
        if filename.endswith((".yml", ".yaml")):
            return _parse_github_actions(content, path)
        if filename == "go.mod":
            return _parse_go_mod(content, path)
        if filename == "Cargo.toml":
            return _parse_cargo_toml(content, path)
        if filename == "Cargo.lock":
            return _parse_cargo_lock(content, path)
        if filename == "pom.xml":
            return _parse_pom_xml(content, path)
        if filename == "build.gradle":
            return _parse_build_gradle(content, path)
        if filename == "Gemfile":
            return _parse_gemfile(content, path)
        if filename == "Gemfile.lock":
            return _parse_gemfile_lock(content, path)
        if filename == "composer.json":
            return _parse_composer_json(content, path)
        if filename == "composer.lock":
            return _parse_composer_lock(content, path)
        if filename == "packages.lock.json":
            return _parse_packages_lock_json(content, path)
        if filename.endswith(".csproj"):
            return _parse_csproj(content, path)
    except Exception as exc:
        logger.debug("Parse error for %s: %s", path, exc)
    return []


def _parse_package_lock(content: str, path: str) -> list[Package]:
    """Parse package-lock.json (v2/v3). Returns exact pinned versions."""
    data = json.loads(content)
    packages: list[Package] = []
    # v2/v3 format: packages["node_modules/name"]["version"]
    for key, info in data.get("packages", {}).items():
        if not key or key == "":  # skip the root entry
            continue
        name = key.removeprefix("node_modules/")
        version = info.get("version")
        if name and version:
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_package_json(content: str, path: str) -> list[Package]:
    """Parse package.json. Uses semver ranges — extracts the base version."""
    data = json.loads(content)
    packages: list[Package] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version_spec in (data.get(section) or {}).items():
            version = _extract_version(str(version_spec))
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _npm_package_name_from_lockfile_spec(spec: str) -> str | None:
    """Extract the package name from a yarn.lock header spec.

    Specs look like "name@range" (v1, e.g. "lodash@^4.17.0") or
    "name@protocol:range" (v2+/Berry, e.g. "lodash@npm:^4.17.0"). Scoped
    packages start with their own "@": "@babel/core@npm:^7.20.0". Finding the
    separating "@" (skipping index 0 for scoped names) handles both shapes
    identically since only the version/protocol side ever changes.
    """
    if not spec:
        return None
    if spec.startswith("@"):
        at_idx = spec.find("@", 1)
        return spec[:at_idx] if at_idx > 0 else None
    at_idx = spec.rfind("@")
    return spec[:at_idx] if at_idx > 0 else None


def _parse_yarn_lock(content: str, path: str) -> list[Package]:
    """Parse yarn.lock — dispatches between the two incompatible formats.

    v1 (classic) is a custom format; v2+ (Berry) is valid YAML with a
    top-level __metadata key. Detect by looking for that key.
    """
    if re.search(r"^__metadata:", content, re.MULTILINE):
        return _parse_yarn_lock_v2(content, path)
    return _parse_yarn_lock_v1(content, path)


def _parse_yarn_lock_v1(content: str, path: str) -> list[Package]:
    """Parse yarn.lock v1 (classic): comma-separated header specs followed
    by an indented `version "x.y.z"` line, e.g.:

        "lodash@^4.17.0", "lodash@^4.17.20":
          version "4.17.21"
          resolved "..."
    """
    packages: list[Package] = []
    pending_name: str | None = None
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace():
            header = line.rstrip().rstrip(":")
            first_spec = header.split(",")[0].strip().strip('"')
            pending_name = _npm_package_name_from_lockfile_spec(first_spec)
            continue
        if pending_name is not None:
            m = re.match(r'\s+version\s+"?([^"\s]+)"?\s*$', line)
            if m:
                packages.append(
                    Package(
                        name=pending_name,
                        version=m.group(1),
                        ecosystem="npm",
                        manifest_path=path,
                        repo_full_name="",
                    )
                )
                pending_name = None  # only the first "version" line per block counts
    return packages


def _parse_yarn_lock_v2(content: str, path: str) -> list[Package]:
    """Parse yarn.lock v2+ (Berry) — valid YAML; every top-level key besides
    __metadata is a comma-separated list of "name@protocol:range" specs
    sharing one resolved `version`."""
    data = yaml.safe_load(content)
    packages: list[Package] = []
    if not isinstance(data, dict):
        return packages
    for key, info in data.items():
        if key == "__metadata" or not isinstance(info, dict):
            continue
        version = info.get("version")
        if not version:
            continue
        first_spec = str(key).split(",")[0].strip().strip('"')
        name = _npm_package_name_from_lockfile_spec(first_spec)
        if name:
            packages.append(
                Package(
                    name=name,
                    version=str(version),
                    ecosystem="npm",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_pnpm_lock(content: str, path: str) -> list[Package]:
    """Parse pnpm-lock.yaml. The `packages:` map key format changed between
    lockfileVersion generations: older versions use "/name/version" (with an
    extra leading path segment for scoped packages, e.g. "/@babel/core/7.20.0"),
    newer ones use "name@version" directly (e.g. "@babel/core@7.20.0"). Peer
    dependency suffixes ("_hash" or "(peer@ver)") are stripped from the version.
    """
    data = yaml.safe_load(content)
    packages: list[Package] = []
    if not isinstance(data, dict):
        return packages
    for raw_key in data.get("packages") or {}:
        # Strip the peer-dependency suffix ("(react@18.2.0)") first — it can
        # itself contain "@", which would otherwise confuse the name/version
        # split below.
        key = str(raw_key).split("(", 1)[0]
        if key.startswith("/"):
            name, _, version = key[1:].rpartition("/")
        else:
            name, sep, version = key.rpartition("@")
            if not sep:
                continue
        if not name or not version:
            continue
        version = version.split("_", 1)[0].strip("'\"")
        packages.append(
            Package(
                name=name, version=version, ecosystem="npm", manifest_path=path, repo_full_name=""
            )
        )
    return packages


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"\s*([><=!~^][^;#\s]*)?"  # optional version spec
)


def _parse_requirements_txt(content: str, path: str) -> list[Package]:
    """Parse requirements.txt. Handles comments, -r includes, and extras."""
    packages: list[Package] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "http")):
            continue
        # Strip inline comments and extras
        line = line.split("#")[0].split(";")[0].strip()
        line = re.sub(r"\[.*?\]", "", line)  # remove extras like package[extra]
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        version = _extract_version(m.group(3) or "")
        packages.append(
            Package(
                name=name, version=version, ecosystem="PyPI", manifest_path=path, repo_full_name=""
            )
        )
    return packages


def _parse_pipfile(content: str, path: str) -> list[Package]:
    """Parse Pipfile (TOML). Handles string versions and dict versions."""
    data = tomllib.loads(content)
    packages: list[Package] = []
    for section in ("packages", "dev-packages"):
        for name, version_spec in (data.get(section) or {}).items():
            if name == "python_version":
                continue
            if isinstance(version_spec, dict):
                version = _extract_version(version_spec.get("version") or "")
            else:
                version = _extract_version(str(version_spec))
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="PyPI",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_pyproject_toml(content: str, path: str) -> list[Package]:
    """Parse pyproject.toml [project.dependencies] (PEP 621)."""
    data = tomllib.loads(content)
    packages: list[Package] = []
    deps = data.get("project", {}).get("dependencies") or []
    for dep in deps:
        # PEP 508 format: "name>=1.0,<2.0" or "name"
        m = re.match(r"([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(.*)", dep)
        if not m:
            continue
        name = m.group(1)
        version = _extract_version(m.group(3).strip())
        packages.append(
            Package(
                name=name, version=version, ecosystem="PyPI", manifest_path=path, repo_full_name=""
            )
        )
    return packages


def _parse_toml_package_array(content: str, path: str) -> list[Package]:
    """Shared parser for TOML lockfiles using `[[package]]` array-of-tables
    with name/version fields — poetry.lock and uv.lock share this shape."""
    data = tomllib.loads(content)
    packages: list[Package] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="PyPI",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_poetry_lock(content: str, path: str) -> list[Package]:
    """Parse poetry.lock — TOML [[package]] blocks with name/version."""
    return _parse_toml_package_array(content, path)


def _parse_uv_lock(content: str, path: str) -> list[Package]:
    """Parse uv.lock — TOML [[package]] blocks, same shape as poetry.lock."""
    return _parse_toml_package_array(content, path)


_USES_RE = re.compile(r"uses:\s*([^@\s]+)@([^\s#]+)")


def _parse_github_actions(content: str, path: str) -> list[Package]:
    """Parse GitHub Actions workflow YAML for `uses:` references."""
    packages: list[Package] = []
    for match in _USES_RE.finditer(content):
        action_name = match.group(1).strip()
        version = match.group(2).strip()
        # Skip local actions (./path/to/action)
        if action_name.startswith("."):
            continue
        packages.append(
            Package(
                name=action_name,
                version=version,
                ecosystem="GitHub Actions",
                manifest_path=path,
                repo_full_name="",
            )
        )
    return packages


def _parse_go_mod(content: str, path: str) -> list[Package]:
    """Parse go.mod require directives. Strips the leading v from versions."""
    packages: list[Package] = []
    in_require = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if line == ")":
                in_require = False
                continue
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                version = parts[1].lstrip("v") or None
                packages.append(
                    Package(
                        name=parts[0],
                        version=version,
                        ecosystem="Go",
                        manifest_path=path,
                        repo_full_name="",
                    )
                )
        elif line.startswith("require ") and "(" not in line:
            parts = line.split()
            if len(parts) >= 3:
                version = parts[2].lstrip("v") or None
                packages.append(
                    Package(
                        name=parts[1],
                        version=version,
                        ecosystem="Go",
                        manifest_path=path,
                        repo_full_name="",
                    )
                )
    return packages


def _parse_cargo_toml(content: str, path: str) -> list[Package]:
    """Parse Cargo.toml [dependencies] sections. Skips git/path deps."""
    data = tomllib.loads(content)
    packages: list[Package] = []
    dep_sections = ("dependencies", "dev-dependencies", "build-dependencies")
    for section in dep_sections:
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str):
                version = _extract_version(spec)
            elif isinstance(spec, dict):
                if "git" in spec or "path" in spec:
                    continue
                version = _extract_version(spec.get("version") or "")
            else:
                continue
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="crates.io",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_cargo_lock(content: str, path: str) -> list[Package]:
    """Parse Cargo.lock (TOML). Only includes registry crates, not path/git deps."""
    data = tomllib.loads(content)
    packages: list[Package] = []
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", "")
        if name and version and source.startswith("registry+"):
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="crates.io",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_pom_xml(content: str, path: str) -> list[Package]:
    """Parse Maven pom.xml <dependencies>. Package name is groupId:artifactId."""
    packages: list[Package] = []
    root = ET.fromstring(content)
    ns_match = re.match(r"\{([^}]+)\}", root.tag)
    ns = f"{{{ns_match.group(1)}}}" if ns_match else ""
    for dep in root.iter(f"{ns}dependency"):
        group_id = dep.findtext(f"{ns}groupId") or ""
        artifact_id = dep.findtext(f"{ns}artifactId") or ""
        version_text = dep.findtext(f"{ns}version") or ""
        if not group_id or not artifact_id:
            continue
        # Skip Maven property references like ${spring.version}
        if version_text.startswith("${"):
            version_text = ""
        packages.append(
            Package(
                name=f"{group_id}:{artifact_id}",
                version=_extract_version(version_text),
                ecosystem="Maven",
                manifest_path=path,
                repo_full_name="",
            )
        )
    return packages


_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile)\s+"""
    r"""['"]([^'"]+):([^'"]+):([^'"]+)['"]"""
)
_GRADLE_MAP_RE = re.compile(
    r"""group:\s*['"]([^'"]+)['"]\s*,\s*name:\s*['"]([^'"]+)['"]\s*,\s*version:\s*['"]([^'"]+)['"]"""
)


def _parse_build_gradle(content: str, path: str) -> list[Package]:
    """Parse build.gradle string and map-style dependency declarations."""
    packages: list[Package] = []
    for m in _GRADLE_DEP_RE.finditer(content):
        packages.append(
            Package(
                name=f"{m.group(1)}:{m.group(2)}",
                version=_extract_version(m.group(3)),
                ecosystem="Maven",
                manifest_path=path,
                repo_full_name="",
            )
        )
    for m in _GRADLE_MAP_RE.finditer(content):
        packages.append(
            Package(
                name=f"{m.group(1)}:{m.group(2)}",
                version=_extract_version(m.group(3)),
                ecosystem="Maven",
                manifest_path=path,
                repo_full_name="",
            )
        )
    return packages


_GEMFILE_GEM_RE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""")


def _parse_gemfile(content: str, path: str) -> list[Package]:
    """Parse Gemfile gem declarations."""
    packages: list[Package] = []
    for line in content.splitlines():
        m = _GEMFILE_GEM_RE.match(line)
        if m:
            packages.append(
                Package(
                    name=m.group(1),
                    version=_extract_version(m.group(2) or ""),
                    ecosystem="RubyGems",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_gemfile_lock(content: str, path: str) -> list[Package]:
    """Parse Gemfile.lock specs from the GEM (rubygems.org) section only."""
    packages: list[Package] = []
    in_gem_section = False
    in_specs = False
    for raw_line in content.splitlines():
        stripped = raw_line.rstrip()
        if stripped == "GEM":
            in_gem_section = True
            in_specs = False
            continue
        if stripped in ("GIT", "PATH", "BUNDLED WITH", "PLATFORMS", "DEPENDENCIES"):
            in_gem_section = False
            in_specs = False
            continue
        if in_gem_section and stripped == "  specs:":
            in_specs = True
            continue
        if in_specs:
            # Top-level gem entries have exactly 4-space indent: "    name (version)"
            m = re.match(r"^    (\S+) \(([^)]+)\)", raw_line)
            if m:
                # Strip platform suffix, e.g. "1.15.4-x86_64-linux" → "1.15.4"
                version = re.sub(r"-[a-zA-Z].*$", "", m.group(2))
                packages.append(
                    Package(
                        name=m.group(1),
                        version=version or None,
                        ecosystem="RubyGems",
                        manifest_path=path,
                        repo_full_name="",
                    )
                )
    return packages


def _parse_composer_json(content: str, path: str) -> list[Package]:
    """Parse composer.json require/require-dev. Platform requirements (php,
    ext-mbstring, lib-curl, ...) have no vendor/package slash and are
    skipped — they aren't real Packagist packages."""
    data = json.loads(content)
    packages: list[Package] = []
    for section in ("require", "require-dev"):
        for name, version_spec in (data.get(section) or {}).items():
            if "/" not in name:
                continue
            packages.append(
                Package(
                    name=name,
                    version=_extract_version(str(version_spec)),
                    ecosystem="Packagist",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_composer_lock(content: str, path: str) -> list[Package]:
    """Parse composer.lock packages + packages-dev arrays."""
    data = json.loads(content)
    packages: list[Package] = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name = pkg.get("name")
            if not name:
                continue
            packages.append(
                Package(
                    name=name,
                    version=_extract_version(str(pkg.get("version", ""))),
                    ecosystem="Packagist",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_packages_lock_json(content: str, path: str) -> list[Package]:
    """Parse NuGet packages.lock.json. Dependencies are nested per target
    framework moniker (net6.0, net8.0, ...) — the same package commonly
    appears under several; dedup by (name, resolved version)."""
    data = json.loads(content)
    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for framework_deps in (data.get("dependencies") or {}).values():
        if not isinstance(framework_deps, dict):
            continue
        for name, info in framework_deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("resolved")
            if not name or not version:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="NuGet",
                    manifest_path=path,
                    repo_full_name="",
                )
            )
    return packages


def _parse_csproj(content: str, path: str) -> list[Package]:
    """Parse a .csproj file's <PackageReference> elements. Modern SDK-style
    projects have no XML namespace; older non-SDK projects do — handle both
    the same way _parse_pom_xml does. Version can be the "Version" attribute
    or a nested <Version> child element."""
    packages: list[Package] = []
    root = ET.fromstring(content)
    ns_match = re.match(r"\{([^}]+)\}", root.tag)
    ns = f"{{{ns_match.group(1)}}}" if ns_match else ""
    for ref in root.iter(f"{ns}PackageReference"):
        name = ref.get("Include") or ref.get("Update")
        if not name:
            continue
        version = ref.get("Version")
        if not version:
            version_el = ref.find(f"{ns}Version")
            version = version_el.text if version_el is not None else None
        packages.append(
            Package(
                name=name,
                version=_extract_version(version or ""),
                ecosystem="NuGet",
                manifest_path=path,
                repo_full_name="",
            )
        )
    return packages


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------

_VERSION_OPERATORS_RE = re.compile(r"^[\^~>=<!]+")
_NUMERIC_START_RE = re.compile(r"(\d[\d.a-zA-Z\-]*)")


def _extract_version(spec: str) -> str | None:
    """Extract a single usable version string from a version specifier.

    Examples:
        "^4.18.0"     → "4.18.0"
        ">=1.0,<2.0"  → "1.0"   (lower bound)
        "*"           → None
        "4.18.2"      → "4.18.2"
        "v3"          → "3"      (GitHub Actions v-prefix)
        "v4.6.1"      → "4.6.1"
    """
    if not spec:
        return None
    spec = spec.strip()
    if spec in ("*", "latest", ""):
        return None
    # Take first segment for comma-separated ranges
    segment = spec.split(",")[0].strip()
    # Strip leading v/V (GitHub Actions tags: v4, v3.1)
    if segment and segment[0] in ("v", "V"):
        segment = segment[1:]
    # Strip version operators
    clean = _VERSION_OPERATORS_RE.sub("", segment).strip()
    m = _NUMERIC_START_RE.match(clean)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# OSV.dev querying
# ---------------------------------------------------------------------------


def _process_all_packages(
    conn: sqlite3.Connection,
    client: httpx.Client,
    config: AppConfig,
    packages: list[Package],
    kev_cves: set[str],
    stats: ScannerStats,
) -> None:
    """Query OSV.dev in batches and process findings."""
    # Filter: only query packages with a known version
    queryable = [p for p in packages if p.version]
    if not queryable:
        return

    # Process in batches
    for batch_start in range(0, len(queryable), _OSV_BATCH_SIZE):
        batch = queryable[batch_start : batch_start + _OSV_BATCH_SIZE]
        _query_and_store_batch(conn, client, config, batch, kev_cves, stats)


def _fetch_vuln_detail(client: httpx.Client, vuln_id: str) -> dict:
    """Fetch one OSV vulnerability's full detail. Never raises — falls back
    to a bare {"id": vuln_id} stub on failure so the finding is still stored,
    just without a CVSS score."""
    try:
        r = client.get(f"{_OSV_VULN_URL}/{vuln_id}", timeout=_HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
        logger.warning("OSV.dev vuln detail fetch failed for %s: %s", vuln_id, exc)
        return {"id": vuln_id}


def _query_and_store_batch(
    conn: sqlite3.Connection,
    client: httpx.Client,
    config: AppConfig,
    batch: list[Package],
    kev_cves: set[str],
    stats: ScannerStats,
) -> None:
    # The querybatch endpoint returns only {id, modified} — collect IDs so we
    # can fetch full details (severity, affected versions, etc.) per vuln.
    #
    # Pagination: a package with many advisories gets a next_page_token on
    # its *own* result entry, independent of the other packages in the
    # batch — so each round only re-queries the indices still paginating,
    # carrying that index's page_token forward.
    queries: dict[int, dict] = {
        i: {"version": pkg.version, "package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
        for i, pkg in enumerate(batch)
    }
    active = list(range(len(batch)))
    pkg_vuln_pairs: list[tuple[int, str]] = []

    for _page in range(_OSV_BATCH_MAX_PAGES):
        if not active:
            break
        try:
            payload = {"queries": [queries[i] for i in active]}
            response = client.post(_OSV_BATCH_URL, json=payload, timeout=_HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
            logger.warning("OSV.dev batch query failed: %s", exc)
            return

        results = data.get("results", [])
        still_active = []
        for pos, i in enumerate(active):
            if pos >= len(results):
                continue
            result = results[pos]
            for vuln in result.get("vulns") or []:
                vuln_id = vuln.get("id")
                if vuln_id:
                    pkg_vuln_pairs.append((i, vuln_id))
            token = result.get("next_page_token")
            if token:
                queries[i]["page_token"] = token
                still_active.append(i)
        active = still_active
    else:
        if active:
            logger.warning(
                "OSV.dev: hit the %d-page pagination cap with %d package(s) "
                "still paginating — some advisories may be missed this run",
                _OSV_BATCH_MAX_PAGES,
                len(active),
            )

    if not pkg_vuln_pairs:
        return

    unique_ids = {vuln_id for _, vuln_id in pkg_vuln_pairs}
    vuln_details: dict[str, dict] = {}
    # Each detail fetch is an independent GET with no shared state — a
    # thread pool cuts this from one request-per-vuln sequentially to
    # _OSV_DETAIL_FETCH_WORKERS in flight at once, which is the dominant
    # wall-clock cost of a scan. httpx.Client is safe to share across
    # threads for concurrent requests.
    with ThreadPoolExecutor(max_workers=_OSV_DETAIL_FETCH_WORKERS) as executor:
        future_to_id = {
            executor.submit(_fetch_vuln_detail, client, vuln_id): vuln_id for vuln_id in unique_ids
        }
        for future in as_completed(future_to_id):
            vuln_id = future_to_id[future]
            vuln_details[vuln_id] = future.result()

    # Deduplicate: OSV batch results can include both the GHSA primary ID and the
    # aliased CVE ID for the same vulnerability. After fixing cve_id extraction both
    # would resolve to identical (cve_id, ghsa_id) pairs — skip the second occurrence.
    seen_pkg_cve: set[tuple[int, str]] = set()
    seen_pkg_ghsa: set[tuple[int, str]] = set()
    for pkg_i, vuln_id in pkg_vuln_pairs:
        vuln = vuln_details.get(vuln_id, {"id": vuln_id})
        vid = vuln.get("id", "")
        valiases: list[str] = vuln.get("aliases") or []
        vcve = (
            vid
            if vid.startswith("CVE-")
            else next((a for a in valiases if a.startswith("CVE-")), "")
        )
        vghsa = (
            vid
            if vid.startswith("GHSA-")
            else next((a for a in valiases if a.startswith("GHSA-")), "")
        )
        if vcve and (pkg_i, vcve) in seen_pkg_cve:
            continue
        if vghsa and (pkg_i, vghsa) in seen_pkg_ghsa:
            continue
        if vcve:
            seen_pkg_cve.add((pkg_i, vcve))
        if vghsa:
            seen_pkg_ghsa.add((pkg_i, vghsa))
        _store_osv_finding(conn, config, batch[pkg_i], vuln, kev_cves, stats)


# ---------------------------------------------------------------------------
# Latest-version enrichment
# ---------------------------------------------------------------------------


def _lookup_latest_pypi(name: str, client: httpx.Client) -> str | None:
    try:
        r = client.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
        r.raise_for_status()
        return r.json()["info"]["version"]
    except Exception:
        return None


def _lookup_latest_npm(name: str, client: httpx.Client) -> str | None:
    try:
        r = client.get(f"https://registry.npmjs.org/{name}/latest", timeout=10)
        r.raise_for_status()
        return r.json()["version"]
    except Exception:
        return None


def _lookup_latest_crates(name: str, client: httpx.Client) -> str | None:
    try:
        r = client.get(
            f"https://crates.io/api/v1/crates/{name}",
            headers={"User-Agent": "DIVE-security-scanner/1.0 (github.com/bladzv/dive)"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()["crate"]["max_stable_version"]
    except Exception:
        return None


def _lookup_latest_go(name: str, client: httpx.Client) -> str | None:
    try:
        r = client.get(f"https://proxy.golang.org/{name.lower()}/@latest", timeout=10)
        r.raise_for_status()
        return r.json()["Version"]
    except Exception:
        return None


def _lookup_latest_rubygems(name: str, client: httpx.Client) -> str | None:
    try:
        r = client.get(f"https://rubygems.org/api/v1/gems/{name}.json", timeout=10)
        r.raise_for_status()
        return r.json()["version"]
    except Exception:
        return None


def _lookup_latest_maven(name: str, client: httpx.Client) -> str | None:
    """Maven uses 'group:artifact' coordinates. Query search.maven.org for the
    latest release of the artifact."""
    if ":" not in name:
        return None
    group_id, artifact_id = name.split(":", 1)
    try:
        r = client.get(
            "https://search.maven.org/solrsearch/select",
            params={
                "q": f'g:"{group_id}" AND a:"{artifact_id}"',
                "rows": "1",
                "wt": "json",
            },
            timeout=10,
        )
        r.raise_for_status()
        docs = (r.json().get("response") or {}).get("docs") or []
        if not docs:
            return None
        return docs[0].get("latestVersion") or None
    except Exception:
        return None


def _lookup_latest_nuget(name: str, client: httpx.Client) -> str | None:
    """NuGet package IDs are case-insensitive but the registration index URL is
    lowercase. Return the highest published version."""
    lname = name.lower()
    try:
        r = client.get(
            f"https://api.nuget.org/v3-flatcontainer/{lname}/index.json",
            timeout=10,
        )
        r.raise_for_status()
        versions = r.json().get("versions") or []
        # Filter out prerelease tags (anything containing '-') first; fall back
        # to the highest entry if every version is prerelease.
        stable = [v for v in versions if "-" not in v]
        candidates = stable or versions
        return candidates[-1] if candidates else None
    except Exception:
        return None


def _lookup_latest_packagist(name: str, client: httpx.Client) -> str | None:
    """Composer/Packagist uses 'vendor/package' coordinates. The p2 endpoint
    returns versions newest-first."""
    if "/" not in name:
        return None
    try:
        r = client.get(f"https://repo.packagist.org/p2/{name}.json", timeout=10)
        r.raise_for_status()
        packages = (r.json().get("packages") or {}).get(name) or []
        for entry in packages:
            v = entry.get("version") or ""
            # Skip 'dev-*' branches and prereleases when a stable release exists
            if not v or v.startswith("dev-"):
                continue
            return v
        # Fall back to the first entry if only dev/prerelease available
        if packages:
            return packages[0].get("version") or None
        return None
    except Exception:
        return None


_LATEST_VERSION_REGISTRIES: dict[str, Any] = {
    "PyPI": _lookup_latest_pypi,
    "npm": _lookup_latest_npm,
    "crates.io": _lookup_latest_crates,
    "Go": _lookup_latest_go,
    "RubyGems": _lookup_latest_rubygems,
    "Maven": _lookup_latest_maven,
    "NuGet": _lookup_latest_nuget,
    "Packagist": _lookup_latest_packagist,
}


def _check_latest_osv_vuln_count(
    package: str, ecosystem: str, version: str, client: httpx.Client
) -> int:
    """Return the number of known OSV vulnerabilities for package@version, or -1 on error."""
    try:
        r = client.post(
            "https://api.osv.dev/v1/query",
            json={"version": version, "package": {"name": package, "ecosystem": ecosystem}},
            timeout=15,
        )
        r.raise_for_status()
        return len(r.json().get("vulns", []))
    except Exception:
        return -1


def _lookup_one_latest_version(
    package: str, ecosystem: str, client: httpx.Client
) -> tuple[str, str, str, int] | None:
    """Network-only half of latest-version enrichment for one (package,
    ecosystem) — returns (package, ecosystem, latest, vuln_count) or None to
    skip. Kept separate from the DB write so it can run in a thread pool:
    sqlite3 connections aren't safe for concurrent writes from multiple
    threads, so all db.update_latest_version_for_package() calls happen back
    on the caller's thread after every lookup has finished.
    """
    lookup_fn = _LATEST_VERSION_REGISTRIES.get(ecosystem)
    if not lookup_fn:
        return None
    try:
        latest = lookup_fn(package, client)
        if not latest:
            return None
        vuln_count = _check_latest_osv_vuln_count(package, ecosystem, latest, client)
        if vuln_count < 0:
            return None
        return (package, ecosystem, latest, vuln_count)
    except Exception:
        logger.debug("Failed to enrich %s/%s", ecosystem, package, exc_info=True)
        return None


def _enrich_latest_versions(
    conn: sqlite3.Connection,
    queue: set[tuple[str, str]],
) -> None:
    """Look up the latest published version for each (package, ecosystem) in queue.

    For each, query OSV to see whether that version is clean. Updates every
    matching finding row so the UI can always show the current latest release
    next to the affected and patched ranges.
    """
    logger.info("Checking latest versions for %d package(s)", len(queue))
    results: list[tuple[str, str, str, int]] = []
    with (
        httpx.Client(follow_redirects=True) as client,
        ThreadPoolExecutor(max_workers=_LATEST_VERSION_WORKERS) as executor,
    ):
        futures = [
            executor.submit(_lookup_one_latest_version, package, ecosystem, client)
            for package, ecosystem in queue
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    for package, ecosystem, latest, vuln_count in results:
        db.update_latest_version_for_package(conn, package, ecosystem, latest, vuln_count)
        logger.debug("Latest %s/%s: %s (%d known vuln(s))", ecosystem, package, latest, vuln_count)


# ---------------------------------------------------------------------------
# OSV finding storage
# ---------------------------------------------------------------------------


def _store_osv_finding(
    conn: sqlite3.Connection,
    config: AppConfig,
    pkg: Package,
    vuln: dict,
    kev_cves: set[str],
    stats: ScannerStats,
) -> None:
    """Map one OSV vulnerability to a finding and upsert it."""
    osv_id = vuln.get("id", "")
    aliases: list[str] = vuln.get("aliases") or []
    cve_id = (
        osv_id
        if osv_id.startswith("CVE-")
        else next((a for a in aliases if a.startswith("CVE-")), None)
    )
    ghsa_id = (
        osv_id
        if osv_id.startswith("GHSA-")
        else next((a for a in aliases if a.startswith("GHSA-")), None)
    )

    severity_text, cvss_score = _extract_severity(vuln)
    fixed_version = _extract_fixed_version(vuln, pkg.ecosystem, pkg.name)
    affected_versions = _extract_affected_versions(vuln, pkg.ecosystem, pkg.name)
    patch_available = fixed_version is not None
    is_kev = bool(cve_id and cve_id.upper() in kev_cves)
    priority = _priority_score(cvss_score, is_kev, patch_available)

    # Record every finding key so lifecycle.auto_resolve_gone() never treats a
    # still-present vulnerability as resolved.
    stats.finding_keys.add(
        (
            pkg.repo_full_name,
            pkg.name,
            pkg.ecosystem,
            cve_id or "",
            ghsa_id or "",
        )
    )

    # NOTE: the severity threshold is a NOTIFICATION-time gate (applied in
    # main.py::_apply_severity_threshold). It does NOT gate storage — every
    # finding the scanner discovers is persisted so the operator can see the
    # full inventory on the Vulnerabilities page regardless of how loud they
    # want their alert channels.

    finding = {
        "repo_full_name": pkg.repo_full_name,
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "package_name": pkg.name,
        "package_ecosystem": pkg.ecosystem,
        "installed_version": pkg.version,
        "fixed_version": fixed_version,
        "affected_versions": affected_versions,
        "cvss_score": cvss_score,
        "is_kev": is_kev,
        "patch_available": patch_available,
        "priority_score": priority,
        "manifest_path": pkg.manifest_path,
    }

    is_new = db.upsert_finding(conn, finding)

    # Queue every (package, ecosystem) pair for latest-version enrichment so the
    # UI can always show the current latest release alongside the affected/fixed
    # ranges — not just when OSV omitted a fix.
    stats._enrich_queue.add((pkg.name, pkg.ecosystem))

    if is_new:
        stats.findings_new += 1
        if severity_text in _HIGH_SEVERITY and st.is_feature_enabled(conn, "llm_ai_next_steps"):
            _generate_next_steps_for_finding(conn, config, finding["id"], finding, vuln)
    else:
        stats.findings_updated += 1


# ---------------------------------------------------------------------------
# Severity and CVSS helpers
# ---------------------------------------------------------------------------

_SEVERITY_CVSS_MAP = {
    "CRITICAL": 9.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
}


def _extract_severity(vuln: dict) -> tuple[str, float | None]:
    """Return (severity_text, cvss_score) for an OSV vulnerability.

    Prefers a calculated CVSS base score from the severity vector array.
    Falls back to the database_specific.severity text label with an approximate
    midpoint score when no vector is present.
    """
    # 1. Top-level severity array (most databases).
    for sev_entry in vuln.get("severity") or []:
        if "CVSS" in sev_entry.get("type", ""):
            score = _score_from_vector(sev_entry.get("score", ""))
            if score is not None:
                return _cvss_to_severity_text(score), score

    # 2. Per-affected-version severity (Go, npm, crates.io advisories often
    #    omit the top-level array and place CVSS vectors here instead).
    for affected in vuln.get("affected") or []:
        for sev_entry in affected.get("severity") or []:
            if "CVSS" in sev_entry.get("type", ""):
                score = _score_from_vector(sev_entry.get("score", ""))
                if score is not None:
                    return _cvss_to_severity_text(score), score

    # 3. Text severity label from database_specific (reliable for GitHub advisories).
    db_sev = (vuln.get("database_specific") or {}).get("severity", "").upper()
    if db_sev in _SEVERITY_CVSS_MAP:
        text = "Critical" if db_sev == "CRITICAL" else db_sev.capitalize()
        return text, _SEVERITY_CVSS_MAP[db_sev]

    return "Unknown", None


def _score_from_vector(vector: str) -> float | None:
    """Calculate CVSS base score from a vector string.

    Uses the cvss library when available. Falls back to an impact-metric
    heuristic (accurate within ~0.5 for most common vectors) when the library
    is not installed.
    """
    if not vector:
        return None

    if _CVSS_AVAILABLE:
        try:
            if vector.startswith("CVSS:4"):
                return float(_CVSS4(vector).base_score)
            if vector.startswith("CVSS:3"):
                return float(_CVSS3(vector).base_score)
            # CVSS v2 vectors don't carry a version prefix
            return float(_CVSS2(vector).base_score)
        except Exception:
            pass

    # Fallback heuristic: score from C/I/A impact levels in the vector.
    # C:H/I:H/A:H = all three high impacts → almost always Critical/High.
    v = vector.upper()
    high_impacts = sum(1 for m in ("C:H", "I:H", "A:H") if m in v)
    if high_impacts == 3:
        return 9.0
    if high_impacts == 2:
        return 7.5
    if high_impacts == 1:
        return 5.0
    # Check for medium impacts
    if any(m in v for m in ("C:M", "I:M", "A:M")):
        return 4.0
    return 2.5


def _cvss_to_severity_text(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _extract_affected_versions(vuln: dict, ecosystem: str, package_name: str) -> str | None:
    """Return a human-readable affected-version range string from OSV data.

    E.g. "< 2.32.0" or ">= 1.0.0, < 2.32.0". Returns None when no range is found.
    Multiple disjoint ranges are joined with " | ".
    """
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        ranges: list[str] = []
        for range_ in affected.get("ranges") or []:
            if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced: str | None = None
            fixed: str | None = None
            last_affected: str | None = None
            for event in range_.get("events") or []:
                if event.get("introduced"):
                    introduced = event["introduced"]
                if event.get("fixed"):
                    fixed = event["fixed"]
                if event.get("last_affected"):
                    last_affected = event["last_affected"]
            parts: list[str] = []
            if introduced and introduced != "0":
                parts.append(f">= {introduced}")
            if fixed:
                parts.append(f"< {fixed}")
            elif last_affected:
                parts.append(f"<= {last_affected}")
            if parts:
                ranges.append(", ".join(parts))
        if ranges:
            return " | ".join(ranges)
    return None


def _extract_fixed_version(vuln: dict, ecosystem: str, package_name: str) -> str | None:
    """Extract the fixed version from OSV affected ranges.

    Checks ECOSYSTEM and SEMVER range types for a 'fixed' event first.
    Falls back to 'last_affected' when no fixed event exists, prefixed with
    '>' so the dashboard shows '>X.Y.Z' (upgrade past the last affected version).
    """
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        last_affected = None
        for range_ in affected.get("ranges") or []:
            if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in range_.get("events") or []:
                if event.get("fixed"):
                    return event["fixed"]
                if event.get("last_affected"):
                    last_affected = event["last_affected"]
        if last_affected:
            return f">{last_affected}"
    return None


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------


def _priority_score(
    cvss_score: float | None,
    is_kev: bool,
    patch_available: bool,
) -> float:
    """Compute a 0–100 priority score.

    Weights:
      CVSS (0-10) × 6  → up to 60 points
      CISA KEV          → +25 points (known to be actively exploited)
      No patch          → -5  points (increases urgency)
    """
    score = float(cvss_score or 0.0) * 6.0
    if is_kev:
        score += 25.0
    if not patch_available:
        score -= 5.0
    return round(min(max(score, 0.0), 100.0), 1)


# ---------------------------------------------------------------------------
# AI next steps
# ---------------------------------------------------------------------------


def _generate_next_steps_for_finding(
    conn: sqlite3.Connection,
    config: AppConfig,
    finding_id: int,
    finding: dict,
    vuln: dict,
) -> None:
    """Call Ollama to generate plain-English next steps for a new finding.

    finding_id is the row id stamped onto `finding["id"]` by db.upsert_finding
    — the caller threads it straight through rather than this function
    re-deriving it via a natural-key lookup. The old lookup matched on
    cve_id alone (ignoring ghsa_id), so a package with two advisories that
    differ only in GHSA and share cve_id=NULL could attach next-steps to the
    wrong row.

    Failures are logged but never propagate — the scan result is still stored.
    """
    prompt = _build_next_steps_prompt(finding, vuln)
    url = f"{config.ollama.host.rstrip('/')}/api/generate"
    active_model = db.get_setting(conn, "active_model") or config.ollama.model
    payload = {
        "model": active_model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }

    try:
        with _make_http_client() as client:
            response = client.post(url, json=payload, timeout=60.0)
            response.raise_for_status()
            raw = response.json().get("response", "")
            next_steps = _parse_next_steps(raw)
            if next_steps:
                db.update_finding_next_steps(conn, finding_id, next_steps)
    except Exception as exc:
        logger.debug("Could not generate next steps for finding %d: %s", finding_id, exc)


def _build_next_steps_prompt(finding: dict, vuln: dict) -> str:
    summary = (vuln.get("summary") or "")[:300]
    identifier = finding.get("cve_id") or finding.get("ghsa_id") or "unknown"
    fixed = finding.get("fixed_version") or "no patch available"
    return f"""You are a security advisor helping a developer fix a vulnerability.

Output ONLY valid JSON with exactly these three fields:
{{
  "impact": "one sentence — what an attacker could do if this is exploited",
  "fix": "the specific command or code change to fix this (be concrete)",
  "effort": "Low" or "Medium" or "High"
}}

Vulnerability: {identifier}
Package: {finding["package_name"]} {finding.get("installed_version", "")} ({finding["package_ecosystem"]})
Fixed in: {fixed}
Summary: {summary}"""


def _parse_next_steps(raw: str) -> dict | None:
    try:
        data = json.loads(raw.strip())
        if not isinstance(data, dict):
            return None
        if not all(k in data for k in ("impact", "fix", "effort")):
            return None
        if data.get("effort") not in ("Low", "Medium", "High"):
            data["effort"] = "Medium"
        return {
            "impact": str(data.get("impact") or "")[:500],
            "fix": str(data.get("fix") or "")[:500],
            "effort": data["effort"],
        }
    except (json.JSONDecodeError, TypeError):
        return None


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def _make_http_client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=False,
        timeout=_HTTP_TIMEOUT,
        headers={"User-Agent": "dive/0.1"},
    )
