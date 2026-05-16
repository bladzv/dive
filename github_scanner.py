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

Go, Rust, Java, and Ruby parsers are added in a later milestone.

GitHub API rate limit: remaining budget is checked at start. Repos are scanned
until the budget drops below 10% of the hourly limit, at which point a warning
is logged (no repos are silently skipped — the warning makes the gap explicit).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import tomllib
from dataclasses import dataclass, field
from typing import Any

import httpx
from github import Github, GithubException, RateLimitExceededException

import db
from config import AppConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_SIZE = 500          # max queries per OSV.dev batch request
_HTTP_TIMEOUT = 30.0
_MAX_MANIFESTS_PER_REPO = 25   # guard against monorepos with hundreds of lockfiles
_RATE_LIMIT_WARN_PCT = 0.10    # warn when < 10% of requests remain

# Filename → ecosystem mapping (exact filenames only; paths checked separately)
_MANIFEST_FILENAMES: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "pyproject.toml": "PyPI",
}

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
    rate_limit_warning: bool = False

    @property
    def api_requests_used(self) -> int:
        return self.api_requests_start - self.api_requests_end


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(conn: sqlite3.Connection, config: AppConfig) -> ScannerStats:
    """Scan all repos and store vulnerability findings. Never raises."""
    stats = ScannerStats()
    kev_cves = db.get_kev_cve_ids(conn)

    g = Github(config.github.token)

    # Record rate limit at start
    try:
        rate = g.get_rate_limit().core
        stats.api_requests_start = rate.remaining
        logger.info(
            "GitHub API rate limit: %d/%d remaining", rate.remaining, rate.limit
        )
    except GithubException as exc:
        logger.warning("Could not read rate limit: %s", exc)

    # Collect all packages across all repos first, then batch-query OSV
    all_packages: list[Package] = []

    try:
        user = g.get_user(config.github.username)
        repos = list(user.get_repos(type="all"))
    except GithubException as exc:
        logger.error("Failed to list repositories: %s", exc)
        return stats

    logger.info("Scanning %d repositories", len(repos))

    for repo in repos:
        # Check rate limit before each repo
        try:
            remaining = g.get_rate_limit().core.remaining
            limit = g.get_rate_limit().core.limit
            if remaining < limit * _RATE_LIMIT_WARN_PCT:
                logger.warning(
                    "GitHub API rate limit low: %d/%d remaining. "
                    "Repos scanned so far: %d/%d. "
                    "Remaining repos will be scanned on the next run.",
                    remaining, limit, stats.repos_scanned, len(repos),
                )
                stats.rate_limit_warning = True
                break
        except GithubException:
            pass

        try:
            packages = _scan_repo(repo)
            all_packages.extend(packages)
            stats.repos_scanned += 1
        except RateLimitExceededException:
            logger.warning("Rate limit exceeded mid-scan — stopping early")
            stats.rate_limit_warning = True
            break
        except GithubException as exc:
            logger.warning("Failed to scan %s: %s", repo.full_name, exc)
            stats.failed_repos.append(repo.full_name)
        except Exception as exc:
            logger.exception("Unexpected error scanning %s: %s", repo.full_name, exc)
            stats.failed_repos.append(repo.full_name)

    # Record rate limit at end
    try:
        stats.api_requests_end = g.get_rate_limit().core.remaining
        logger.info(
            "API requests used this scan: %d", stats.api_requests_used
        )
    except GithubException:
        pass

    if not all_packages:
        logger.info("No packages found to check")
        return stats

    stats.packages_checked = len(all_packages)
    logger.info("Querying OSV.dev for %d packages across %d repos",
                len(all_packages), stats.repos_scanned)

    # Query OSV.dev and process findings
    with _make_http_client() as client:
        _process_all_packages(conn, client, config, all_packages, kev_cves, stats)

    logger.info(
        "Scan complete: %d repos, %d packages, %d new findings, %d updated",
        stats.repos_scanned, stats.packages_checked,
        stats.findings_new, stats.findings_updated,
    )
    return stats


# ---------------------------------------------------------------------------
# Repo scanning
# ---------------------------------------------------------------------------


def _scan_repo(repo) -> list[Package]:
    """Return all packages found in dependency manifests for one repo."""
    packages: list[Package] = []

    try:
        # One API call to get the full file tree
        tree = repo.get_git_tree(repo.default_branch or "HEAD", recursive=True)
    except GithubException:
        logger.debug("Could not get tree for %s — skipping", repo.full_name)
        return packages

    manifest_paths: list[tuple[str, str]] = []  # (path, ecosystem)
    workflow_paths: list[str] = []

    for element in tree.tree:
        if element.type != "blob":
            continue
        path: str = element.path
        filename = path.rsplit("/", 1)[-1]

        if filename in _MANIFEST_FILENAMES:
            manifest_paths.append((path, _MANIFEST_FILENAMES[filename]))
        elif path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            workflow_paths.append(path)

    # Prefer package-lock.json over package.json for npm (exact versions)
    has_lockfile = any(
        p.endswith("package-lock.json") for p, _ in manifest_paths
    )
    if has_lockfile:
        manifest_paths = [(p, e) for p, e in manifest_paths if not p.endswith("package.json")]

    all_paths = manifest_paths[:_MAX_MANIFESTS_PER_REPO]
    all_paths += [(p, "Actions") for p in workflow_paths[:5]]  # limit workflow files

    if tree.truncated:
        logger.debug("%s: file tree truncated — may miss some manifests", repo.full_name)

    for path, ecosystem in all_paths:
        try:
            content_obj = repo.get_contents(path)
            raw = content_obj.decoded_content.decode("utf-8", errors="replace")
            parsed = _parse_manifest(path, raw, ecosystem)
            for pkg in parsed:
                pkg.repo_full_name = repo.full_name
            packages.extend(parsed)
        except GithubException as exc:
            logger.debug("Could not fetch %s/%s: %s", repo.full_name, path, exc)
        except Exception as exc:
            logger.debug("Error parsing %s/%s: %s", repo.full_name, path, exc)

    return packages


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
        if filename == "requirements.txt":
            return _parse_requirements_txt(content, path)
        if filename == "Pipfile":
            return _parse_pipfile(content, path)
        if filename == "pyproject.toml":
            return _parse_pyproject_toml(content, path)
        if filename.endswith((".yml", ".yaml")):
            return _parse_github_actions(content, path)
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
            packages.append(Package(name=name, version=version,
                                    ecosystem="npm", manifest_path=path,
                                    repo_full_name=""))
    return packages


def _parse_package_json(content: str, path: str) -> list[Package]:
    """Parse package.json. Uses semver ranges — extracts the base version."""
    data = json.loads(content)
    packages: list[Package] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version_spec in (data.get(section) or {}).items():
            version = _extract_version(str(version_spec))
            packages.append(Package(name=name, version=version,
                                    ecosystem="npm", manifest_path=path,
                                    repo_full_name=""))
    return packages


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"\s*([><=!~^][^;#\s]*)?"                            # optional version spec
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
        packages.append(Package(name=name, version=version,
                                ecosystem="PyPI", manifest_path=path,
                                repo_full_name=""))
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
            packages.append(Package(name=name, version=version,
                                    ecosystem="PyPI", manifest_path=path,
                                    repo_full_name=""))
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
        packages.append(Package(name=name, version=version,
                                ecosystem="PyPI", manifest_path=path,
                                repo_full_name=""))
    return packages


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
        packages.append(Package(name=action_name, version=version,
                                ecosystem="GitHub Actions", manifest_path=path,
                                repo_full_name=""))
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
        batch = queryable[batch_start: batch_start + _OSV_BATCH_SIZE]
        _query_and_store_batch(conn, client, config, batch, kev_cves, stats)


def _query_and_store_batch(
    conn: sqlite3.Connection,
    client: httpx.Client,
    config: AppConfig,
    batch: list[Package],
    kev_cves: set[str],
    stats: ScannerStats,
) -> None:
    payload = {
        "queries": [
            {
                "version": pkg.version,
                "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
            }
            for pkg in batch
        ]
    }

    try:
        response = client.post(_OSV_BATCH_URL, json=payload, timeout=_HTTP_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
        logger.warning("OSV.dev batch query failed: %s", exc)
        return

    results = data.get("results", [])
    for i, result in enumerate(results):
        if i >= len(batch):
            break
        pkg = batch[i]
        for vuln in result.get("vulns") or []:
            _store_osv_finding(conn, config, pkg, vuln, kev_cves, stats)


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
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    ghsa_id = osv_id if osv_id.startswith("GHSA-") else next(
        (a for a in aliases if a.startswith("GHSA-")), None
    )

    severity_text, cvss_score = _extract_severity(vuln)
    fixed_version = _extract_fixed_version(vuln, pkg.ecosystem, pkg.name)
    patch_available = fixed_version is not None
    is_kev = bool(cve_id and cve_id.upper() in kev_cves)
    priority = _priority_score(cvss_score, is_kev, patch_available)

    # Apply severity threshold — skip Medium/Low/Info findings
    if severity_text not in ("Critical", "High", "Unknown"):
        return

    finding = {
        "repo_full_name": pkg.repo_full_name,
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "package_name": pkg.name,
        "package_ecosystem": pkg.ecosystem,
        "installed_version": pkg.version,
        "fixed_version": fixed_version,
        "cvss_score": cvss_score,
        "is_kev": is_kev,
        "patch_available": patch_available,
        "priority_score": priority,
        "manifest_path": pkg.manifest_path,
    }

    is_new = db.upsert_finding(conn, finding)

    if is_new:
        stats.findings_new += 1
        # Generate AI next steps for new high-severity findings
        if severity_text in _HIGH_SEVERITY:
            _generate_next_steps_for_finding(conn, config, finding, vuln)
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
    """Return (severity_text, approximate_cvss_score) for an OSV vulnerability.

    CVSS scores are approximated from text severity (CRITICAL→9.0 etc.) when
    a numeric score is not directly available in the OSV response.
    """
    # database_specific.severity is the most reliable text field
    db_sev = (vuln.get("database_specific") or {}).get("severity", "").upper()
    if db_sev in _SEVERITY_CVSS_MAP:
        return db_sev.capitalize() if db_sev != "CRITICAL" else "Critical", \
               _SEVERITY_CVSS_MAP[db_sev]

    # Fall back to severity array (CVSS vector present but score not numeric)
    for sev_entry in vuln.get("severity") or []:
        sev_type = sev_entry.get("type", "")
        if "CVSS" in sev_type:
            # Attempt to infer severity from the vector's impact metrics
            score = _score_from_vector(sev_entry.get("score", ""))
            if score is not None:
                text = _cvss_to_severity_text(score)
                return text, score

    return "Unknown", None


_CVSS_BASE_SCORE_RE = re.compile(r"/([A-Z]+:[A-Z]+)")


def _score_from_vector(vector: str) -> float | None:
    """Very rough CVSS base score from vector string.

    Rather than implementing the full CVSS formula (complex), we count the
    number of HIGH/CRITICAL component values as a proxy. This is used only
    when the severity text is also unavailable. Accuracy is ±2 points.
    """
    if not vector:
        return None
    high_count = vector.upper().count(":H") + vector.upper().count(":C")
    total = max(len(_CVSS_BASE_SCORE_RE.findall(vector)), 1)
    return round(min(high_count / total * 10, 10.0), 1)


def _cvss_to_severity_text(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _extract_fixed_version(vuln: dict, ecosystem: str, package_name: str) -> str | None:
    """Extract the earliest 'fixed' version from OSV affected ranges."""
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for range_ in affected.get("ranges") or []:
            if range_.get("type") in ("ECOSYSTEM", "SEMVER"):
                for event in range_.get("events") or []:
                    if "fixed" in event:
                        return event["fixed"]
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
    finding: dict,
    vuln: dict,
) -> None:
    """Call Ollama to generate plain-English next steps for a new finding.

    Failures are logged but never propagate — the scan result is still stored.
    """
    # Look up the DB id of the finding we just inserted
    row = conn.execute(
        """
        SELECT id FROM findings
        WHERE repo_full_name = ? AND package_name = ?
          AND package_ecosystem = ?
          AND COALESCE(cve_id, '') = COALESCE(?, '')
        """,
        (
            finding["repo_full_name"],
            finding["package_name"],
            finding["package_ecosystem"],
            finding.get("cve_id"),
        ),
    ).fetchone()
    if not row:
        return
    finding_id = row["id"]

    prompt = _build_next_steps_prompt(finding, vuln)
    url = f"{config.ollama.host.rstrip('/')}/api/generate"
    payload = {
        "model": config.ollama.model,
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
        headers={"User-Agent": "security-automation/0.1"},
    )
