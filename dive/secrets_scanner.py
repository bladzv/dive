"""
secrets_scanner.py — Scan GitHub repositories for leaked secrets using gitleaks.

For each repo owned by the authenticated user:
  1. Shallow-clone (default: last 30 commits) into a temp directory.
  2. Run `gitleaks detect` — scans all commits in the shallow clone.
  3. Parse JSON output, upsert findings by fingerprint into secret_findings.
  4. Findings already marked false-positive are never re-reported.

Requires gitleaks on $PATH.
  Docker:     installed at /usr/local/bin/gitleaks via Dockerfile.
  Bare-metal: brew install gitleaks  /  apt install gitleaks  /
              or download from https://github.com/gitleaks/gitleaks/releases

If gitleaks is not found a warning is logged and the step returns empty stats.
The caller (main.py) continues the pipeline regardless.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from github import Github, GithubException

from . import db
from .config import AppConfig
from .github_scanner import probe_private_repo_access

logger = logging.getLogger(__name__)

DEFAULT_SCAN_DEPTH = 30
_DEFAULT_SCAN_DEPTH = DEFAULT_SCAN_DEPTH
_CLONE_TIMEOUT = 120  # seconds per repo
_SCAN_TIMEOUT = 180  # seconds per repo


@dataclass
class ScanStats:
    repos_scanned: int = 0
    secrets_new: int = 0
    failed_repos: list[str] = field(default_factory=list)
    gitleaks_missing: bool = False
    token_permission_warning: str | None = None


def run(
    conn: sqlite3.Connection,
    config: AppConfig,
    excluded_repos: list[str] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> ScanStats:
    """Entry point: scan all user repos for secrets. Called by the pipeline."""
    stats = ScanStats()
    _excluded = set(excluded_repos or [])

    if not shutil.which("gitleaks"):
        logger.warning(
            "gitleaks binary not found — secrets scanning skipped. "
            "See https://github.com/gitleaks/gitleaks#installing"
        )
        stats.gitleaks_missing = True
        return stats

    scan_depth = _get_scan_depth(conn)
    fp_fingerprints = db.get_false_positive_fingerprints(conn)

    gh = Github(config.github.token)
    try:
        # gh.get_user() with NO argument returns the AuthenticatedUser, whose
        # get_repos() hits GET /user/repos (public + private). Passing the
        # username instead returns a NamedUser, whose get_repos() hits
        # GET /users/{username}/repos — public repos only, even with a valid
        # token. type="all" matches github_scanner.py's repo listing.
        repos = list(gh.get_user().get_repos(type="all"))
    except GithubException as exc:
        logger.error("Failed to list repos for secrets scan: %s", exc)
        return stats

    stats.token_permission_warning = probe_private_repo_access(repos)
    if stats.token_permission_warning:
        logger.warning(stats.token_permission_warning)

    scannable = [r for r in repos if r.full_name not in _excluded]
    total = len(scannable)
    for repo in scannable:
        try:
            new_count = _scan_repo(conn, repo, config.github.token, scan_depth, fp_fingerprints)
            stats.repos_scanned += 1
            stats.secrets_new += new_count
        except Exception as exc:
            logger.error("Secrets scan failed for %s: %s", repo.full_name, exc)
            stats.failed_repos.append(repo.full_name)
        if on_progress:
            on_progress(stats.repos_scanned + len(stats.failed_repos), total)

    logger.info(
        "Secrets scanner: %d repos, %d new findings, %d failed",
        stats.repos_scanned,
        stats.secrets_new,
        len(stats.failed_repos),
    )
    return stats


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_scan_depth(conn: sqlite3.Connection) -> int:
    stored = db.get_setting(conn, "secrets_scan_depth", str(_DEFAULT_SCAN_DEPTH))
    try:
        return max(1, int(stored))
    except ValueError:
        return _DEFAULT_SCAN_DEPTH


def _scan_repo(
    conn: sqlite3.Connection,
    repo,
    token: str,
    depth: int,
    fp_fingerprints: set[str],
) -> int:
    """Shallow-clone repo, run gitleaks, upsert findings. Returns count of new findings."""
    # Embed token in clone URL — not logged; temp dir is deleted immediately after.
    clone_url = f"https://x-access-token:{token}@github.com/{repo.full_name}.git"

    with tempfile.TemporaryDirectory() as tmpdir:
        ok, detail = _clone(clone_url, tmpdir, depth, token)
        if not ok:
            raise RuntimeError(f"git clone failed for {repo.full_name}: {detail}")

        raw_findings = _run_gitleaks(tmpdir)

    new_count = 0
    for raw in raw_findings:
        fingerprint = raw.get("Fingerprint", "").strip()
        if not fingerprint or fingerprint in fp_fingerprints:
            continue

        is_new = db.upsert_secret_finding(
            conn,
            {
                "repo_full_name": repo.full_name,
                "file_path": raw.get("File", ""),
                "line_number": raw.get("StartLine"),
                "commit_sha": raw.get("Commit", ""),
                "secret_type": raw.get("Description") or raw.get("RuleID") or "Unknown",
                "rule_id": raw.get("RuleID", ""),
                "fingerprint": fingerprint,
            },
        )
        if is_new:
            new_count += 1

    return new_count


def _clone(url: str, dest: str, depth: int, token: str) -> tuple[bool, str]:
    """Shallow-clone at most depth+1 commits. Returns (success, detail).

    On failure, detail is git's stderr — e.g. "Write access to repository not
    granted" for a token-permission gap, which was previously discarded,
    leaving only a bare "git clone failed for X" with no reason. The clone
    URL embeds the access token; git normally strips credentials from the
    URLs it echoes back, but that's not a guarantee worth trusting for a live
    PAT that would otherwise land in log_entries and get rendered on /logs,
    so the token is redacted unconditionally.
    """
    result = subprocess.run(
        ["git", "clone", "--depth", str(depth + 1), "--quiet", url, dest],
        capture_output=True,
        timeout=_CLONE_TIMEOUT,
    )
    if result.returncode == 0:
        return True, ""
    detail = result.stderr.decode(errors="replace")[:300].replace(token, "<TOKEN>")
    return False, detail


def _run_gitleaks(source_dir: str) -> list[dict]:
    """Run gitleaks detect on source_dir and return parsed finding dicts.

    Returns an empty list when no leaks are found or on any gitleaks error.
    gitleaks exits 0 = no leaks, 1 = leaks found; anything else is an error.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    try:
        result = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                source_dir,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-banner",
                "--redact",  # replace actual secret values with REDACTED
            ],
            capture_output=True,
            timeout=_SCAN_TIMEOUT,
        )

        if result.returncode not in (0, 1):
            stderr = result.stderr.decode(errors="replace")[:300]
            logger.warning("gitleaks exited %d: %s", result.returncode, stderr)
            return []

        content = Path(report_path).read_text().strip()
        if not content:
            return []

        data = json.loads(content)
        return data if isinstance(data, list) else []

    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read gitleaks report: %s", exc)
        return []
    finally:
        Path(report_path).unlink(missing_ok=True)
