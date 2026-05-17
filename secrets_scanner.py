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
from dataclasses import dataclass, field
from pathlib import Path

from github import Github, GithubException

import db
from config import AppConfig

logger = logging.getLogger(__name__)

_DEFAULT_SCAN_DEPTH = 30
_CLONE_TIMEOUT = 120  # seconds per repo
_SCAN_TIMEOUT = 180  # seconds per repo


@dataclass
class ScanStats:
    repos_scanned: int = 0
    secrets_new: int = 0
    failed_repos: list[str] = field(default_factory=list)
    gitleaks_missing: bool = False


def run(
    conn: sqlite3.Connection,
    config: AppConfig,
    excluded_repos: list[str] | None = None,
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
        repos = list(gh.get_user(config.github.username).get_repos())
    except GithubException as exc:
        logger.error("Failed to list repos for secrets scan: %s", exc)
        return stats

    for repo in repos:
        if repo.full_name in _excluded:
            logger.debug("Skipping excluded repo (secrets scan): %s", repo.full_name)
            continue
        try:
            new_count = _scan_repo(conn, repo, config.github.token, scan_depth, fp_fingerprints)
            stats.repos_scanned += 1
            stats.secrets_new += new_count
        except Exception as exc:
            logger.error("Secrets scan failed for %s: %s", repo.full_name, exc)
            stats.failed_repos.append(repo.full_name)

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
        if not _clone(clone_url, tmpdir, depth):
            raise RuntimeError(f"git clone failed for {repo.full_name}")

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


def _clone(url: str, dest: str, depth: int) -> bool:
    """Shallow-clone at most depth+1 commits. Returns True on success."""
    result = subprocess.run(
        ["git", "clone", "--depth", str(depth + 1), "--quiet", url, dest],
        capture_output=True,
        timeout=_CLONE_TIMEOUT,
    )
    return result.returncode == 0


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
