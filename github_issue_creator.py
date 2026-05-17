"""
github_issue_creator.py — Auto-create GitHub issues for new security findings.

Feature toggle: ``github_issue_creation`` (off by default).

For each new finding that has not yet had an issue filed:
  1. Look for an open issue in the affected repo whose title starts with
     ``[Security] <vuln-id>`` — skips creation if one already exists.
  2. Otherwise create a ``[Security]``-prefixed issue with severity,
     package info, and AI-generated next steps.
  3. Store the new issue URL in ``findings.github_issue_url``.

The module is intentionally side-effect-free when the toggle is off or
when no findings need issues — callers can always call ``run()`` safely.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from github import Github, GithubException, UnknownObjectException

import db
from config import AppConfig

logger = logging.getLogger(__name__)

# Label applied to every auto-created issue so they are easy to filter.
_LABEL_NAME = "security"
_ISSUE_TITLE_PREFIX = "[Security]"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class IssueCreationStats:
    issues_created: int = 0
    issues_skipped: int = 0  # duplicate open issue found
    issues_failed: int = 0
    failed_repos: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run(conn: sqlite3.Connection, config: AppConfig) -> IssueCreationStats:
    """Create GitHub issues for all new findings that don't have one yet.

    Reads ``github_issue_url IS NULL`` findings from the DB, attempts to
    create (or skip if duplicate) a GitHub issue for each, then stamps the
    URL back onto the finding row.

    Errors for individual repos are caught and counted; the loop continues
    so a single inaccessible repo does not abort the rest.
    """
    stats = IssueCreationStats()

    findings = db.get_findings_for_issue_creation(conn)
    if not findings:
        return stats

    gh = Github(config.github.token)

    for finding in findings:
        repo_name = finding["repo_full_name"]
        try:
            url, was_created = _create_or_skip(gh, finding)
            db.set_finding_github_issue_url(conn, finding["id"], url)
            if was_created:
                stats.issues_created += 1
                logger.info("GitHub issue created: %s", url)
            else:
                stats.issues_skipped += 1
                logger.debug("Existing GitHub issue found, URL stamped: %s", url)
        except GithubException as exc:
            logger.warning(
                "Could not create GitHub issue for %s (%s): %s",
                repo_name,
                finding["cve_id"] or finding["ghsa_id"] or "no-id",
                exc,
            )
            stats.issues_failed += 1
            if repo_name not in stats.failed_repos:
                stats.failed_repos.append(repo_name)
        except Exception as exc:
            logger.error(
                "Unexpected error creating issue for %s: %s", repo_name, exc, exc_info=True
            )
            stats.issues_failed += 1
            if repo_name not in stats.failed_repos:
                stats.failed_repos.append(repo_name)

    return stats


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _vuln_id(finding: sqlite3.Row) -> str:
    """Return the primary vulnerability identifier for this finding."""
    return finding["cve_id"] or finding["ghsa_id"] or "no-id"


def _issue_title(finding: sqlite3.Row) -> str:
    vid = _vuln_id(finding)
    pkg = finding["package_name"]
    return f"{_ISSUE_TITLE_PREFIX} {vid} in {pkg}"


def _severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _nvd_url(cve_id: str | None) -> str | None:
    if cve_id and cve_id.upper().startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return None


def _ghsa_url(ghsa_id: str | None) -> str | None:
    if ghsa_id and ghsa_id.upper().startswith("GHSA-"):
        return f"https://github.com/advisories/{ghsa_id}"
    return None


def _build_issue_body(finding: sqlite3.Row) -> str:
    vid = _vuln_id(finding)
    pkg = finding["package_name"]
    eco = finding["package_ecosystem"]
    inst_ver = finding["installed_version"] or "unknown"
    fix_ver = finding["fixed_version"]
    cvss = finding["cvss_score"]
    sev = _severity_label(cvss)
    is_kev = bool(finding["is_kev"])

    # Build vuln ID link
    link = _nvd_url(finding["cve_id"]) or _ghsa_url(finding["ghsa_id"])
    vid_md = f"[{vid}]({link})" if link else vid

    lines = [
        "## Security Vulnerability Detected",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Vulnerability** | {vid_md} |",
        f"| **Package** | `{pkg}` ({eco}) |",
        f"| **Installed version** | `{inst_ver}` |",
    ]
    if fix_ver:
        lines.append(f"| **Fixed in** | `{fix_ver}` |")
    if cvss is not None:
        lines.append(f"| **CVSS score** | {cvss:.1f} ({sev}) |")
    if is_kev:
        lines.append("| **CISA KEV** | ⚠️ Yes — actively exploited |")

    # AI next steps
    ai_raw = finding["ai_next_steps"]
    if ai_raw:
        import json

        try:
            ns: dict[str, Any] = json.loads(ai_raw) if isinstance(ai_raw, str) else ai_raw
            impact = ns.get("impact", "")
            fix = ns.get("fix", "")
            effort = ns.get("effort", "")
            if impact or fix:
                lines += [
                    "",
                    "### Suggested next steps",
                    "",
                ]
                if impact:
                    lines.append(f"**Impact:** {impact}")
                if fix:
                    lines.append(f"**Fix:** {fix}")
                if effort:
                    lines.append(f"**Estimated effort:** {effort}")
        except Exception:
            pass

    lines += [
        "",
        "---",
        "*Detected by [DIVE](https://github.com/bladzv/dive) — "
        "Dependency Intelligence for Vulnerability Exposure.*",
    ]
    return "\n".join(lines)


def _ensure_label(repo: Any) -> None:
    """Create the 'security' label in the repo if it does not already exist."""
    try:
        repo.get_label(_LABEL_NAME)
    except UnknownObjectException:
        try:
            repo.create_label(_LABEL_NAME, "d73a4a", "Automated security finding from DIVE")
        except GithubException:
            pass  # label creation is best-effort


def _create_or_skip(gh: Github, finding: sqlite3.Row) -> tuple[str, bool]:
    """Return (issue_url, was_created).

    was_created=True  → a new issue was opened.
    was_created=False → an open issue with the same title already existed;
                        its URL is returned so the caller can stamp the row
                        and avoid re-checking on every subsequent pipeline run.
    """
    repo_name = finding["repo_full_name"]
    title = _issue_title(finding)

    repo = gh.get_repo(repo_name)

    # Deduplicate: return existing URL so the row gets stamped and skipped next run
    issues = repo.get_issues(state="open", labels=[])
    for issue in issues:
        if issue.title == title:
            logger.debug("Duplicate open issue found for %s in %s — stamping URL", title, repo_name)
            return issue.html_url, False

    body = _build_issue_body(finding)
    _ensure_label(repo)

    try:
        label = repo.get_label(_LABEL_NAME)
        new_issue = repo.create_issue(title=title, body=body, labels=[label])
    except GithubException:
        new_issue = repo.create_issue(title=title, body=body)

    return new_issue.html_url, True
