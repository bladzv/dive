"""
lifecycle.py — Finding state-machine for the DIVE pipeline.

States
------
new          Finding just discovered; alert not yet sent.
acknowledged User has seen and triaged the finding (set via dashboard).
resolved     Finding no longer appears in the latest scan of that repo.

Transitions
-----------
scanner run  → new   (first detection)
scanner run  → new   (Resolved finding reappears — reversal)
user action  → acknowledged  (via dashboard / API)
user action  → resolved      (via dashboard / API, or auto when gone from scan)

This module is called by main.py after each scanner run.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Post-scan reconciliation
# ---------------------------------------------------------------------------


def recheck_resolved(
    conn: sqlite3.Connection,
    current_finding_keys: set[tuple[str, str, str, str, str]],
) -> int:
    """
    After a full scanner run, any finding in 'resolved' state that is *still*
    present in the current scan should be reverted to 'new' — the fix was
    rolled back or the repo was forked.

    current_finding_keys: set of (repo_full_name, package_name,
                                   package_ecosystem, cve_id_or_empty,
                                   ghsa_id_or_empty) tuples produced by
                          this run.

    Returns the count of findings reverted from resolved → new.
    """
    resolved_rows = conn.execute(
        "SELECT id, repo_full_name, package_name, package_ecosystem, "
        "       COALESCE(cve_id,'') AS cve_key, COALESCE(ghsa_id,'') AS ghsa_key "
        "FROM findings WHERE state = 'resolved'"
    ).fetchall()

    reverted = 0
    for row in resolved_rows:
        key = (
            row["repo_full_name"],
            row["package_name"],
            row["package_ecosystem"],
            row["cve_key"],
            row["ghsa_key"],
        )
        if key in current_finding_keys:
            conn.execute(
                "UPDATE findings SET state = 'new', notified_at = NULL " "WHERE id = ?",
                (row["id"],),
            )
            reverted += 1
            logger.info(
                "Reverted resolved→new: %s %s (%s/%s)",
                row["repo_full_name"],
                row["package_name"],
                row["cve_key"] or row["ghsa_key"] or "no-id",
                row["package_ecosystem"],
            )

    if reverted:
        logger.warning(
            "%d resolved finding(s) reverted to new — fix may have been rolled back", reverted
        )
    return reverted


def auto_resolve_gone(
    conn: sqlite3.Connection,
    current_finding_keys: set[tuple[str, str, str, str, str]],
) -> int:
    """
    Mark 'new' or 'acknowledged' findings as 'resolved' when they are no
    longer present in the current scan for a repo that *was* scanned.

    Only resolves findings for repos that appear in current_finding_keys
    (i.e. we actually scanned those repos this run — don't auto-resolve
    findings for repos we couldn't reach due to API errors).

    Returns the count of findings auto-resolved.
    """
    if not current_finding_keys:
        return 0

    # Repos that were successfully scanned this run
    scanned_repos = {key[0] for key in current_finding_keys}

    active_rows = conn.execute(
        "SELECT id, repo_full_name, package_name, package_ecosystem, "
        "       COALESCE(cve_id,'') AS cve_key, COALESCE(ghsa_id,'') AS ghsa_key "
        "FROM findings WHERE state IN ('new', 'acknowledged')"
    ).fetchall()

    resolved = 0
    now = datetime.now(UTC).isoformat()
    for row in active_rows:
        if row["repo_full_name"] not in scanned_repos:
            continue  # Repo wasn't scanned this run — don't auto-resolve
        key = (
            row["repo_full_name"],
            row["package_name"],
            row["package_ecosystem"],
            row["cve_key"],
            row["ghsa_key"],
        )
        if key not in current_finding_keys:
            conn.execute(
                "UPDATE findings SET state = 'resolved', resolved_at = ? " "WHERE id = ?",
                (now, row["id"]),
            )
            resolved += 1
            logger.info(
                "Auto-resolved: %s %s (%s)",
                row["repo_full_name"],
                row["package_name"],
                row["cve_key"] or row["ghsa_key"] or "no-id",
            )

    return resolved


# ---------------------------------------------------------------------------
# User-driven state transitions (called by API endpoints in main.py)
# ---------------------------------------------------------------------------


def acknowledge(conn: sqlite3.Connection, finding_id: int) -> bool:
    """
    Mark a finding as acknowledged (user has triaged it).
    Returns True if the finding existed and was updated.
    """
    cur = conn.execute(
        "UPDATE findings SET state = 'acknowledged' WHERE id = ? AND state = 'new'",
        (finding_id,),
    )
    return cur.rowcount > 0


def resolve(conn: sqlite3.Connection, finding_id: int) -> bool:
    """
    Manually mark a finding as resolved.
    Returns True if the finding existed and was updated.
    """
    now = datetime.now(UTC).isoformat()
    cur = conn.execute(
        "UPDATE findings SET state = 'resolved', resolved_at = ? "
        "WHERE id = ? AND state IN ('new', 'acknowledged')",
        (now, finding_id),
    )
    return cur.rowcount > 0


def reopen(conn: sqlite3.Connection, finding_id: int) -> bool:
    """
    Reopen a resolved or acknowledged finding (manual override).
    Returns True if updated.
    """
    cur = conn.execute(
        "UPDATE findings SET state = 'new', notified_at = NULL, resolved_at = NULL "
        "WHERE id = ? AND state IN ('resolved', 'acknowledged')",
        (finding_id,),
    )
    return cur.rowcount > 0
