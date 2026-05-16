"""
notifier.py — Deliver security alerts to configured channels.

Channels supported (all optional, configured in config.yaml):
  • Slack   — incoming webhook
  • Discord — incoming webhook
  • Email   — SMTP with STARTTLS

Message design
--------------
Findings are grouped by severity, sorted by priority_score descending.
Each alert lists up to MAX_FINDINGS_PER_ALERT findings.  If there are
more, a "+ N more" footer is appended.

Two alert types:
  send_findings_alert(config, findings)  — new vulnerability findings
  send_failure_alert(config, error_msg)  — pipeline / scan error

All channels are attempted independently; a failure on one channel does
NOT prevent delivery to others.
"""

from __future__ import annotations

import logging
import smtplib
import sqlite3
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

import httpx

import db
from config import AppConfig

logger = logging.getLogger(__name__)

MAX_FINDINGS_PER_ALERT = 20

# Severity → emoji
_SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Unknown": "⚪",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def send_findings_alert(
    config: AppConfig,
    findings: list[sqlite3.Row],
) -> None:
    """Send a new-findings alert to all configured channels.

    findings: rows from db.get_unnotified_findings(), already filtered to
              Critical/High (or all severities — caller decides).
    Does nothing when findings is empty.
    """
    if not findings:
        return

    if not config.has_any_notification_channel:
        logger.debug("No notification channels configured — skipping alert")
        return

    text_body = _build_findings_text(findings)
    slack_blocks = _build_slack_blocks(findings)

    _dispatch(config, subject=f"🚨 {len(findings)} new security finding(s)", text=text_body, slack_blocks=slack_blocks)


def send_weekly_digest(config: AppConfig, conn: sqlite3.Connection) -> None:
    """Build and send the weekly security digest, then persist it for the /weekly view.

    Fired by a Monday 08:00 cron job. Stored even when no channels are configured
    so the /weekly view always has something to show.
    """
    items_count   = db.get_weekly_items_collected(conn)
    new_count     = db.get_weekly_new_findings_count(conn)
    resolved_count = db.get_weekly_resolved_count(conn)
    top_findings  = db.get_weekly_digest_top_findings(conn)
    top_repos     = db.get_top_affected_repos(conn, limit=5)

    now = datetime.now(timezone.utc)
    week_label = now.strftime("Week of %B %-d, %Y")

    # Build serialisable snapshot for /weekly view
    digest_data = {
        "generated_at":  now.isoformat(),
        "week_label":    week_label,
        "items_collected": items_count,
        "new_findings":  new_count,
        "resolved_count": resolved_count,
        "top_findings": [
            {
                "repo":       r["repo_full_name"],
                "id":         r["cve_id"] or r["ghsa_id"] or "—",
                "package":    r["package_name"],
                "cvss":       r["cvss_score"],
                "priority":   r["priority_score"],
                "is_kev":     bool(r["is_kev"]),
                "has_patch":  bool(r["patch_available"]),
                "state":      r["state"],
            }
            for r in top_findings
        ],
        "top_repos": [
            {
                "repo":         r["repo_full_name"],
                "finding_count": r["finding_count"],
            }
            for r in top_repos
        ],
    }
    db.save_weekly_digest(conn, digest_data)
    logger.info("Weekly digest saved (%d findings, %d repos)", new_count, len(top_repos))

    if not config.has_any_notification_channel:
        logger.debug("No notification channels — weekly digest stored but not sent")
        return

    lines = [
        f"📅 {week_label} — Security Weekly Digest\n",
        f"News items collected:  {items_count}",
        f"New findings this week: {new_count}",
        f"Resolved this week:     {resolved_count}",
    ]
    if top_findings:
        lines.append("\nTop active findings (by priority):")
        for r in top_findings[:10]:
            cve = r["cve_id"] or r["ghsa_id"] or "no-id"
            kev = " [KEV]" if r["is_kev"] else ""
            patch = " [patch available]" if r["patch_available"] else ""
            lines.append(f"  • {r['repo_full_name']} | {cve} | {r['package_name']}{kev}{patch}")
    if top_repos:
        lines.append("\nMost affected repos:")
        for r in top_repos:
            lines.append(f"  • {r['repo_full_name']} — {r['finding_count']} finding(s)")

    text_body = "\n".join(lines)
    _dispatch(config, subject=f"📅 {week_label} — Security Weekly Digest", text=text_body)


def send_failure_alert(config: AppConfig, error_msg: str) -> None:
    """Send a pipeline-failure alert to all configured channels."""
    if not config.has_any_notification_channel:
        return

    body = f"⚠️ DIVE pipeline error:\n\n{error_msg}"
    _dispatch(config, subject="⚠️ DIVE pipeline error", text=body)


def send_pipeline_start_alert(config: AppConfig) -> None:
    """Send a notification when the pipeline begins running."""
    if not config.has_any_notification_channel:
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = f"⚙️ DIVE pipeline started at {now}"
    _dispatch(config, subject="⚙️ DIVE pipeline started", text=body)


def send_pipeline_summary_alert(
    config: AppConfig,
    *,
    items_collected: int,
    items_categorized: int,
    findings_new: int,
    secrets_new: int,
    duration_secs: float,
) -> None:
    """Send a summary notification after a successful pipeline run."""
    if not config.has_any_notification_channel:
        return

    mins = int(duration_secs // 60)
    secs = int(duration_secs % 60)
    duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    lines = [
        f"✅ DIVE pipeline completed in {duration_str}",
        "",
        f"📰 News items collected:  {items_collected}",
        f"🏷️  Items categorized:     {items_categorized}",
        f"🔍 New findings:          {findings_new}",
        f"🔑 New secrets detected:  {secrets_new}",
    ]
    text = "\n".join(lines)
    slack_blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"✅ Pipeline completed in {duration_str}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*News collected:*\n{items_collected}"},
                {"type": "mrkdwn", "text": f"*Categorized:*\n{items_categorized}"},
                {"type": "mrkdwn", "text": f"*New findings:*\n{findings_new}"},
                {"type": "mrkdwn", "text": f"*New secrets:*\n{secrets_new}"},
            ],
        },
    ]
    _dispatch(config, subject="✅ DIVE pipeline completed", text=text, slack_blocks=slack_blocks)


def send_secrets_alert(
    config: AppConfig,
    secret_findings: list[sqlite3.Row],
) -> None:
    """Send an urgent secrets-detected alert to all configured channels.

    New secrets always alert regardless of severity threshold.
    Does nothing when secret_findings is empty.
    """
    if not secret_findings:
        return

    if not config.has_any_notification_channel:
        logger.debug("No notification channels configured — skipping secrets alert")
        return

    text_body = _build_secrets_text(secret_findings)
    slack_blocks = _build_secrets_slack_blocks(secret_findings)

    _dispatch(
        config,
        subject=f"🔑 {len(secret_findings)} new secret(s) detected",
        text=text_body,
        slack_blocks=slack_blocks,
    )


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------


def _secret_line(row: sqlite3.Row) -> str:
    sha = (row["commit_sha"] or "")[:8]
    return f"🔑 {row['repo_full_name']} | {row['secret_type']} | {row['file_path']}:{row['line_number'] or '?'} | {sha}"


def _build_secrets_text(secret_findings: list[sqlite3.Row]) -> str:
    shown = secret_findings[:MAX_FINDINGS_PER_ALERT]
    lines = [f"🔑 {len(secret_findings)} new secret(s) detected in your repositories:\n"]
    for row in shown:
        lines.append(_secret_line(row))
    if len(secret_findings) > MAX_FINDINGS_PER_ALERT:
        lines.append(f"\n+ {len(secret_findings) - MAX_FINDINGS_PER_ALERT} more — check the Secrets view.")
    return "\n".join(lines)


def _build_secrets_slack_blocks(secret_findings: list[sqlite3.Row]) -> list[dict[str, Any]]:
    shown = secret_findings[:MAX_FINDINGS_PER_ALERT]
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔑 {len(secret_findings)} new secret(s) detected"},
        }
    ]
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "\n".join(_secret_line(r) for r in shown)},
    })
    if len(secret_findings) > MAX_FINDINGS_PER_ALERT:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"+ {len(secret_findings) - MAX_FINDINGS_PER_ALERT} more — check the Secrets view"}],
        })
    return blocks


def _severity_label(row: sqlite3.Row) -> str:
    score = row["cvss_score"]
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _finding_line(row: sqlite3.Row) -> str:
    sev = _severity_label(row)
    emoji = _SEVERITY_EMOJI.get(sev, "⚪")
    cve = row["cve_id"] or row["ghsa_id"] or "no-id"
    pkg = f"{row['package_name']} {row['installed_version'] or '?'}"
    fixed = f" → fix: {row['fixed_version']}" if row["fixed_version"] else ""
    kev = " [KEV]" if row["is_kev"] else ""
    return f"{emoji} {sev} | {row['repo_full_name']} | {cve} | {pkg}{fixed}{kev}"


def _build_findings_text(findings: list[sqlite3.Row]) -> str:
    shown = findings[:MAX_FINDINGS_PER_ALERT]
    lines = ["New security findings detected:\n"]
    for row in shown:
        lines.append(_finding_line(row))
    if len(findings) > MAX_FINDINGS_PER_ALERT:
        lines.append(f"\n+ {len(findings) - MAX_FINDINGS_PER_ALERT} more finding(s) — check the dashboard.")
    return "\n".join(lines)


def _build_slack_blocks(findings: list[sqlite3.Row]) -> list[dict[str, Any]]:
    shown = findings[:MAX_FINDINGS_PER_ALERT]
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🚨 {len(findings)} new security finding(s)"},
        }
    ]
    lines = [_finding_line(row) for row in shown]
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "\n".join(lines)},
    })
    if len(findings) > MAX_FINDINGS_PER_ALERT:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"+ {len(findings) - MAX_FINDINGS_PER_ALERT} more — check the dashboard",
                }
            ],
        })
    return blocks


# ---------------------------------------------------------------------------
# Channel dispatch
# ---------------------------------------------------------------------------


def _dispatch(
    config: AppConfig,
    *,
    subject: str,
    text: str,
    slack_blocks: list[dict[str, Any]] | None = None,
) -> None:
    notif = config.notifications
    errors: list[str] = []

    if notif.slack and notif.slack.webhook_url:
        try:
            _send_slack(notif.slack.webhook_url, text=text, blocks=slack_blocks)
            logger.info("Slack alert delivered")
        except Exception as exc:
            logger.error("Slack delivery failed: %s", exc)
            errors.append(f"Slack: {exc}")

    if notif.discord and notif.discord.webhook_url:
        try:
            _send_discord(notif.discord.webhook_url, text=text)
            logger.info("Discord alert delivered")
        except Exception as exc:
            logger.error("Discord delivery failed: %s", exc)
            errors.append(f"Discord: {exc}")

    if notif.email and notif.email.smtp_host:
        try:
            _send_email(notif.email, subject=subject, body=text)
            logger.info("Email alert delivered to %s", notif.email.to_address)
        except Exception as exc:
            logger.error("Email delivery failed: %s", exc)
            errors.append(f"Email: {exc}")

    if errors:
        logger.warning("Some notification channels failed: %s", "; ".join(errors))


# ---------------------------------------------------------------------------
# Channel implementations
# ---------------------------------------------------------------------------


def _send_slack(webhook_url: str, *, text: str, blocks: list[dict] | None = None) -> None:
    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    with httpx.Client(timeout=15) as client:
        resp = client.post(webhook_url, json=payload)
        resp.raise_for_status()


def _send_discord(webhook_url: str, *, text: str) -> None:
    # Discord webhooks cap at 2000 chars per message
    MAX = 1990
    chunk = text[:MAX] + ("…" if len(text) > MAX else "")
    with httpx.Client(timeout=15) as client:
        resp = client.post(webhook_url, json={"content": chunk})
        resp.raise_for_status()


def _send_email(email_cfg: Any, *, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email_cfg.from_address
    msg["To"] = email_cfg.to_address
    msg.set_content(body)

    with smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        if email_cfg.smtp_username and email_cfg.smtp_password:
            smtp.login(email_cfg.smtp_username, email_cfg.smtp_password)
        smtp.send_message(msg)
