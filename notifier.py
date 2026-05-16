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
from email.message import EmailMessage
from typing import Any

import httpx

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

    if not config.notifications.has_any_notification_channel:
        logger.debug("No notification channels configured — skipping alert")
        return

    text_body = _build_findings_text(findings)
    slack_blocks = _build_slack_blocks(findings)

    _dispatch(config, subject=f"🚨 {len(findings)} new security finding(s)", text=text_body, slack_blocks=slack_blocks)


def send_failure_alert(config: AppConfig, error_msg: str) -> None:
    """Send a pipeline-failure alert to all configured channels."""
    if not config.notifications.has_any_notification_channel:
        return

    body = f"⚠️ Security Automation pipeline error:\n\n{error_msg}"
    _dispatch(config, subject="⚠️ Security Automation pipeline error", text=body)


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------


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
