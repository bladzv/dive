"""
Unit tests for notifier.py — message formatting and channel dispatch.

No real network calls are made — httpx and smtplib are mocked throughout.
"""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

import notifier
from notifier import (
    MAX_FINDINGS_PER_ALERT,
    _build_findings_text,
    _build_slack_blocks,
    _finding_line,
    _severity_label,
    send_failure_alert,
    send_findings_alert,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(**kwargs) -> sqlite3.Row:
    """Return a sqlite3.Row-like dict (accessible by key)."""
    defaults = {
        "id": 1,
        "repo_full_name": "user/repo",
        "cve_id": "CVE-2024-1234",
        "ghsa_id": None,
        "package_name": "requests",
        "package_ecosystem": "PyPI",
        "installed_version": "2.28.0",
        "fixed_version": "2.32.0",
        "cvss_score": 9.1,
        "is_kev": 0,
        "patch_available": 1,
        "priority_score": 54.6,
        "state": "new",
        "manifest_path": "requirements.txt",
        "notified_at": None,
    }
    defaults.update(kwargs)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cols = list(defaults.keys())
    vals = list(defaults.values())
    placeholders = ", ".join("?" * len(cols))
    conn.execute(f"CREATE TABLE t ({', '.join(cols)})")
    conn.execute(f"INSERT INTO t VALUES ({placeholders})", vals)
    return conn.execute("SELECT * FROM t").fetchone()


def _make_config(
    slack_url: str | None = None,
    discord_url: str | None = None,
    email: bool = False,
) -> MagicMock:
    cfg = MagicMock()
    # Slack
    if slack_url:
        cfg.notifications.slack.webhook_url = slack_url
    else:
        cfg.notifications.slack = None
    # Discord
    if discord_url:
        cfg.notifications.discord.webhook_url = discord_url
    else:
        cfg.notifications.discord = None
    # Email
    if email:
        cfg.notifications.email.smtp_host = "smtp.example.com"
        cfg.notifications.email.smtp_port = 587
        cfg.notifications.email.smtp_username = "user"
        cfg.notifications.email.smtp_password = "pass"
        cfg.notifications.email.from_address = "from@example.com"
        cfg.notifications.email.to_address = "to@example.com"
    else:
        cfg.notifications.email = None
    cfg.notifications.has_any_notification_channel = bool(slack_url or discord_url or email)
    return cfg


# ---------------------------------------------------------------------------
# _severity_label
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.1, "Critical"),
        (9.0, "Critical"),
        (8.9, "High"),
        (7.0, "High"),
        (6.9, "Medium"),
        (4.0, "Medium"),
        (3.9, "Low"),
        (0.0, "Low"),
        (None, "Unknown"),
    ],
)
def test_severity_label(score, expected):
    row = _row(cvss_score=score)
    assert _severity_label(row) == expected


# ---------------------------------------------------------------------------
# _finding_line
# ---------------------------------------------------------------------------


def test_finding_line_contains_repo(dummy_row=None):
    row = _row()
    assert "user/repo" in _finding_line(row)


def test_finding_line_contains_cve():
    row = _row()
    assert "CVE-2024-1234" in _finding_line(row)


def test_finding_line_contains_package():
    row = _row()
    line = _finding_line(row)
    assert "requests" in line
    assert "2.28.0" in line


def test_finding_line_contains_fixed_version():
    row = _row()
    assert "2.32.0" in _finding_line(row)


def test_finding_line_no_fixed_version_omits_arrow():
    row = _row(fixed_version=None)
    assert "→" not in _finding_line(row)


def test_finding_line_kev_flag():
    row = _row(is_kev=1)
    assert "[KEV]" in _finding_line(row)


def test_finding_line_no_kev_flag():
    row = _row(is_kev=0)
    assert "[KEV]" not in _finding_line(row)


def test_finding_line_uses_ghsa_when_no_cve():
    row = _row(cve_id=None, ghsa_id="GHSA-xxxx-yyyy-zzzz")
    assert "GHSA-xxxx-yyyy-zzzz" in _finding_line(row)


def test_finding_line_no_id_fallback():
    row = _row(cve_id=None, ghsa_id=None)
    assert "no-id" in _finding_line(row)


# ---------------------------------------------------------------------------
# _build_findings_text
# ---------------------------------------------------------------------------


def test_build_text_includes_header():
    rows = [_row()]
    text = _build_findings_text(rows)
    assert "New security findings" in text


def test_build_text_respects_max_findings():
    rows = [_row(id=i, package_name=f"pkg{i}") for i in range(MAX_FINDINGS_PER_ALERT + 5)]
    text = _build_findings_text(rows)
    assert "5 more" in text


def test_build_text_no_truncation_under_max():
    rows = [_row(id=i, package_name=f"pkg{i}") for i in range(3)]
    text = _build_findings_text(rows)
    assert "more" not in text


# ---------------------------------------------------------------------------
# _build_slack_blocks
# ---------------------------------------------------------------------------


def test_slack_blocks_is_list():
    assert isinstance(_build_slack_blocks([_row()]), list)


def test_slack_blocks_has_header():
    blocks = _build_slack_blocks([_row()])
    assert any(b.get("type") == "header" for b in blocks)


def test_slack_blocks_overflow_context():
    rows = [_row(id=i, package_name=f"pkg{i}") for i in range(MAX_FINDINGS_PER_ALERT + 2)]
    blocks = _build_slack_blocks(rows)
    types = [b.get("type") for b in blocks]
    assert "context" in types


def test_slack_blocks_no_overflow_context_under_max():
    rows = [_row(id=i, package_name=f"pkg{i}") for i in range(3)]
    blocks = _build_slack_blocks(rows)
    assert not any(b.get("type") == "context" for b in blocks)


# ---------------------------------------------------------------------------
# send_findings_alert — channel dispatch
# ---------------------------------------------------------------------------


def test_send_findings_alert_no_channels_does_nothing():
    cfg = _make_config()
    # Should not raise, and no HTTP calls made
    send_findings_alert(cfg, [_row()])


def test_send_findings_alert_empty_findings_does_nothing():
    cfg = _make_config(slack_url="https://hooks.slack.com/test")
    with patch("notifier._send_slack") as mock_slack:
        send_findings_alert(cfg, [])
        mock_slack.assert_not_called()


def test_send_findings_alert_calls_slack():
    cfg = _make_config(slack_url="https://hooks.slack.com/test")
    with patch("notifier._send_slack") as mock_slack:
        send_findings_alert(cfg, [_row()])
        mock_slack.assert_called_once()
        args, kwargs = mock_slack.call_args
        assert args[0] == "https://hooks.slack.com/test"


def test_send_findings_alert_calls_discord():
    cfg = _make_config(discord_url="https://discord.com/api/webhooks/test")
    with patch("notifier._send_discord") as mock_discord:
        send_findings_alert(cfg, [_row()])
        mock_discord.assert_called_once()


def test_send_findings_alert_calls_both_channels():
    cfg = _make_config(
        slack_url="https://hooks.slack.com/test",
        discord_url="https://discord.com/api/webhooks/test",
    )
    with (
        patch("notifier._send_slack") as mock_slack,
        patch("notifier._send_discord") as mock_discord,
    ):
        send_findings_alert(cfg, [_row()])
        mock_slack.assert_called_once()
        mock_discord.assert_called_once()


def test_send_findings_alert_slack_failure_does_not_block_discord():
    cfg = _make_config(
        slack_url="https://hooks.slack.com/test",
        discord_url="https://discord.com/api/webhooks/test",
    )
    with (
        patch("notifier._send_slack", side_effect=Exception("Slack down")),
        patch("notifier._send_discord") as mock_discord,
    ):
        send_findings_alert(cfg, [_row()])
        mock_discord.assert_called_once()  # Discord still called despite Slack failure


# ---------------------------------------------------------------------------
# send_failure_alert
# ---------------------------------------------------------------------------


def test_send_failure_alert_calls_slack():
    cfg = _make_config(slack_url="https://hooks.slack.com/test")
    with patch("notifier._send_slack") as mock_slack:
        send_failure_alert(cfg, "Something broke")
        mock_slack.assert_called_once()
        _, kwargs = mock_slack.call_args
        assert "Something broke" in kwargs.get("text", "")


def test_send_failure_alert_no_channels_does_nothing():
    cfg = _make_config()
    send_failure_alert(cfg, "error")  # Should not raise


# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------


def test_send_email_uses_starttls():
    cfg = _make_config(email=True)

    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        send_findings_alert(cfg, [_row()])

        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once()
        mock_smtp.send_message.assert_called_once()


# ---------------------------------------------------------------------------
# Discord truncation
# ---------------------------------------------------------------------------


def test_discord_truncates_long_message():
    # Create a very long finding line
    long_text = "x" * 3000
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_resp

        notifier._send_discord("https://discord.com/api/webhooks/test", text=long_text)

        _, kwargs = mock_client.post.call_args
        sent = kwargs["json"]["content"]
        assert len(sent) <= 1991  # 1990 + possible ellipsis
