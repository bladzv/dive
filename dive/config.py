"""
config.py — Load and validate config.yaml (secrets).

Secrets live here: GitHub token, dashboard credentials, webhook URLs,
SMTP credentials, NVD API key.

Preferences (schedule, model, RSS feeds, feature toggles) are stored in the
SQLite settings table (db.py) and managed through the dashboard UI.

Usage:
    from .config import load
    cfg = load()              # reads config.yaml in the working directory
    cfg = load("path/to/config.yaml")   # explicit path (tests, custom setups)
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path(os.environ.get("CONFIG_PATH", "config.yaml"))


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GitHubConfig:
    token: str
    username: str


@dataclass
class DashboardConfig:
    username: str = "admin"
    password: str = ""


@dataclass
class OllamaConfig:
    host: str = "http://ollama:11434"
    model: str = "qwen2.5:3b"


@dataclass
class NvdConfig:
    api_key: str = ""


@dataclass
class SlackConfig:
    webhook_url: str = ""


@dataclass
class DiscordConfig:
    webhook_url: str = ""


@dataclass
class EmailConfig:
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_address: str = ""
    to_address: str = ""


@dataclass
class NotificationsConfig:
    slack: SlackConfig = field(default_factory=SlackConfig)
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    email: EmailConfig = field(default_factory=EmailConfig)


@dataclass
class AppConfig:
    github: GitHubConfig
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    nvd: NvdConfig = field(default_factory=NvdConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)

    @property
    def has_any_notification_channel(self) -> bool:
        n = self.notifications
        has_email = bool(n.email.username and n.email.to_address)
        return bool(n.slack.webhook_url or n.discord.webhook_url or has_email)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load(path: Path | str | None = None) -> AppConfig:
    """Load, validate, and return the application configuration.

    Raises:
        FileNotFoundError: config.yaml does not exist.
        ValueError: a required field is missing or invalid.
    """
    config_path = Path(path) if path else _DEFAULT_PATH

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}\n"
            "Copy config.yaml.example to config.yaml and fill in your credentials."
        )

    _warn_if_world_readable(config_path)

    with config_path.open() as fh:
        raw: dict = yaml.safe_load(fh) or {}

    cfg = _parse(raw)

    if not cfg.has_any_notification_channel:
        logger.warning(
            "No notification channel configured in config.yaml. "
            "Add a Slack webhook, Discord webhook, or email credentials to receive alerts."
        )

    return cfg


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _warn_if_world_readable(path: Path) -> None:
    """Log a warning if config.yaml is readable by group or others."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            logger.warning(
                "%s permissions are too open (mode %s). Run: chmod 600 %s",
                path,
                oct(mode),
                path,
            )
    except OSError:
        pass  # Windows / unusual filesystems — skip the check


def _parse(raw: dict) -> AppConfig:
    gh = raw.get("github") or {}
    token = str(gh.get("token") or "").strip()
    username = str(gh.get("username") or "").strip()

    if not token:
        raise ValueError(
            "github.token is not set in config.yaml.\n"
            "Generate a fine-grained PAT at: "
            "github.com → Settings → Developer settings → Fine-grained tokens"
        )
    if not username:
        raise ValueError("github.username is not set in config.yaml.")

    dash = raw.get("dashboard") or {}
    password = str(dash.get("password") or "").strip()
    if not password:
        raise ValueError(
            "dashboard.password is not set in config.yaml. "
            "Choose a strong password — the dashboard is accessible to anyone on your network."
        )

    ollama = raw.get("ollama") or {}
    nvd = raw.get("nvd") or {}
    notif = raw.get("notifications") or {}
    slack = notif.get("slack") or {}
    discord = notif.get("discord") or {}
    email = notif.get("email") or {}

    return AppConfig(
        github=GitHubConfig(token=token, username=username),
        dashboard=DashboardConfig(
            username=str(dash.get("username") or "admin"),
            password=password,
        ),
        ollama=OllamaConfig(
            host=str(ollama.get("host") or "http://ollama:11434"),
            model=str(ollama.get("model") or "qwen2.5:3b"),
        ),
        nvd=NvdConfig(api_key=str(nvd.get("api_key") or "")),
        notifications=NotificationsConfig(
            slack=SlackConfig(webhook_url=str(slack.get("webhook_url") or "")),
            discord=DiscordConfig(webhook_url=str(discord.get("webhook_url") or "")),
            email=EmailConfig(
                smtp_host=str(email.get("smtp_host") or "smtp.gmail.com"),
                smtp_port=int(email.get("smtp_port") or 587),
                username=str(email.get("username") or ""),
                password=str(email.get("password") or ""),
                from_address=str(email.get("from_address") or ""),
                to_address=str(email.get("to_address") or ""),
            ),
        ),
    )
