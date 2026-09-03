"""
DIVE — main entrypoint.

FastAPI application with:
  • APScheduler BackgroundScheduler — runs the full pipeline on a
    configurable interval (default 6h, stored in settings table).
  • Signed session-cookie auth (itsdangerous, 7-day expiry) — all
    non-health routes require a session established via POST /login
    against config.yaml dashboard.username / dashboard.password.
  • POST /api/run — trigger an immediate pipeline run (X-Run-Token header
    required as CSRF protection).
  • File-based lock (filelock) — prevents concurrent pipeline runs.
  • GET /api/health — unauthenticated, minimal (Docker healthcheck target).
    GET /api/status — authenticated; the full live pipeline status.
  • Jinja2 dashboard — /, /findings, /settings served as HTML.
"""

from __future__ import annotations

import asyncio
import calendar as _cal
import copy
import csv
import io
import json
import logging
import logging.handlers
import queue
import re
import secrets
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import httpx
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from filelock import FileLock, Timeout
from itsdangerous import URLSafeTimedSerializer

from . import config as cfg_module
from . import db, lifecycle, notifier
from . import github_issue_creator as gic
from . import github_scanner as gs
from . import secrets_scanner as ss
from . import settings as st

try:
    from . import categorizer as categorizer_module
    from . import collector as collector_module

    _COLLECTOR_AVAILABLE = True
except ImportError:
    _COLLECTOR_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# httpx logs every request URL at INFO. The SQLite log handler captures INFO+,
# so that wrote ~162 rows per pipeline run into log_entries — and any
# credential carried in a URL (as the NVD apiKey once was, before it moved to
# a request header) landed in the database in plaintext. Warnings and errors
# still come through.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# BASE_DIR points to the project root (one level above this package directory)
# so we can find static/ and templates/ regardless of how Python was invoked.
BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# SQLite log handler — captures INFO+ log messages to the log_entries table.
# Uses a QueueHandler/QueueListener so log() calls never block the caller.
# ---------------------------------------------------------------------------

_log_queue: queue.Queue = queue.Queue(maxsize=2000)
_log_listener: logging.handlers.QueueListener | None = None
_sqlite_log_handler: _SQLiteLogHandler | None = None

_LOG_INSERT_ATTEMPTS = 3
_LOG_INSERT_BACKOFF_S = 0.25

# db._make_connection()'s default PRAGMA busy_timeout is 5000ms, sized for
# request-handling connections that must not stall a response. The pipeline
# can hold a write transaction open for an entire step, not just a brief
# window — a live 15-repo secrets scan measured at 48.9s total, with
# db.upsert_secret_finding() never committing mid-loop (see main.py's
# `with db.get_conn() as conn: sec_stats = secrets_scanner.run(conn, ...)`).
# A 5s busy_timeout plus a short Python-level backoff (~15.75s worst case)
# was measured losing exactly the ERROR record for a mid-scan failure. This
# handler's connection is dedicated to a single background thread with
# nothing else to do but wait, so it gets a much longer budget instead.
_LOG_CONN_BUSY_TIMEOUT_MS = 60_000


class _SQLiteLogHandler(logging.Handler):
    """Write log records to the log_entries table via one long-lived
    connection, reused across calls.

    Safe because QueueListener runs every emit() on a single dedicated
    thread, never concurrently — unlike request handlers, which each open
    their own connection precisely because they run on different threads.
    A fresh connection per record was measurable overhead at normal INFO
    log volume, and could contend with the pipeline holding a long write
    transaction open during a scan.
    """

    def __init__(self) -> None:
        super().__init__()
        self._conn: sqlite3.Connection | None = None
        self._dropped = 0

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = db._make_connection(db._DEFAULT_DB_PATH)
            # Override the request-connection default (5s) — see
            # _LOG_CONN_BUSY_TIMEOUT_MS above. Only this dedicated background
            # connection is affected; request/pipeline connections keep the
            # 5s default from _make_connection().
            self._conn.execute(f"PRAGMA busy_timeout={_LOG_CONN_BUSY_TIMEOUT_MS}")
        return self._conn

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ts = datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%S")
            msg = self.format(record)
        except Exception:
            self._dropped += 1
            return

        for attempt in range(_LOG_INSERT_ATTEMPTS):
            try:
                conn = self._get_conn()
                db.insert_log_entry(conn, ts, record.levelname, record.name, msg)
                conn.commit()
                return
            except sqlite3.OperationalError:
                # Each attempt above already blocks for up to
                # _LOG_CONN_BUSY_TIMEOUT_MS inside SQLite's own busy handler
                # before raising — this loop is a second layer for the rare
                # case that budget is *still* not enough (an unusually long
                # step) or the lock clears in the gap right after giving up.
                # This runs only on the QueueListener thread, never a request
                # thread, so several minutes of total worst-case wait here
                # cannot block a request or the pipeline itself.
                if attempt == _LOG_INSERT_ATTEMPTS - 1:
                    break
                time.sleep(_LOG_INSERT_BACKOFF_S)
            except Exception:
                break

        # Never raise from a log handler. Drop the (possibly broken)
        # connection so the next record gets a fresh one instead of
        # repeating the same failure forever.
        self._dropped += 1
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


def _setup_sqlite_logging() -> None:
    """Wire the SQLite handler behind a QueueListener so logging never blocks."""
    global _log_listener, _sqlite_log_handler
    sqlite_handler = _SQLiteLogHandler()
    sqlite_handler.setFormatter(logging.Formatter("%(message)s"))
    sqlite_handler.setLevel(logging.INFO)
    _sqlite_log_handler = sqlite_handler
    _log_listener = logging.handlers.QueueListener(
        _log_queue, sqlite_handler, respect_handler_level=True
    )
    queue_handler = logging.handlers.QueueHandler(_log_queue)
    queue_handler.setLevel(logging.INFO)
    logging.getLogger().addHandler(queue_handler)
    _log_listener.start()


def _get_dropped_log_count() -> int:
    """Number of log records lost by the SQLite handler since startup —
    surfaced in /api/status as `log_drops` so a silent loss is visible
    instead of just incrementing an internal counter nobody reads."""
    return _sqlite_log_handler._dropped if _sqlite_log_handler is not None else 0


# ---------------------------------------------------------------------------
# Process-level state (set during lifespan startup, read-only after that)
# ---------------------------------------------------------------------------

_config: cfg_module.AppConfig | None = None
_scheduler: BackgroundScheduler | None = None
_session_serializer: URLSafeTimedSerializer | None = None

_SESSION_COOKIE = "dive_session"
_SESSION_MAX_AGE = 86400 * 7  # 7 days


class _LoginRedirect(Exception):
    """Raised by _require_auth to redirect a browser to the login page."""

    def __init__(self, location: str) -> None:
        self.location = location


# Pipeline run state — written under _pipeline_lock
_pipeline_lock = threading.Lock()
_pipeline_status: dict = {
    "running": False,
    "last_started": None,
    "last_completed": None,
    "last_status": "never_run",
    "last_error": None,
    "current_step": None,  # key of the step currently executing, or None
    "step_history": [],  # [{key, status}] in order, cleared at run start
    "paused": False,  # True when a pause is in effect
    "step_progress": {},  # {step_key: {"done": int, "total": int}}
    "step_stats": {},  # {step_key: {stat_name: value}} — outcome stats per step
    "step_times": {},  # {step_key: {"start": iso, "end": iso, "duration_s": float}}
    "run_duration_s": None,  # total wall-clock seconds for the last completed run
}

# Canonical list of pipeline steps shown in the UI step ticker. The pipeline
# in _run_pipeline() advances through these in order; if a step is gated by a
# feature toggle and skipped, it is still listed with status "skipped" so the
# ticker is always the same shape.
PIPELINE_STEPS = [
    {"key": "collect", "label": "Collect"},
    {"key": "categorize", "label": "Categorize"},
    {"key": "scan", "label": "Scan repos"},
    {"key": "issues", "label": "Issues"},
    {"key": "secrets", "label": "Scan secrets"},
    {"key": "lifecycle", "label": "Reconcile"},
    {"key": "notify", "label": "Notify"},
]

# Pipeline control — checked between steps for cancellation and pause. Pause
# blocks the runner on _pipeline_pause_event; cancel makes _check_control()
# return False so the runner exits cleanly at the next checkpoint.
_pipeline_control: dict = {"cancel_requested": False, "pause_requested": False}
_pipeline_pause_event = threading.Event()
_pipeline_pause_event.set()  # default: not paused (event is set)

# How long a pause is allowed to hold the runner before it self-resumes. Avoids
# leaving the pipeline thread blocked forever if the operator forgets.
_MAX_PAUSE_SECONDS = 1800  # 30 minutes

# File lock path (prevents concurrent runs across processes / restarts)
_LOCK_FILE = Path("data/.pipeline.lock")

# Self-exclusion lock for the idle categorization job (prevents two processes
# from picking the same batch; max_instances=1 covers the in-process case).
_IDLE_CATEGORIZE_LOCK_FILE = Path("data/.idle_categorize.lock")

# Pagination constants
_PAGE_SIZE_OPTIONS = [10, 25, 50, 100]
_DEFAULT_PAGE_SIZE = 25

# Interval select options shown in the settings page
_INTERVAL_OPTIONS = [
    ("3", "Every 3 hours"),
    ("6", "Every 6 hours (default)"),
    ("12", "Every 12 hours"),
    ("24", "Every 24 hours"),
    ("168", "Once a week"),
    ("720", "Once a month"),
]

# Suggested Ollama models shown in the settings page
_SUGGESTED_MODELS = [
    {"name": "qwen2.5:3b", "description": "~1.9 GB · 5–8 tok/s · Recommended for Pi 4"},
    {"name": "gemma2:2b", "description": "~1.6 GB · 8–12 tok/s · Fastest on Pi 4"},
    {"name": "phi3.5:mini", "description": "~2.2 GB · 4–6 tok/s · Strong reasoning"},
    {"name": "llama3.2:3b", "description": "~2.0 GB · 4–7 tok/s · Good general-purpose"},
    {"name": "qwen2.5:7b", "description": "~4.7 GB · Better quality, 8 GB+ RAM"},
    {"name": "llama3.1:8b", "description": "~4.7 GB · Strong general-purpose, Apple Silicon"},
    {"name": "qwen2.5:14b", "description": "~9 GB · High quality, 16 GB+ RAM"},
]


# ---------------------------------------------------------------------------
# Pipeline / scheduled tasks
# ---------------------------------------------------------------------------


def _run_weekly_digest() -> None:
    """Build the weekly digest and send it. Fires every Monday at 08:00."""
    global _config
    if _config is None:
        return
    try:
        with db.get_conn() as conn:
            if not st.is_feature_enabled(conn, "weekly_digest"):
                logger.info("Weekly digest disabled by feature toggle — skipping")
                return
            notifier.send_weekly_digest(_config, conn)
    except Exception as exc:
        logger.error("Weekly digest failed: %s", exc, exc_info=True)


def _run_news_cleanup() -> None:
    """Delete news older than the configured retention window. Fires daily at
    03:00. No-op when retention is disabled (0 days). Bookmarked items are kept.
    """
    try:
        with db.get_conn() as conn:
            days = st.get_news_retention_days(conn)
            if days <= 0:
                return
            deleted = db.delete_old_news(conn, days, preserve_bookmarked=True)
            if deleted:
                logger.info("News retention: deleted %d items older than %d days", deleted, days)
    except Exception as exc:
        logger.error("News cleanup failed: %s", exc, exc_info=True)


def _run_log_cleanup() -> None:
    """Delete log entries older than the configured retention window. Fires daily at 03:10."""
    try:
        with db.get_conn() as conn:
            days = st.get_log_retention_days(conn)
            if days <= 0:
                return
            deleted = db.delete_old_log_entries(conn, days)
            if deleted:
                logger.info("Log retention: deleted %d entries older than %d days", deleted, days)
    except Exception as exc:
        logger.error("Log cleanup failed: %s", exc, exc_info=True)


def _run_idle_categorize() -> None:
    """Categorize one batch of pending news items while the pipeline is idle.

    Fires on a configurable interval (idle_categorize_interval_minutes,
    default 15). Off unless both the "llm_categorizer" and
    "idle_categorization" feature toggles are enabled. Deliberately does not
    hold the pipeline file lock for the duration of the batch — only probes
    it to detect a running pipeline — because holding it would make the next
    scheduled pipeline run see "already running" and skip an entire run (up
    to run_interval_hours of lost coverage) just to avoid the small chance of
    one duplicated batch. A pipeline run starting mid-batch here can select
    the same rows; db.update_item_categorization is an id-keyed UPDATE, so
    the worst outcome is one batch of duplicated Ollama work, not corruption.
    """
    if _config is None or not _COLLECTOR_AVAILABLE:
        return

    with _pipeline_lock:
        if _pipeline_status["running"]:
            return

    try:
        _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        probe = FileLock(str(_LOCK_FILE), timeout=0)
        try:
            probe.acquire()
        except Timeout:
            return
        else:
            probe.release()

        idle_lock = FileLock(str(_IDLE_CATEGORIZE_LOCK_FILE), timeout=0)
        try:
            idle_lock.acquire()
        except Timeout:
            return

        try:
            with db.get_conn() as conn:
                if not st.is_feature_enabled(conn, "llm_categorizer"):
                    return
                if not st.is_feature_enabled(conn, "idle_categorization"):
                    return
                batch_size = st.get_categorize_batch_size(conn)
                stats = categorizer_module.run(conn, _config, max_items=batch_size)
            if stats.total_processed:
                logger.info(
                    "Idle categorization: %d categorized, %d uncategorized",
                    stats.categorized,
                    stats.uncategorized,
                )
        finally:
            idle_lock.release()
    except Exception as exc:
        logger.error("Idle categorization failed: %s", exc, exc_info=True)


class _PipelineCancelled(Exception):
    """Raised internally when the operator cancels a running pipeline. Caught
    in the _run_pipeline outer handler so the run logs a 'cancelled' status."""


def _enter_step(key: str) -> bool:
    """Mark `key` as the currently-running step, honour pause, and check cancel.

    Returns True if the runner should proceed with the step, False if the
    operator has requested cancellation. Blocks here (with a hard timeout) while
    a pause is in effect so the pipeline halts cleanly at the next boundary.
    """
    # Honour pause first: wait until the event is set or until the timeout.
    if not _pipeline_pause_event.is_set():
        with _pipeline_lock:
            _pipeline_status["paused"] = True
        _pipeline_pause_event.wait(timeout=_MAX_PAUSE_SECONDS)
        # If we timed out (event still not set), force-clear the pause so
        # subsequent steps don't each wait another full timeout cycle.
        if not _pipeline_pause_event.is_set():
            _pipeline_pause_event.set()
            with _pipeline_lock:
                _pipeline_control["pause_requested"] = False
        with _pipeline_lock:
            _pipeline_status["paused"] = False

    # Cancel takes priority over starting the next step.
    with _pipeline_lock:
        if _pipeline_control["cancel_requested"]:
            return False

    with _pipeline_lock:
        _pipeline_status["current_step"] = key
        _pipeline_status["step_times"].setdefault(key, {})["start"] = datetime.now(UTC).isoformat()
    return True


def _finish_step(key: str, status: str = "ok") -> None:
    """Record a step's completion in step_history. status: ok | error | skipped."""
    with _pipeline_lock:
        _pipeline_status["step_history"].append({"key": key, "status": status})
        _pipeline_status["current_step"] = None
        times = _pipeline_status["step_times"].setdefault(key, {})
        end = datetime.now(UTC)
        times["end"] = end.isoformat()
        start_iso = times.get("start")
        if start_iso:
            try:
                start = datetime.fromisoformat(start_iso)
                times["duration_s"] = round((end - start).total_seconds(), 1)
            except Exception:
                pass


def _set_step_progress(key: str, done: int, total: int) -> None:
    """Update per-step progress counters. Called from pipeline step callbacks."""
    with _pipeline_lock:
        _pipeline_status["step_progress"][key] = {"done": done, "total": total}


def _set_step_stats(key: str, **kwargs: object) -> None:
    """Record outcome stats for a completed step. Called after _finish_step."""
    with _pipeline_lock:
        _pipeline_status["step_stats"][key] = {k: v for k, v in kwargs.items() if v is not None}


_SNAPSHOT_FIELDS = (
    "last_started",
    "last_completed",
    "last_status",
    "last_error",
    "step_history",
    "step_progress",
    "step_stats",
    "step_times",
    "run_duration_s",
)


def _persist_pipeline_snapshot() -> None:
    """Save the last-completed-run fields of _pipeline_status to the settings
    table, so the drawer's per-step detail survives a process restart. Called
    at each of the three terminal points in _run_pipeline() (success, error,
    cancelled) — never while a run is in progress.
    """
    with _pipeline_lock:
        snapshot = {k: _pipeline_status[k] for k in _SNAPSHOT_FIELDS}
    try:
        with db.get_conn() as conn:
            db.save_pipeline_snapshot(conn, snapshot)
    except Exception:
        logger.warning("Failed to persist pipeline snapshot", exc_info=True)


def _reset_pipeline_control() -> None:
    """Clear cancel + pause flags and discard the previous run's per-step
    detail. Called at the START of a run only — the drawer needs the
    just-finished run's step_history/step_stats/etc. to stay in place after
    completion (until the user closes it or the next run starts), so this
    must NOT be called again once a run finishes. See
    _reset_pipeline_control_flags() for the finally-block equivalent.
    """
    _pipeline_pause_event.set()
    with _pipeline_lock:
        _pipeline_control["cancel_requested"] = False
        _pipeline_control["pause_requested"] = False
        _pipeline_status["current_step"] = None
        _pipeline_status["step_history"] = []
        _pipeline_status["paused"] = False
        _pipeline_status["step_progress"] = {}
        _pipeline_status["step_stats"] = {}
        _pipeline_status["step_times"] = {}
        _pipeline_status["run_duration_s"] = None


def _reset_pipeline_control_flags() -> None:
    """Clear cancel + pause flags only, without touching step detail. Called
    unconditionally in the _run_pipeline() `finally` block so a stale
    pause/cancel request never blocks the next run — unlike
    _reset_pipeline_control(), this preserves step_history/step_stats/etc.
    so the drawer can keep showing the just-finished run's detail.
    """
    _pipeline_pause_event.set()
    with _pipeline_lock:
        _pipeline_control["cancel_requested"] = False
        _pipeline_control["pause_requested"] = False
        _pipeline_status["paused"] = False


def _run_pipeline() -> None:
    """Full pipeline: collect → categorize → scan → lifecycle → notify.

    Guarded by a file lock so only one run can execute at a time.
    If a run is already in progress the new trigger is silently skipped.
    """
    global _config

    _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = FileLock(str(_LOCK_FILE), timeout=0)
    try:
        lock.acquire()
    except Timeout:
        logger.warning("Pipeline already running — skipping this trigger")
        # /api/run may have already flipped "running" to True (to close a
        # race between two near-simultaneous trigger requests) before this
        # thread got here and lost the file lock — undo that so the status
        # doesn't get stuck reporting a run that never actually started.
        with _pipeline_lock:
            _pipeline_status["running"] = False
        return

    run_id: int | None = None
    _pipeline_start_time = datetime.now(UTC)
    _reset_pipeline_control()
    try:
        with _pipeline_lock:
            _pipeline_status["running"] = True
            _pipeline_status["last_started"] = _pipeline_start_time.isoformat()
            _pipeline_status["last_error"] = None

        logger.info("Pipeline run starting")

        if _config:
            try:
                notifier.send_pipeline_start_alert(_config)
            except Exception as exc:
                logger.warning("Pipeline start alert failed: %s", exc)

        with db.get_conn() as conn:
            run_id = db.start_run(conn)

        items_collected = 0
        items_categorized = 0
        findings_new_total = 0

        # ------------------------------------------------------------------
        # Step 1 — Collect security news
        # ------------------------------------------------------------------
        if not _enter_step("collect"):
            raise _PipelineCancelled()
        if _COLLECTOR_AVAILABLE:
            try:
                with db.get_conn() as conn:
                    stats = collector_module.run(
                        conn,
                        _config,
                        on_progress=lambda d, t: _set_step_progress("collect", d, t),
                    )
                    items_collected = stats.items_fetched
                    logger.info(
                        "Collector: %d new items (%d failed sources)",
                        items_collected,
                        len(stats.failed_sources),
                    )
                _finish_step("collect")
                _set_step_stats(
                    "collect",
                    items_new=stats.items_new,
                    failed_sources=stats.failed_sources or None,
                )
            except Exception as exc:
                logger.error("Collector failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Collector error: {exc}")
                _finish_step("collect", "error")
        else:
            _finish_step("collect", "skipped")

        # ------------------------------------------------------------------
        # Step 2 — Categorize with Ollama
        # ------------------------------------------------------------------
        if not _enter_step("categorize"):
            raise _PipelineCancelled()
        with db.get_conn() as conn:
            _llm_categorizer_on = st.is_feature_enabled(conn, "llm_categorizer")
        if _COLLECTOR_AVAILABLE and _llm_categorizer_on:
            try:
                with db.get_conn() as conn:
                    cat_stats = categorizer_module.run(
                        conn,
                        _config,
                        on_progress=lambda d, t: _set_step_progress("categorize", d, t),
                    )
                    items_categorized = cat_stats.categorized
                    if cat_stats.uncategorized_rate > 0.2:
                        logger.warning("Categorizer: >20%% of items fell back to Uncategorized")
                    logger.info(
                        "Categorizer: %d categorized, %d uncategorized",
                        items_categorized,
                        cat_stats.uncategorized,
                    )
                _finish_step("categorize")
                _set_step_stats(
                    "categorize",
                    categorized=cat_stats.categorized,
                    uncategorized=cat_stats.uncategorized or None,
                )
            except Exception as exc:
                logger.error("Categorizer failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Categorizer error: {exc}")
                _finish_step("categorize", "error")
        else:
            _finish_step("categorize", "skipped")

        # ------------------------------------------------------------------
        # Step 3 — GitHub scanner
        # ------------------------------------------------------------------
        if not _enter_step("scan"):
            raise _PipelineCancelled()
        current_finding_keys: set[tuple] = set()
        scanned_repos: set[str] = set()
        with db.get_conn() as conn:
            _github_scanning_on = st.is_feature_enabled(conn, "github_scanning")
            _excluded_repos = st.get_excluded_repos(conn)
        if _github_scanning_on:
            try:
                with db.get_conn() as conn:
                    scan_stats = gs.run(
                        conn,
                        _config,
                        excluded_repos=_excluded_repos,
                        on_progress=lambda d, t: _set_step_progress("scan", d, t),
                    )
                    findings_new_total = scan_stats.findings_new
                    current_finding_keys = scan_stats.finding_keys
                    scanned_repos = scan_stats.scanned_repos

                    logger.info(
                        "Scanner: %d repos, %d packages, %d new findings",
                        scan_stats.repos_scanned,
                        scan_stats.packages_checked,
                        scan_stats.findings_new,
                    )
                    if scan_stats.failed_repos:
                        logger.warning("Scanner failed repos: %s", scan_stats.failed_repos)
                    if scan_stats.skipped_repos:
                        logger.warning("Scanner skipped repos: %s", scan_stats.skipped_repos)
                _finish_step("scan")
                _set_step_stats(
                    "scan",
                    repos_scanned=scan_stats.repos_scanned,
                    packages_checked=scan_stats.packages_checked,
                    findings_new=scan_stats.findings_new or None,
                    failed_repos=scan_stats.failed_repos or None,
                    skipped_repos=scan_stats.skipped_repos or None,
                    token_permission_warning=scan_stats.token_permission_warning,
                )
            except Exception as exc:
                logger.error("Scanner failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Scanner error: {exc}")
                _finish_step("scan", "error")
        else:
            logger.info("GitHub scanning disabled by feature toggle — skipping Step 3")
            _finish_step("scan", "skipped")

        # ------------------------------------------------------------------
        # Step 3.5 — GitHub issue auto-creation
        # ------------------------------------------------------------------
        if not _enter_step("issues"):
            raise _PipelineCancelled()
        with db.get_conn() as conn:
            _issue_creation_on = st.is_feature_enabled(conn, "github_issue_creation")
        if _issue_creation_on:
            try:
                with db.get_conn() as conn:
                    issue_stats = gic.run(conn, _config)
                    if issue_stats.issues_created:
                        logger.info(
                            "GitHub issues: %d created, %d skipped (duplicates), %d failed",
                            issue_stats.issues_created,
                            issue_stats.issues_skipped,
                            issue_stats.issues_failed,
                        )
                    if issue_stats.failed_repos:
                        logger.warning("Issue creation failed repos: %s", issue_stats.failed_repos)
                _finish_step("issues")
                _set_step_stats(
                    "issues",
                    created=issue_stats.issues_created or None,
                    skipped=issue_stats.issues_skipped or None,
                    failed_repos=issue_stats.failed_repos or None,
                )
            except Exception as exc:
                logger.error("GitHub issue creation failed: %s", exc, exc_info=True)
                _finish_step("issues", "error")
        else:
            logger.debug(
                "GitHub issue auto-creation disabled by feature toggle — skipping Step 3.5"
            )
            _finish_step("issues", "skipped")

        # ------------------------------------------------------------------
        # Step 4 — Secrets scanner (gitleaks)
        # ------------------------------------------------------------------
        if not _enter_step("secrets"):
            raise _PipelineCancelled()
        with db.get_conn() as conn:
            _secrets_scanning_on = st.is_feature_enabled(conn, "secrets_scanning")
        secrets_new_total = 0
        if _secrets_scanning_on:
            secrets_status = "ok"
            sec_stats = None
            try:
                with db.get_conn() as conn:
                    sec_stats = ss.run(
                        conn,
                        _config,
                        excluded_repos=_excluded_repos,
                        on_progress=lambda d, t: _set_step_progress("secrets", d, t),
                    )
                    secrets_new_total = sec_stats.secrets_new
                    if sec_stats.failed_repos:
                        logger.warning("Secrets scanner failed repos: %s", sec_stats.failed_repos)
            except Exception as exc:
                logger.error("Secrets scanner failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Secrets scanner error: {exc}")
                secrets_status = "error"

            try:
                with db.get_conn() as conn:
                    unnotified_secrets = db.get_unnotified_secret_findings(conn)
                    if unnotified_secrets:
                        notifier.send_secrets_alert(_config, list(unnotified_secrets))
                        db.mark_secret_findings_notified(
                            conn, [r["id"] for r in unnotified_secrets]
                        )
                        logger.info("Notifier: %d secrets alerted", len(unnotified_secrets))
            except Exception as exc:
                logger.error("Secrets notifier failed: %s", exc, exc_info=True)
            _finish_step("secrets", secrets_status)
            if sec_stats is not None:
                _set_step_stats(
                    "secrets",
                    repos_scanned=sec_stats.repos_scanned,
                    secrets_new=sec_stats.secrets_new or None,
                    failed_repos=sec_stats.failed_repos or None,
                    token_permission_warning=sec_stats.token_permission_warning,
                )
        else:
            logger.info("Secrets scanning disabled by feature toggle — skipping Step 4")
            _finish_step("secrets", "skipped")

        # ------------------------------------------------------------------
        # Step 5 — Lifecycle reconciliation
        # ------------------------------------------------------------------
        if not _enter_step("lifecycle"):
            raise _PipelineCancelled()
        try:
            with db.get_conn() as conn:
                reverted = lifecycle.recheck_resolved(conn, current_finding_keys)
                resolved = lifecycle.auto_resolve_gone(conn, current_finding_keys, scanned_repos)
                if reverted:
                    logger.info("Lifecycle: %d resolved→new (regression)", reverted)
                if resolved:
                    logger.info("Lifecycle: %d auto-resolved (no longer present)", resolved)
            _finish_step("lifecycle")
            _set_step_stats(
                "lifecycle",
                auto_resolved=resolved or None,
                regressions=reverted or None,
            )
        except Exception as exc:
            logger.error("Lifecycle reconciliation failed: %s", exc, exc_info=True)
            _finish_step("lifecycle", "error")

        # ------------------------------------------------------------------
        # Step 6 — Notify findings (delta only, filtered by severity threshold)
        # ------------------------------------------------------------------
        if not _enter_step("notify"):
            raise _PipelineCancelled()
        try:
            with db.get_conn() as conn:
                threshold = st.get_severity_threshold(conn)
                unnotified = db.get_unnotified_findings(conn)
                if unnotified:
                    # Mark ALL new findings as notified regardless of threshold so
                    # they never accumulate in the unnotified queue.
                    db.mark_findings_notified(conn, [r["id"] for r in unnotified])
                    to_alert = _apply_severity_threshold(list(unnotified), threshold)
                    if to_alert:
                        notifier.send_findings_alert(_config, to_alert)
                    logger.info(
                        "Notifier: %d findings alerted (threshold: %s, %d suppressed below threshold)",
                        len(to_alert),
                        threshold,
                        len(unnotified) - len(to_alert),
                    )
            _finish_step("notify")
            _set_step_stats(
                "notify",
                alerted=len(to_alert) if unnotified else None,
                suppressed=(len(unnotified) - len(to_alert)) or None if unnotified else None,
            )
        except Exception as exc:
            logger.error("Notifier failed: %s", exc, exc_info=True)
            _finish_step("notify", "error")

        # ------------------------------------------------------------------
        # Finish run log
        # ------------------------------------------------------------------
        with db.get_conn() as conn:
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            db.finish_run(
                conn,
                run_id,
                status="success",
                items_collected=items_collected,
                items_categorized=items_categorized,
                findings_new=findings_new_total,
                findings_total=total_findings,
            )

        duration = round((datetime.now(UTC) - _pipeline_start_time).total_seconds(), 1)
        with _pipeline_lock:
            _pipeline_status["running"] = False
            _pipeline_status["last_completed"] = datetime.now(UTC).isoformat()
            _pipeline_status["last_status"] = "success"
            _pipeline_status["run_duration_s"] = duration
        _persist_pipeline_snapshot()
        if _config:
            try:
                with db.get_conn() as conn:
                    _notify_run = st.is_feature_enabled(conn, "notify_pipeline_run")
                if _notify_run:
                    notifier.send_pipeline_summary_alert(
                        _config,
                        items_collected=items_collected,
                        items_categorized=items_categorized,
                        findings_new=findings_new_total,
                        secrets_new=secrets_new_total,
                        duration_secs=duration,
                    )
            except Exception as exc:
                logger.warning("Pipeline summary alert failed: %s", exc)

        logger.info("Pipeline run completed successfully")

    except _PipelineCancelled:
        logger.info("Pipeline run cancelled by operator")
        with _pipeline_lock:
            _pipeline_status["running"] = False
            _pipeline_status["last_completed"] = datetime.now(UTC).isoformat()
            _pipeline_status["last_status"] = "cancelled"
            _pipeline_status["current_step"] = None
        _persist_pipeline_snapshot()
        try:
            if run_id is not None:
                with db.get_conn() as conn:
                    db.finish_run(
                        conn, run_id, status="cancelled", error_message="Cancelled by operator"
                    )
        except Exception:
            pass
    except Exception as exc:
        logger.error("Pipeline run failed: %s", exc, exc_info=True)
        with _pipeline_lock:
            _pipeline_status["running"] = False
            _pipeline_status["last_completed"] = datetime.now(UTC).isoformat()
            _pipeline_status["last_status"] = "error"
            _pipeline_status["last_error"] = str(exc)
            _pipeline_status["current_step"] = None
        _persist_pipeline_snapshot()
        try:
            if run_id is not None:
                with db.get_conn() as conn:
                    db.finish_run(conn, run_id, status="error", error_message=str(exc))
        except Exception:
            pass
        if _config:
            notifier.send_failure_alert(_config, str(exc))
    finally:
        _reset_pipeline_control_flags()
        lock.release()


# ---------------------------------------------------------------------------
# Scheduler helpers
# ---------------------------------------------------------------------------


def _interval_hours(config: cfg_module.AppConfig) -> float:
    """Read the run interval from the settings table; fall back to config default."""
    try:
        with db.get_conn() as conn:
            stored = db.get_setting(conn, "run_interval_hours")
            if stored:
                return float(stored)
    except Exception:
        pass
    return float(getattr(config, "run_interval_hours", 6))


def _reschedule(new_hours: float) -> None:
    """Replace the scheduler job with a new interval."""
    global _scheduler
    if _scheduler is None:
        return
    _scheduler.reschedule_job("pipeline", trigger=IntervalTrigger(hours=new_hours))
    logger.info("Pipeline rescheduled: every %.1f hours", new_hours)


def _reschedule_idle_categorize(new_minutes: int) -> None:
    """Replace the idle categorization job with a new interval."""
    global _scheduler
    if _scheduler is None:
        return
    _scheduler.reschedule_job("idle_categorize", trigger=IntervalTrigger(minutes=new_minutes))
    logger.info("Idle categorization rescheduled: every %d minutes", new_minutes)


# ---------------------------------------------------------------------------
# FastAPI lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    global _config, _scheduler, _session_serializer

    logger.info("DIVE starting up")

    _config = cfg_module.load()
    logger.info(
        "Configuration loaded (Ollama: %s, model: %s)",
        _config.ollama.host,
        _config.ollama.model,
    )

    db.init()
    _setup_sqlite_logging()
    logger.info("Database ready")

    with db.get_conn() as conn:
        st.sync_default_feed_urls(conn)
        # Generate run token if not already stored (CSRF protection for Run Now)
        if not db.get_setting(conn, "run_token"):
            db.set_setting(conn, "run_token", secrets.token_hex(32))
            logger.debug("Run token generated")
        # Generate session secret if not already stored
        session_secret = db.get_setting(conn, "session_secret")
        if not session_secret:
            session_secret = secrets.token_hex(32)
            db.set_setting(conn, "session_secret", session_secret)
            logger.debug("Session secret generated")

        # Close out any run left 'running' by a process that died mid-run, then
        # hydrate in-memory pipeline status from persisted history so the "Last
        # run" badge — and the pipeline drawer's full per-step detail — survive
        # a restart instead of resetting to "Never" / empty.
        db.reconcile_interrupted_runs(conn)
        snapshot = db.get_pipeline_snapshot(conn)
        recent_runs = None if snapshot else db.get_run_history(conn, limit=1)
        idle_categorize_minutes = st.get_idle_categorize_interval_minutes(conn)

    _session_serializer = URLSafeTimedSerializer(session_secret)

    if snapshot:
        with _pipeline_lock:
            for key in _SNAPSHOT_FIELDS:
                if key in snapshot:
                    _pipeline_status[key] = snapshot[key]
        logger.info("Restored last pipeline run snapshot: %s", snapshot.get("last_status"))
    elif recent_runs:
        # Fallback for installs upgrading from before snapshots existed — only
        # the coarse run_log columns are available, no per-step detail.
        last = recent_runs[0]
        with _pipeline_lock:
            _pipeline_status["last_started"] = last["started_at"]
            _pipeline_status["last_completed"] = last["completed_at"]
            _pipeline_status["last_status"] = last["status"]
            _pipeline_status["last_error"] = last["error_message"]
            if last["completed_at"]:
                try:
                    start = datetime.fromisoformat(last["started_at"])
                    end = datetime.fromisoformat(last["completed_at"])
                    _pipeline_status["run_duration_s"] = round((end - start).total_seconds(), 1)
                except Exception:
                    pass
        logger.info("Restored last pipeline run status from history: %s", last["status"])

    interval = _interval_hours(_config)
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _run_pipeline,
        trigger=IntervalTrigger(hours=interval),
        id="pipeline",
        name="Security pipeline",
        max_instances=1,
        replace_existing=True,
    )
    _scheduler.add_job(
        _run_weekly_digest,
        trigger=CronTrigger(day_of_week="mon", hour=8, minute=0),
        id="weekly_digest",
        name="Weekly security digest",
        max_instances=1,
        replace_existing=True,
    )
    _scheduler.add_job(
        _run_news_cleanup,
        trigger=CronTrigger(hour=3, minute=0),
        id="news_cleanup",
        name="News retention cleanup",
        max_instances=1,
        replace_existing=True,
    )
    _scheduler.add_job(
        _run_log_cleanup,
        trigger=CronTrigger(hour=3, minute=10),
        id="log_cleanup",
        name="Log retention cleanup",
        max_instances=1,
        replace_existing=True,
    )
    _scheduler.add_job(
        _run_idle_categorize,
        trigger=IntervalTrigger(minutes=idle_categorize_minutes),
        id="idle_categorize",
        name="Idle news categorization",
        max_instances=1,
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Scheduler started — pipeline runs every %.1f hours", interval)

    yield

    logger.info("DIVE shutting down")
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DIVE — Dependency Intelligence for Vulnerability Exposure",
    description="Self-hosted security news aggregator and GitHub dependency scanner",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.exception_handler(_LoginRedirect)
async def _login_redirect_handler(request: Request, exc: _LoginRedirect) -> RedirectResponse:
    return RedirectResponse(url=exc.location, status_code=302)


def _replace_query_param(url: Any, key: str, value: Any) -> str:
    """Jinja2 filter: replace or add a single query param while preserving others."""
    from urllib.parse import parse_qs, urlencode, urlparse

    parsed = urlparse(str(url))
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [str(value)]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    from urllib.parse import urlunparse

    return urlunparse(parsed._replace(query=new_query))


def _with_params(url: Any, **changes: Any) -> str:
    """Jinja2 filter: return `url` with `changes` applied to its query string,
    preserving every param not named.

    A None or "" value DELETES the param — that is how "All repos" / "no
    severity filter" / "clear this chip" is expressed. `page` is ALWAYS
    dropped, because any filter change invalidates the current page offset
    (the same rule table-tools.js's _navigate() applies).

    Returns a path+query rather than an absolute URL so the result stays
    origin-agnostic behind a reverse proxy, and so the pjax router in
    base.html treats it as same-origin and intercepts it.

    This is what fixes filter params being silently dropped: a state-tab
    href built through here keeps severity/sort/direction/per_page instead
    of discarding them.

    Distinct from _replace_query_param above, which sets exactly one key,
    cannot delete, and keeps `page` — that one still backs pagination links.
    """
    from urllib.parse import parse_qsl, urlencode, urlparse

    parsed = urlparse(str(url))
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in changes.items():
        if value is None or value == "":
            params.pop(key, None)
        else:
            params[key] = str(value)
    params.pop("page", None)
    query = urlencode(params)
    return parsed.path + (f"?{query}" if query else "")


templates.env.filters["replace_query_param"] = _replace_query_param
templates.env.filters["with_params"] = _with_params
templates.env.globals["nav_badges"] = lambda: _nav_badges()


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def _get_session(request: Request) -> dict:
    """Decode the signed session cookie; returns {} if absent or invalid."""
    if _session_serializer is None:
        return {}
    token = request.cookies.get(_SESSION_COOKIE)
    if not token:
        return {}
    try:
        return _session_serializer.loads(token, max_age=_SESSION_MAX_AGE)  # type: ignore[arg-type]
    except Exception:
        return {}


def _make_session_token(data: dict) -> str:
    assert _session_serializer is not None
    return _session_serializer.dumps(data)  # type: ignore[return-value]


def _safe_next(value: str) -> str:
    """Sanitize a `next` redirect target to same-origin paths only.

    A naive `value.startswith("/")` check (as previously used in the login
    POST handler, and not used at all in the GET handler) still lets
    protocol-relative URLs through: "//evil.tld" and "/\\evil.tld" (which
    browsers normalize to "//evil.tld") both start with "/" but navigate
    off-site.
    """
    if not value.startswith("/"):
        return "/"
    if len(value) > 1 and value[1] in ("/", "\\"):
        return "/"
    return value


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


def _require_auth(request: Request) -> str:
    """Check session cookie; redirect to /login for page routes, 401 for API routes."""
    session = _get_session(request)
    if not session.get("authenticated"):
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="Not authenticated")
        from urllib.parse import quote

        raise _LoginRedirect(f"/login?next={quote(request.url.path, safe='/')}")
    return session.get("username", "")


def _require_csrf(request: Request) -> None:
    """Validate X-Run-Token header on mutation endpoints (CSRF protection)."""
    token = request.headers.get("X-Run-Token", "")
    stored = _get_run_token()
    if not stored or not secrets.compare_digest(token, stored):
        raise HTTPException(status_code=403, detail="Invalid or missing X-Run-Token")


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------


_SEVERITY_THRESHOLD_SCORES: dict[str, float | None] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.0,
    "all": None,  # no minimum score — include all findings
}


def _apply_severity_threshold(findings: list, threshold: str) -> list:
    """Return only the findings at or above the configured severity threshold.

    Findings with no CVSS score are excluded for every threshold except "all",
    since their severity cannot be determined.
    """
    min_score = _SEVERITY_THRESHOLD_SCORES.get(threshold, 7.0)
    if min_score is None:
        return findings
    return [r for r in findings if r["cvss_score"] is not None and r["cvss_score"] >= min_score]


def _cvss_severity(score: float | None) -> tuple[str, str]:
    """Return (label, css_class) for a CVSS score."""
    if score is None:
        return "Unknown", "unknown"
    if score >= 9.0:
        return "Critical", "critical"
    if score >= 7.0:
        return "High", "high"
    if score >= 4.0:
        return "Medium", "medium"
    return "Low", "low"


def _time_ago(iso_str: str | None) -> str:
    """Return a human-readable relative time string."""
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str)
        diff = (datetime.now(UTC) - dt).total_seconds()
        if diff < 60:
            return "just now"
        if diff < 3600:
            return f"{int(diff / 60)}m ago"
        if diff < 86400:
            return f"{int(diff / 3600)}h ago"
        return f"{int(diff / 86400)}d ago"
    except Exception:
        return iso_str[:10]


def _enrich_finding(row) -> dict:
    d = dict(row)
    label, cls = _cvss_severity(d.get("cvss_score"))
    d["severity_label"] = label
    d["severity_class"] = cls
    return d


def _enrich_news(row) -> dict:
    d = dict(row)
    d["time_ago"] = _time_ago(d.get("fetched_at") or d.get("published_at"))
    d["published_human"] = _format_published(d.get("published_at"))
    return d


def _format_published(iso_str: str | None) -> str:
    """Render the source-supplied publish timestamp as a short absolute label.

    Returns "" if no timestamp is present so the template can decide whether to
    render the line. The format intentionally drops seconds and includes the
    year only when it differs from the current year to keep the row compact.
    """
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    now = datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if dt.year == now.year:
        return dt.strftime("%d %b · %H:%M UTC")
    return dt.strftime("%d %b %Y · %H:%M UTC")


_MODEL_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-./]*(?::[a-zA-Z0-9_\-.]+)?$")

_SUGGESTED_MODEL_NAMES = {m["name"] for m in _SUGGESTED_MODELS}


def _validate_ollama_model(model: str) -> None:
    """Raise HTTPException(400) if model is not a valid/known Ollama model name.

    Validates format, then checks against installed + suggested models when
    Ollama is reachable. Falls through silently if Ollama is unreachable so
    users can pre-configure a model they plan to pull.
    """
    if not _MODEL_NAME_RE.match(model):
        raise HTTPException(status_code=400, detail=f"Invalid model name: {model!r}")

    if _config is None:
        return

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{_config.ollama.host}/api/tags")
            resp.raise_for_status()
            installed = {m["name"] for m in resp.json().get("models", [])}
    except Exception:
        logger.warning("Could not reach Ollama to validate model name — saving anyway")
        return

    allowed = installed | _SUGGESTED_MODEL_NAMES
    if model not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Model {model!r} is not installed or recognised. Pull it first with `ollama pull {model}`.",
        )


def _fetch_installed_ollama_models(ollama_host: str) -> list[str]:
    """Blocking HTTP call — always run via asyncio.to_thread from a route."""
    try:
        with httpx.Client(timeout=8) as client:
            resp = client.get(f"{ollama_host}/api/tags")
            resp.raise_for_status()
            data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception as exc:
        logger.warning("Could not reach Ollama for model list: %s", exc)
        return []


def _check_ollama_status() -> bool:
    """Return True if Ollama is reachable and the configured model is loaded."""
    if _config is None:
        return False
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{_config.ollama.host}/api/tags")
            if not resp.is_success:
                return False
            tags = resp.json()
            model_base = _config.ollama.model.split(":")[0]
            return any(m.get("name", "").startswith(model_base) for m in tags.get("models", []))
    except Exception:
        return False


def _get_run_token(conn: sqlite3.Connection | None = None) -> str:
    """Reads the run_token setting. Pass an open `conn` (e.g. a route's own
    request-scoped connection) to avoid opening a second one; otherwise
    opens its own — every call site keeps working either way."""
    try:
        if conn is not None:
            return db.get_setting(conn, "run_token", "")
        with db.get_conn() as c:
            return db.get_setting(c, "run_token", "")
    except Exception:
        return ""


def _get_current_model(conn: sqlite3.Connection | None = None) -> str:
    try:
        if conn is not None:
            stored = db.get_setting(conn, "active_model")
        else:
            with db.get_conn() as c:
                stored = db.get_setting(c, "active_model")
        if stored:
            return stored
    except Exception:
        pass
    return _config.ollama.model if _config else "—"


def _paginate(page: int, per_page: int, total: int) -> dict:
    """Compute pagination metadata for a template."""
    per_page = per_page if per_page in _PAGE_SIZE_OPTIONS else _DEFAULT_PAGE_SIZE
    page = max(1, page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "offset": (page - 1) * per_page,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "page_size_options": _PAGE_SIZE_OPTIONS,
    }


def _state_window(conn: sqlite3.Connection, state: str | None) -> str | None:
    """The `first_seen_at >= ?` bound implied by a pseudo-state, or None.

    Only 'new' is time-bounded — it means "first seen in the latest
    successful run". Every other state, 'unresolved' included, is unbounded,
    which is what makes Unresolved a strict *superset* of New: a finding
    first seen in the latest run shows up under both. (It used to carry an
    upper bound of the same timestamp, which made the two tabs disjoint and
    hid brand-new findings from the Unresolved view entirely.)

    The 9999 sentinel means "no successful run has ever completed", which
    must show nothing rather than everything.

    This is the single source of truth for what the New tab means. The page
    routes and the export routes all call it, so the on-screen row set and
    the exported row set cannot drift apart.
    """
    if state != "new":
        return None
    last_run = db.get_last_successful_run(conn)
    return last_run["started_at"] if last_run else "9999-01-01"


def _secrets_summary(conn: sqlite3.Connection | None = None) -> dict:
    """Return per-state counts from secret_findings."""
    try:
        if conn is not None:
            return db.get_secret_findings_summary(conn)
        with db.get_conn() as c:
            return db.get_secret_findings_summary(c)
    except Exception:
        return {"new": 0, "false_positive": 0, "resolved": 0}


def _nav_badges_query(conn: sqlite3.Connection) -> dict:
    findings_open = conn.execute(
        "SELECT COUNT(*) AS c FROM findings WHERE state IN ('new','acknowledged')"
    ).fetchone()["c"]
    secrets_open = conn.execute(
        "SELECT COUNT(*) AS c FROM secret_findings WHERE state = 'new'"
    ).fetchone()["c"]
    news_recent = conn.execute(
        "SELECT COUNT(*) AS c FROM news_items WHERE fetched_at >= datetime('now', '-1 day')"
    ).fetchone()["c"]
    return {
        "findings": int(findings_open or 0),
        "secrets": int(secrets_open or 0),
        "news": int(news_recent or 0),
    }


def _nav_badges(conn: sqlite3.Connection | None = None) -> dict:
    """Counts shown next to sidebar nav items. Also registered as a Jinja
    global (called with no args on every template render), so it must keep
    working standalone in addition to accepting a route's own connection."""
    try:
        if conn is not None:
            return _nav_badges_query(conn)
        with db.get_conn() as c:
            return _nav_badges_query(c)
    except Exception:
        return {"findings": 0, "secrets": 0, "news": 0}


def _dashboard_extras(conn: sqlite3.Connection | None = None) -> dict:
    """Top affected repos, top CVEs, and activity heatmap for the dashboard.

    Pass an open `conn` to reuse the caller's connection instead of opening
    a new one — the dashboard route already has one open for its other
    queries.
    """
    out: dict = {"top_repos": [], "top_cves": [], "heatmap_weeks": [], "heatmap_max": 0}
    try:
        if conn is not None:
            _dashboard_extras_query(conn, out)
        else:
            with db.get_conn() as c:
                _dashboard_extras_query(c, out)
        return out
    except Exception:
        return out


def _dashboard_extras_query(conn: sqlite3.Connection, out: dict) -> None:
    # Top affected repos by open finding count, with severity breakdown
    rows = conn.execute("""
        SELECT
            repo_full_name AS repo,
            COUNT(*) AS total,
            SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END) AS crit,
            SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END) AS med,
            SUM(CASE WHEN cvss_score IS NOT NULL AND cvss_score < 4.0 THEN 1 ELSE 0 END) AS low
        FROM findings
        WHERE state IN ('new','acknowledged')
        GROUP BY repo_full_name
        ORDER BY total DESC
        LIMIT 6
    """).fetchall()
    out["top_repos"] = [
        {
            "repo": r["repo"],
            "total": int(r["total"] or 0),
            "crit": int(r["crit"] or 0),
            "high": int(r["high"] or 0),
            "med": int(r["med"] or 0),
            "low": int(r["low"] or 0),
        }
        for r in rows
    ]

    # Top CVEs by priority score (or CVSS), open only
    cve_rows = conn.execute("""
        SELECT id, repo_full_name, package_name, cve_id, ghsa_id,
               cvss_score, priority_score, is_kev, patch_available,
               fixed_version, installed_version
        FROM findings
        WHERE state IN ('new','acknowledged')
        ORDER BY COALESCE(priority_score, 0) DESC,
                 COALESCE(cvss_score, 0) DESC
        LIMIT 6
    """).fetchall()
    out["top_cves"] = [_enrich_finding(r) for r in cve_rows]

    # 3-month GitHub-style activity heatmap — news items per day
    hm_rows = conn.execute("""
        SELECT DATE(fetched_at) AS d, COUNT(*) AS c
        FROM news_items
        WHERE fetched_at >= datetime('now', '-95 days')
        GROUP BY DATE(fetched_at)
    """).fetchall()
    counts = {r["d"]: int(r["c"] or 0) for r in hm_rows}

    today = date.today()
    max_count = max(counts.values(), default=1) or 1

    # Align start to the Sunday on or before (today - 90 days)
    # isoweekday(): Mon=1 … Sun=7 → Sunday offset = isoweekday() % 7
    start_raw = today - timedelta(days=90)
    start = start_raw - timedelta(days=start_raw.isoweekday() % 7)

    weeks = []
    current = start
    prev_month: str | None = None
    while current <= today:
        days = []
        for i in range(7):
            d = current + timedelta(days=i)
            if d > today:
                days.append(None)
            else:
                c = counts.get(d.isoformat(), 0)
                ratio = c / max_count
                lvl = (
                    0
                    if c == 0
                    else (1 if ratio < 0.25 else (2 if ratio < 0.5 else (3 if ratio < 0.75 else 4)))
                )
                days.append(
                    {
                        "d": d.isoformat(),
                        "c": c,
                        "level": lvl,
                        "label": _cal.month_abbr[d.month] + " " + str(d.day),
                    }
                )
        month_label = None
        first = next((x for x in days if x is not None), None)
        if first:
            m = first["d"][:7]
            if m != prev_month:
                month_label = _cal.month_abbr[int(m[5:7])]
                prev_month = m
        weeks.append({"days": days, "month_label": month_label})
        current += timedelta(days=7)

    out["heatmap_weeks"] = weeks
    out["heatmap_max"] = max_count


def _findings_summary_query(conn: sqlite3.Connection) -> sqlite3.Row:
    return conn.execute("""
        SELECT
            SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END)                     AS critical,
            SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN cvss_score IS NOT NULL AND cvss_score < 4.0 THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN state = 'new'          THEN 1 ELSE 0 END)                 AS new,
            SUM(CASE WHEN state = 'acknowledged'  THEN 1 ELSE 0 END)                AS acknowledged,
            SUM(CASE WHEN state = 'resolved'      THEN 1 ELSE 0 END)                AS resolved,
            SUM(CASE WHEN is_kev = 1 AND state != 'resolved' THEN 1 ELSE 0 END)     AS kev,
            SUM(CASE WHEN patch_available = 1 AND state != 'resolved' THEN 1 ELSE 0 END) AS patchable
        FROM findings
    """).fetchone()


def _findings_summary(conn: sqlite3.Connection | None = None) -> dict:
    """Return per-severity and per-state counts from the database."""
    try:
        if conn is not None:
            row = _findings_summary_query(conn)
        else:
            with db.get_conn() as c:
                row = _findings_summary_query(c)
        return {
            "critical": int(row["critical"] or 0),
            "high": int(row["high"] or 0),
            "medium": int(row["medium"] or 0),
            "low": int(row["low"] or 0),
            "new": int(row["new"] or 0),
            "acknowledged": int(row["acknowledged"] or 0),
            "resolved": int(row["resolved"] or 0),
            "kev": int(row["kev"] or 0),
            "patchable": int(row["patchable"] or 0),
        }
    except Exception:
        return {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "new": 0,
            "acknowledged": 0,
            "resolved": 0,
            "kev": 0,
            "patchable": 0,
        }


# ---------------------------------------------------------------------------
# Login / logout routes (unauthenticated)
# ---------------------------------------------------------------------------

# Simple in-process brute-force deterrent on the login form. There is a
# single shared dashboard password, so this exists to slow down credential
# guessing — not to serve as a robust distributed rate limiter. State is
# in-memory only and resets on restart; that's an accepted trade-off for a
# single-process, self-hosted app rather than adding a dependency.
_LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10
_LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = threading.Lock()


def _login_rate_limit_retry_after(client_ip: str) -> int | None:
    """Return seconds to wait before this client may try again, or None if
    it's under the limit. Only failed attempts count (see _record_failed_login)
    so a user who mistypes once and then logs in successfully isn't penalized.
    """
    now = time.monotonic()
    cutoff = now - _LOGIN_RATE_LIMIT_WINDOW_SECONDS
    with _login_attempts_lock:
        attempts = [t for t in _login_attempts.get(client_ip, []) if t > cutoff]
        _login_attempts[client_ip] = attempts
        if len(attempts) < _LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
            return None
        return int(attempts[0] + _LOGIN_RATE_LIMIT_WINDOW_SECONDS - now) + 1


def _record_failed_login(client_ip: str) -> None:
    with _login_attempts_lock:
        _login_attempts.setdefault(client_ip, []).append(time.monotonic())


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, next: str = "/") -> HTMLResponse:
    if _get_session(request).get("authenticated"):
        return RedirectResponse(url=_safe_next(next), status_code=302)  # type: ignore[return-value]
    return templates.TemplateResponse(request, "login.html", {"next_url": next, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form(default="/"),
) -> HTMLResponse:
    client_ip = request.client.host if request.client else "unknown"
    retry_after = _login_rate_limit_retry_after(client_ip)
    if retry_after is not None:
        # Render the styled login template rather than raising HTTPException:
        # a raw FastAPI JSON error page is the worst possible thing to show
        # right when the user is already locked out and confused. Retry-After
        # is kept as the one machine-readable part of the response.
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next_url": next_url,
                "error": f"Too many attempts. Try again in {retry_after}s.",
            },
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    cfg = _config
    valid = (
        cfg is not None
        and secrets.compare_digest(username.encode(), cfg.dashboard.username.encode())
        and secrets.compare_digest(password.encode(), cfg.dashboard.password.encode())
    )
    if not valid:
        _record_failed_login(client_ip)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"next_url": next_url, "error": "Invalid username or password"},
            status_code=401,
        )
    token = _make_session_token({"authenticated": True, "username": username})
    resp = RedirectResponse(url=_safe_next(next_url), status_code=303)
    resp.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=_SESSION_MAX_AGE,
        # Only require HTTPS for the cookie when the request itself arrived
        # over HTTPS — plain HTTP must keep working for localhost/Tailscale
        # access, which is the documented deployment model for this app.
        secure=request.url.scheme == "https",
    )
    return resp  # type: ignore[return-value]


@app.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


# ---------------------------------------------------------------------------
# Dashboard HTML routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Main dashboard — recent news + open findings summary."""
    d = await asyncio.to_thread(_dashboard_data)

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "nav_active": "dashboard",
            "run_token": d["run_token"],
            "current_model": d["current_model"],
            "recent_findings": [_enrich_finding(r) for r in d["findings_rows"]],
            "news_items": [_enrich_news(r) for r in d["news_rows"]],
            "summary": d["summary"],
            "secrets_summary": d["secrets_summary"],
            "bookmarked_ids": list(d["bookmarked_ids"]),
            "top_repos": d["extras"]["top_repos"],
            "top_cves": d["extras"]["top_cves"],
            "heatmap_weeks": d["extras"]["heatmap_weeks"],
            "heatmap_max": d["extras"]["heatmap_max"],
        },
    )


def _dashboard_data() -> dict:
    """All of the dashboard route's DB work, run via asyncio.to_thread so a
    slow query (e.g. WAL lock contention while the pipeline is running)
    doesn't block the event loop for every other concurrent request."""
    with db.get_conn() as conn:
        return {
            "findings_rows": db.get_findings(conn, state="new", limit=10),
            "news_rows": db.get_recent_items(conn, hours=24, limit=15),
            "bookmarked_ids": db.get_bookmarked_ids(conn),
            "extras": _dashboard_extras(conn),
            "run_token": _get_run_token(conn),
            "current_model": _get_current_model(conn),
            "summary": _findings_summary(conn),
            "secrets_summary": _secrets_summary(conn),
        }


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
    severity: str | None = None,
    sort: str | None = None,
    direction: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """Findings table with filter controls and pagination."""
    if state is None:
        state = "unresolved"

    d = await asyncio.to_thread(
        _findings_page_data, state, repo, severity, sort, direction, page, per_page
    )

    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "nav_active": "findings",
            "run_token": d["run_token"],
            "current_model": d["current_model"],
            "findings": [_enrich_finding(r) for r in d["rows"]],
            "state_filter": state,
            "repo_filter": repo,
            "severity_filter": severity,
            "sort": sort,
            "direction": direction,
            "repos": d["repos"],
            "pagination": d["pagination"],
        },
    )


def _findings_page_data(
    state: str,
    repo: str | None,
    severity: str | None,
    sort: str | None,
    direction: str | None,
    page: int,
    per_page: int,
) -> dict:
    """All of the /findings route's DB work, run via asyncio.to_thread."""
    with db.get_conn() as conn:
        since = _state_window(conn, state)

        total = db.get_findings_count(conn, state=state, repo=repo, since=since, severity=severity)
        pg = _paginate(page, per_page, total)
        rows = db.get_findings(
            conn,
            state=state,
            repo=repo,
            since=since,
            severity=severity,
            sort=sort,
            direction=direction,
            limit=pg["per_page"],
            offset=pg["offset"],
        )
        return {
            "rows": rows,
            "repos": db.get_finding_repos(conn, state=state, since=since),
            "pagination": pg,
            "run_token": _get_run_token(conn),
            "current_model": _get_current_model(conn),
        }


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Settings page — run interval + model selection."""
    with db.get_conn() as conn:
        current_interval = db.get_setting(conn, "run_interval_hours", "6")

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "nav_active": "settings",
            "run_token": _get_run_token(),
            "current_model": _get_current_model(),
            "current_interval": current_interval,
            "interval_options": _INTERVAL_OPTIONS,
            "interval_values": [v for v, _ in _INTERVAL_OPTIONS],
        },
    )


@app.get("/secrets", response_class=HTMLResponse)
async def secrets_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
    sort: str | None = None,
    direction: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """Secrets view — leaked credentials detected by gitleaks."""
    if state is None:
        state = "unresolved"

    d = await asyncio.to_thread(_secrets_page_data, state, repo, sort, direction, page, per_page)

    return templates.TemplateResponse(
        request,
        "secrets.html",
        {
            "nav_active": "secrets",
            "run_token": d["run_token"],
            "current_model": d["current_model"],
            "secrets": [dict(r) for r in d["rows"]],
            "state_filter": state,
            "repo_filter": repo,
            "sort": sort,
            "direction": direction,
            "repos": d["repos"],
            "pagination": d["pagination"],
        },
    )


def _secrets_page_data(
    state: str,
    repo: str | None,
    sort: str | None,
    direction: str | None,
    page: int,
    per_page: int,
) -> dict:
    """All of the /secrets route's DB work, run via asyncio.to_thread.

    Mirrors _findings_page_data. This used to run inline on the event loop,
    which stalled every concurrent request — including the 5s status poll —
    for the duration of the query on a Pi-class host with a large
    secret_findings table.
    """
    with db.get_conn() as conn:
        since = _state_window(conn, state)

        total = db.get_secret_findings_count(conn, state=state, repo=repo, since=since)
        pg = _paginate(page, per_page, total)
        rows = db.get_secret_findings(
            conn,
            state=state,
            repo=repo,
            since=since,
            sort=sort,
            direction=direction,
            limit=pg["per_page"],
            offset=pg["offset"],
        )
        return {
            "rows": rows,
            "repos": db.get_secret_repos(conn, state=state, since=since),
            "pagination": pg,
            "run_token": _get_run_token(conn),
            "current_model": _get_current_model(conn),
        }


@app.get("/personal", response_class=HTMLResponse)
async def personal_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Personal workspace — bookmarks and annotated findings."""
    with db.get_conn() as conn:
        bookmarks = db.get_bookmarks(conn)
        annotated = db.get_annotated_findings(conn)

    enriched_annotated = [_enrich_finding(r) for r in annotated]

    return templates.TemplateResponse(
        request,
        "personal.html",
        {
            "nav_active": "personal",
            "run_token": _get_run_token(),
            "current_model": _get_current_model(),
            "bookmarks": [dict(r) for r in bookmarks],
            "annotated": enriched_annotated,
        },
    )


@app.get("/history", response_class=HTMLResponse)
async def history_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """History view — trend charts and source reliability."""
    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "nav_active": "history",
            "run_token": _get_run_token(),
            "current_model": _get_current_model(),
        },
    )


@app.get("/weekly", response_class=HTMLResponse)
async def weekly_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Weekly summary view — most recent Monday digest."""
    with db.get_conn() as conn:
        digest = db.get_weekly_digest(conn)

    return templates.TemplateResponse(
        request,
        "weekly.html",
        {
            "nav_active": "weekly",
            "run_token": _get_run_token(),
            "current_model": _get_current_model(),
            "digest": digest,
        },
    )


@app.get("/news", response_class=HTMLResponse)
async def news_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
    sort: str = "published_desc",
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """All news items with category/severity/source/search filters and pagination."""
    if sort not in ("published_desc", "published_asc"):
        sort = "published_desc"

    d = await asyncio.to_thread(
        _news_page_data, category, severity, source, search, sort, page, per_page
    )

    return templates.TemplateResponse(
        request,
        "news.html",
        {
            "nav_active": "news",
            "run_token": d["run_token"],
            "current_model": d["current_model"],
            "news_items": [_enrich_news(r) for r in d["rows"]],
            "bookmarked_ids": list(d["bookmarked_ids"]),
            "categories": [r["category"] for r in d["cat_rows"]],
            "sources": [r["source"] for r in d["src_rows"]],
            "category_filter": category,
            "severity_filter": severity,
            "source_filter": source,
            "search_filter": search,
            "sort": sort,
            "pagination": d["pagination"],
        },
    )


def _news_page_data(
    category: str | None,
    severity: str | None,
    source: str | None,
    search: str | None,
    sort: str,
    page: int,
    per_page: int,
) -> dict:
    """All of the /news route's DB work, run via asyncio.to_thread."""
    with db.get_conn() as conn:
        total = db.get_news_items_count(
            conn, category=category, severity=severity, source=source, search=search
        )
        pg = _paginate(page, per_page, total)
        rows = db.get_news_items_paginated(
            conn,
            category=category,
            severity=severity,
            source=source,
            search=search,
            sort=sort,
            limit=pg["per_page"],
            offset=pg["offset"],
        )
        bookmarked_ids = db.get_bookmarked_ids(conn)
        cat_rows = conn.execute(
            "SELECT DISTINCT category FROM news_items WHERE category IS NOT NULL ORDER BY category"
        ).fetchall()
        src_rows = conn.execute(
            "SELECT DISTINCT source FROM news_items WHERE source IS NOT NULL ORDER BY source"
        ).fetchall()
        return {
            "rows": rows,
            "bookmarked_ids": bookmarked_ids,
            "cat_rows": cat_rows,
            "src_rows": src_rows,
            "pagination": pg,
            "run_token": _get_run_token(conn),
            "current_model": _get_current_model(conn),
        }


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    level: str = "",
    search: str = "",
    sort: str | None = None,
    direction: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """Application log viewer with level filter, search, and pagination."""
    level = level.upper() if level in ("INFO", "WARNING", "ERROR", "CRITICAL") else ""
    with db.get_conn() as conn:
        total = db.count_log_entries(conn, level=level, search=search)
        pg = _paginate(page, per_page, total)
        rows = db.get_log_entries(
            conn,
            page=pg["page"],
            per_page=pg["per_page"],
            level=level,
            search=search,
            sort=sort,
            direction=direction,
        )
    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "nav_active": "logs",
            "run_token": _get_run_token(),
            "current_model": _get_current_model(),
            "log_entries": [dict(r) for r in rows],
            "level_filter": level,
            "search_filter": search,
            "sort": sort,
            "direction": direction,
            "pagination": pg,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health() -> JSONResponse:
    """Minimal, unauthenticated health check for Docker HEALTHCHECK.

    Deliberately returns nothing about pipeline state — that used to live
    here and leaked private repo names (step_stats.scan/secrets.failed_repos)
    and raw exception text (last_error) to anyone who could reach the port,
    with no auth at all. See /api/status for the full, authenticated payload.
    """
    return JSONResponse({"status": "ok", "version": "0.1.0"})


@app.get("/api/status")
async def status(_user: Annotated[str, Depends(_require_auth)]) -> JSONResponse:
    """Full pipeline/runtime status for the dashboard UI. Authenticated —
    this is the endpoint /api/health used to be before it was split out."""
    with _pipeline_lock:
        pipeline = copy.deepcopy(_pipeline_status)
    next_run: str | None = None
    if _scheduler:
        job = _scheduler.get_job("pipeline")
        if job and job.next_run_time:
            next_run = job.next_run_time.isoformat()
    ollama_ok = await asyncio.to_thread(_check_ollama_status)
    return JSONResponse(
        {
            "status": "ok",
            "version": "0.1.0",
            "pipeline": pipeline,
            "pipeline_steps": PIPELINE_STEPS,
            "next_run": next_run,
            "ollama_ok": ollama_ok,
            "active_model": _get_current_model(),
            "log_drops": _get_dropped_log_count(),
        }
    )


@app.get("/api/news/recent")
async def get_news_recent(
    _user: Annotated[str, Depends(_require_auth)],
    since: str | None = None,
    max_age_minutes: int = 60,
    limit: int = 20,
) -> JSONResponse:
    """Return news items newer than `since` (ISO8601), capped at `limit`.

    Used by the dashboard's live ticker which polls every 30s. The
    `max_age_minutes` window keeps the ticker focused on truly recent items so
    it stays distinct from the full /news page (which shows everything).
    """
    # Bounds on caller-controlled inputs.
    if max_age_minutes < 1 or max_age_minutes > 1440:
        max_age_minutes = 60
    if limit < 1 or limit > 50:
        limit = 20

    # Compute effective cutoff: max(since, now - max_age_minutes).
    cutoff = datetime.now(UTC) - timedelta(minutes=max_age_minutes)
    if since:
        try:
            sdt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if sdt.tzinfo is None:
                sdt = sdt.replace(tzinfo=UTC)
            if sdt > cutoff:
                cutoff = sdt
        except (ValueError, TypeError):
            pass

    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, title, source, published_at, fetched_at, summary, category,
                   severity, url
            FROM news_items
            WHERE fetched_at > ?
            ORDER BY fetched_at DESC
            LIMIT ?
            """,
            (cutoff.isoformat(), int(limit)),
        ).fetchall()

        # On the initial load (no `since`) fall back to the most recent items
        # so the ticker is never empty when news exists but is older than the window.
        if not rows and not since:
            rows = conn.execute(
                """
                SELECT id, title, source, published_at, fetched_at, summary, category,
                       severity, url
                FROM news_items
                ORDER BY fetched_at DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()

    items = [_enrich_news(r) for r in rows]
    server_now = datetime.now(UTC).isoformat()
    return JSONResponse({"items": items, "server_now": server_now})


@app.get("/api/nav-badges")
async def get_nav_badges(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Live nav badge counts (findings / secrets / recent news). Polled by the
    sidebar so badge numbers update after Clear Data or other state changes
    without requiring a full-page reload."""
    return JSONResponse(_nav_badges())


@app.post("/api/run/cancel")
async def cancel_run(
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Request cancellation of a running pipeline. The current step finishes
    naturally; cancellation is honoured at the next step boundary."""
    with _pipeline_lock:
        if not _pipeline_status["running"]:
            raise HTTPException(status_code=409, detail="No pipeline is currently running")
        _pipeline_control["cancel_requested"] = True
    # Release any pause so the runner can observe the cancel flag and exit.
    _pipeline_pause_event.set()
    return JSONResponse({"status": "cancel_requested"})


@app.post("/api/run/pause")
async def pause_run(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Toggle pause for a running pipeline. Body: {"pause": true|false}."""
    body = await request.json()
    pause = bool(body.get("pause"))
    with _pipeline_lock:
        if not _pipeline_status["running"]:
            raise HTTPException(status_code=409, detail="No pipeline is currently running")
        _pipeline_control["pause_requested"] = pause
    if pause:
        _pipeline_pause_event.clear()
    else:
        _pipeline_pause_event.set()
    return JSONResponse({"status": "paused" if pause else "resumed"})


@app.post("/api/run")
async def trigger_run(
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Trigger an immediate pipeline run.

    Requires an authenticated session + X-Run-Token header (CSRF protection).
    """
    with _pipeline_lock:
        if _pipeline_status["running"]:
            return JSONResponse(
                {"status": "already_running", "message": "Pipeline is already in progress"},
                status_code=409,
            )
        # Claim "running" here, under the lock, rather than leaving it to
        # _run_pipeline() itself — otherwise two near-simultaneous requests
        # can both observe running=False and both report "started", with the
        # second silently dying on the pipeline file lock.
        _pipeline_status["running"] = True

    thread = threading.Thread(target=_run_pipeline, daemon=True, name="pipeline-manual")
    thread.start()
    return JSONResponse({"status": "started", "message": "Pipeline run triggered"})


@app.get("/api/findings")
async def get_findings_api(
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
    limit: int = 100,
) -> JSONResponse:
    """Return findings as JSON, optionally filtered by state and/or repo."""
    with db.get_conn() as conn:
        rows = db.get_findings(conn, state=state, repo=repo, limit=min(limit, 500))
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/news")
async def get_news(
    _user: Annotated[str, Depends(_require_auth)],
    hours: int = 24,
    limit: int = 50,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
) -> JSONResponse:
    """Return recent news items as JSON, with optional filters."""
    with db.get_conn() as conn:
        rows = db.get_recent_items(
            conn,
            hours=min(hours, 720),
            limit=min(limit, 200),
            category=category,
            severity=severity,
            source=source,
            search=search,
        )
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/ollama/models")
async def get_ollama_models(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Return installed Ollama models plus suggested models.

    Response shape:
        {
            "installed": ["qwen2.5:3b", ...],
            "suggested": [{"name": ..., "description": ...}, ...],
            "current":   "qwen2.5:3b"
        }
    """
    ollama_host = _config.ollama.host if _config else "http://localhost:11434"
    installed = await asyncio.to_thread(_fetch_installed_ollama_models, ollama_host)

    return JSONResponse(
        {
            "installed": installed,
            "suggested": _SUGGESTED_MODELS,
            "current": _get_current_model(),
        }
    )


@app.post("/api/findings/{finding_id}/acknowledge")
async def acknowledge_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Mark a finding as acknowledged."""
    with db.get_conn() as conn:
        updated = lifecycle.acknowledge(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or not in 'new' state")
    return JSONResponse({"status": "acknowledged", "finding_id": finding_id})


@app.post("/api/findings/{finding_id}/resolve")
async def resolve_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Manually mark a finding as resolved."""
    with db.get_conn() as conn:
        updated = lifecycle.resolve(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or already resolved")
    return JSONResponse({"status": "resolved", "finding_id": finding_id})


@app.post("/api/findings/{finding_id}/reopen")
async def reopen_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Reopen a resolved or acknowledged finding."""
    with db.get_conn() as conn:
        updated = lifecycle.reopen(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or already new")
    return JSONResponse({"status": "new", "finding_id": finding_id})


@app.post("/api/findings/bulk")
async def bulk_findings_action(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Apply an action to multiple findings at once."""
    body = await request.json()
    try:
        ids = [int(i) for i in body.get("ids", [])]
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="ids must be a list of integers")
    action = str(body.get("action", ""))
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")
    if len(ids) > 500:
        raise HTTPException(status_code=400, detail="Too many IDs (max 500)")
    if action not in ("acknowledge", "resolve", "reopen"):
        raise HTTPException(status_code=400, detail=f"Invalid action '{action}'")
    with db.get_conn() as conn:
        count = db.bulk_update_finding_state(conn, ids, action)
    return JSONResponse({"updated": count, "action": action})


@app.get("/api/secrets")
async def get_secrets_api(
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
    limit: int = 100,
) -> JSONResponse:
    """Return secret findings as JSON, optionally filtered by state and/or repo."""
    with db.get_conn() as conn:
        rows = db.get_secret_findings(conn, state=state, repo=repo, limit=min(limit, 500))
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/secrets/{finding_id}/snippet")
async def get_secret_snippet(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Fetch the ±2 lines of source around a leaked secret from GitHub.

    The actual credential is *not* stored in the database (gitleaks is run with
    --redact), so this endpoint reaches out to GitHub on demand. The response
    is never cached and never persisted; once the modal closes the data is
    gone. The reveal is logged so abuse leaves a trail.

    Security notes:
    - The repo path comes from the DB row, not from user input — no injection.
    - We refuse to reveal anything for repos outside the configured GitHub
      username so a hostile dashboard user can't probe arbitrary public repos.
    - The endpoint is auth-gated; reading the snippet exposes the live secret
      to anyone with dashboard access.
    """
    if _config is None or not _config.github.token:
        raise HTTPException(status_code=503, detail="GitHub is not configured")

    with db.get_conn() as conn:
        row = db.get_secret_finding(conn, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    repo_full = str(row["repo_full_name"] or "")
    owner = repo_full.split("/", 1)[0] if "/" in repo_full else ""
    if owner.lower() != _config.github.username.lower():
        # Audit-defence: never fetch from a repo we don't own.
        logger.warning(
            "Snippet reveal blocked for finding %s — repo %s outside configured account",
            finding_id,
            repo_full,
        )
        raise HTTPException(status_code=403, detail="Repo is outside the configured account")

    path = str(row["file_path"] or "")
    commit = str(row["commit_sha"] or "")
    line_number = int(row["line_number"] or 0)
    if not path or not commit or line_number <= 0:
        raise HTTPException(status_code=400, detail="Secret row is missing path/commit/line")

    # Audit log: who revealed which secret. The dashboard user is HTTP-Basic so
    # _user is the configured operator name; this is best-effort attribution.
    logger.info(
        "Snippet revealed for finding %s (%s @ %s line %d) by %s",
        finding_id,
        path,
        commit[:8],
        line_number,
        _user,
    )

    import base64

    import httpx

    api_url = f"https://api.github.com/repos/{repo_full}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {_config.github.token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "dive/secret-snippet",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(api_url, params={"ref": commit}, headers=headers)
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="File not found at that commit")
        resp.raise_for_status()
        body = resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("GitHub contents fetch failed for %s: %s", path, exc)
        raise HTTPException(status_code=502, detail="GitHub fetch failed")

    if body.get("encoding") != "base64" or "content" not in body:
        raise HTTPException(status_code=502, detail="Unsupported file response from GitHub")

    try:
        raw = base64.b64decode(body["content"])
    except Exception:
        raise HTTPException(status_code=502, detail="Could not decode file content") from None

    # Reject binaries / oversized files so we don't ship megabytes back to the browser.
    if len(raw) > 500_000:
        raise HTTPException(status_code=413, detail="File too large to reveal")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=415, detail="File is not UTF-8 text") from None

    lines = text.splitlines()
    if line_number > len(lines):
        raise HTTPException(status_code=404, detail="Line number out of range for the file")

    start = max(0, line_number - 3)
    end = min(len(lines), line_number + 2)
    snippet = [
        {"n": i + 1, "text": lines[i], "is_secret": (i + 1) == line_number}
        for i in range(start, end)
    ]

    return JSONResponse(
        {
            "file_path": path,
            "line_number": line_number,
            "commit_sha": commit,
            "secret_type": row["secret_type"],
            "lines": snippet,
        }
    )


@app.post("/api/secrets/{finding_id}/false-positive")
async def mark_secret_false_positive(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Mark a secret finding as a false positive — suppresses future re-reporting."""
    with db.get_conn() as conn:
        updated = db.mark_secret_finding_false_positive(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or not in 'new' state")
    return JSONResponse({"status": "false_positive", "finding_id": finding_id})


@app.post("/api/secrets/{finding_id}/unmark-false-positive")
async def unmark_secret_false_positive(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Revert a false-positive secret finding back to 'new'."""
    with db.get_conn() as conn:
        updated = db.unmark_secret_false_positive(conn, finding_id)
    if not updated:
        raise HTTPException(
            status_code=404, detail="Finding not found or not in 'false_positive' state"
        )
    return JSONResponse({"status": "new", "finding_id": finding_id})


@app.post("/api/secrets/{finding_id}/resolve")
async def resolve_secret_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Mark a secret finding as resolved (credential revoked and history cleaned)."""
    with db.get_conn() as conn:
        updated = db.mark_secret_finding_resolved(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or already resolved")
    return JSONResponse({"status": "resolved", "finding_id": finding_id})


@app.post("/api/secrets/{finding_id}/reopen")
async def reopen_secret_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Revert a resolved secret finding back to 'new'.

    A resolved secret previously had no way back — the UI offered Reveal and
    nothing else — while dependency findings have always had Reopen. Also
    the undo target for the Resolve action.
    """
    with db.get_conn() as conn:
        updated = db.reopen_secret_finding(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or not resolved")
    return JSONResponse({"status": "new", "finding_id": finding_id})


@app.post("/api/secrets/bulk")
async def bulk_secrets_action(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Apply an action to multiple secret findings at once."""
    body = await request.json()
    try:
        ids = [int(i) for i in body.get("ids", [])]
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="ids must be a list of integers")
    action = str(body.get("action", ""))
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")
    if len(ids) > 500:
        raise HTTPException(status_code=400, detail="Too many IDs (max 500)")
    if action not in ("false-positive", "resolve"):
        raise HTTPException(status_code=400, detail=f"Invalid action '{action}'")
    with db.get_conn() as conn:
        count = db.bulk_update_secret_state(conn, ids, action)
    return JSONResponse({"updated": count, "action": action})


# ---------------------------------------------------------------------------
# Config API — feeds, keywords, toggles, scanner settings
# ---------------------------------------------------------------------------


@app.get("/api/config/feeds")
async def list_feeds(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Return all RSS feeds with their enabled state and fetch stats."""
    with db.get_conn() as conn:
        rows = st.get_feeds(conn)
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/config/feeds")
async def add_feed(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Add a new RSS feed after validating it is a reachable RSS/Atom URL."""
    body = await request.json()
    url = str(body.get("url", "")).strip()
    name = str(body.get("name", "")).strip()

    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    if not name:
        raise HTTPException(status_code=400, detail="name is required")

    is_valid = await asyncio.to_thread(_validate_feed_url, url)
    if not is_valid:
        raise HTTPException(
            status_code=422,
            detail="URL does not appear to be a valid RSS/Atom feed or is unreachable.",
        )

    try:
        with db.get_conn() as conn:
            row = st.add_feed(conn, name, url)
        return JSONResponse(dict(row), status_code=201)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.patch("/api/config/feeds/{feed_id}")
async def update_feed(
    feed_id: int,
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Update a feed. Accepts {enabled}, {name}, {url}, or any combination."""
    body = await request.json()

    if "enabled" in body:
        with db.get_conn() as conn:
            updated = st.set_feed_enabled(conn, feed_id, bool(body["enabled"]))
        if not updated:
            raise HTTPException(status_code=404, detail="Feed not found")
        return JSONResponse(
            {"status": "updated", "feed_id": feed_id, "enabled": bool(body["enabled"])}
        )

    name = str(body["name"]).strip() if "name" in body else None
    url = str(body["url"]).strip() if "url" in body else None

    if name is not None and not name:
        raise HTTPException(status_code=400, detail="name cannot be blank")
    if url is not None:
        if not url:
            raise HTTPException(status_code=400, detail="url cannot be blank")
        is_valid = await asyncio.to_thread(_validate_feed_url, url)
        if not is_valid:
            raise HTTPException(status_code=422, detail="URL is not a reachable RSS/Atom feed.")

    if name is None and url is None:
        raise HTTPException(status_code=400, detail="No updatable fields provided")

    try:
        with db.get_conn() as conn:
            updated = st.update_feed(conn, feed_id, name=name, url=url)
        if not updated:
            raise HTTPException(status_code=404, detail="Feed not found")
        return JSONResponse({"status": "updated", "feed_id": feed_id})
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.delete("/api/config/feeds/{feed_id}")
async def delete_feed(
    feed_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Delete a user-added feed. Default feeds cannot be deleted."""
    try:
        with db.get_conn() as conn:
            deleted = st.remove_feed(conn, feed_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Feed not found")
        return JSONResponse({"status": "deleted", "feed_id": feed_id})
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/api/config/keywords")
async def list_keywords(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Return all keywords in the watchlist."""
    with db.get_conn() as conn:
        rows = st.get_keywords(conn)
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/config/keywords")
async def add_keyword(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Add a keyword to the watchlist."""
    body = await request.json()
    keyword = str(body.get("keyword", "")).strip()
    if not keyword:
        raise HTTPException(status_code=400, detail="keyword is required")
    try:
        with db.get_conn() as conn:
            row = st.add_keyword(conn, keyword)
        return JSONResponse(dict(row), status_code=201)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.delete("/api/config/keywords/{keyword_id}")
async def delete_keyword(
    keyword_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Remove a keyword from the watchlist."""
    with db.get_conn() as conn:
        deleted = st.remove_keyword(conn, keyword_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Keyword not found")
    return JSONResponse({"status": "deleted", "keyword_id": keyword_id})


@app.get("/api/config/toggles")
async def get_toggles(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Return current state of all feature toggles."""
    with db.get_conn() as conn:
        toggles = st.get_feature_toggles(conn)
    meta = {k: {"label": v["label"], "enabled": toggles[k]} for k, v in st.FEATURE_TOGGLES.items()}
    return JSONResponse(meta)


@app.post("/api/config/toggles")
async def update_toggles(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Update one or more feature toggles. Body: {\"<key>\": true|false, ...}"""
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object")
    errors: list[str] = []
    with db.get_conn() as conn:
        for key, value in body.items():
            try:
                st.set_feature_toggle(conn, key, bool(value))
            except ValueError as exc:
                errors.append(str(exc))
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    return JSONResponse({"status": "updated"})


@app.get("/api/config/scanner")
async def get_scanner_settings(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Return scanner settings: severity threshold, excluded repos, secrets scan depth, and categorizer batch size."""
    with db.get_conn() as conn:
        raw_depth = db.get_setting(conn, "secrets_scan_depth", str(ss.DEFAULT_SCAN_DEPTH))
        try:
            scan_depth = max(1, int(raw_depth))
        except ValueError:
            scan_depth = ss.DEFAULT_SCAN_DEPTH
        return JSONResponse(
            {
                "severity_threshold": st.get_severity_threshold(conn),
                "excluded_repos": st.get_excluded_repos(conn),
                "severity_levels": st.SEVERITY_LEVELS,
                "secrets_scan_depth": scan_depth,
                "categorize_batch_size": st.get_categorize_batch_size(conn),
                "news_retention_days": st.get_news_retention_days(conn),
                "log_retention_days": st.get_log_retention_days(conn),
                "idle_categorize_interval_minutes": st.get_idle_categorize_interval_minutes(conn),
            }
        )


@app.post("/api/config/scanner")
async def update_scanner_settings(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Update scanner settings."""
    body = await request.json()
    with db.get_conn() as conn:
        if "severity_threshold" in body:
            try:
                st.set_severity_threshold(conn, str(body["severity_threshold"]))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        if "excluded_repos" in body:
            repos = body["excluded_repos"]
            if not isinstance(repos, list):
                raise HTTPException(status_code=400, detail="excluded_repos must be a list")
            st.set_excluded_repos(conn, [str(r) for r in repos])
        if "secrets_scan_depth" in body:
            try:
                depth = int(body["secrets_scan_depth"])
                if depth < 1:
                    raise ValueError
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=400, detail="secrets_scan_depth must be a positive integer"
                )
            db.set_setting(conn, "secrets_scan_depth", str(depth))
        if "categorize_batch_size" in body:
            try:
                st.set_categorize_batch_size(conn, int(body["categorize_batch_size"]))
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        if "news_retention_days" in body:
            try:
                st.set_news_retention_days(conn, int(body["news_retention_days"]))
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        if "log_retention_days" in body:
            try:
                st.set_log_retention_days(conn, int(body["log_retention_days"]))
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        if "idle_categorize_interval_minutes" in body:
            try:
                idle_minutes = int(body["idle_categorize_interval_minutes"])
                st.set_idle_categorize_interval_minutes(conn, idle_minutes)
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            _reschedule_idle_categorize(idle_minutes)
    return JSONResponse({"status": "updated"})


def _is_ssrf_safe(url: str) -> bool:
    """Return False if the URL resolves to a private, loopback, or reserved address."""
    import ipaddress
    import socket
    import urllib.parse

    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        addr = ipaddress.ip_address(socket.gethostbyname(host))
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except Exception:
        return False


def _validate_feed_url(url: str) -> bool:
    """Return True if url is a reachable RSS/Atom feed. Runs in a thread pool."""
    import feedparser
    import httpx as _httpx

    if not _is_ssrf_safe(url):
        logger.warning("Feed URL rejected (private/reserved address): %s", url)
        return False

    try:
        with _httpx.Client(timeout=10, follow_redirects=True, max_redirects=5) as client:
            resp = client.get(url)
            resp.raise_for_status()
        # Re-check the final URL after redirects — guards against open-redirect
        # chains that bounce through a public URL to reach an internal host.
        final_url = str(resp.url)
        if final_url != url and not _is_ssrf_safe(final_url):
            logger.warning("Feed URL rejected after redirect to private address: %s", final_url)
            return False
        feed = feedparser.parse(resp.text)
        return bool(feed.feed.get("title") or feed.entries)
    except Exception:
        return False


@app.get("/api/settings")
async def get_settings(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Return editable pipeline settings."""
    with db.get_conn() as conn:
        interval = db.get_setting(conn, "run_interval_hours", "6")
        model = db.get_setting(conn, "active_model", "")
    return JSONResponse(
        {
            "run_interval_hours": interval,
            "active_model": model or (_config.ollama.model if _config else ""),
        }
    )


@app.post("/api/settings")
async def update_settings(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Update pipeline settings: run_interval_hours and/or active_model."""
    body = await request.json()

    if "run_interval_hours" in body:
        try:
            hours = float(body["run_interval_hours"])
            if hours <= 0:
                raise ValueError
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400, detail="run_interval_hours must be a positive number"
            )
        with db.get_conn() as conn:
            db.set_setting(conn, "run_interval_hours", str(hours))
        _reschedule(hours)

    if "active_model" in body:
        model = str(body["active_model"]).strip()
        if model:
            await asyncio.to_thread(_validate_ollama_model, model)
            with db.get_conn() as conn:
                db.set_setting(conn, "active_model", model)
            logger.info("Active model changed to: %s", model)

    return JSONResponse({"status": "updated"})


# ---------------------------------------------------------------------------
# Personal workspace API
# ---------------------------------------------------------------------------


@app.post("/api/news/{item_id}/bookmark")
async def toggle_bookmark(
    item_id: int,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Toggle bookmark on a news item. Returns current bookmarked state."""
    with db.get_conn() as conn:
        if db.is_bookmarked(conn, item_id):
            db.remove_bookmark(conn, item_id)
            return JSONResponse({"bookmarked": False})
        else:
            db.add_bookmark(conn, item_id)
            return JSONResponse({"bookmarked": True})


@app.get("/api/bookmarks")
async def list_bookmarks(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    with db.get_conn() as conn:
        rows = db.get_bookmarks(conn)
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/findings/{finding_id}/annotate")
async def annotate_finding(
    finding_id: int,
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Set or clear a personal annotation on a finding."""
    body = await request.json()
    text = str(body.get("annotation", "")).strip()
    with db.get_conn() as conn:
        updated = db.set_finding_annotation(conn, finding_id, text or None)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return JSONResponse({"annotation": text or None})


# ---------------------------------------------------------------------------
# Data export API
# ---------------------------------------------------------------------------


def _findings_to_csv(rows) -> str:
    output = io.StringIO()
    fieldnames = [
        "id",
        "repo_full_name",
        "cve_id",
        "ghsa_id",
        "package_name",
        "package_ecosystem",
        "installed_version",
        "fixed_version",
        "cvss_score",
        "is_kev",
        "patch_available",
        "priority_score",
        "state",
        "first_seen_at",
        "last_seen_at",
        "resolved_at",
        "manifest_path",
        "annotation",
        "github_issue_url",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(dict(r))
    return output.getvalue()


def _news_to_csv(rows) -> str:
    output = io.StringIO()
    fieldnames = [
        "id",
        "title",
        "url",
        "source",
        "published_at",
        "fetched_at",
        "summary",
        "category",
        "severity",
        "affected_products",
        "tags",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(dict(r))
    return output.getvalue()


def _secrets_to_csv(rows) -> str:
    """Serialise secret findings to CSV — redacted metadata only.

    extrasaction="ignore" is load-bearing, not incidental: it is the
    structural guarantee that widening the SELECT in
    db.get_secret_findings_for_export() (or a schema migration adding a
    column) cannot silently widen this file.
    """
    output = io.StringIO()
    fieldnames = [
        "id",
        "repo_full_name",
        "file_path",
        "line_number",
        "commit_sha",
        "secret_type",
        "rule_id",
        "state",
        "first_seen_at",
        "last_seen_at",
        "notified_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(dict(r))
    return output.getvalue()


@app.get("/api/export/findings")
async def export_findings(
    _user: Annotated[str, Depends(_require_auth)],
    format: str = "json",
    state: str | None = None,
    repo: str | None = None,
    severity: str | None = None,
    annotated: bool = False,
) -> StreamingResponse:
    """Export findings as JSON or CSV, honoring the same state/repo/severity
    filters as the findings list view.

    The pseudo-state window comes from _state_window(), the same helper the
    page route uses — that shared call is what keeps `?state=new` here
    meaning the same rows the New tab shows, rather than every all-time row
    in state='new'. The window is deliberately NOT a URL parameter: a raw
    run timestamp in a bookmarkable export link would silently go stale as
    soon as the next run moved the boundary.

    `annotated=1` narrows to findings carrying a note (the /personal page's
    "Findings with notes" export).

    Row *set* matches the view; row *order* does not — the export is always
    priority-ordered and ignores the view's sort/direction, since consumers
    re-sort anyway.
    """
    with db.get_conn() as conn:
        rows = db.get_findings_for_export(
            conn,
            state=state,
            repo=repo,
            severity=severity,
            since=_state_window(conn, state),
            annotated=annotated,
        )

    if format == "csv":
        content = _findings_to_csv(rows)
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )

    data = [dict(r) for r in rows]
    content = json.dumps(data, ensure_ascii=False, indent=2)
    return StreamingResponse(
        io.StringIO(content),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.json"},
    )


@app.get("/api/export/news")
async def export_news(
    _user: Annotated[str, Depends(_require_auth)],
    format: str = "json",
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
    bookmarked: bool = False,
) -> StreamingResponse:
    """Export news as JSON or CSV, honoring the same category/severity/source/
    search filters as the news list view (filtered export matches the screen).

    `bookmarked=1` narrows to saved items (the /personal page's "Bookmarks"
    export).
    """
    with db.get_conn() as conn:
        rows = db.get_news_items_for_export(
            conn,
            category=category,
            severity=severity,
            source=source,
            search=search,
            bookmarked=bookmarked,
        )

    if format == "csv":
        content = _news_to_csv(rows)
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=news.csv"},
        )

    data = [dict(r) for r in rows]
    content = json.dumps(data, ensure_ascii=False, indent=2)
    return StreamingResponse(
        io.StringIO(content),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=news.json"},
    )


@app.get("/api/export/secrets")
async def export_secrets(
    _user: Annotated[str, Depends(_require_auth)],
    format: str = "json",
    state: str | None = None,
    repo: str | None = None,
) -> StreamingResponse:
    """Export secret findings as JSON or CSV, honoring the same state/repo
    filters as the secrets list view.

    Redacted metadata only — never the credential itself. gitleaks runs with
    --redact so no secret_findings column holds secret text in the first
    place; the live secret exists only behind GET /api/secrets/{id}/snippet,
    which fetches it from GitHub per request. Do NOT "enrich" this export
    with snippet data: it would turn a metadata download into a bulk
    credential dump.

    No `severity` parameter — secret_findings has no severity column.
    """
    with db.get_conn() as conn:
        rows = db.get_secret_findings_for_export(
            conn, state=state, repo=repo, since=_state_window(conn, state)
        )

    if format == "csv":
        content = _secrets_to_csv(rows)
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=secrets.csv"},
        )

    data = [dict(r) for r in rows]
    content = json.dumps(data, ensure_ascii=False, indent=2)
    return StreamingResponse(
        io.StringIO(content),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=secrets.json"},
    )


# ---------------------------------------------------------------------------
# Data management API
# ---------------------------------------------------------------------------


@app.delete("/api/data/clear")
async def clear_data(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    _csrf: Annotated[None, Depends(_require_csrf)],
) -> JSONResponse:
    """Delete selected data types, optionally scoped to items older than N days.

    Body: {"types": ["news", "findings", "secrets", "run_history"], "days_back": 30}
    Omit days_back (or set null) to delete all records of the selected types.
    """
    body = await request.json()
    types = body.get("types") or []
    days_back = body.get("days_back")

    if days_back is not None:
        try:
            days_back = int(days_back)
            if days_back <= 0:
                raise ValueError
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="days_back must be a positive integer")

    valid_types = {"news", "findings", "secrets", "run_history"}
    unknown = set(types) - valid_types
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown types: {sorted(unknown)}")

    deleted: dict[str, int] = {}
    with db.get_conn() as conn:
        if "news" in types:
            deleted["news"] = db.clear_news_items(conn, days_back=days_back)
        if "findings" in types:
            deleted["findings"] = db.clear_findings(conn, days_back=days_back)
        if "secrets" in types:
            deleted["secrets"] = db.clear_secret_findings(conn, days_back=days_back)
        if "run_history" in types:
            deleted["run_history"] = db.clear_run_history(conn, days_back=days_back)

    total = sum(deleted.values())
    logger.info("Data cleared by user: %s (days_back=%s, total=%d)", deleted, days_back, total)
    return JSONResponse({"status": "cleared", "deleted": deleted, "total": total})


# ---------------------------------------------------------------------------
# History API
# ---------------------------------------------------------------------------


@app.get("/api/history/news-trend")
async def api_news_trend(
    _user: Annotated[str, Depends(_require_auth)],
    days: int = 30,
) -> JSONResponse:
    days = min(max(days, 1), 365)
    with db.get_conn() as conn:
        rows = db.get_news_trend(conn, days=days)
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/history/findings-trend")
async def api_findings_trend(
    _user: Annotated[str, Depends(_require_auth)],
    days: int = 30,
) -> JSONResponse:
    days = min(max(days, 1), 365)
    with db.get_conn() as conn:
        rows = db.get_findings_by_day(conn, days=days)
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/history/sources")
async def api_source_stats(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    with db.get_conn() as conn:
        rows = db.get_source_stats(conn)
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/history/runs")
async def api_run_history(
    _user: Annotated[str, Depends(_require_auth)],
    limit: int = 30,
) -> JSONResponse:
    with db.get_conn() as conn:
        rows = db.get_run_history(conn, limit=min(limit, 100))
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/history/feed-analytics")
async def api_feed_analytics(
    _user: Annotated[str, Depends(_require_auth)],
    days: int = 30,
) -> JSONResponse:
    days = min(max(days, 1), 365)
    with db.get_conn() as conn:
        rows = db.get_feed_analytics(conn, days=days)
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/weekly")
async def api_weekly_digest(
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    with db.get_conn() as conn:
        digest = db.get_weekly_digest(conn)
    if digest is None:
        return JSONResponse({"detail": "No digest available yet"}, status_code=404)
    return JSONResponse(digest)


if __name__ == "__main__":
    uvicorn.run("dive.main:app", host="0.0.0.0", port=8000, reload=False)
