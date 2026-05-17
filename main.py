"""
DIVE — main entrypoint.

FastAPI application with:
  • APScheduler BackgroundScheduler — runs the full pipeline on a
    configurable interval (default 6h, stored in settings table).
  • HTTP Basic Auth — all non-health routes require credentials from
    config.yaml dashboard.username / dashboard.password.
  • POST /api/run — trigger an immediate pipeline run (X-Run-Token header
    required as CSRF protection).
  • File-based lock (filelock) — prevents concurrent pipeline runs.
  • GET /api/health — unauthenticated; includes live pipeline status.
  • Jinja2 dashboard — /, /findings, /settings served as HTML.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import secrets
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from filelock import FileLock, Timeout
from itsdangerous import URLSafeTimedSerializer

import asyncio

from apscheduler.triggers.cron import CronTrigger

import config as cfg_module
import db
import github_issue_creator as gic
import github_scanner as gs
import lifecycle
import notifier
import secrets_scanner as ss
import settings as st

try:
    import collector as collector_module
    import categorizer as categorizer_module
    _COLLECTOR_AVAILABLE = True
except ImportError:
    _COLLECTOR_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent

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
}

# File lock path (prevents concurrent runs across processes / restarts)
_LOCK_FILE = Path("data/.pipeline.lock")

# Pagination constants
_PAGE_SIZE_OPTIONS = [10, 25, 50, 100]
_DEFAULT_PAGE_SIZE = 25

# Interval select options shown in the settings page
_INTERVAL_OPTIONS = [
    ("3",   "Every 3 hours"),
    ("6",   "Every 6 hours (default)"),
    ("12",  "Every 12 hours"),
    ("24",  "Every 24 hours"),
    ("168", "Once a week"),
    ("720", "Once a month"),
]

# Suggested Ollama models shown in the settings page
_SUGGESTED_MODELS = [
    {"name": "qwen2.5:3b",   "description": "~1.9 GB · 5–8 tok/s · Recommended for Pi 4"},
    {"name": "gemma2:2b",    "description": "~1.6 GB · 8–12 tok/s · Fastest on Pi 4"},
    {"name": "phi3.5:mini",  "description": "~2.2 GB · 4–6 tok/s · Strong reasoning"},
    {"name": "llama3.2:3b",  "description": "~2.0 GB · 4–7 tok/s · Good general-purpose"},
    {"name": "qwen2.5:7b",   "description": "~4.7 GB · Better quality, 8 GB+ RAM"},
    {"name": "llama3.1:8b",  "description": "~4.7 GB · Strong general-purpose, Apple Silicon"},
    {"name": "qwen2.5:14b",  "description": "~9 GB · High quality, 16 GB+ RAM"},
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
            notifier.send_weekly_digest(_config, conn)
    except Exception as exc:
        logger.error("Weekly digest failed: %s", exc, exc_info=True)


def _run_pipeline() -> None:
    """Full pipeline: collect → categorize → scan → lifecycle → notify.

    Guarded by a file lock so only one run can execute at a time.
    If a run is already in progress the new trigger is silently skipped.
    """
    global _config

    lock = FileLock(str(_LOCK_FILE), timeout=0)
    try:
        lock.acquire()
    except Timeout:
        logger.warning("Pipeline already running — skipping this trigger")
        return

    run_id: int | None = None
    _pipeline_start_time = datetime.now(UTC)
    try:
        with _pipeline_lock:
            _pipeline_status["running"] = True
            _pipeline_status["last_started"] = _pipeline_start_time.isoformat()
            _pipeline_status["last_error"] = None

        _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
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
        if _COLLECTOR_AVAILABLE:
            try:
                with db.get_conn() as conn:
                    stats = collector_module.run(conn, _config)
                    items_collected = stats.items_fetched
                    logger.info(
                        "Collector: %d new items (%d failed sources)",
                        items_collected,
                        len(stats.failed_sources),
                    )
            except Exception as exc:
                logger.error("Collector failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Collector error: {exc}")

        # ------------------------------------------------------------------
        # Step 2 — Categorize with Ollama
        # ------------------------------------------------------------------
        if _COLLECTOR_AVAILABLE:
            try:
                with db.get_conn() as conn:
                    cat_stats = categorizer_module.run(conn, _config)
                    items_categorized = cat_stats.categorized
                    if cat_stats.uncategorized_rate > 0.2:
                        logger.warning("Categorizer: >20%% of items fell back to Uncategorized")
                    logger.info(
                        "Categorizer: %d categorized, %d uncategorized",
                        items_categorized,
                        cat_stats.uncategorized,
                    )
            except Exception as exc:
                logger.error("Categorizer failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Categorizer error: {exc}")

        # ------------------------------------------------------------------
        # Step 3 — GitHub scanner
        # ------------------------------------------------------------------
        current_finding_keys: set[tuple] = set()
        with db.get_conn() as conn:
            _github_scanning_on = st.is_feature_enabled(conn, "github_scanning")
            _excluded_repos = st.get_excluded_repos(conn)
        if _github_scanning_on:
            try:
                with db.get_conn() as conn:
                    scan_stats = gs.run(conn, _config, excluded_repos=_excluded_repos)
                    findings_new_total = scan_stats.findings_new
                    # Use only keys found in this scan run — reading all DB findings
                    # would prevent auto-resolving patched packages.
                    current_finding_keys = scan_stats.finding_keys

                    logger.info(
                        "Scanner: %d repos, %d packages, %d new findings",
                        scan_stats.repos_scanned,
                        scan_stats.packages_checked,
                        scan_stats.findings_new,
                    )
                    if scan_stats.failed_repos:
                        logger.warning("Scanner failed repos: %s", scan_stats.failed_repos)
            except Exception as exc:
                logger.error("Scanner failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Scanner error: {exc}")
        else:
            logger.info("GitHub scanning disabled by feature toggle — skipping Step 3")

        # ------------------------------------------------------------------
        # Step 3.5 — GitHub issue auto-creation
        # ------------------------------------------------------------------
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
            except Exception as exc:
                logger.error("GitHub issue creation failed: %s", exc, exc_info=True)
        else:
            logger.debug("GitHub issue auto-creation disabled by feature toggle — skipping Step 3.5")

        # ------------------------------------------------------------------
        # Step 4 — Secrets scanner (gitleaks)
        # ------------------------------------------------------------------
        with db.get_conn() as conn:
            _secrets_scanning_on = st.is_feature_enabled(conn, "secrets_scanning")
        secrets_new_total = 0
        if _secrets_scanning_on:
            try:
                with db.get_conn() as conn:
                    sec_stats = ss.run(conn, _config, excluded_repos=_excluded_repos)
                    secrets_new_total = sec_stats.secrets_new
                    if sec_stats.failed_repos:
                        logger.warning("Secrets scanner failed repos: %s", sec_stats.failed_repos)
            except Exception as exc:
                logger.error("Secrets scanner failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Secrets scanner error: {exc}")

            try:
                with db.get_conn() as conn:
                    unnotified_secrets = db.get_unnotified_secret_findings(conn)
                    if unnotified_secrets:
                        notifier.send_secrets_alert(_config, list(unnotified_secrets))
                        db.mark_secret_findings_notified(conn, [r["id"] for r in unnotified_secrets])
                        logger.info("Notifier: %d secrets alerted", len(unnotified_secrets))
            except Exception as exc:
                logger.error("Secrets notifier failed: %s", exc, exc_info=True)
        else:
            logger.info("Secrets scanning disabled by feature toggle — skipping Step 4")

        # ------------------------------------------------------------------
        # Step 5 — Lifecycle reconciliation
        # ------------------------------------------------------------------
        try:
            with db.get_conn() as conn:
                reverted = lifecycle.recheck_resolved(conn, current_finding_keys)
                resolved = lifecycle.auto_resolve_gone(conn, current_finding_keys)
                if reverted:
                    logger.info("Lifecycle: %d resolved→new (regression)", reverted)
                if resolved:
                    logger.info("Lifecycle: %d auto-resolved (no longer present)", resolved)
        except Exception as exc:
            logger.error("Lifecycle reconciliation failed: %s", exc, exc_info=True)

        # ------------------------------------------------------------------
        # Step 6 — Notify findings (delta only, filtered by severity threshold)
        # ------------------------------------------------------------------
        try:
            with db.get_conn() as conn:
                threshold  = st.get_severity_threshold(conn)
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
        except Exception as exc:
            logger.error("Notifier failed: %s", exc, exc_info=True)

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

        with _pipeline_lock:
            _pipeline_status["running"] = False
            _pipeline_status["last_completed"] = datetime.now(UTC).isoformat()
            _pipeline_status["last_status"] = "success"

        duration = (datetime.now(UTC) - _pipeline_start_time).total_seconds()
        if _config:
            try:
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

    except Exception as exc:
        logger.error("Pipeline run failed: %s", exc, exc_info=True)
        with _pipeline_lock:
            _pipeline_status["running"] = False
            _pipeline_status["last_completed"] = datetime.now(UTC).isoformat()
            _pipeline_status["last_status"] = "error"
            _pipeline_status["last_error"] = str(exc)
        try:
            if run_id is not None:
                with db.get_conn() as conn:
                    db.finish_run(conn, run_id, status="error", error_message=str(exc))
        except Exception:
            pass
        if _config:
            notifier.send_failure_alert(_config, str(exc))
    finally:
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
    logger.info("Database ready")

    with db.get_conn() as conn:
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

    _session_serializer = URLSafeTimedSerializer(session_secret)

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
    from urllib.parse import urlencode, urlparse, parse_qs
    parsed = urlparse(str(url))
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [str(value)]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    from urllib.parse import urlunparse
    return urlunparse(parsed._replace(query=new_query))


templates.env.filters["replace_query_param"] = _replace_query_param


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


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------


_SEVERITY_THRESHOLD_SCORES: dict[str, float | None] = {
    "critical": 9.0,
    "high":     7.0,
    "medium":   4.0,
    "low":      0.0,
    "all":      None,  # no minimum score — include all findings
}


def _apply_severity_threshold(findings: list, threshold: str) -> list:
    """Return only the findings at or above the configured severity threshold.

    Findings with no CVSS score are excluded for every threshold except "all",
    since their severity cannot be determined.
    """
    min_score = _SEVERITY_THRESHOLD_SCORES.get(threshold, 7.0)
    if min_score is None:
        return findings
    return [
        r for r in findings
        if r["cvss_score"] is not None and r["cvss_score"] >= min_score
    ]


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
    return d


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
            return any(
                m.get("name", "").startswith(model_base)
                for m in tags.get("models", [])
            )
    except Exception:
        return False


def _get_run_token() -> str:
    try:
        with db.get_conn() as conn:
            return db.get_setting(conn, "run_token", "")
    except Exception:
        return ""


def _get_current_model() -> str:
    try:
        with db.get_conn() as conn:
            stored = db.get_setting(conn, "active_model")
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
        "page":             page,
        "per_page":         per_page,
        "total":            total,
        "total_pages":      total_pages,
        "offset":           (page - 1) * per_page,
        "has_prev":         page > 1,
        "has_next":         page < total_pages,
        "page_size_options": _PAGE_SIZE_OPTIONS,
    }


def _secrets_summary() -> dict:
    """Return per-state counts from secret_findings."""
    try:
        with db.get_conn() as conn:
            return db.get_secret_findings_summary(conn)
    except Exception:
        return {"new": 0, "false_positive": 0, "resolved": 0}


def _findings_summary() -> dict:
    """Return per-severity and per-state counts from the database."""
    try:
        with db.get_conn() as conn:
            row = conn.execute("""
                SELECT
                    SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END)                     AS critical,
                    SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN cvss_score IS NOT NULL AND cvss_score < 4.0 THEN 1 ELSE 0 END) AS low,
                    SUM(CASE WHEN state = 'new'          THEN 1 ELSE 0 END)                 AS new,
                    SUM(CASE WHEN state = 'acknowledged'  THEN 1 ELSE 0 END)                AS acknowledged,
                    SUM(CASE WHEN state = 'resolved'      THEN 1 ELSE 0 END)                AS resolved
                FROM findings
            """).fetchone()
        return {
            "critical":     int(row["critical"] or 0),
            "high":         int(row["high"] or 0),
            "medium":       int(row["medium"] or 0),
            "low":          int(row["low"] or 0),
            "new":          int(row["new"] or 0),
            "acknowledged": int(row["acknowledged"] or 0),
            "resolved":     int(row["resolved"] or 0),
        }
    except Exception:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "new": 0, "acknowledged": 0, "resolved": 0}


# ---------------------------------------------------------------------------
# Login / logout routes (unauthenticated)
# ---------------------------------------------------------------------------


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, next: str = "/") -> HTMLResponse:
    if _get_session(request).get("authenticated"):
        return RedirectResponse(url=next, status_code=302)  # type: ignore[return-value]
    return templates.TemplateResponse(request, "login.html", {"next_url": next, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form(default="/"),
) -> HTMLResponse:
    cfg = _config
    valid = (
        cfg is not None
        and secrets.compare_digest(username.encode(), cfg.dashboard.username.encode())
        and secrets.compare_digest(password.encode(), cfg.dashboard.password.encode())
    )
    if not valid:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"next_url": next_url, "error": "Invalid username or password"},
            status_code=401,
        )
    token = _make_session_token({"authenticated": True, "username": username})
    resp = RedirectResponse(url=next_url if next_url.startswith("/") else "/", status_code=303)
    resp.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=_SESSION_MAX_AGE,
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
    with db.get_conn() as conn:
        findings_rows  = db.get_findings(conn, state="new", limit=10)
        news_rows      = db.get_recent_items(conn, hours=24, limit=15)
        bookmarked_ids = db.get_bookmarked_ids(conn)

    return templates.TemplateResponse(request, "index.html", {
        "nav_active":      "dashboard",
        "run_token":       _get_run_token(),
        "current_model":   _get_current_model(),
        "recent_findings": [_enrich_finding(r) for r in findings_rows],
        "news_items":      [_enrich_news(r) for r in news_rows],
        "summary":         _findings_summary(),
        "secrets_summary": _secrets_summary(),
        "bookmarked_ids":  list(bookmarked_ids),
    })


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """Findings table with filter controls and pagination."""
    with db.get_conn() as conn:
        total = db.get_findings_count(conn, state=state, repo=repo)
        pg = _paginate(page, per_page, total)
        rows = db.get_findings(conn, state=state, repo=repo, limit=pg["per_page"], offset=pg["offset"])
        repo_rows = conn.execute(
            "SELECT DISTINCT repo_full_name FROM findings ORDER BY repo_full_name"
        ).fetchall()

    return templates.TemplateResponse(request, "findings.html", {
        "nav_active":   "findings",
        "run_token":    _get_run_token(),
        "current_model": _get_current_model(),
        "findings":     [_enrich_finding(r) for r in rows],
        "state_filter": state,
        "repo_filter":  repo,
        "repos":        [r["repo_full_name"] for r in repo_rows],
        "pagination":   pg,
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Settings page — run interval + model selection."""
    with db.get_conn() as conn:
        current_interval = db.get_setting(conn, "run_interval_hours", "6")

    return templates.TemplateResponse(request, "settings.html", {
        "nav_active":        "settings",
        "run_token":         _get_run_token(),
        "current_model":     _get_current_model(),
        "current_interval":  current_interval,
        "interval_options":  _INTERVAL_OPTIONS,
        "interval_values":   [v for v, _ in _INTERVAL_OPTIONS],
    })


@app.get("/secrets", response_class=HTMLResponse)
async def secrets_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """Secrets view — leaked credentials detected by gitleaks."""
    with db.get_conn() as conn:
        total = db.get_secret_findings_count(conn, state=state, repo=repo)
        pg = _paginate(page, per_page, total)
        rows = db.get_secret_findings(conn, state=state, repo=repo, limit=pg["per_page"], offset=pg["offset"])
        repo_rows = conn.execute(
            "SELECT DISTINCT repo_full_name FROM secret_findings ORDER BY repo_full_name"
        ).fetchall()

    return templates.TemplateResponse(request, "secrets.html", {
        "nav_active":   "secrets",
        "run_token":    _get_run_token(),
        "current_model": _get_current_model(),
        "secrets":      [dict(r) for r in rows],
        "state_filter": state,
        "repo_filter":  repo,
        "repos":        [r["repo_full_name"] for r in repo_rows],
        "pagination":   pg,
    })


@app.get("/personal", response_class=HTMLResponse)
async def personal_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Personal workspace — bookmarks and annotated findings."""
    with db.get_conn() as conn:
        bookmarks        = db.get_bookmarks(conn)
        annotated        = db.get_annotated_findings(conn)

    enriched_annotated = [_enrich_finding(r) for r in annotated]

    return templates.TemplateResponse(request, "personal.html", {
        "nav_active":    "personal",
        "run_token":     _get_run_token(),
        "current_model": _get_current_model(),
        "bookmarks":     [dict(r) for r in bookmarks],
        "annotated":     enriched_annotated,
    })


@app.get("/history", response_class=HTMLResponse)
async def history_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """History view — trend charts and source reliability."""
    return templates.TemplateResponse(request, "history.html", {
        "nav_active":    "history",
        "run_token":     _get_run_token(),
        "current_model": _get_current_model(),
    })


@app.get("/weekly", response_class=HTMLResponse)
async def weekly_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Weekly summary view — most recent Monday digest."""
    with db.get_conn() as conn:
        digest = db.get_weekly_digest(conn)

    return templates.TemplateResponse(request, "weekly.html", {
        "nav_active":    "weekly",
        "run_token":     _get_run_token(),
        "current_model": _get_current_model(),
        "digest":        digest,
    })


@app.get("/news", response_class=HTMLResponse)
async def news_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    category: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> HTMLResponse:
    """All news items with category/severity/search filters and pagination."""
    with db.get_conn() as conn:
        total = db.get_news_items_count(conn, category=category, severity=severity, search=search)
        pg = _paginate(page, per_page, total)
        rows = db.get_news_items_paginated(
            conn,
            category=category,
            severity=severity,
            search=search,
            limit=pg["per_page"],
            offset=pg["offset"],
        )
        bookmarked_ids = db.get_bookmarked_ids(conn)
        cat_rows = conn.execute(
            "SELECT DISTINCT category FROM news_items WHERE category IS NOT NULL ORDER BY category"
        ).fetchall()

    return templates.TemplateResponse(request, "news.html", {
        "nav_active":       "news",
        "run_token":        _get_run_token(),
        "current_model":    _get_current_model(),
        "news_items":       [_enrich_news(r) for r in rows],
        "bookmarked_ids":   list(bookmarked_ids),
        "categories":       [r["category"] for r in cat_rows],
        "category_filter":  category,
        "severity_filter":  severity,
        "search_filter":    search,
        "pagination":       pg,
    })


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health() -> JSONResponse:
    """Health check — intentionally unauthenticated. Used by Docker HEALTHCHECK."""
    with _pipeline_lock:
        pipeline = dict(_pipeline_status)
    next_run: str | None = None
    if _scheduler:
        job = _scheduler.get_job("pipeline")
        if job and job.next_run_time:
            next_run = job.next_run_time.isoformat()
    ollama_ok = await asyncio.to_thread(_check_ollama_status)
    return JSONResponse({
        "status":       "ok",
        "version":      "0.1.0",
        "pipeline":     pipeline,
        "next_run":     next_run,
        "ollama_ok":    ollama_ok,
    })


@app.post("/api/run")
async def trigger_run(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Trigger an immediate pipeline run.

    Requires HTTP Basic Auth + X-Run-Token header (CSRF protection).
    """
    run_token = request.headers.get("X-Run-Token", "")
    try:
        with db.get_conn() as conn:
            stored_token = db.get_setting(conn, "run_token")
    except Exception:
        stored_token = ""

    if not stored_token or not secrets.compare_digest(run_token, stored_token):
        raise HTTPException(status_code=403, detail="Invalid or missing X-Run-Token")

    with _pipeline_lock:
        if _pipeline_status["running"]:
            return JSONResponse(
                {"status": "already_running", "message": "Pipeline is already in progress"},
                status_code=409,
            )

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
) -> JSONResponse:
    """Return recent news items as JSON."""
    with db.get_conn() as conn:
        rows = db.get_recent_items(conn, hours=min(hours, 720), limit=min(limit, 200))
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
    installed: list[str] = []
    ollama_host = _config.ollama.host if _config else "http://localhost:11434"
    try:
        with httpx.Client(timeout=8) as client:
            resp = client.get(f"{ollama_host}/api/tags")
            resp.raise_for_status()
            data = resp.json()
        installed = [m["name"] for m in data.get("models", [])]
    except Exception as exc:
        logger.warning("Could not reach Ollama for model list: %s", exc)

    return JSONResponse({
        "installed": installed,
        "suggested": _SUGGESTED_MODELS,
        "current":   _get_current_model(),
    })


@app.post("/api/findings/{finding_id}/acknowledge")
async def acknowledge_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
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
) -> JSONResponse:
    """Reopen a resolved or acknowledged finding."""
    with db.get_conn() as conn:
        updated = lifecycle.reopen(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or already new")
    return JSONResponse({"status": "new", "finding_id": finding_id})


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


@app.post("/api/secrets/{finding_id}/false-positive")
async def mark_secret_false_positive(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Mark a secret finding as a false positive — suppresses future re-reporting."""
    with db.get_conn() as conn:
        updated = db.mark_secret_finding_false_positive(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or not in 'new' state")
    return JSONResponse({"status": "false_positive", "finding_id": finding_id})


@app.post("/api/secrets/{finding_id}/resolve")
async def resolve_secret_finding(
    finding_id: int,
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Mark a secret finding as resolved (credential revoked and history cleaned)."""
    with db.get_conn() as conn:
        updated = db.mark_secret_finding_resolved(conn, finding_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or already resolved")
    return JSONResponse({"status": "resolved", "finding_id": finding_id})


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
) -> JSONResponse:
    """Add a new RSS feed after validating it is a reachable RSS/Atom URL."""
    body = await request.json()
    url  = str(body.get("url",  "")).strip()
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
async def toggle_feed(
    feed_id: int,
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Enable or disable a feed. Body: {\"enabled\": true|false}"""
    body = await request.json()
    if "enabled" not in body:
        raise HTTPException(status_code=400, detail="enabled field required")
    with db.get_conn() as conn:
        updated = st.set_feed_enabled(conn, feed_id, bool(body["enabled"]))
    if not updated:
        raise HTTPException(status_code=404, detail="Feed not found")
    return JSONResponse({"status": "updated", "feed_id": feed_id, "enabled": bool(body["enabled"])})


@app.delete("/api/config/feeds/{feed_id}")
async def delete_feed(
    feed_id: int,
    _user: Annotated[str, Depends(_require_auth)],
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
    """Return scanner settings: severity threshold and excluded repos."""
    with db.get_conn() as conn:
        return JSONResponse({
            "severity_threshold": st.get_severity_threshold(conn),
            "excluded_repos":     st.get_excluded_repos(conn),
            "severity_levels":    st.SEVERITY_LEVELS,
        })


@app.post("/api/config/scanner")
async def update_scanner_settings(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
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
    return JSONResponse({"status": "updated"})


def _validate_feed_url(url: str) -> bool:
    """Return True if url is a reachable RSS/Atom feed. Runs in a thread pool."""
    import feedparser
    import httpx as _httpx
    try:
        with _httpx.Client(timeout=10, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
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
        model    = db.get_setting(conn, "active_model", "")
    return JSONResponse({
        "run_interval_hours": interval,
        "active_model":       model or (_config.ollama.model if _config else ""),
    })


@app.post("/api/settings")
async def update_settings(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> JSONResponse:
    """Update pipeline settings: run_interval_hours and/or active_model."""
    body = await request.json()

    if "run_interval_hours" in body:
        try:
            hours = float(body["run_interval_hours"])
            if hours <= 0:
                raise ValueError
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="run_interval_hours must be a positive number")
        with db.get_conn() as conn:
            db.set_setting(conn, "run_interval_hours", str(hours))
        _reschedule(hours)

    if "active_model" in body:
        model = str(body["active_model"]).strip()
        if model:
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
        "id", "repo_full_name", "cve_id", "ghsa_id", "package_name",
        "package_ecosystem", "installed_version", "fixed_version",
        "cvss_score", "is_kev", "patch_available", "priority_score",
        "state", "first_seen_at", "last_seen_at", "resolved_at",
        "manifest_path", "annotation", "github_issue_url",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(dict(r))
    return output.getvalue()


def _news_to_csv(rows) -> str:
    output = io.StringIO()
    fieldnames = [
        "id", "title", "url", "source", "published_at", "fetched_at",
        "summary", "category", "severity", "affected_products", "tags",
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
) -> StreamingResponse:
    """Export all findings as JSON or CSV."""
    with db.get_conn() as conn:
        rows = db.get_findings_for_export(conn)

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
) -> StreamingResponse:
    """Export the full news archive as JSON or CSV."""
    with db.get_conn() as conn:
        rows = db.get_news_items_for_export(conn)

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


# ---------------------------------------------------------------------------
# Data management API
# ---------------------------------------------------------------------------


@app.delete("/api/data/clear")
async def clear_data(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
