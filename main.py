"""
Security Automation — main entrypoint.

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

import logging
import secrets
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import httpx
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from filelock import FileLock, Timeout

import config as cfg_module
import db
import github_scanner as gs
import lifecycle
import notifier

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
    {"name": "qwen2.5:3b",  "description": "Default — fast on Pi 4, ~2 GB"},
    {"name": "qwen2.5:7b",  "description": "Higher quality, needs 8 GB RAM"},
    {"name": "llama3.2:3b", "description": "Meta's compact model"},
    {"name": "phi3:mini",   "description": "Very small and fast"},
    {"name": "mistral:7b",  "description": "Balanced quality / size"},
]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


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
    try:
        with _pipeline_lock:
            _pipeline_status["running"] = True
            _pipeline_status["last_started"] = datetime.now(timezone.utc).isoformat()
            _pipeline_status["last_error"] = None

        _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Pipeline run starting")

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
                    items_collected = stats.items_collected
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
                    items_categorized = cat_stats.items_categorized
                    if cat_stats.uncategorized_warning:
                        logger.warning("Categorizer: >20%% of items fell back to Uncategorized")
                    logger.info(
                        "Categorizer: %d categorized, %d failed",
                        items_categorized,
                        cat_stats.items_failed,
                    )
            except Exception as exc:
                logger.error("Categorizer failed: %s", exc, exc_info=True)
                notifier.send_failure_alert(_config, f"Categorizer error: {exc}")

        # ------------------------------------------------------------------
        # Step 3 — GitHub scanner
        # ------------------------------------------------------------------
        current_finding_keys: set[tuple] = set()
        try:
            with db.get_conn() as conn:
                scan_stats = gs.run(conn, _config)
                findings_new_total = scan_stats.findings_new

                rows = db.get_findings(conn, limit=10_000)
                for row in rows:
                    current_finding_keys.add((
                        row["repo_full_name"],
                        row["package_name"],
                        row["package_ecosystem"],
                        row["cve_id"] or "",
                        row["ghsa_id"] or "",
                    ))

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

        # ------------------------------------------------------------------
        # Step 4 — Lifecycle reconciliation
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
        # Step 5 — Notify (delta only)
        # ------------------------------------------------------------------
        try:
            with db.get_conn() as conn:
                unnotified = db.get_unnotified_findings(conn)
                if unnotified:
                    notifier.send_findings_alert(_config, list(unnotified))
                    db.mark_findings_notified(conn, [r["id"] for r in unnotified])
                    logger.info("Notifier: %d findings alerted", len(unnotified))
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
            _pipeline_status["last_completed"] = datetime.now(timezone.utc).isoformat()
            _pipeline_status["last_status"] = "success"

        logger.info("Pipeline run completed successfully")

    except Exception as exc:
        logger.error("Pipeline run failed: %s", exc, exc_info=True)
        with _pipeline_lock:
            _pipeline_status["running"] = False
            _pipeline_status["last_completed"] = datetime.now(timezone.utc).isoformat()
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
    global _config, _scheduler

    logger.info("Security Automation starting up")

    _config = cfg_module.load()
    logger.info(
        "Configuration loaded (Ollama: %s, model: %s)",
        _config.ollama.host,
        _config.ollama.model,
    )

    db.init()
    logger.info("Database ready")

    # Generate run token if not already stored (CSRF protection for Run Now)
    with db.get_conn() as conn:
        if not db.get_setting(conn, "run_token"):
            db.set_setting(conn, "run_token", secrets.token_hex(32))
            logger.debug("Run token generated")

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
    _scheduler.start()
    logger.info("Scheduler started — pipeline runs every %.1f hours", interval)

    yield

    logger.info("Security Automation shutting down")
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

_security = HTTPBasic()


def _require_auth(
    credentials: Annotated[HTTPBasicCredentials, Depends(_security)],
) -> str:
    """Verify HTTP Basic credentials against config.yaml values."""
    cfg = _config
    if cfg is None:
        raise HTTPException(status_code=503, detail="Server starting up")

    correct_user = secrets.compare_digest(
        credentials.username.encode(), cfg.dashboard.username.encode()
    )
    correct_pass = secrets.compare_digest(
        credentials.password.encode(), cfg.dashboard.password.encode()
    )
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------


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
        diff = (datetime.now(timezone.utc) - dt).total_seconds()
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
# Dashboard HTML routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
) -> HTMLResponse:
    """Main dashboard — recent news + open findings summary."""
    with db.get_conn() as conn:
        findings_rows = db.get_findings(conn, state="new", limit=10)
        news_rows = db.get_recent_items(conn, hours=24, limit=15)

    return templates.TemplateResponse(request, "index.html", {
        "nav_active":      "dashboard",
        "run_token":       _get_run_token(),
        "current_model":   _get_current_model(),
        "recent_findings": [_enrich_finding(r) for r in findings_rows],
        "news_items":      [_enrich_news(r) for r in news_rows],
        "summary":         _findings_summary(),
    })


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    _user: Annotated[str, Depends(_require_auth)],
    state: str | None = None,
    repo: str | None = None,
) -> HTMLResponse:
    """Findings table with filter controls."""
    with db.get_conn() as conn:
        rows = db.get_findings(conn, state=state, repo=repo, limit=500)
        # Distinct repos for the filter dropdown
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
        "nav_active":       "settings",
        "run_token":        _get_run_token(),
        "current_model":    _get_current_model(),
        "current_interval": current_interval,
        "interval_options": _INTERVAL_OPTIONS,
    })


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health() -> JSONResponse:
    """Health check — intentionally unauthenticated. Used by Docker HEALTHCHECK."""
    with _pipeline_lock:
        pipeline = dict(_pipeline_status)
    return JSONResponse({"status": "ok", "version": "0.1.0", "pipeline": pipeline})


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


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
