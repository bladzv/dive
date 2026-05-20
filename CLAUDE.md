# DIVE — AI Instructions

DIVE (Dependency Intelligence for Vulnerability Exposure) is a self-hosted Python app that aggregates security news and scans GitHub repositories for vulnerable dependencies, then delivers alerts via Slack, Discord, or email.

## Architecture

### Pipeline (runs on a configurable interval via APScheduler)

```
collector → categorizer → github_scanner → github_issue_creator → secrets_scanner → lifecycle → notifier
```

1. **collector** — fetches RSS feeds, NIST NVD CVEs, CISA KEV, and GitHub Security Advisories into `news_items`
2. **categorizer** — sends uncategorized news to a local Ollama model in batches of 10 for AI triage
3. **github_scanner** — lists all user repos, parses dependency manifests, queries OSV.dev in 500-item batches, upserts `findings`
4. **github_issue_creator** — (step 3.5, off by default) creates `[Security]`-prefixed GitHub issues for new findings; skips if an open issue for the same vuln already exists; stamps `github_issue_url` on the finding row
5. **lifecycle** — reconciles finding states after each scan (new → resolved when gone, resolved → new on regression)
6. **notifier** — sends delta alerts (unnotified findings only) to configured channels

### Key modules

| File | Responsibility |
|---|---|
| `main.py` | FastAPI app, APScheduler setup, HTTP routes, pipeline orchestration |
| `config.py` | Load and validate `config.yaml`; all secrets live here |
| `db.py` | SQLite schema, parameterised query functions, connection management |
| `settings.py` | SQLite-backed user preferences (feeds, keywords, toggles, scanner settings) |
| `collector.py` | RSS/NVD/KEV/GHSA ingestion |
| `categorizer.py` | Ollama batch categorization |
| `github_scanner.py` | GitHub + OSV.dev vulnerability scanning |
| `secrets_scanner.py` | gitleaks-based secrets scanning with false-positive suppression |
| `github_issue_creator.py` | GitHub issue auto-creation for new findings (M10, off by default) |
| `lifecycle.py` | Finding state machine (new / acknowledged / resolved) |
| `notifier.py` | Slack, Discord, SMTP delivery |

### Web UI

FastAPI + Jinja2 templates in `templates/`, CSS in `static/`. All dashboard routes require HTTP Basic Auth. The API also exposes JSON endpoints under `/api/`.

### Data persistence

- SQLite at `data/security_automation.db` (WAL mode, created at startup)
- Runtime config (interval, active model) stored in the `settings` KV table — not in `config.yaml`
- `config.yaml` holds secrets only (GitHub token, dashboard password, webhook URLs)
- `rss_feeds` table: user-managed feed list; default feeds are bootstrapped lazily on first read
- `keywords` table: per-user watchlist; highlighted in news feed
- Feature toggles: stored as `toggle.<key>` keys in `settings` table; defaults in `settings.FEATURE_TOGGLES`
- Scanner settings: stored as `scanner.<key>` keys in `settings` table

## Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp config.yaml.example config.yaml && chmod 600 config.yaml
# Fill in github.token, github.username, dashboard.password

# Run locally
uvicorn dive.main:app --reload --port 8000

# Lint and format
ruff check .
black .

# Tests (unit only — no external deps required)
pytest tests/ --ignore=tests/integration -v

# Integration tests (require live GitHub token and Ollama)
pytest tests/integration/ -v

# Dependency audit
pip-audit -r requirements.txt
```

### Docker

```bash
docker compose up --build        # build and start app + ollama
docker compose exec app python -m pytest tests/ --ignore=tests/integration
```

## CI (`.github/workflows/ci.yml`)

On every push/PR to `main`: ruff → black check → pip-audit → pytest unit tests → docker build.

## Critical constraints

### Security
- **Never use `yaml.load()`** — always `yaml.safe_load()`. Arbitrary-code RCE risk.
- **All DB queries must use parameterised statements** — no string interpolation into SQL.
- All non-health routes require HTTP Basic Auth (`_require_auth` dependency).
- `POST /api/run` additionally requires `X-Run-Token` header (CSRF protection).
- `config.yaml` must never be committed. It is gitignored and `.dockerignore`d.
- The Dockerfile deletes `config.yaml` as a second line of defence.
- Ollama's port 11434 is intentionally not published in `docker-compose.yml`.

### Concurrency
- The pipeline uses a `filelock` (`data/.pipeline.lock`) to prevent concurrent runs across processes.
- `_pipeline_lock` (threading.Lock) guards the in-memory status dict.
- Each DB function opens its own connection — no shared connection objects.

### Resilience
- Each pipeline step catches exceptions independently so a failed step doesn't abort the rest.
- A failed notification channel does not prevent delivery to other channels.
- GitHub rate-limit budget is checked at scan start; a warning is logged (not a hard stop) when below 10%.

## M6 — Secrets scanner

`secrets_scanner.py` wraps the `gitleaks` binary (must be on `$PATH`; installed by Dockerfile).

**Pipeline placement:** Step 4, between the GitHub dep scanner and lifecycle reconciliation. Notification fires immediately (within the same pipeline run) rather than being batched with findings.

**DB table:** `secret_findings` — keyed on gitleaks `Fingerprint` (`commit:file:rule:line`). States: `new` / `false_positive`. False-positive fingerprints are read at scan start and silently skipped on every subsequent run.

**Configurable depth:** `secrets_scan_depth` setting in the `settings` table (default 30). Controls `git clone --depth`.

**Scan depth:** repos are shallow-cloned (`--depth N+1`); gitleaks scans all commits in the clone. Actual secret values are redacted in the report (`--redact`) — only metadata is stored.

**Routes added:** `GET /secrets`, `GET /api/secrets`, `POST /api/secrets/{id}/false-positive`.

**gitleaks version:** pinned to v8.18.4 in Dockerfile. Supports linux/amd64, linux/arm64, linux/armv7 (Raspberry Pi).

## M7 — Configuration Dashboard

`settings.py` owns all non-secret runtime preferences. The `settings` table is a simple KV store; `rss_feeds` and `keywords` are first-class tables.

**Settings page (`/settings`) sections:**
1. **Pipeline Schedule** — `run_interval_hours` saved via `POST /api/settings`; custom interval option reveals a number input
2. **Feature Toggles** — all keys in `FEATURE_TOGGLES`; `GET/POST /api/config/toggles`
3. **RSS Feeds** — table of all feeds; `GET/POST /api/config/feeds`, `PATCH/DELETE /api/config/feeds/{id}`
4. **Keyword Watchlist** — tag chips; `GET/POST /api/config/keywords`, `DELETE /api/config/keywords/{id}`
5. **Scanner Settings** — severity threshold + excluded repos; `GET/POST /api/config/scanner`
6. **Ollama Model** — shows installed/suggested models from `GET /api/ollama/models`; active model saved via `POST /api/settings`

**Feed validation:** `POST /api/config/feeds` validates the URL by fetching it and confirming feedparser can parse at least one entry. This is a blocking operation run via `asyncio.to_thread()` to avoid blocking the event loop.

**Default feed protection:** Default feeds (`is_default=1`) can be disabled but never deleted. `settings.remove_feed()` raises `ValueError`; the API converts this to HTTP 409.

**Next-run display:** `GET /api/health` returns `next_run` (ISO timestamp from APScheduler). The `base.html` header polls this and shows "next run in Xm" via `timeUntil()`.

## M8 — Full dashboard views

**New routes:** `GET /history`, `GET /weekly`  
**New API endpoints:** `GET /api/history/news-trend`, `/api/history/findings-trend`, `/api/history/sources`, `/api/history/runs`, `GET /api/weekly`

**History view (`/history`):** stacked-bar chart of news items by severity per day, line chart of new findings per day (both driven by Chart.js 4 from CDN), source reliability table, recent pipeline runs table. Day range selector (7/14/30/90).

**Weekly summary view (`/weekly`):** renders the most recent stored digest — stat row (items collected, new findings, resolved), top-10 findings table with CVSS colour-coding, top-5 most-affected repos. Digest is auto-generated by a Monday 08:00 cron job.

**Weekly digest cron job:** `_run_weekly_digest()` fires via APScheduler `CronTrigger(day_of_week="mon", hour=8)`. Calls `notifier.send_weekly_digest(config, conn)` which builds a snapshot, stores it as `weekly_digest.latest` in the `settings` table, then dispatches to all configured channels.

**Dark mode toggle:** `data-theme="dark|light"` on `<html>`; light-mode CSS variables defined under `[data-theme="light"]` in `style.css`. Preference persisted in `localStorage`; applied before first paint to avoid flash.

**Ollama status indicator:** green/red dot in the header, updated by the 5-second `pollStatus()` poll from `/api/health` which now includes `ollama_ok` (boolean — checks `/api/tags` on the Ollama host and verifies the active model is listed).

**Mobile-responsive layout:** hamburger toggle collapses nav vertically on ≤600 px screens. Nav is horizontally scrollable on medium screens. Status text and model chip hidden on small screens.

## M9 — Bookmarks, Annotations & Data Export

**Bookmarks:** `bookmarks` table (`id, news_item_id UNIQUE REFERENCES news_items ON DELETE CASCADE, created_at`). Toggle via `POST /api/news/{id}/bookmark` — single idempotent endpoint that adds or removes and returns `{"bookmarked": bool}`. Dashboard initialises bookmark state from `db.get_bookmarked_ids(conn)` passed to the template.

**Annotations:** `annotation TEXT` column added to `findings` via `_migrate()` (`ALTER TABLE findings ADD COLUMN annotation TEXT`). Set via `POST /api/findings/{id}/annotate` with `{"annotation": "..."}` body; blank string clears. Shown inline in the findings table under the package name.

**Personal view (`/personal`):** lists bookmarked news items (with Remove button) and annotated findings. Export buttons for both sections.

**Data export:**
- `GET /api/export/findings?format=json|csv` — all findings; CSV via `_findings_to_csv()` helper using `csv.DictWriter` + `io.StringIO`, returned as `StreamingResponse` with `Content-Disposition: attachment`
- `GET /api/export/news?format=json|csv` — all news items; same pattern via `_news_to_csv()`

**Feed analytics:** `GET /api/history/feed-analytics?days=N` returns per-source item counts per day; uses `LEFT JOIN` so feeds with zero items in the window still appear. Rendered as a stacked-bar Chart.js chart in `/history` with a summary totals table below.

## Adding a new feature

- **New notification channel**: add a config dataclass in `config.py`, implement `_send_<channel>()` in `notifier.py`, wire into `_dispatch()`.
- **New manifest format**: add to `_MANIFEST_FILENAMES` in `github_scanner.py` and implement a `_parse_<format>()` function.
- **New RSS source**: add to `DEFAULT_FEEDS` in `settings.py` (not `collector.py`) — these seed the `rss_feeds` table on first boot.
- **New feature toggle**: add an entry to `FEATURE_TOGGLES` in `settings.py`; check it in the pipeline with `st.is_feature_enabled(conn, "<key>")`.
- **New API endpoint**: add route in `main.py`, add the corresponding DB query in `db.py`.

## Testing conventions

- Unit tests in `tests/` — mock all external I/O (GitHub API, HTTP, Ollama).
- Integration tests in `tests/integration/` — require live credentials and services; excluded from CI.
- Override the DB path with `DB_PATH` env var in tests to avoid writing to `data/`.
- `tests/test_project_structure.py` asserts structural invariants (required files present, secrets not committed).

## M10 — GitHub Issue Auto-Creation

`github_issue_creator.py` creates `[Security]`-prefixed GitHub issues for new vulnerability findings.

**Feature toggle:** `github_issue_creation` in the `settings` table (default off). Enable via the Settings → Feature Toggles UI.

**Pipeline placement:** Step 3.5, between `github_scanner` and `secrets_scanner`. Runs only when the toggle is on.

**Deduplication:** before creating an issue, the module iterates open issues in the target repo and skips creation if any open issue has the exact same `[Security] <vuln-id> in <package>` title. This prevents duplicate issues across pipeline runs.

**Issue format:**
- Title: `[Security] CVE-2024-1234 in requests`
- Body: structured Markdown table (vuln ID with NVD/GHSA link, package + ecosystem, installed/fixed versions, CVSS + severity, CISA KEV status) + AI next steps section when `ai_next_steps` is present
- Label: `security` (created in the repo automatically if absent)

**DB column:** `github_issue_url TEXT` added to `findings` via `_migrate()`. Once an issue is created (or confirmed a duplicate) the URL is stamped on the row so the query `get_findings_for_issue_creation()` never returns that finding again.

**Persistence model:** `db.get_findings_for_issue_creation(conn)` returns `state = 'new' AND github_issue_url IS NULL`. Skipped-duplicate findings are left with `github_issue_url = NULL` so they are re-checked next run (handles the case where the open issue was closed and then re-opened).

**Release workflow:** `.github/workflows/release.yml` builds and pushes a multi-arch Docker image (`linux/amd64` + `linux/arm64`) to `ghcr.io` on every `v*` tag, then creates a GitHub Release with the matching CHANGELOG excerpt.

## Deployment targets

Designed to run on low-power hardware (Raspberry Pi 4, 8 GB). The default Ollama model (`qwen2.5:3b`, ~2 GB) is chosen for Pi compatibility. See `docs/models.md` for alternatives and `docs/` for platform-specific setup guides.
