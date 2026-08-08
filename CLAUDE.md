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

FastAPI + Jinja2 templates in `templates/`, CSS in `static/`. All dashboard routes require an authenticated session — a signed cookie (`itsdangerous.URLSafeTimedSerializer`, 7-day expiry) set by `POST /login`, not HTTP Basic Auth. The API also exposes JSON endpoints under `/api/`.

### Data persistence

- SQLite at `data/dive.db` (WAL mode, created at startup)
- Runtime config (interval, active model) stored in the `settings` KV table — not in `config.yaml`
- `config.yaml` holds secrets only (GitHub token, dashboard password, webhook URLs)
- `rss_feeds` table: user-managed feed list; default feeds are bootstrapped lazily on first read
- `keywords` table: per-user watchlist; highlighted in news feed
- Feature toggles: stored as `toggle.<key>` keys in `settings` table; defaults in `settings.FEATURE_TOGGLES`
- Scanner settings: stored as `scanner.<key>` keys in `settings` table
- `kev_entries` table: the CISA KEV set, independent of `news_items` retention — see M11

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
- All non-health routes require an authenticated session (`_require_auth` dependency — checks a signed session cookie, not HTTP Basic Auth). `POST /login` sets the cookie; it's rate-limited (10 attempts / 15 min per IP, in-memory, resets on restart) and its `next` redirect target is sanitised (`_safe_next()`) against open redirects.
- Mutation endpoints (`POST /api/run` and others) additionally require the `X-Run-Token` header (`_require_csrf` dependency — CSRF protection), read from the same-origin page via the `run-token` meta tag.
- `GET /api/health` is unauthenticated and intentionally minimal (Docker healthcheck target — just `{"status": "ok", ...}`); the full pipeline/status payload lives behind auth at `GET /api/status`. Never move detailed status (repo names, error text, active model) back onto the unauthenticated endpoint.
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
- GitHub rate-limit budget is checked before each repo; dropping below 10% (or a mid-scan `RateLimitExceededException`) stops that scan early — not a hard stop for the *pipeline* (later steps still run) — and logs a warning + sets `ScannerStats.rate_limit_warning` so the gap is visible rather than looking like a clean scan. Unscanned repos are picked up on the next run.

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

**Next-run display:** `GET /api/status` (authenticated) returns `next_run` (ISO timestamp from APScheduler) — this moved off `GET /api/health` when that endpoint was split (see the Security section above). The `base.html` header polls `/api/status` and shows "next run in Xm" via `DIVE.timeUntil()`.

## M8 — Full dashboard views

**New routes:** `GET /history`, `GET /weekly`  
**New API endpoints:** `GET /api/history/news-trend`, `/api/history/findings-trend`, `/api/history/sources`, `/api/history/runs`, `GET /api/weekly`

**History view (`/history`):** stacked-bar chart of news items by severity per day, line chart of new findings per day (both driven by Chart.js 4 from CDN), source reliability table, recent pipeline runs table. Day range selector (7/14/30/90).

**Weekly summary view (`/weekly`):** renders the most recent stored digest — stat row (items collected, new findings, resolved), top-10 findings table with CVSS colour-coding, top-5 most-affected repos. Digest is auto-generated by a Monday 08:00 cron job.

**Weekly digest cron job:** `_run_weekly_digest()` fires via APScheduler `CronTrigger(day_of_week="mon", hour=8)`. Calls `notifier.send_weekly_digest(config, conn)` which builds a snapshot, stores it as `weekly_digest.latest` in the `settings` table, then dispatches to all configured channels.

**Dark mode toggle:** `data-theme="dark|light"` on `<html>`; light-mode CSS variables defined under `[data-theme="light"]` in `style.css`. Preference persisted in `localStorage`; applied before first paint to avoid flash.

**Ollama status indicator:** green/red dot in the header, updated by `pollStatus()`'s poll of `/api/status`, which includes `ollama_ok` (boolean — checks `/api/tags` on the Ollama host and verifies the active model is listed). Polling backs off exponentially on consecutive failures (capped at 60s), shows a "Disconnected" state after 2 misses, and pauses entirely while the tab is hidden (`visibilitychange`).

**Mobile-responsive layout:** hamburger toggle collapses the sidebar into an overlay drawer at ≤980px (paired with a `min-width: 981px` rule that hides the hamburger above that — kept in sync at the same value, zero gap between them). Content reflow (page padding, hero sizing, table card-stacking) uses a separate ≤700px breakpoint, plus a ≤430px sub-breakpoint for a few grids. These are the only three standard breakpoints in `style.css` — don't introduce a fourth without a reason.

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
- **New manifest format**: add to `_MANIFEST_FILENAMES` (exact filename match) or `_MANIFEST_SUFFIXES` (extension match, e.g. `*.csproj`) in `github_scanner.py` and implement a `_parse_<format>()` function. Never let a parser raise — `_parse_manifest`'s blanket `except Exception` will swallow it and silently return `[]`, so write a test rather than relying on that guard to catch a bug.
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

## M11 — UI/UX consolidation, accessibility, and scanner reliability

### Scanner coverage
**Private repos:** both scanners now correctly enumerate private repos via `gh.get_user().get_repos(type="all")` (the authenticated-user endpoint). `secrets_scanner.py` previously used `gh.get_user(username).get_repos()` — the *named*-user endpoint, which only ever returns public repos regardless of token scope. If you're adding a third scanner that lists repos, use the authenticated-user pattern; the tests for both existing scanners assert `get_user` is called with no arguments specifically to catch this regressing.

**New manifest formats** (`github_scanner.py`): `yarn.lock` (v1 custom format and v2+ YAML, detected by a `__metadata` key), `pnpm-lock.yaml`, `poetry.lock` / `uv.lock` (TOML `[[package]]` blocks, shared parser), `composer.json` / `composer.lock`, `packages.lock.json`, and `*.csproj` (NuGet — matched by **suffix**, not exact filename, via `_MANIFEST_SUFFIXES`; the exact-filename table is `_MANIFEST_FILENAMES`). Lock-file preference (prefer the lock file over the manifest when both exist) now also covers yarn/pnpm vs `package.json` and poetry/uv vs `pyproject.toml`.

**`kev_entries` table:** the CISA KEV set used to be derived from `news_items WHERE source = 'CISA KEV'`, so clearing news history (or `news.retention_days`) silently flipped `is_kev` to 0 on every finding. `kev_entries` (`cve_id, added_at, first_seen_at`) is a dedicated table the collector upserts into and retention pruning never touches; `db.get_kev_cve_ids()` reads from it, falling back to the old `news_items` query only if `kev_entries` is empty (first run after upgrade).

### Frontend architecture
**`static/app.js`** — loaded once from `base.html` *without* `data-pjax`, so it survives in-app navigation (the pjax router only re-executes scripts after the `#page-scripts-fence` sentinel). Exposes shared helpers under `window.DIVE` instead of each page redefining its own: `apiFetch`, `showToast`, `timeAgo`, `timeUntil`, `escapeHtml`, `setPageSize`, `toggleBookmark`, `confirmModal`, `openModal`/`closeModal`, `setFieldError`/`clearFieldError`. Add new cross-page utilities here, not inline in a template's `{% block scripts %}`.

**Modal component** — every modal is `.modal-backdrop > .modal-panel`, toggled via the `open` class (see `static/style.css`). `DIVE.openModal(id)` / `DIVE.closeModal(id)` are the *only* way to open/close one: they handle the Tab focus trap, restore focus to the triggering element on close, and are wired once to backdrop-click/Escape dismissal for every current and future modal — don't hand-roll `classList.add('open')` elsewhere. `templates/base.html`'s pjax router also exposes `DIVE.refreshPage()`, which re-fetches and swaps `.page-main` in place; use it after a mutation instead of `location.reload()` (which drops pjax state and resets scroll).

**Tooltip component** — `[data-tip]="..."` on any element gets a hover/focus-revealed bubble (see `static/style.css`, adapted from `designs/colorion-css-tooltips` under its MIT license). Don't use it inside anything with `overflow:hidden` between the trigger and the viewport edge (a truncated table cell, for instance) — the popup gets clipped; use `title=""` there instead. Table headers get a `thead [data-tip]` downward-popping variant automatically (their enclosing `.card`'s `overflow:hidden`, there to round the table's corners, clips the default upward pop). Elements near a container's right edge may need a per-selector right-anchor override like `.badge-kev[data-tip]` — see that rule for the pattern.

**Toggle switch** — `.dive-switch` (a `<span class="dive-switch"><input type="checkbox">…<span class="track"><span class="thumb"></span></span></span>` structure) replaces raw `<input type="checkbox">` + `accent-color` for boolean settings. Written from scratch, not adapted from any `designs/` library (none of the toggle/button/loader/animation libraries there have a verifiable LICENSE file — only `colorion-css-tooltips` does).

**Responsive tables** — the one supported pattern is `.table-stack` + `data-label="Column Name"` on every `<td>`: below 700px, `<thead>` hides and each cell becomes a label/value row via `::before { content: attr(data-label) }`. Don't hide columns by `nth-child` position (drops data with no disclosure) and don't rely on `.table-wrap`'s horizontal scroll as the *only* strategy for a data table — pick `.table-stack` unless there's a specific reason not to. Grid/flex items default to `min-width: auto` (never shrink below content), so a card containing a `.table-stack` needs `min-width: 0` set explicitly at the breakpoint or a wide badge can push the whole grid wider than the viewport — see the `.card, .panel { min-width: 0; }` rule inside the 700px block.

**Breakpoints** — exactly three standard values in `static/style.css`: 700 (content reflow), 980 (tablet / sidebar-collapse-to-hamburger), 1200 (wide). Plus one legitimate sub-breakpoint at 430px for a couple of dense grids. Don't add a new one-off value; fit into one of these three, and if two rules at the same breakpoint must fire in a specific order relative to each other (a min-width/max-width pair, or a "collapse further" cascade), keep them at the *same* pixel value on both sides — a 900px max-width paired with a 901px min-width, for instance, is fragile if only one side ever gets touched again.

**Kinetic easing** — `cubic-bezier(0.34, 1.56, 0.64, 1)` (bouncy overshoot, row hover / drawer slide) and `cubic-bezier(0.16, 1, 0.3, 1)` (gentle decel, modal entrance) replace flat `ease`/`linear` transitions in a few places. These are bare numeric values (not copyrightable expression), inspired by `designs/kinetics` but not copied from it (that repo has no LICENSE file either).

## M12 — Pipeline reliability and notifier hardening

**NVD API key placement:** `collector._fetch_nvd()` sends `config.nvd.api_key` as the `apiKey`
**request header**, never a query parameter — the live NVD API returns HTTP 404 on every request
when the key is passed as `?apiKey=...` instead. Header placement also keeps the key out of any
URL-based logging.

**Collector User-Agent:** `_make_client()` identifies honestly by default
(`_DEFAULT_UA = "DIVE-security-monitor/1.0 ..."`). A spoofed browser UA is not used as the default —
some WAFs fingerprint the TLS handshake and flag a UA claiming to be Chrome that doesn't match
Chrome's real fingerprint as bot impersonation (this is why Bleeping Computer's feed 403'd under the
old default UA while every other feed worked fine either way). `_safe_get()` retries a `403` exactly
once with `_BROWSER_UA` as a fallback (merged into, not replacing, any caller-supplied headers such
as GHSA's `Authorization`), for the rare host that actually rejects non-browser agents.

**`httpx`/`httpcore` logging:** pinned to `WARNING` in `main.py` (right after `logging.basicConfig`).
Both log every request URL at `INFO`, which the SQLite log handler captures — that wrote ~160 rows
per pipeline run into `log_entries`, and would carry any credential embedded in a URL into the
database in plaintext.

**Slack section-block chunking:** `notifier._section_blocks()` packs finding/secret lines across as
many `section` blocks as needed instead of one unbounded block. Slack caps a section's `text.text`
at 3000 characters and a message at 50 blocks; a single oversized block silently fails delivery with
`invalid_payload`. Both `_build_slack_blocks()` and `_build_secrets_slack_blocks()` call this helper
— never reassemble the single-block form, and never "fix" an over-limit alert by lowering
`MAX_FINDINGS_PER_ALERT` (the limit is a function of line length, not count).

**Token-permission diagnostics:** `github_scanner.probe_private_repo_access()` checks read access on
one private repo (skipped entirely if the account has none) and returns a single actionable message
on a 403 — a fine-grained PAT can read a private repo's metadata while lacking the separate
`Contents: Read-only` scope needed for its file tree, which otherwise surfaces as a bare 403 per repo
with no explanation. Both `github_scanner.run()` and `secrets_scanner.run()` call it once per run and
store the result on `ScannerStats.token_permission_warning` / `ScanStats.token_permission_warning`,
rendered in the pipeline drawer. `secrets_scanner._clone()` also returns git's stderr on failure (the
embedded access token redacted unconditionally before it can reach a log line) instead of discarding it.

**Drawer failed-list expand state:** lives in the client-side `_drawerExpanded` Set (keyed by
`"<stepKey>:<label>"`), not the DOM — `updatePipelineDrawer()` rebuilds `#drawer-steps` via
`innerHTML` on every status poll (5s idle / 2s during a run), which would otherwise destroy an
`open` class the instant the next poll landed. Toggling goes through one delegated `click` listener
registered once on `#drawer-steps`, never re-registered inside `updatePipelineDrawer()`. A
`_drawerRenderSig` guard also skips the `innerHTML` rebuild entirely when nothing in
`step_history`/`step_stats`/`step_progress`/`step_times`/`current_step`/`running`/`last_status`/
`last_completed`/`last_error`/`run_duration_s` changed since the last render — placed after the
state-label and drawer open/close logic, which must run unconditionally on every poll.

## M13 — Progress-total accuracy and actionable clone-failure diagnostics

**Collector progress denominator:** `collector.run()` used to call `on_progress(_sources_done,
_sources_done)` on every tick — the same counter as both numerator and denominator — so the pipeline
drawer rendered a moving target (`1/1`, `2/2`, `3/3`, ...) instead of a real fraction. `run()` now
fetches `settings.get_enabled_feeds(conn)` before starting and computes a fixed
`total_sources = len(feeds) + 3` (RSS feeds + NVD + KEV + GHSA) up front, primes the drawer with
`(0, total_sources)`, and every tick reports that constant total. `_run_rss()` takes the
already-fetched `feeds` list via a keyword arg instead of re-querying it. Any new source group added
to the collector must be counted in `total_sources`, not left to an ad-hoc tick.

**`github_scanner` progress denominator:** `total_repos` was `len(repos)` measured *before*
excluding repos, so a run with any excluded repos configured stalled short of 100% — excluded repos
were skipped inside the loop without incrementing the numerator. `run()` now filters to `scannable`
repos first and measures `total_repos` from that list; progress also counts failed and skipped repos
toward the numerator (not just successfully-scanned ones) so a run with failures still reaches
`done == total`.

**Gitleaks clone failures now translate GitHub's misleading 403 message.** `git clone` over HTTPS
only needs read access, but GitHub's git-over-HTTPS endpoint returns the generic string `remote:
Write access to repository not granted` for *any* 403 — including a fine-grained PAT that is simply
missing `Contents: Read-only` (or a classic PAT missing the `repo` scope). `secrets_scanner.py`'s
`_explain_clone_failure()` maps that (and repo-not-found / bad-token) stderr patterns to a
remediation string; do not "fix" future reports of this message by telling users to grant write
access — that scope is never required for cloning. The remediation is threaded through a
`_CloneFailed` exception (subclasses `RuntimeError`, preserving the `"git clone failed for X:
detail"` message so existing tests matching on `RuntimeError` keep passing) and surfaces in two
places: appended inline to the `failed_repos` entry for that repo, and — unless
`probe_private_repo_access()` already set a warning, which takes priority as the more specific
signal — as `ScanStats.token_permission_warning`. A missing `gitleaks` binary and a per-repo
`subprocess.TimeoutExpired` also now set an actionable message instead of failing silently or as a
bare repo name.

**No `secrets_scanner` failure is ever reported as a bare repo name.** Every branch of `run()`'s
per-repo `except` chain (`_CloneFailed` → `_GitleaksFailed` → `subprocess.TimeoutExpired` →
`Exception`, in that order — `_CloneFailed` and `TimeoutExpired` are unrelated exception types, so
this ordering is not load-bearing, but keep it) appends a reason to `failed_repos`, not just
`repo.full_name`. An unrecognised clone failure falls back to `_condense_detail(exc.detail)`, which
picks git's `fatal:` line out of multiline stderr; the generic catch-all includes the exception type
and message. **`TimeoutExpired.cmd` for a clone timeout is the real argv, which embeds a live
access token in the clone URL** — `_clone()`'s redaction only covers the non-timeout failure path —
so only `exc.cmd[0]` (the binary name, to distinguish a git-clone timeout from a gitleaks-scan
timeout) may ever be read from it; never interpolate `exc.cmd`, `str(exc)`, or `exc.args` into a
message, a log line, or `failed_repos`.

**A crashed gitleaks run is a failure, not a clean scan.** `_run_gitleaks()` used to return `[]` on
a non-0/1 exit code and on a malformed report, so `_scan_repo` returned 0 and the repo was counted
in `repos_scanned` with zero findings — indistinguishable from a repo that is actually clean. It now
raises `_GitleaksFailed` for those cases (still returning `[]` only for the two genuine no-findings
cases: an empty report, or valid JSON that isn't a list), which `run()` turns into a `failed_repos`
entry. This is a deliberate behavior change: repos hitting this path move from `repos_scanned` into
`failed_repos`, so the drawer's counts will shift for anyone currently affected.

**`db.upsert_secret_finding()` now checks `fingerprint` as a fallback dedup key, not just
`match_key`.** This bug was found *by* the above changes, on a live run: `secret_findings.fingerprint`
is the column with the actual `UNIQUE` constraint, but the dedup lookup only checked `match_key`
(deliberately commit-independent — see the docstring). gitleaks can report two entries for the exact
same commit/file/rule/line with a different `secret_type` description; those get different
`match_key`s (which includes `secret_type`) but the *same* `fingerprint` (which doesn't), so the
second `INSERT` raised `sqlite3.IntegrityError` instead of being recognized as the same row. The
lookup now falls back to a `fingerprint`-keyed `SELECT` when `match_key` misses, and the `UPDATE`
path also refreshes `match_key`/`secret_type`/`rule_id` (previously only `commit_sha`/`line_number`/
`fingerprint`), so a row never ends up with a `match_key` that describes a different `secret_type`
than what's actually stored.

**The SQLite log handler gets a much longer `busy_timeout`, plus a retry, instead of dropping the
record.** `_SQLiteLogHandler.emit()` previously treated `sqlite3.OperationalError` ("database is
locked") the same as a permanently broken connection — one failed insert and the record was gone,
`self._dropped` incremented, with no consumer anywhere. A pipeline step can hold a write transaction
open across its **entire run**, not just briefly — `db.upsert_secret_finding()` never commits
mid-loop, so `secrets_scanner.run()`'s `with db.get_conn() as conn:` in `main.py` keeps one
transaction open for the whole scan. A live 15-repo run measured this at 48.9s, and lost exactly the
`ERROR` row for the repo that failed mid-scan even with a first-pass fix that only added a short
Python-level retry on top of `_make_connection()`'s 5s default `busy_timeout` (~15.75s worst case
total — still nowhere near 48.9s). The fix is `_LOG_CONN_BUSY_TIMEOUT_MS` (60s): this handler's
`_get_conn()` overrides the busy_timeout **only on its own dedicated connection**, via `PRAGMA
busy_timeout=<ms>` right after opening it — request and pipeline connections keep the 5s default
from `_make_connection()`. This connection runs only on the `QueueListener` thread, which has
nothing else to do but wait, so a long per-attempt block (and `_LOG_INSERT_ATTEMPTS` of them) cannot
stall a request or the pipeline. **This mitigates, it does not eliminate** — a step that holds the
lock longer than the combined retry budget will still drop a record. That is exactly why `log_drops`
exists: the drop count is surfaced in the authenticated `GET /api/status` payload (via
`_get_dropped_log_count()`) and rendered in the drawer summary when non-zero — **never add it to
`GET /api/health`**, which is deliberately minimal. Confirmed live: the drawer showed "1 log
record(s) dropped" for the exact run where this happened, so the operator sees the gap instead of a
silent one. Do not "fix" this by raising SQLite's **global** `busy_timeout` — that slows every
request thread to solve a logging-thread problem; only this handler's connection should ever get a
non-default value.

## M14 — Idle categorization

**Background catch-up job:** `main._run_idle_categorize()` categorizes one batch of pending news
items on a configurable interval (`idle_categorize_interval_minutes` setting, default 15, clamped
5–1440 by `settings.get/set_idle_categorize_interval_minutes()`) whenever the pipeline is not
running. Off by default — gated behind the `idle_categorization` feature toggle (also requires
`llm_categorizer` to be on) so a Pi-class host is never surprised by background Ollama load.
Registered unconditionally as an APScheduler job (`id="idle_categorize"`); the toggle check happens
inside the job body, not at registration, so flipping the toggle takes effect on the next tick
without a scheduler restart. `POST /api/config/scanner`'s `idle_categorize_interval_minutes` field
calls `_reschedule_idle_categorize()` immediately, mirroring how `run_interval_hours` reschedules
the pipeline job.

**`categorizer.run()` gained a `max_items` parameter** (default `None` → the existing 500-item
pipeline cap). Passing `max_items=batch_size` makes the existing per-batch loop run exactly once,
which is how the idle job caps itself to a single small batch per tick instead of draining the
whole backlog.

**Deliberately does not hold the pipeline file lock (`_LOCK_FILE`) for the duration of the batch** —
it only acquires-and-immediately-releases it to detect a running pipeline, then holds its own
separate `_IDLE_CATEGORIZE_LOCK_FILE` for the batch. Holding `_LOCK_FILE` itself would make the next
scheduled pipeline trigger see "already running" and skip an entire run (up to `run_interval_hours`
of lost coverage — collector, scanner, secrets, notify, everything) just to prevent the small chance
of one duplicated batch. The accepted residual race: a pipeline run can start between the idle job's
probe and its batch finishing, and both can select the same rows. `db.update_item_categorization` is
an id-keyed `UPDATE`, so the only cost is one batch of duplicated Ollama work, never corrupted state.
Do not "fix" this race by having the idle job hold `_LOCK_FILE` — that trade is worse than the race.

## Deployment targets

Designed to run on low-power hardware (Raspberry Pi 4, 8 GB). The default Ollama model (`qwen2.5:3b`, ~2 GB) is chosen for Pi compatibility. See `docs/models.md` for alternatives and `docs/` for platform-specific setup guides.
