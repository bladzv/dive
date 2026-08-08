# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

#### M11 — UI/UX overhaul, accessibility, and scanner reliability
- Manifest parsers: `yarn.lock` (v1 and v2+ formats), `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `composer.json`/`composer.lock`, `packages.lock.json`, and `*.csproj` (NuGet, matched by suffix)
- `kev_entries` table — the CISA KEV set now survives `news_items` retention pruning, which previously flipped `is_kev` to 0 on every finding once matching news rows aged out
- `GET /api/status` (authenticated) — full pipeline/runtime status, split out of `/api/health`
- `static/app.js` — shared `window.DIVE` namespace (`apiFetch`, `showToast`, `openModal`/`closeModal`, `setFieldError`/`clearFieldError`, and more), loaded once and persisted across in-app navigation
- One shared modal component (`.modal-backdrop`/`.modal-panel` + `DIVE.openModal`/`closeModal`) with a Tab focus trap and focus restore, replacing three separate hand-rolled modal implementations
- `[data-tip]` tooltip component (adapted from `designs/colorion-css-tooltips`, MIT-licensed) for severity badges and abbreviated column headers
- `.dive-switch` toggle-switch component replacing raw checkboxes on the Settings feature-toggle list and RSS feed rows
- `.table-stack` responsive-table pattern (`data-label` card-stacking) as the one standardised mobile-table strategy
- A real `<h1>` (visually hidden via a new `.sr-only` utility where the topbar already shows the title) on every page
- Login rate limiting (10 attempts / 15 minutes per IP, in-memory)
- Inline field validation (`DIVE.setFieldError`/`clearFieldError`) for the scanner settings fields
- Vendored Inter/JetBrains Mono fonts and Chart.js — the dashboard now makes zero third-party network requests
- Kinetic easing-curve micro-interactions (row hover, drawer slide, toast entrance, modal entrance) and a distinct treatment for the primary RUN action

### Changed
- **Both scanners now correctly enumerate private repos** via the authenticated-user endpoint (`gh.get_user().get_repos(type="all")`); the secrets scanner previously used the named-user endpoint, which only ever returns public repos
- `/api/health` reduced to a minimal, unauthenticated `{"status": "ok"}` payload; full pipeline status moved to the new authenticated `/api/status`
- Toast notifications are now announced to screen readers (`role="status"`/`role="alert"`, `aria-live`)
- Post-mutation UI updates (acknowledge/resolve findings, mark/unmark false-positive secrets, annotate) refresh via a pjax-aware `DIVE.refreshPage()` instead of `location.reload()`, preserving scroll position and in-app navigation state
- History charts and the dashboard's repo-concentration donut read colours live from theme CSS variables and redraw on theme toggle, instead of going stale until the next reload
- CSS breakpoints consolidated from 7 distinct values across 12 `@media` blocks down to 3 standard tiers (700/980/1200px) plus one legitimate 430px sub-breakpoint
- A global `:focus-visible` ring now covers buttons, links, and custom interactive elements — previously the only focus style in the entire stylesheet was on form inputs

### Fixed
- `UnboundLocalError` in the pipeline's secrets-scanner step aborted lifecycle reconciliation and notifications for the rest of that run whenever the secrets scanner itself failed
- `FileLock` was constructed before its parent directory existed, raising an uncaught `FileNotFoundError` on a fresh install instead of the intended `Timeout`
- NVD collector could loop forever if the API returned an empty page with a nonzero total
- GitHub Security Advisory collector only ever fetched the first page of results
- `/logs` rows-per-page control stopped working after any in-app (pjax) navigation to the page
- `POST /api/run` could report `started` for a run a concurrent request had already rejected (a race on the in-memory running flag)
- Manifests over 1MB (the GitHub Contents API's limit) were silently dropped — large `package-lock.json`/`Gemfile.lock` files now fetch via the Git Blobs API instead
- `pnpm-lock.yaml` parsing mis-split package names with a peer-dependency suffix (e.g. `react-dom@18.2.0(react@18.2.0)`)
- Several missing indexes on `findings`/`secret_findings` columns used in every list/export query's `ORDER BY`
- OSV.dev query pagination and `github_issue_creator`'s N+1 repo/issue-list fetch pattern
- A tooltip on the KEV badge could clip past the table card's right edge
- NIST NVD collector returned HTTP 404 on every request — the API key must be sent as a request header (`apiKey`), not a query parameter, so zero CVEs were ever ingested from NVD
- Bleeping Computer's feed returned HTTP 403 — the collector's spoofed browser User-Agent was getting flagged by TLS-fingerprint WAF checks; the collector now identifies honestly by default and falls back to a browser UA only if a host actually rejects that
- The Slack alert for secret findings could silently fail with `invalid_payload` once enough secrets were found to push a single section block past Slack's 3000-character limit — findings/secrets are now packed across as many blocks as needed
- `git clone failed for <repo>` gave no reason — `secrets_scanner` now surfaces git's stderr (with the embedded access token unconditionally redacted first)
- A fine-grained GitHub PAT missing the `Contents: Read-only` scope produced a cryptic 403 per private repo in both scanners with no explanation; a single preflight check now reports the cause once per run
- Expanding a "N failed sources/repos" list in the pipeline drawer collapsed itself a few seconds later — expand state now lives outside the DOM nodes that the drawer's per-poll re-render destroys

### Security
- `/api/health` no longer leaks private repository names, raw exception text, or the active Ollama model to unauthenticated callers
- Open redirect on `GET /login?next=...` (the `POST /login` handler already guarded this; `GET` did not)
- `settings.is_feature_enabled()` now fails closed (was fail-open) for an unrecognised toggle key
- `httpx`/`httpcore` request logging pinned to `WARNING` — their `INFO`-level per-request URL logs were writing ~160 rows per pipeline run into `log_entries`, including any credential embedded in a URL

#### M10 — GitHub issue auto-creation & release pipeline
- `github_issue_creator.py` — creates `[Security]`-prefixed GitHub issues for new findings; deduplicates against open issues with matching title; stamps `github_issue_url` on the finding row; off by default (`github_issue_creation` feature toggle)
- `findings.github_issue_url TEXT` column — persists the created issue URL via schema migration
- `db.get_findings_for_issue_creation()` and `db.set_finding_github_issue_url()` DB helpers
- Pipeline step 3.5 in `main.py` — issue creation runs between the dependency scanner and secrets scanner when the toggle is on
- `github_issue_url` included in findings CSV/JSON export
- `.github/workflows/release.yml` — multi-arch Docker image (`linux/amd64` + `linux/arm64`) pushed to `ghcr.io` on `v*` tags; GitHub Release created with CHANGELOG excerpt
- Unit tests for `github_issue_creator` (title formatting, severity labels, body generation, run loop with mocked GitHub API)

---

## [1.0.0] — 2026-05-16

### Added

#### Core pipeline
- RSS/Atom feed ingestion from 9 default security sources
- NIST NVD, CISA KEV, and GitHub Security Advisory ingestion
- Ollama-powered AI categorization in batches of 10 (category, severity, summary, tags)
- Fallback to `Uncategorized / Unknown` if model output fails schema validation
- GitHub repository dependency scanning via PyGithub + OSV.dev batch API
- Manifest support: `requirements.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `package-lock.json`, GitHub Actions `*.yml`
- CVSS-based priority scoring with KEV and patch-availability bonuses
- Ollama-generated plain-English next steps (impact, fix command, effort estimate) per new Critical/High finding
- Finding lifecycle state machine: New → Acknowledged → Resolved, with automatic regression detection
- Delta-only notifications: Slack (Block Kit), Discord, and SMTP email
- Failure alert notifications (timestamp + error summary per failed pipeline stage)
- Weekly digest notifications (every Monday 08:00, configurable) with top CVEs, resolved findings, and affected repo list
- `gitleaks`-based secrets scanning on the most recent N commits (default 30); immediate alert on new secrets
- Concurrent-run protection via `filelock`; Run Now button disabled while pipeline runs

#### Web dashboard
- FastAPI + Jinja2 server-side templates; HTTP Basic Auth on all routes
- Dashboard (last 24 h summary: Critical/High/Medium/Low/New/Resolved/Secrets counts)
- Findings view: filter by state/repo, priority score, inline Acknowledge/Resolve/Reopen actions
- Secrets view: detected credential leaks with false-positive suppression
- History view: stacked-bar news trend, line chart for new findings per day, source reliability table, pipeline run log, feed analytics stacked-bar chart
- Weekly summary view: digest rendered from SQLite snapshot
- Personal view: bookmarked news items and annotated findings
- Settings view: pipeline schedule, feature toggles, RSS feed management, keyword watchlist, scanner settings, Ollama model selector
- Dark/light mode toggle; preference persisted in `localStorage`; applied before first paint (no flash)
- Ollama status indicator (green/red dot) in header, updated every 5 seconds
- Mobile-responsive layout; hamburger nav on ≤600 px screens
- Run Now button with CSRF protection (`X-Run-Token` header)

#### Data & configuration
- SQLite with WAL mode; schema auto-migrated at startup
- All runtime preferences stored in SQLite (`settings` KV table); secrets stay in `config.yaml`
- Bookmark toggle (`POST /api/news/{id}/bookmark`) — idempotent
- Finding annotations (`POST /api/findings/{id}/annotate`)
- Data export: findings and news as JSON or CSV (`StreamingResponse` with `Content-Disposition: attachment`)
- Feed analytics API (`GET /api/history/feed-analytics?days=N`)
- GitHub issue auto-creation per new finding (off by default; deduplicated on open issues)

#### Infrastructure
- Multi-arch Docker image (linux/amd64 + linux/arm64) via GitHub Actions `release.yml`
- CI: ruff lint → black format check → pip-audit → pytest unit tests → Docker build on every push/PR to `main`
- Bare-metal setup script (`setup.sh`), systemd unit (`dive.service`), logrotate config

[Unreleased]: https://github.com/bladzv/dive/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bladzv/dive/releases/tag/v1.0.0
