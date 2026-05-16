# Product Requirements Document
## DIVE — News Aggregator & Repository Scanner

**Version:** 0.8  
**Date:** 2026-05-12  
**Status:** Draft

---

## 1. Overview

An open-source, self-hosted security tool that aggregates news, categorizes it with a local AI model, scans your GitHub repositories for vulnerabilities, and surfaces everything in a personal dashboard. Runs on a **Raspberry Pi 4**, any **Linux machine**, or a **Mac** — via Docker (recommended) or bare-metal.

**Zero paid dependencies.** All AI runs locally via Ollama.

---

## 2. Goals

1. Eliminate manual security news triage by consolidating all relevant sources into one place.
2. Provide AI-assisted categorization and clustering so signal is separated from noise.
3. Identify which personal/org GitHub repositories are affected by newly published vulnerabilities.
4. Track vulnerability lifecycle so the same finding never notifies more than once.
5. Deliver actionable, prioritized next steps per affected repository.
6. Expose all configuration through the dashboard — no file editing for day-to-day use.
7. Keep everything local — no cloud backend, no third-party data storage, no API costs.
8. Be easy to self-host for anyone: one Docker command to get started, full bare-metal option for Pi users who want tighter OS integration.

## 3. Non-Goals

- Not a SIEM or real-time threat detection system.
- Not a replacement for Dependabot or GitHub's native security alerts.
- Does not patch or modify repositories automatically.
- Does not support team/multi-user deployments (single-user local tool).
- Does not monitor infrastructure or runtime environments.
- Does not provide macOS-native notifications (alerts delivered via Slack/Discord/email).

---

## 4. Users

**Primary user:** A developer who wants automated, local, zero-cost security monitoring for their personal GitHub repositories.

**Deployment profiles:**
- **Docker on Pi** — always-on headless server at home; dashboard accessible via Tailscale from anywhere.
- **Docker on Mac/Linux** — run on a personal machine; useful for occasional scans or development.
- **Bare-metal on Pi** — tighter OS integration (systemd watchdog, logrotate, ufw); preferred by users comfortable with Linux administration.

---

## 5. Features

### 5.1 News Collection (automatic, scheduled)

Pulls from two source types. The full source list is managed via the configuration dashboard (§5.7).

**Default RSS/Blog Feeds**
| Source | Focus |
|---|---|
| Bleeping Computer | Breaking news, breaches, malware, CVEs |
| Krebs on Security | In-depth investigative journalism |
| The Hacker News | High-volume daily security news |
| SANS Internet Storm Center | Daily threat diary, handler writeups |
| Cisco Talos | Threat research, malware analysis |
| Palo Alto Unit 42 | APT research, incident reports |
| Google Mandiant | APT research, IR findings |
| CrowdStrike Blog | Adversary intelligence |
| Dark Reading | Enterprise security news and analysis |

**Structured APIs**
| Source | Focus |
|---|---|
| NIST NVD | Canonical CVE database, CVSS scores, CPE data |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| OSV.dev | Open source package vulnerability matching |
| GitHub Security Advisories | Advisory database for dependency scanning |

> **NIST NVD rate limits:** unauthenticated requests are capped at 5 req/30s; authenticated requests (free API key from nvd.nist.gov) allow 50 req/30s. The collector requests an NVD API key be set in `config.yaml` and warns at startup if it is missing. Fetches are spaced with a small delay to stay within the unauthenticated limit even if no key is configured, so the app still works without one.

Deduplication on URL + title hash. Failed sources are skipped and logged — the run continues.

### 5.2 AI Categorization & News Clustering

New items are batch-processed through a locally running Ollama model (up to 10 items per prompt). Ollama runs as a persistent service so the model stays warm between runs.

**Default model:** `qwen2.5:3b`. Configurable via the dashboard. See [MODELS.md](MODELS.md).

**Per-item output:** category, severity, affected products/vendors, one-line summary (≤160 chars), tags.

**Fallback:** if the model produces a response that fails schema validation after two retries, the item is stored with `category = "Uncategorized"` and `severity = "Unknown"` so it still appears in the feed. This prevents a flaky model from stalling the whole pipeline. If the uncategorized rate exceeds 20% of a batch, a warning is logged — a signal to evaluate a different model.

**News clustering:** items covering the same underlying story are grouped into a single card in the dashboard. When multiple sources cover the same breach, you see one story with a source count — not duplicates.

### 5.3 Local Web Dashboard

Served at `http://localhost:8000` (Docker) or `http://<pi-hostname>:8000` (bare-metal). Accessible remotely via Tailscale.

**Protected by HTTP Basic Auth.** Responsive layout — works on desktop, tablet, and mobile.

**Dark mode** — toggle in the top navigation bar. Preference persisted in the browser.

**Views:**

| View | Content |
|---|---|
| Feed | All collected items, newest first. Clustered by story. Filterable + full-text search. Keyword-matched items highlighted. |
| CVE Detail | CVSS score, affected CPEs, CISA KEV status, patch availability, advisory links. |
| Affected Repos | Findings grouped by priority score. Lifecycle state per finding. Inline acknowledge/resolve actions. |
| Secrets | Repos with detected credential leaks — file path, commit SHA, secret type. Mark as false positive inline. |
| History | Trend charts: items/day, severity distribution, findings lifecycle over time, source reliability. |
| Weekly Summary | Most recent weekly digest — top CVEs, most affected repos, patch availability changes, resolved findings. |
| Personal | Bookmarked items, annotated findings. See §5.9. |
| Configuration | See §5.7. |

**Dashboard header:** Ollama status indicator (green = running and model loaded, red = unavailable), last-run timestamp, next scheduled run time, Run Now button.

### 5.4 GitHub Repository Scanner

Runs each cycle, after categorization. Scope: all repos owned by the authenticated user (public and private), including org repos. Configurable exclusions via the dashboard.

**Dependency manifests scanned** (implemented in priority order — npm and Python first, remaining formats added incrementally):
- `package.json` / `package-lock.json` (npm) — **first**
- `requirements.txt` / `Pipfile` / `pyproject.toml` (Python) — **first**
- `.github/workflows/*.yml` (GitHub Actions — parses `uses:` lines) — **first**
- `go.mod` (Go)
- `Cargo.toml` (Rust)
- `pom.xml` / `build.gradle` (Java)
- `Gemfile` (Ruby)

**Vulnerability matching:** OSV.dev + GitHub Security Advisories, cross-referenced with CISA KEV + NIST NVD. Filtered to configured severity threshold (default: Critical & High).

**Priority scoring:** composite of CVSS score, CISA KEV exploitation status, patch availability, and number of affected repos.

**AI-generated next steps:** for each new finding, Ollama generates a plain-English impact explanation, suggested fix, and estimated effort (Low / Medium / High).

**Outdated dependency tracking:** packages 2+ major versions behind latest are flagged as Outdated in a low-urgency dashboard list. Not included in notifications.

**Secrets scanning:** `gitleaks` scans the most recent 30 commits of each repo (default; configurable). Detects API keys, tokens, passwords, private keys, and connection strings. Always alerts on new secrets regardless of severity threshold. Users can mark findings as false positives inline — suppressed findings are remembered and never re-reported.

**GitHub issue auto-creation:** optionally creates a `[Security]`-prefixed GitHub issue in the affected repo per new finding. Deduplicated — skips if an open issue for the same CVE already exists. Off by default; configurable globally or per repo.

**Patch availability tracking:** if a previously-seen finding gains a patch, a notification is sent on the next run regardless of normal delta logic.

**GitHub API rate limit handling:** the scanner uses conditional requests (`If-None-Match` / `If-Modified-Since` headers) to skip re-fetching unchanged manifest files, minimising request count against the 5,000 req/hr authenticated limit. A per-run request counter is logged. If usage would exceed 80% of the hourly budget, scanning continues but a warning is added to the run summary. The scanner never silently skips repos — partial results are clearly flagged.

### 5.5 Vulnerability Lifecycle

Each finding (CVE × repository) has a state:

| State | Meaning | Notification |
|---|---|---|
| **New** | First time seen in this repo | Triggers alert |
| **Acknowledged** | User is aware, not yet fixed | Suppressed |
| **Resolved** | Fixed or risk accepted | Suppressed; shown in history |

State transitions from the Affected Repos view. On each run, Resolved findings are re-verified — if the vulnerable version is still present, the finding returns to New and re-notifies.

### 5.6 Notifications

**Delta-only:** only findings that transitioned to New this run trigger a notification.

| Event | Channel |
|---|---|
| New Critical/High repo match | Slack/Discord + email — sorted by priority score, one message per run |
| New secret detected | Immediate Slack/Discord + email — treated as urgent regardless of run schedule |
| Patch now available | Slack/Discord + email — fires when a previously-known finding gains a fix |
| Run failure | Slack/Discord — timestamp, error summary, failed stage |
| Weekly digest | Slack/Discord + email — every Monday 08:00 (configurable) — top CVEs, resolved findings, patch changes |

No notification when a run succeeds with no new state-changed findings.

### 5.7 Configuration Dashboard

All non-secret settings managed in the UI. Secrets (tokens, passwords, webhook URLs) stay in `config.yaml` — they are never exposed in the dashboard.

**RSS Feed Management**
Table of all feeds: name, URL, last successful fetch, item count per run, enabled/disabled toggle. Add new feeds (URL validated as a valid RSS/Atom feed before saving). Remove feeds. Default feeds can be disabled but not deleted.

**Keyword Watchlist**
User-defined keywords highlighted in the feed and used for filtering. Add / remove. Examples: `nginx`, `Kubernetes`, `supply chain`.

**Feature Toggles**

| Feature | Default |
|---|---|
| GitHub repository scanning | On |
| Secrets scanning | On |
| GitHub issue auto-creation | Off |
| News clustering | On |
| Outdated dependency tracking | On |
| Weekly digest | On |
| Patch availability change alerts | On |

**Scanner Settings**
Severity threshold, GitHub issue auto-creation overrides per repo, repos excluded from scanning.

**Schedule Settings**

Pipeline run frequency:

| Option | Interval |
|---|---|
| Every 3 hours | 3h |
| Every 6 hours *(default)* | 6h |
| Every 12 hours | 12h |
| Once a day | 24h |
| Once a week | 168h |
| Once a month | 720h |
| Custom | User-entered whole number of hours (minimum 1) |

Next scheduled run time updates immediately in the header on save. Weekly digest schedule is configured separately.

**Model Settings**

A table of all supported models — installed and not yet installed — curated to Pi-appropriate options (matches [MODELS.md](MODELS.md)). Each row shows model name, download size, estimated speed on Pi 4, a quality note, and status.

| Status | Action |
|---|---|
| Active | Highlighted with a checkmark |
| Installed | **Select** button — activates on next run |
| Not installed | **How to install** — expands inline panel |

The inline panel for not-installed models shows a copy-to-clipboard install command, estimated download size, and approximate download time. For Docker users:
```
docker compose exec ollama ollama pull qwen2.5:3b
```
For bare-metal users:
```
ollama pull qwen2.5:3b
```
The dashboard does not trigger downloads — installation always requires a manual command (CVE-2025-51471).

### 5.8 Personal Workspace

**Bookmarks**
Save any news item or CVE to a personal reading list. Bookmarks persist across sessions and are shown in the Personal view.

**Annotations**
Add a personal note to any finding — e.g., "fixing in v2.1", "discussed with team", "accepted risk — internal tool only". Notes are visible in the Affected Repos view alongside the finding and are preserved when the finding transitions states.

**Data Export**
Export current findings or the full news archive from the dashboard as JSON or CSV. A single button per view. Useful for reporting, sharing, or importing into another tool.

### 5.9 Feed Analytics

A sub-view within History showing per-source statistics:

| Metric | Description |
|---|---|
| Items collected | Total items fetched from this source over the selected period |
| Matched to repos | Items that led to a repo finding |
| Acknowledged | Findings from this source that were actioned |
| Failure rate | Percentage of fetch attempts that failed |
| Last successful fetch | Timestamp |

Helps identify which feeds produce actionable signal and which are noise, informing decisions about which feeds to keep enabled.

### 5.10 Run Control

- **Scheduled runs:** configurable interval via APScheduler.
- **On-demand:** Run Now button in dashboard.
- **Overlap protection:** file-based lock prevents concurrent runs.
- **Watchdog:** bare-metal only — systemd heartbeat restarts the service if it hangs. Docker uses `restart: unless-stopped`.

---

## 6. Technical Architecture

### Deployment Modes

Two supported deployment modes with full feature parity:

| | Docker (recommended) | Bare-metal Pi |
|---|---|---|
| **Setup** | `docker compose up` | Full manual setup (see [SETUP.md](SETUP.md)) |
| **Best for** | Mac, Linux, Pi — anyone wanting a quick start | Pi users wanting tight OS integration |
| **Process management** | Docker `restart: unless-stopped` | systemd service + watchdog |
| **Log management** | Docker log driver | logrotate |
| **OS updates** | User pulls updated image | unattended-upgrades |
| **Ollama isolation** | Internal Docker bridge network (stronger — port never exposed to host) | Bound to `127.0.0.1` via env var |
| **Tailscale** | Run on host; maps through to container port | Run on Pi host |

### Docker Architecture

Two services defined in `docker-compose.yml`:

**`app` service**
- Runs FastAPI + APScheduler
- Calls Ollama at `http://ollama:11434` (Docker internal network)
- Mounts `config.yaml` read-only
- Named volume for SQLite data and logs
- Runs as non-root user
- Publishes port 8000 to host

**`ollama` service**
- Uses the official `ollama/ollama` image (supports ARM64 + AMD64)
- Port 11434 **not published to host** — accessible only within the Docker bridge network
- Named volume for model storage (models persist across container restarts)

```yaml
# docker-compose.yml (illustrative)
services:
  app:
    image: ghcr.io/<owner>/dive:latest
    ports:
      - "8000:8000"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - app-data:/app/data
      - app-logs:/app/logs
    environment:
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      ollama:
        condition: service_healthy
    restart: unless-stopped

  ollama:
    image: ollama/ollama
    volumes:
      - ollama-models:/root/.ollama
    restart: unless-stopped
    # port 11434 intentionally not published

volumes:
  app-data:
  app-logs:
  ollama-models:
```

### Stack
| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Web framework | FastAPI |
| Scheduler | APScheduler (in-process) |
| Database | SQLite (`sqlite3` stdlib) |
| RSS parsing | `feedparser` |
| HTTP client | `httpx` (async) |
| GitHub API | `PyGithub` |
| Local AI | Ollama HTTP API |
| Secrets scanning | `gitleaks` (binary in Docker image; system install for bare-metal) |
| Containerisation | Docker + Docker Compose |
| CI/CD | GitHub Actions |
| Image registry | GitHub Container Registry (`ghcr.io`) |
| Code quality | `ruff` (lint + format) + `black` |
| Tests | `pytest` |
| Bare-metal process manager | `systemd` |
| Bare-metal log rotation | `logrotate` |
| Bare-metal OS updates | `unattended-upgrades` |
| Systemd heartbeat | `sdnotify` |
| Remote access | Tailscale (optional, host-level) |

### Configuration Split

| Store | What lives here |
|---|---|
| `config.yaml` (gitignored, secrets) | GitHub token, dashboard credentials, SMTP settings, webhook URLs, Ollama host, NVD API key (optional — higher rate limit) |
| SQLite `settings` table (preferences) | RSS feeds, keyword watchlist, feature toggles, schedule, severity threshold, model selection, per-repo overrides |

Preferences are managed via the dashboard. Secrets require editing `config.yaml` directly.

### Project Structure
```
dive/
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── main.py                        # FastAPI + APScheduler entrypoint
├── collector.py
├── categorizer.py
├── github_scanner.py
├── secrets_scanner.py             # gitleaks wrapper
├── notifier.py
├── lifecycle.py                   # New/Acknowledged/Resolved state machine
├── db.py                          # SQLite schema + queries
├── config.py                      # config.yaml loader (secrets)
├── settings.py                    # SQLite-backed preferences
├── config.yaml.example
├── config.yaml                    # gitignored
├── setup.sh                       # Bare-metal Pi setup script
├── dive.service    # systemd unit template
├── dive.logrotate  # logrotate config template
├── frontend/
│   ├── index.html
│   ├── app.js
│   ├── style.css                  # Responsive + dark mode
│   └── views/
│       ├── feed.js
│       ├── affected-repos.js
│       ├── secrets.js
│       ├── history.js
│       ├── analytics.js
│       ├── weekly.js
│       ├── personal.js            # Bookmarks + annotations
│       └── config.js
├── tests/
│   ├── test_categorizer.py
│   ├── test_lifecycle.py
│   ├── test_priority_scoring.py
│   └── test_settings.py
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                 # Lint + test on every PR
│   │   └── release.yml            # Build + push multi-arch Docker image on tag
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── mac-preparation.md
│   ├── raspberry-pi-setup.md
│   ├── tailscale-setup.md
│   └── docker-setup.md            # New
├── requirements.txt
├── requirements-dev.txt           # pytest, ruff, black
├── .gitignore
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── SECURITY.md
├── MODELS.md
├── SETUP.md
└── README.md
```

---

## 7. Schedule / Run Cycle

```
Docker startup:
  ollama container starts     → model warm in memory
  app container starts        → FastAPI + APScheduler running

Every N hours (configurable, default 6h):
  1. collector.py       — fetch RSS + APIs, deduplicate, store
  2. categorizer.py     — batch Ollama calls, categorize + cluster
  3. github_scanner.py  — deps + Actions, priority scoring,
                          outdated deps, patch availability changes
  4. secrets_scanner.py — gitleaks scan on repos with new commits
  5. lifecycle.py       — transition states, re-verify Resolved
  6. notifier.py        — delta alerts, secrets, patch-available, failures

Every Monday 08:00 (configurable):
  notifier.py           — weekly digest

On demand (Run Now button):
  Steps 1–6 immediately
```

---

## 8. Security Requirements

### 8.1 Dependency Constraints

| Package | Min Version | CVE | Risk |
|---|---|---|---|
| `PyYAML` | `>=6.0` | CVE-2020-1747, CVE-2020-14343 | CVSS 9.8 — RCE via unsafe YAML |
| `httpx` | `>=0.23.0` | CVE-2021-41945 | CVSS 9.1 — SSRF via URL parsing |

`yaml.safe_load()` only. `requirements.txt` pins exact versions. `pip audit` in CI.

### 8.2 Ollama Hardening

- **Minimum version: 0.17.1** — checked at startup.
- **Docker:** Ollama port not published to host. `OLLAMA_HOST=http://ollama:11434` (internal network only). DNS rebinding risk is eliminated — Ollama is unreachable from any browser.
- **Bare-metal:** `OLLAMA_HOST=127.0.0.1:11434` and `OLLAMA_ORIGINS=http://raspberrypi.local:8000` in systemd override.
- **No automated model pulls** in either deployment mode (CVE-2025-51471).
- Official models only.

### 8.3 Prompt Injection Defense

Strip HTML + control characters from feed content. Truncate to 200/500 chars. XML-style delimiters in prompts. Strict JSON schema output. Response schema-validated before use.

### 8.4 FastAPI Dashboard Hardening

- HTTP Basic Auth on all routes except `GET /api/health`.
- CORS restricted to own hostname.
- `POST /api/run` requires `X-Run-Token` header.
- Config write endpoints server-side validated. Changes logged to SQLite with timestamp.
- No `innerHTML` — all external content via `textContent`.

### 8.5 Docker-Specific Security

- App container runs as non-root user (`USER appuser` in Dockerfile).
- `config.yaml` mounted read-only (`:ro`).
- Ollama container has no published ports — only reachable on internal bridge network.
- `.dockerignore` excludes `config.yaml`, `.env`, `*.db`, `*.sqlite` from image build context.
- Multi-arch image built and signed via GitHub Actions on release.

### 8.6 Secret Handling

- `config.yaml` gitignored; checked for world-readable permissions at startup (`chmod 600`).
- Secrets never exposed in dashboard UI, API responses, logs, or notification payloads.
- All secrets support environment variable overrides.

### 8.7 HTTP Client Safety

All `httpx` requests: 10MB response cap, no auto-redirects, 30s timeout, HTTP-only source URLs warned.

### 8.8 Data Integrity

Parameterized SQLite queries only. Email content from sanitized DB fields. Webhook payloads schema-validated.

### 8.9 Concurrent Run Protection

File-based lock. If a Run Now request arrives while the lock is held, the request is rejected with a clear status — not silently dropped. The dashboard header shows "Pipeline running — started N min ago" while a run is active, and the Run Now button is disabled with that label. Logs record `run rejected: pipeline already running` with a timestamp.

---

## 9. Open Source Standards

This section defines the non-code deliverables required for a well-maintained public GitHub project.

### 9.1 Repository Files

| File | Purpose |
|---|---|
| `README.md` | Project overview, screenshot/demo GIF, feature list, quick-start (Docker + bare-metal), hardware requirements, link to full docs |
| `CONTRIBUTING.md` | Dev environment setup (Docker), code style, how to run tests, PR process |
| `CHANGELOG.md` | Version history in [Keep a Changelog](https://keepachangelog.com) format |
| `SECURITY.md` | How to responsibly report a vulnerability in this project |
| `CODE_OF_CONDUCT.md` | Contributor Covenant standard |
| `LICENSE` | MIT |

### 9.2 GitHub Configuration

| File | Purpose |
|---|---|
| `.github/ISSUE_TEMPLATE/bug_report.md` | Structured bug report (steps to reproduce, expected vs actual, environment) |
| `.github/ISSUE_TEMPLATE/feature_request.md` | Structured feature request (problem, proposed solution, alternatives) |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR checklist: what changed, tests added, security implications checked |

### 9.3 Releases

- Semantic versioning: `v1.0.0`, `v1.1.0`, `v1.2.0` etc.
- GitHub Releases created on each version tag with a changelog excerpt.
- Docker image tagged with version and `latest` on each release.

### 9.4 CI/CD (GitHub Actions)

**`ci.yml` — runs on every PR and push to main:**
- `ruff check .` — linting
- `black --check .` — formatting
- `pip audit` — dependency vulnerability check
- `pytest tests/` — unit tests
- Build Docker image (without pushing) to catch Dockerfile errors early

**`release.yml` — runs on version tags (`v*`):**
- Build multi-arch Docker image (linux/amd64 + linux/arm64)
- Push to GitHub Container Registry (`ghcr.io/<owner>/dive`)
- Tag with version number and `latest`
- Create GitHub Release with changelog excerpt

### 9.5 Code Quality

- `ruff` — linting and import sorting (replaces flake8 + isort)
- `black` — code formatting
- Both enforced in CI; configuration in `pyproject.toml`

### 9.6 Tests

**Unit tests** in `tests/` — run in CI, no external dependencies:
- Categorizer: schema validation, batch splitting, malformed response handling
- Lifecycle: state transitions, Resolved re-verification logic
- Priority scoring: score calculation for different CVE/KEV combinations
- Settings: read/write to SQLite settings table

**Local integration scripts** in `tests/integration/` — run manually, require live credentials:
- `test_collector.py` — fetches one page from each RSS feed and one response from each API; asserts non-empty results and expected field shapes
- `test_scanner.py` — runs the dependency scanner against one real repo; asserts OSV.dev returns a parseable response and findings have required fields
- `test_notifier.py` — sends a test notification to each configured channel; confirms delivery

These scripts are not run in CI (they require live GitHub token, Ollama, and notification credentials). They are documented in `CONTRIBUTING.md` as the first thing to run after `docker compose up` during development. The M2 and M3 quality checkpoints use these scripts as their validation method.

---

## 10. Prior Art

| Tool | Overlap | Gap |
|---|---|---|
| OSV-Scanner (Google) | Dependency vulnerability scanning | No news, no dashboard, CLI only |
| Trivy (Aqua) | Deep vuln + secrets scanning | No news aggregation, no personal dashboard |
| Dependency-Track (OWASP) | SBOM + vuln management | Java/Docker, enterprise complexity, overkill |
| FreshRSS / Miniflux | Self-hosted RSS reading | No security features, no GitHub integration |
| Dependabot (GitHub) | Automated dep update PRs | Cloud-only, no news, no unified view |
| Wazuh | SIEM | Infrastructure focus, completely different scope |

GitHub's built-in **Dependabot + Security Advisories** covers some of the repo scanning and is worth using alongside this project. This project adds news context, AI-generated explanations, secrets scanning, cross-source CVE correlation, priority scoring, personal lifecycle tracking, and offline/local operation.

---

## 11. Success Metrics

| Metric | Target |
|---|---|
| Collection reliability | < 2 failed source fetches per week |
| Categorization accuracy | ≥ 90% correct category on spot-check |
| Repo match precision | No false positives on exact package+version matches |
| Notification latency | Within 15 minutes of scheduled run |
| Dashboard load time | < 2s local, < 4s via Tailscale |
| Pipeline run duration | < 30 minutes end-to-end on Pi 4 |
| Duplicate notification rate | Zero — same finding never notifies twice |
| Docker startup time | < 60s from `docker compose up` to dashboard accessible |
| CI pass rate | 100% on main branch |

---

## 12. Out of Scope (Potential v2)

- macOS-native push notifications.
- Docker image / container vulnerability scanning.
- SBOM generation and export.
- License compliance checking.
- Multi-repo consolidated fix PRs.
- Integration with Linear / Jira.
- HTTPS on the local dashboard.
- Larger model support (llama3.1:8b+) on Apple Silicon.
- Browser extension for inline CVE lookup.

---

## 13. Setup Guide

Full setup instructions in [SETUP.md](SETUP.md):
- [Docker Setup](docs/docker-setup.md) — recommended for most users
- [Credential Preparation](docs/mac-preparation.md) — credentials setup (required for both paths)
- [Raspberry Pi Setup](docs/raspberry-pi-setup.md) — bare-metal Pi installation
- [Tailscale — Remote Access](docs/tailscale-setup.md) — optional remote access

---

## 14. Implementation Milestones

The goal is to ship the MVP — all four user-facing features working end-to-end — as early as possible, then layer on polish and secondary features. Docker infrastructure comes first so that every subsequent milestone is built and tested inside the same container environment that production will use.

### MVP — Core Pipeline + Basic Visibility

The MVP delivers all four original goals: news aggregated and categorized, repos scanned, a local dashboard to view results, and Slack/Discord/email notifications with delta-only logic. The config UI, secrets scanner, personal workspace, analytics, and open-source polish are explicitly post-MVP.

| Milestone | Scope |
|---|---|
| **M1 — Docker infrastructure** | `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `config.yaml.example`, basic `ci.yml` (lint + test on PRs). All remaining milestones are developed and tested inside this Docker environment. |
| **M2 — Data pipeline** | `db.py` (schema), `collector.py` (**RSS feeds first** — structured APIs added once RSS is stable), `categorizer.py` (batched Ollama calls, news clustering, schema-validation fallback). **Quality checkpoint:** run categorization on live RSS output and check the uncategorized rate and category accuracy before continuing. If qwen2.5:3b is unreliable, the fallback (§5.2) keeps the pipeline running, but evaluate an alternative model before building M3–M5 on top of it. |
| **M3 — GitHub scanner** | `github_scanner.py` — **npm + Python + Actions manifests first**; Go/Rust/Java/Ruby added incrementally. OSV.dev + GHSA matching, priority scoring, patch availability tracking, GitHub API rate limit handling. **Integration checkpoint:** validate OSV.dev matches against a real `package.json` and `requirements.txt` from an actual repo before wiring lifecycle on top — catch data shape surprises early. |
| **M4 — Lifecycle + notifications** | `lifecycle.py` (New/Acknowledged/Resolved state machine, Resolved re-verification), `notifier.py` (delta Slack/Discord/email, failure alerts). HTTP Basic Auth on all FastAPI routes. First complete end-to-end pipeline run. |
| **M5 — Minimal web dashboard** | FastAPI routes, feed view (list of categorized items), affected repos view (findings with lifecycle state + inline ack/resolve), Run Now button, last-run timestamp, Ollama status in header. **← MVP boundary. Use this in production for 2–4 weeks before building further. Gaps and missing features will surface from real use.** |

### Post-MVP

| Milestone | Scope |
|---|---|
| **M6 — Secrets scanner** | `secrets_scanner.py` — gitleaks integration, configurable commit window (default: last 30 commits), false-positive suppression, dedicated Secrets view in dashboard. |
| **M7 — Configuration dashboard** | Config view — RSS feed management, keyword watchlist, feature toggles, schedule selector, model selector with inline install instructions. `settings.py` SQLite-backed preferences; secrets remain in `config.yaml`. |
| **M8 — Full dashboard views** | History view (trend charts, source reliability), weekly summary view, dark mode toggle, mobile-responsive layout, Ollama status indicator. Weekly digest in `notifier.py` (every Monday 08:00). |
| **M9 — Personal workspace + analytics** | Bookmarks, annotations, data export (JSON/CSV), feed analytics view (per-source signal quality metrics). |
| **M10 — Open source polish** | README with screenshots/demo GIF, CONTRIBUTING.md, CHANGELOG.md, SECURITY.md, CODE_OF_CONDUCT.md, issue/PR templates, unit tests (`pytest`), multi-arch Docker build via `release.yml` (linux/amd64 + linux/arm64), semver releases via GitHub Releases, GitHub issue auto-creation feature, bare-metal hardening files (systemd unit, logrotate config, `setup.sh`). |
