# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

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
