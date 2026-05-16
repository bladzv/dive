# DIVE — Dependency Intelligence for Vulnerability Exposure

A self-hosted security intelligence tool that runs on a Raspberry Pi (or any Linux box). Every few hours it collects newly published security news, categorises it with a local AI model, scans your GitHub repositories for known CVEs, and sends alerts to Slack, Discord, or email — all without any paid APIs or cloud services.

![Dashboard screenshot](docs/screenshot.png)
*(screenshot after first run)*

---

## What it does

| Step | What happens |
|------|-------------|
| **Collect** | Fetches security news from 9 RSS feeds plus NVD, CISA KEV, and GitHub Advisories |
| **Categorise** | Uses a local Ollama model to label each item by category, severity, and CVE cluster |
| **Scan** | Checks every manifest file in your GitHub repos against OSV.dev for known vulnerabilities |
| **Alert** | Sends delta notifications (new findings only) to Slack, Discord, or email |
| **Dashboard** | Serves a web UI at `:8000` for browsing news, triaging findings, and changing settings |

---

## Requirements

- **Docker** and **Docker Compose** (V2)
- A machine with at least **4 GB RAM** (8 GB recommended for larger models)
- A **GitHub fine-grained PAT** with *Contents: Read-only* + *Metadata: Read-only*
- Internet access for the first model pull (~2 GB); subsequent runs work offline

Tested on Raspberry Pi 4 (8 GB) running Raspberry Pi OS Bookworm 64-bit, and on macOS/Linux x86-64.

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/bladzv/dive.git
cd dive

# 2. Configure
cp config.yaml.example config.yaml
chmod 600 config.yaml
nano config.yaml          # fill in github.token, github.username, dashboard.password,
                          # and at least one notification channel

# 3. Start
docker compose up -d

# 4. Pull the AI model (first time only — ~2 GB)
docker compose exec ollama ollama pull qwen2.5:3b

# 5. Open the dashboard
open http://localhost:8000   # log in with dashboard.username / dashboard.password
                             # then click ▶ Run Now to trigger the first scan
```

> **Accessing from another device on the same network?** Replace `localhost` with the host machine's local IP address (e.g. `http://192.168.1.x:8000`). Run `hostname -I` (Linux/Pi) or `ipconfig getifaddr en0` (Mac) on the host to find it. Docker already listens on all interfaces — no extra config needed. For remote access outside your network, see [`docs/tailscale-setup.md`](docs/tailscale-setup.md).

---

## Features

- **Zero paid dependencies** — all AI inference runs locally via [Ollama](https://ollama.com)
- **Vulnerability deduplication** — findings are deduplicated across runs; only net-new vulnerabilities trigger alerts
- **KEV enrichment** — findings are cross-referenced with the CISA Known Exploited Vulnerabilities catalogue and flagged with a priority score
- **Priority scoring** — CVSS × 6 + KEV bonus + patch-availability penalty, clamped to 0–100
- **Finding lifecycle** — New → Acknowledged → Resolved state machine with automatic resolution when a vulnerability disappears from a repo
- **Manifest coverage** — `requirements.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `package-lock.json`, GitHub Actions workflows
- **Multi-channel notifications** — Slack (Block Kit), Discord, and SMTP email; channels are independent (failure on one does not block others)
- **Configurable schedule** — 3 h, 6 h, 12 h, 24 h, weekly, monthly, or a custom value; changeable from the Settings page without restarting
- **Model switching** — select any installed Ollama model from the Settings page; install commands shown inline for models not yet pulled
- **Concurrent-run protection** — file-based lock prevents overlapping pipeline runs
- **CSRF protection** — Run Now button requires a per-deployment token stored in the database

---

## Configuration

All configuration lives in `config.yaml` (never committed). Copy the example and fill in your values:

```bash
cp config.yaml.example config.yaml
chmod 600 config.yaml
```

The minimum required fields:

```yaml
github:
  token: "github_pat_..."   # fine-grained PAT, 90-day expiry
  username: "your-username"

dashboard:
  password: "choose-a-strong-password"

notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."  # or discord / email
```

See [`config.yaml.example`](config.yaml.example) for all options and inline documentation.

---

## Documentation

| Guide | What it covers |
|-------|----------------|
| [`docs/setup.md`](docs/setup.md) | Overview of all setup paths and guides |
| [`docs/raspberry-pi-setup.md`](docs/raspberry-pi-setup.md) | Preparing a fresh Pi: OS, Docker, firewall, SSH hardening |
| [`docs/docker-setup.md`](docs/docker-setup.md) | Running with Docker Compose; updating; backups |
| [`docs/tailscale-setup.md`](docs/tailscale-setup.md) | Remote access from any device via Tailscale |
| [`docs/mac-preparation.md`](docs/mac-preparation.md) | Getting your GitHub PAT and notification webhook URLs |
| [`docs/models.md`](docs/models.md) | Choosing an Ollama model; trade-offs for Pi vs. larger hardware |

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Web framework | [FastAPI](https://fastapi.tiangolo.com) + [uvicorn](https://www.uvicorn.org) |
| Scheduler | [APScheduler](https://apscheduler.readthedocs.io) 3.x (in-process) |
| Database | SQLite with WAL mode ([`db.py`](db.py)) |
| AI inference | [Ollama](https://ollama.com) — local, no GPU required |
| HTTP client | [httpx](https://www.python-httpx.org) |
| GitHub API | [PyGitHub](https://pygithub.readthedocs.io) |
| Vulnerability data | [OSV.dev](https://osv.dev) batch API (free, no key needed) |
| News sources | RSS/Atom via [feedparser](https://feedparser.readthedocs.io), NVD REST API, CISA KEV JSON |
| Templates | [Jinja2](https://jinja.palletsprojects.com) — server-side HTML, no build step |
| Containerisation | Docker + Docker Compose |

---

## Development

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run tests (no network or Ollama needed)
pytest

# Lint
ruff check . && black --check .

# Run the app locally (needs config.yaml and Ollama running)
python main.py
```

Tests live in `tests/` (unit) and `tests/integration/` (live network — skipped in CI).

---

## License

MIT — see [`LICENSE`](LICENSE).

---

*DIVE — Dependency Intelligence for Vulnerability Exposure*
