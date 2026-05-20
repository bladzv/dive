# Contributing to DIVE

Thank you for your interest in contributing! This document explains how to set up a development environment, run tests, and submit changes.

## Development environment

### Docker (recommended)

```bash
git clone https://github.com/bladzv/dive.git
cd dive
cp config.yaml.example config.yaml
chmod 600 config.yaml
# Fill in github.token, github.username, dashboard.password
docker compose up --build
```

The app is available at `http://localhost:8000`. All subsequent steps assume you are working inside this environment.

### Bare-metal

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
# Requires a running Ollama instance and a filled-in config.yaml
uvicorn dive.main:app --reload --port 8000
```

## Running tests

```bash
# Unit tests — no external services required
pytest tests/ --ignore=tests/integration -v

# Inside Docker
docker compose exec app pytest tests/ --ignore=tests/integration -v

# Integration tests — require a live GitHub token and Ollama
pytest tests/integration/ -v
```

## Linting and formatting

```bash
ruff check .       # lint
black .            # format
black --check .    # CI-style format check (no changes)
```

Both are enforced in CI. Run them before opening a PR.

## Project structure

| File / directory | Purpose |
|---|---|
| `main.py` | FastAPI app, APScheduler setup, all HTTP routes |
| `db.py` | SQLite schema, parameterised query functions |
| `settings.py` | SQLite-backed user preferences |
| `collector.py` | RSS/NVD/KEV/GHSA ingestion |
| `categorizer.py` | Ollama batch categorization |
| `github_scanner.py` | GitHub + OSV.dev vulnerability scanning |
| `secrets_scanner.py` | gitleaks-based secrets scanning |
| `lifecycle.py` | Finding state machine |
| `notifier.py` | Slack, Discord, SMTP delivery |
| `config.py` | `config.yaml` loader |
| `templates/` | Jinja2 HTML templates |
| `static/` | CSS (no build step) |
| `tests/` | Unit tests |
| `tests/integration/` | Integration tests (excluded from CI) |

## Code conventions

- **No `yaml.load()`** — always `yaml.safe_load()`.
- **Parameterised SQL only** — no string interpolation into queries.
- Each DB function opens its own connection — no shared connection objects.
- Avoid bare `except:` — catch specific exception types.
- Keep comments minimal; name things well instead.

## Adding a feature

- **New notification channel:** config dataclass in `config.py`, `_send_<channel>()` in `notifier.py`, wired into `_dispatch()`.
- **New manifest format:** entry in `_MANIFEST_FILENAMES` in `github_scanner.py` + `_parse_<format>()` function.
- **New RSS source:** add to `DEFAULT_FEEDS` in `settings.py`.
- **New feature toggle:** add entry to `FEATURE_TOGGLES` in `settings.py`; check with `st.is_feature_enabled(conn, "<key>")`.
- **New API endpoint:** route in `main.py`, query function in `db.py`.

## Pull request process

1. Fork the repository and create a feature branch from `main`.
2. Write or update tests for any changed behaviour.
3. Run `ruff check .` and `black --check .` — both must pass.
4. Run `pytest tests/ --ignore=tests/integration` — all tests must pass.
5. Open a PR against `main`. Fill in the PR template.
6. A maintainer will review within a few days.

## Security issues

Please **do not** open a public GitHub issue for security vulnerabilities. Follow the process in [`SECURITY.md`](SECURITY.md).
