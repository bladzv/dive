# Security Policy

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing the maintainer directly. Include as much detail as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if possible)
- Affected versions
- Any suggested mitigations

You will receive a response within 5 business days. If the issue is confirmed, a fix will be prioritised and a patched release published as soon as possible. You will be credited in the release notes unless you prefer to remain anonymous.

## Security design notes

### Secrets handling
- `config.yaml` is gitignored and `.dockerignore`d — it is never included in the Docker image
- The Dockerfile deletes `config.yaml` as a second line of defence
- Secrets (GitHub token, webhook URLs, SMTP password) are never returned by any API endpoint, logged, or included in notification payloads

### Authentication
- All dashboard routes require HTTP Basic Auth
- `POST /api/run` additionally requires an `X-Run-Token` header (per-deployment CSRF token stored in SQLite)
- `GET /api/health` is intentionally unauthenticated (returns only pipeline status and Ollama reachability)

### AI / Ollama
- Ollama's port 11434 is not published in `docker-compose.yml` — only accessible on the internal Docker bridge network
- Bare-metal installs bind Ollama to `127.0.0.1` via `OLLAMA_HOST`
- The dashboard never triggers model downloads (mitigates CVE-2025-51471)
- Feed content is HTML-stripped, control-character-stripped, and truncated before being sent to the model

### Database
- All SQLite queries use parameterised statements — no string interpolation
- The database file is stored in the Docker named volume, not in the image

### HTTP client
- All outbound `httpx` requests: 10 MB response cap, no auto-redirects, 30 s timeout
- `yaml.safe_load()` only — never `yaml.load()`
