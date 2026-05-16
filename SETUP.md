# Setup Guide

Everything you need to get the project running, explained step by step.

---

## Choose Your Setup Path

| Path | Best for | Time |
|---|---|---|
| [Docker](docs/docker-setup.md) ⭐ **Recommended** | Most users — Mac, Linux, or Raspberry Pi. Fastest start, no manual dependency setup. | ~15 min |
| [Bare-metal Pi](docs/raspberry-pi-setup.md) | Raspberry Pi users who want tighter OS integration — systemd, logrotate, ufw, unattended upgrades. | ~30 min |

Both paths require completing **Credential Preparation** first.

---

## Guides

| # | Guide | Required | Description |
|---|---|---|---|
| 1 | [Credential Preparation](docs/mac-preparation.md) | Yes (both paths) | Create your GitHub token, Slack/Discord webhooks, and Gmail app password — done in a browser on any device before touching the Pi or terminal. |
| 2a | [Docker Setup](docs/docker-setup.md) | If using Docker | Start the app with `docker compose up`. Works on Mac, Linux, and Raspberry Pi. |
| 2b | [Raspberry Pi Setup](docs/raspberry-pi-setup.md) | If using bare-metal | Full manual setup — OS updates, Python, Ollama, systemd service, firewall, log rotation. |
| 3 | [Tailscale — Remote Access](docs/tailscale-setup.md) | Optional | Access the dashboard from anywhere via an encrypted private network. Works with both Docker and bare-metal. |

---

## Before You Start

**What you need:**
- A Mac, Linux machine, or Raspberry Pi 4 (8GB RAM recommended)
- Docker Desktop (Mac) or Docker Engine (Linux / Pi) — if using the Docker path
- Internet access

**How to connect to a headless Raspberry Pi:**
```bash
ssh pi@raspberrypi.local
```
Replace `pi` with your Pi's username if you set a different one during OS setup.

---

## Other Reference Docs

- [MODELS.md](MODELS.md) — what Ollama and models are, supported models, how to switch
- [PRD.md](PRD.md) — full product requirements document
