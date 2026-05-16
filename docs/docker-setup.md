# Docker Setup

The fastest way to get started. Docker handles all dependencies — Python, Ollama, gitleaks — so you only need Docker installed on your machine.

**Works on:** Raspberry Pi 4 (ARM64), Mac (Apple Silicon + Intel), Linux (x86_64).

**Time:** approximately 15 minutes.

← Back to [Setup Guide](setup.md) | Also needed: [Credential Preparation](mac-preparation.md) →

---

## Before You Start

Make sure you've completed [Credential Preparation](mac-preparation.md) and have your credentials ready.

**You need:**
- Docker Desktop (Mac / Windows) or Docker Engine + Docker Compose plugin (Linux / Pi)
- Git
- Your credentials from Credential Preparation (GitHub token, webhook URLs, etc.)

---

## Step 1 — Install Docker

**On a Mac:**  
Download Docker Desktop from **docker.com/products/docker-desktop** and install it. Open Docker Desktop and wait for the whale icon in the menu bar to stop animating — that means Docker is ready.

**On a Raspberry Pi or Linux:**
```bash
$ curl -fsSL https://get.docker.com | sh
```
- `curl -fsSL https://get.docker.com | sh` — downloads and runs Docker's official install script. This installs both the Docker Engine and the Compose plugin in one step.

> **Security note:** this runs a script downloaded from the internet directly in your shell. This is Docker's officially documented installation method and the script is served over HTTPS. If you prefer to inspect the script before running it, download it first (`curl -fsSL https://get.docker.com -o install-docker.sh`), review it, then run `sh install-docker.sh`.

Add your user to the `docker` group so you can run Docker commands without `sudo`:
```bash
$ sudo usermod -aG docker $USER
```
- `usermod -aG docker` — adds the user to the `docker` group, granting permission to run Docker commands.
- `$USER` — a variable that automatically expands to your current username.

Log out and back in for the group change to take effect, then verify:
```bash
$ docker --version
$ docker compose version
```
Both commands should print a version number.

---

## Step 2 — Download the Project

```bash
$ git clone https://github.com/<your-username>/dive.git
$ cd dive
```
- `git clone` — downloads a complete copy of the project from GitHub.
- `cd dive` — moves into the project folder. All remaining commands must be run from here.

---

## Step 3 — Create Your Configuration File

```bash
$ cp config.yaml.example config.yaml
```
- `cp` — copies a file. `config.yaml.example` is the public template; `config.yaml` is your private copy.

Open it in a text editor and fill in your credentials:

```bash
$ nano config.yaml
```

Fill in the fields using what you created in [Credential Preparation](mac-preparation.md). Leave any notification fields blank if you're not using that method.

Save and close: `Ctrl+X`, then `Y`, then `Enter`.

Restrict permissions so only your user can read the file:
```bash
$ chmod 600 config.yaml
```
- `chmod 600` — sets the file so only the owner can read and write it. The app checks this at startup and will warn if the file is too permissive.

---

## Step 4 — Download the AI Model

This downloads the default AI model (~2GB). It only needs to be done once — the model is stored in a Docker volume that persists across container restarts.

First, start just the Ollama service:
```bash
$ docker compose up ollama -d
```
- `docker compose up ollama` — starts only the `ollama` service defined in `docker-compose.yml`.
- `-d` — "detached" mode. Runs the container in the background so your terminal is free.

Wait about 10 seconds for Ollama to be ready, then pull the model:
```bash
$ docker compose exec ollama ollama pull qwen2.5:3b
```
- `docker compose exec ollama` — runs a command inside the running `ollama` container.
- `ollama pull qwen2.5:3b` — downloads the model from the official Ollama registry.

A progress bar shows the download. This takes a few minutes depending on your internet speed.

> **Why not just let the app download it automatically?** Automated pulls can expose your Ollama registry credentials to a specific attack (CVE-2025-51471). Manual download is the safe approach. This is the only command in this guide that is Docker-specific — it follows the same principle as the bare-metal `ollama pull` command.

Verify the model downloaded:
```bash
$ docker compose exec ollama ollama list
```
You should see `qwen2.5:3b` in the list.

> **Want a different model?** See [models.md](models.md) for all supported options. Replace `qwen2.5:3b` in the command above with your chosen model name, then select it in the dashboard settings after starting the app.

---

## Step 5 — Start the Application

```bash
$ docker compose up -d
```
- `docker compose up` — starts all services defined in `docker-compose.yml` (the `app` service and the `ollama` service).
- `-d` — runs them in the background.

Wait about 15 seconds, then open a browser and go to:
```
http://localhost:8000
```
You should see the dashboard login screen. Sign in with the `dashboard.username` and `dashboard.password` you set in `config.yaml`.

> **Accessing from another device on the same network?** `localhost` only works on the machine running the app. From any other device, use Device A's local IP address instead:
> ```bash
> # Run this on Device A to find its IP:
> hostname -I          # Linux / Raspberry Pi — use the first address shown
> ipconfig getifaddr en0   # Mac (Wi-Fi); use en1 for Ethernet
> ```
> Then open `http://192.168.x.x:8000` from Device B's browser. Docker already maps port 8000 to all network interfaces (`0.0.0.0:8000`), so no extra configuration is needed — just the correct IP.

To confirm both containers are running:
```bash
$ docker compose ps
```
Both `app` and `ollama` should show `running` in the Status column.

---

## Step 6 — Run the First Scan

The pipeline runs automatically every 6 hours. To trigger it immediately without waiting, click the **Run Now** button in the dashboard.

You can also watch the logs in real time while the first run executes:
```bash
$ docker compose logs -f app
```
- `logs` — shows output from a container.
- `-f` — "follow" — keeps streaming new lines as they appear. Press `Ctrl+C` to stop watching.

---

## Keeping the App Updated

When a new version is released:
```bash
$ docker compose pull
$ docker compose up -d
```
- `docker compose pull` — downloads the latest version of the image from GitHub Container Registry.
- `docker compose up -d` — restarts the containers with the new image. Your data (SQLite database, model files) is stored in named volumes and is not affected.

---

## Useful Commands

| Command | What it does |
|---|---|
| `docker compose up -d` | Start all services in the background |
| `docker compose down` | Stop all services |
| `docker compose ps` | Check which containers are running |
| `docker compose logs -f app` | Stream live logs from the app |
| `docker compose logs -f ollama` | Stream live logs from Ollama |
| `docker compose restart app` | Restart just the app (after config changes) |
| `docker compose exec ollama ollama list` | List downloaded models |
| `docker compose exec ollama ollama pull <model>` | Download a new model |
| `docker compose exec ollama ollama rm <model>` | Remove a downloaded model |
| `docker compose pull && docker compose up -d` | Update to the latest version |

---

## Running on Raspberry Pi

The Docker image is built for both AMD64 (Mac/Linux) and ARM64 (Pi), so the same `docker compose up` command works on a Pi with no changes.

**Install Docker on Pi:**
```bash
$ curl -fsSL https://get.docker.com | sh
$ sudo usermod -aG docker $USER
```
Log out and back in, then follow this guide from Step 2.

**For always-on Pi use**, you may also want to:
- Set up Tailscale on the Pi host for remote dashboard access → [Tailscale Setup](tailscale-setup.md)
- Configure Docker to start on boot (already enabled by default when using the official install script)
- Assign a static IP to the Pi so the dashboard URL doesn't change → see [Raspberry Pi Setup — Step 14](raspberry-pi-setup.md#step-14--optional-assign-a-permanent-ip-to-your-pi)
