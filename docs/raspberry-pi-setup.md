# Raspberry Pi Setup

This guide installs and configures everything the project needs on your Raspberry Pi.

**Time:** approximately 30 minutes.

← [Credential Preparation](mac-preparation.md) | Back to [Setup Guide](../SETUP.md) | Next: [Tailscale — Remote Access](tailscale-setup.md) →

---

## Before You Start

Make sure you've completed [Credential Preparation](mac-preparation.md) and have your credentials ready.

**Connect to your Pi:**  
If your Pi has no monitor attached, open Terminal on your Mac and connect via SSH:
```bash
ssh pi@raspberrypi.local
```
Replace `pi` with your Pi's username if you chose a different one during setup.

**Reading the commands:**  
Each command in this guide starts with `$`. That symbol represents the terminal prompt — it's not part of the command and you don't type it. Everything after `$` is what you type.

---

## Step 1 — Update the Operating System

Updating ensures any known security vulnerabilities in system software are patched before you start.

```bash
$ sudo apt update
```
- `sudo` — runs the command as an administrator. Required for system-level changes (similar to "Run as Admin" on Windows).
- `apt` — the package manager for Raspberry Pi OS. Think of it as the App Store for Linux.
- `update` — downloads the latest *list* of available software. It does not install anything yet — it just refreshes what packages are available and what updates exist.

```bash
$ sudo apt upgrade -y
```
- `upgrade` — installs all the pending updates that the previous command discovered.
- `-y` — automatically answers "yes" to any confirmation prompts so you don't have to wait.

---

## Step 2 — Enable Automatic Security Updates

This configures the Pi to automatically install OS security patches without you having to do it manually — important for a device running 24/7 unattended.

```bash
$ sudo apt install unattended-upgrades -y
```
- `install` — downloads and installs a package.
- `unattended-upgrades` — the tool that handles automatic background updates.

```bash
$ sudo dpkg-reconfigure --priority=low unattended-upgrades
```
- `dpkg-reconfigure` — opens the configuration wizard for an already-installed package.
- `--priority=low` — shows all available options, including less common ones.
- A text dialog will appear in your terminal. Use the arrow keys to highlight **Yes** and press **Enter** to enable automatic security updates.

---

## Step 3 — Install Python and Git

Python is the programming language the project is written in. Git is the tool used to download the project code from GitHub.

```bash
$ sudo apt install python3 python3-pip python3-venv git -y
```
- `python3` — the Python 3 runtime (the engine that executes `.py` files).
- `python3-pip` — pip, Python's package manager (equivalent to npm for Node.js).
- `python3-venv` — a tool that creates isolated Python environments so this project's packages don't interfere with anything else on the Pi.
- `git` — version control tool used to download (clone) code repositories from GitHub.

Verify Python is version 3.11 or higher:
```bash
$ python3 --version
```
Expected output: `Python 3.11.x` or higher. If you see a lower version, install 3.11 specifically:
```bash
$ sudo apt install python3.11 -y
```

---

## Step 4 — Install Ollama

Ollama is the software that runs AI models locally on the Pi. Think of it as the engine — the AI model (`qwen2.5:3b`) is what runs inside it. See [MODELS.md](../MODELS.md) for a full explanation of how Ollama and models work together.

```bash
$ curl -fsSL https://ollama.com/install.sh | sh
```
- `curl` — a tool for downloading files from the internet.
- `-fsSL` — a combination of flags: `-f` exits cleanly on server errors, `-s` hides the download progress bar, `-S` still shows error messages if something goes wrong, `-L` follows URL redirects automatically.
- `https://ollama.com/install.sh` — the official Ollama install script directly from their website.
- `| sh` — the pipe symbol (`|`) sends the downloaded script directly to `sh` (the shell), which runs it immediately. This is Ollama's officially documented installation method.

> **Security note:** this runs a script downloaded from the internet directly in your shell. This is Ollama's officially documented method and the script is served over HTTPS. If you prefer to inspect the script before running it, download it first (`curl -fsSL https://ollama.com/install.sh -o install-ollama.sh`), review it, then run `sh install-ollama.sh`.

The installer also sets Ollama up as a system service that starts automatically when the Pi boots.

Verify Ollama installed and check the version:
```bash
$ ollama --version
```
The version must be **0.17.1 or higher**. If it's lower, run the install script again to update:
```bash
$ curl -fsSL https://ollama.com/install.sh | sh
```

---

## Step 5 — Lock Down the Ollama API

By default, Ollama could accept connections from other devices on your network, and a malicious website open in a browser could interact with it. We fix both by adding two settings to Ollama's system service configuration.

```bash
$ sudo systemctl edit ollama
```
- `systemctl` — the tool for managing system services (background programs that run automatically).
- `edit ollama` — opens a text editor to add custom settings to the Ollama service. It creates an "override" file that sits on top of the original configuration without replacing it.

A text editor (nano) opens with some comment lines already present. **Type the following in the empty space between the comment blocks:**

```
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_ORIGINS=http://raspberrypi.local:8000"
```

What these do:
- `OLLAMA_HOST=127.0.0.1:11434` — restricts Ollama to only listen on `127.0.0.1`, which means "this device only". Port `11434` is Ollama's default port. Without this setting, Ollama listens on all network interfaces and could be reached by other devices on your network.
- `OLLAMA_ORIGINS=http://raspberrypi.local:8000` — tells Ollama to only accept requests coming from your dashboard. This prevents a browser attack called DNS rebinding, where a malicious website can trick your browser into secretly making requests to the Ollama API (CVE-2024-28224).

Save and close: press `Ctrl+X`, then `Y`, then `Enter`.

Apply the changes and restart Ollama:
```bash
$ sudo systemctl daemon-reload
```
- `daemon-reload` — tells systemd (the service manager) to re-read all service configuration files. Must be run after any configuration change.

```bash
$ sudo systemctl restart ollama
```
- `restart` — stops the Ollama service and starts it again with the new configuration applied.

Confirm Ollama is running:
```bash
$ sudo systemctl status ollama
```
Look for `Active: active (running)` in green. Press `q` to exit.

---

## Step 6 — Download the AI Model

This downloads the `qwen2.5:3b` AI model — approximately 2GB. Only needs to be done once.

We do this manually rather than having the app do it automatically because automated model downloads can expose your Ollama registry credentials to an attack (CVE-2025-51471).

```bash
$ ollama pull qwen2.5:3b
```
- `ollama pull` — downloads a model from the official Ollama model registry at `ollama.com/library`.
- `qwen2.5:3b` — the model name. `qwen2.5` is the model family, `3b` means 3 billion parameters (a measure of the model's size and capability).

A progress bar shows the download. This takes a few minutes depending on your internet speed.

Confirm the model downloaded successfully:
```bash
$ ollama list
```
You should see `qwen2.5:3b` in the list with its file size shown.

> Want to use a different model or understand what "3b" means? See [MODELS.md](../MODELS.md).

---

## Step 7 — Download the Project

```bash
$ git clone https://github.com/<your-username>/security-automation.git
```
- `git clone` — downloads a complete copy of the project repository from GitHub to your Pi.
- Replace `<your-username>` with your actual GitHub username.

```bash
$ cd security-automation
```
- `cd` — "change directory". Moves you into the project folder. All remaining commands in this guide must be run from inside this folder.

---

## Step 8 — Set Up the Python Environment

A virtual environment is an isolated folder containing only this project's Python packages. This prevents version conflicts with other Python software on the Pi.

```bash
$ python3 -m venv venv
```
- `-m venv` — tells Python to run its built-in virtual environment module.
- The second `venv` is the name of the folder it will create. You can call it anything, but `venv` is the standard convention.

```bash
$ source venv/bin/activate
```
- `source` — runs a script file within the current terminal session (rather than in a separate sub-process).
- `venv/bin/activate` — the activation script for the virtual environment. After running this, all `python` and `pip` commands use the packages inside this folder, not the system-wide ones.
- Your prompt changes to show `(venv)` at the start — this confirms the environment is active.

```bash
$ pip install -r requirements.txt
```
- `pip install` — downloads and installs Python packages.
- `-r requirements.txt` — reads the package list (with exact version numbers) from this file and installs everything in it.

```bash
$ pip audit
```
- Scans all installed packages against known security vulnerability databases and flags any issues. Run this after every `pip install` as a safety check. You should see no vulnerabilities reported.

---

## Step 9 — Create Your Configuration File

```bash
$ cp config.yaml.example config.yaml
```
- `cp` — copies a file.
- `config.yaml.example` — the template included with the project. It contains placeholder values and is safe to share publicly.
- `config.yaml` — your personal copy, which you'll fill in with real credentials. This file is excluded from Git so your secrets are never accidentally uploaded to GitHub.

Open the file to edit it:
```bash
$ nano config.yaml
```
- `nano` — a simple text editor that works in the terminal. Use the arrow keys to move the cursor.

Fill in each value using the credentials you created in [Credential Preparation](mac-preparation.md):

| Field | What to enter |
|---|---|
| `github.token` | Your GitHub Personal Access Token (`ghp_...`) |
| `dashboard.username` | A username to protect the web dashboard — choose anything |
| `dashboard.password` | A password for the web dashboard — choose anything |
| `notifications.slack_webhook_url` | Your Slack webhook URL (leave blank if not using Slack) |
| `notifications.discord_webhook_url` | Your Discord webhook URL (leave blank if not using Discord) |
| `notifications.email.smtp_host` | Your SMTP server (e.g., `smtp.gmail.com` for Gmail) |
| `notifications.email.smtp_port` | SMTP port — use `587` for Gmail |
| `notifications.email.username` | Your email address |
| `notifications.email.password` | Your Gmail App Password (the 16-character one) |
| `notifications.email.recipient` | The email address to send notifications to |

Leave any notification fields blank if you're not using that method.

Save and close: press `Ctrl+X`, then `Y`, then `Enter`.

Restrict the file so only your account can read it. The app will refuse to start if this file is accessible to other users:
```bash
$ chmod 600 config.yaml
```
- `chmod` — changes a file's access permissions.
- `600` — a code meaning: the owner of the file can read and write it; everyone else has zero access.

---

## Step 10 — Set Up the Firewall

The firewall controls which network connections are allowed to reach the Pi. The goal is to allow SSH (so you can connect remotely) and the dashboard (from your home network only), and block everything else.

```bash
$ sudo apt install ufw -y
```
- `ufw` stands for "Uncomplicated Firewall" — a simplified tool for managing Linux's built-in firewall.

```bash
$ sudo ufw default deny incoming
```
- Sets the default to block all incoming connections. Nothing is allowed in unless we explicitly say so.

```bash
$ sudo ufw default allow outgoing
```
- Allows all outgoing connections so the Pi can reach the internet to fetch news and vulnerability data.

```bash
$ sudo ufw allow ssh
```
- Creates an exception to allow SSH connections on port 22. **Always do this before enabling the firewall** — otherwise you'll lock yourself out of the Pi.

**Find your home network range:**

On your Mac, open a new Terminal window (not the SSH session) and run:
```bash
ipconfig getifaddr en0
```
You'll see an IP address like `192.168.1.105`. Your home network range is the first three numbers with `.0/24` added at the end — the `/24` means "all 256 addresses in this block":
- IP `192.168.1.105` → range is `192.168.1.0/24`
- IP `10.0.1.5` → range is `10.0.1.0/24`

> **Note:** always use `/24` (not `/8`). A `/8` range like `10.0.0.0/8` covers 16 million addresses — far more than your home network.

Back on the Pi, run this command with your actual network range:
```bash
$ sudo ufw allow from 192.168.1.0/24 to any port 8000
```
- `allow from 192.168.1.0/24` — only allow connections from devices on your home network. Replace `192.168.1.0/24` with your actual range.
- `to any port 8000` — specifically for port 8000, where the dashboard runs.

Enable the firewall:
```bash
$ sudo ufw enable
```
Type `y` and press Enter to confirm. The firewall is now active and will automatically re-enable on every reboot.

Verify your rules:
```bash
$ sudo ufw status
```
You should see entries for SSH (`22`) and port `8000` showing as `ALLOW`.

> If you plan to set up Tailscale for remote access later, you'll add one more rule in [Tailscale — Remote Access](tailscale-setup.md).

---

## Step 11 — Install the App as a System Service

A systemd service is a background program that starts automatically when the Pi boots and restarts automatically if it ever crashes.

```bash
$ sudo cp security-automation.service /etc/systemd/system/security-automation.service
```
- Copies the service configuration template (included in the project) to the folder where systemd looks for service definitions.

Open the file to update the username and paths for your specific Pi:
```bash
$ sudo nano /etc/systemd/system/security-automation.service
```

Find these three lines and update them. Replace `pi` with your Pi's actual username, and make sure the path matches where you cloned the project:
```
User=pi
WorkingDirectory=/home/pi/security-automation
ExecStart=/home/pi/security-automation/venv/bin/python main.py
```

Save and close (`Ctrl+X`, `Y`, `Enter`).

Register the service:
```bash
$ sudo systemctl daemon-reload
```
- Tells systemd to re-read all service files. Required after adding or editing any service.

```bash
$ sudo systemctl enable security-automation
```
- `enable` — marks this service to start automatically every time the Pi boots.

```bash
$ sudo systemctl start security-automation
```
- `start` — starts the service right now, without needing to reboot.

Confirm it's running:
```bash
$ sudo systemctl status security-automation
```
Look for `Active: active (running)`. If you see an error, check the logs to find out what went wrong:
```bash
$ journalctl -u security-automation -n 50
```
- `journalctl` — views logs produced by systemd services.
- `-u security-automation` — filters to show only logs from this service.
- `-n 50` — shows the last 50 lines.

---

## Step 12 — Set Up Log Rotation

Without log rotation, the app's log file grows indefinitely and can fill up your storage over weeks or months.

```bash
$ sudo cp security-automation.logrotate /etc/logrotate.d/security-automation
```
- Copies the logrotate configuration template (included in the project) to the folder where logrotate checks for configurations.

This sets logrotate to:
- Archive the current log file once per day and start a fresh one
- Keep 7 days of archived logs
- Compress archived logs to save space
- Delete anything older than 7 days automatically

Verify the configuration has no errors:
```bash
$ sudo logrotate --debug /etc/logrotate.d/security-automation
```
- `--debug` — performs a dry run without actually rotating anything. If no errors appear in the output, the configuration is correct.

---

## Step 13 — Verify Everything is Working

Check that both services are running:
```bash
$ sudo systemctl status ollama
$ sudo systemctl status security-automation
```
Both should show `Active: active (running)`.

Find your Pi's IP address on your home network:
```bash
$ hostname -I
```
This prints the Pi's current IP (e.g., `192.168.1.42`).

On your Mac, open a browser and go to:
```
http://192.168.1.42:8000
```
Replace the IP with your Pi's actual address. You should see the dashboard login screen. Sign in with the username and password you set in `config.yaml`.

To run the pipeline immediately without waiting 6 hours, click the **Run Now** button in the dashboard.

---

## Step 14 — Optional: Assign a Permanent IP to Your Pi

By default, your router gives the Pi a different IP address each time it reconnects to the network. This means the dashboard URL could change after a reboot.

Assigning a permanent (static) IP fixes this. The exact steps differ by router brand, but the general process is:

1. Log into your router's admin page — usually `192.168.1.1` or `192.168.0.1` typed into a browser (check the label on your router if unsure)
2. Find the list of connected devices and locate your Pi (look for `raspberrypi` in the device name)
3. Find an option called **Static IP**, **Reserved IP**, or **DHCP Reservation** — this tells your router to always assign the same address to your Pi
4. Set a fixed IP (e.g., `192.168.1.100`) and save

After this, you can also access the dashboard using the hostname instead of the IP:
```
http://raspberrypi.local:8000
```
This works from your Mac as long as both devices are on the same network.

---

## All Done

Your Pi is fully set up. The pipeline will run automatically every 6 hours and send notifications when it finds Critical or High severity vulnerabilities in your GitHub repositories.

**Next steps:**
- Set up remote access from anywhere → [Tailscale — Remote Access](tailscale-setup.md)
- Change the AI model → [MODELS.md](../MODELS.md)
