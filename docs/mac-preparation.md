# Credential Preparation

Before touching the Raspberry Pi, you need to create the credentials the project will use. All of these steps are done in a browser — on a Mac, Linux desktop, Windows, or any device with a web browser.

**Time:** approximately 10 minutes.

← Back to [Setup Guide](../SETUP.md) | Next: [Raspberry Pi Setup](raspberry-pi-setup.md) →

---

## What You'll Create

| Credential | Required | Used For |
|---|---|---|
| GitHub Personal Access Token | Yes | Reading your repositories and dependency files |
| Slack Webhook URL | No | Receiving notifications in a Slack channel |
| Discord Webhook URL | No | Receiving notifications in a Discord channel |
| Gmail App Password | No | Receiving notifications by email via Gmail |

You need at least one notification method (Slack, Discord, or email) to receive alerts when the pipeline finds vulnerabilities. You can set up more than one.

---

## Step 1 — Create a GitHub Personal Access Token

A Personal Access Token (PAT) is like a password that lets the app read your GitHub repositories on your behalf — without giving it access to anything else on your account.

This guide uses a **fine-grained PAT**, which lets you grant the minimum permissions needed and set a mandatory expiration date. This is safer than a classic PAT — if the token is ever leaked, the blast radius is much smaller.

1. Go to **github.com** and sign in
2. Click your profile picture in the top-right corner → **Settings**
3. Scroll all the way to the bottom of the left sidebar → click **Developer settings**
4. Click **Personal access tokens** → **Fine-grained tokens**
5. Click **Generate new token**
6. In the **Token name** field, type: `security-automation`
7. Set **Expiration** to **90 days** (or choose a shorter period — you will need to regenerate it when it expires, and update `config.yaml` with the new token)
8. Under **Resource owner**, select your personal account
9. Under **Repository access**, select **All repositories** *(or choose specific repos if you prefer to limit scope)*
10. Under **Permissions → Repository permissions**, set exactly these:
    - **Contents** → **Read-only** — allows reading dependency files and code
    - **Metadata** → **Read-only** — allows listing repositories *(auto-selected, required)*
11. Click **Generate token**
12. **Copy the token immediately** — GitHub only shows it once. It looks like `github_pat_xxxxxxxxxxxxxxxxxxxx`. Paste it somewhere temporary (like a notes app) — you'll add it to the config file during setup.

> **Token renewal:** when your token expires, the scanner will fail with an authentication error. Generate a new token using the same steps above, then update the `github.token` field in `config.yaml` and restart the app.

> **If you belong to a GitHub organization:** org repos require the token owner to have `read` access to those repos. No additional PAT scope is needed for fine-grained tokens — org repo access is determined by your org membership.

---

## Step 2 — Create a Slack Webhook URL (optional)

A webhook URL is a special address you send messages to, and Slack automatically posts those messages to a channel of your choice.

1. Go to **api.slack.com/apps** and sign in to your Slack account
2. Click **Create New App** → choose **From scratch**
3. Name it `Security Automation`, select your workspace from the dropdown → click **Create App**
4. In the left sidebar under **Features**, click **Incoming Webhooks**
5. Toggle **Activate Incoming Webhooks** to **On** (the toggle turns blue)
6. Click **Add New Webhook to Workspace** (at the bottom of the page)
7. In the dropdown, choose the Slack channel you want notifications sent to (e.g., `#security` or `#general`) → click **Allow**
8. Under **Webhook URLs for Your Workspace**, copy the URL that appears  
   *(It starts with `https://hooks.slack.com/services/...`)*

Keep this URL somewhere safe — anyone with it can post messages to your Slack channel.

---

## Step 3 — Create a Discord Webhook URL (optional)

1. Open Discord and go to the server and channel where you want notifications
2. Click the gear icon (⚙️) next to the channel name to open **Channel Settings**
3. In the left sidebar, click **Integrations**
4. Click **Webhooks** → **New Webhook**
5. Give it a name like `Security Automation`
6. Click **Copy Webhook URL**

---

## Step 4 — Create a Gmail App Password (optional)

Regular Gmail passwords won't work for sending email from an app. When 2-Step Verification is enabled (which it must be), Google requires a separate "App Password" — a one-time password generated just for this app.

1. Go to **myaccount.google.com/security** and sign in
2. Confirm that **2-Step Verification** is turned on. If it's not, click it and follow the steps to enable it — this is required before App Passwords become available
3. In the search bar at the top of the page, type **App passwords** and click the result
4. Under "Select app", choose **Mail**
5. Under "Select device", choose **Other (custom name)**, type `Security Automation` → click **Generate**
6. A 16-character password will appear (formatted as four groups of four letters). Copy it — this is your SMTP password. Google will not show it again

> This app password only works for sending email — it cannot be used to log into your Gmail account.

---

## All Done

You should now have:
- [x] A GitHub Personal Access Token (starts with `github_pat_`)
- [x] A Slack Webhook URL (optional, starts with `https://hooks.slack.com/`)
- [x] A Discord Webhook URL (optional)
- [x] A Gmail App Password (optional, 16 characters)

Keep these handy — you'll paste them into the config file in the next guide.

**Next:** [Raspberry Pi Setup →](raspberry-pi-setup.md)
