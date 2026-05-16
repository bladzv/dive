# How DIVE Works

A plain-English walkthrough for beginners.

---

## What is DIVE?

DIVE is a **security watchdog** for your GitHub repositories. It runs in the background and automatically:

1. Collects security news from the internet
2. Scans your code for known vulnerabilities
3. Alerts you via Slack, Discord, or email

Think of it like a smoke detector, but for software security issues.

---

## The pipeline

Every few hours (you configure the interval), DIVE runs a **pipeline** — a series of steps that each do one job. Each step saves its results to a database file on disk, so the next step can read them.

```
1. collector          → Downloads security news (RSS feeds, CVE databases, etc.)
2. categorizer        → Uses an AI model to label news by severity
3. github_scanner     → Scans your GitHub repos for vulnerable packages
4. github_issue_creator → (optional) Opens GitHub issues for findings
5. secrets_scanner    → Looks for accidentally committed secrets (passwords, tokens)
6. lifecycle          → Tracks whether vulnerabilities are new, resolved, or regressed
7. notifier           → Sends alerts for anything new
```

A failed step does not abort the rest. Each step catches its own errors so the pipeline always runs to completion.

---

## What you interact with

DIVE has a **web dashboard** where you can:

- Read the latest security news
- See what vulnerabilities were found in your repos
- Manage settings (which feeds to follow, which repos to ignore, etc.)
- View history charts and weekly summaries

---

## A concrete example

1. You have a Python project that uses `requests==2.28.0`
2. A CVE is published saying that version has a security bug
3. DIVE's scanner finds your `requirements.txt`, queries a public vulnerability database, and records the match
4. The notifier sends you a Slack message: "Found CVE-2024-XXXX in requests in repo my-app"
5. You update the package — next scan, DIVE marks it resolved

---

## How the GitHub scanner works

The scanner **never clones your repositories**. Cloning would be slow and expensive. Instead it uses three targeted steps:

### Step 1 — Get the file list (1 API call per repo)

```python
tree = repo.get_git_tree(repo.default_branch, recursive=True)
```

This asks GitHub: *"Give me a list of every file path in this repo."* It gets back filenames like `src/app.py`, `requirements.txt`, `package.json` — but not the file contents yet.

### Step 2 — Find only the dependency files

It scans that list looking for known filenames:

| File | Language |
|---|---|
| `requirements.txt`, `Pipfile`, `pyproject.toml` | Python |
| `package-lock.json`, `package.json` | JavaScript (npm) |
| `go.mod` | Go |
| `Cargo.lock`, `Cargo.toml` | Rust |
| `pom.xml`, `build.gradle` | Java |
| `Gemfile.lock`, `Gemfile` | Ruby |
| `.github/workflows/*.yml` | GitHub Actions |

If a repo has 500 files but only one `requirements.txt`, only that one file is downloaded.

When both a lock file and a loose manifest exist (e.g. `Cargo.lock` and `Cargo.toml`), DIVE prefers the lock file because it contains exact pinned versions rather than version ranges.

### Step 3 — Download and parse just those files

It fetches the raw text of each manifest and extracts a list of packages and versions. For example, `requests==2.28.0` becomes: package name `requests`, version `2.28.0`, ecosystem `PyPI`.

### Step 4 — Ask a vulnerability database "are any of these vulnerable?"

After scanning all repos, it sends one batch request to [OSV.dev](https://osv.dev) (a free public vulnerability database) asking: *"Here are 300 packages with their versions — which ones have known CVEs?"*

OSV.dev replies with a list of vulnerabilities for each match. DIVE stores those as **findings**.

### Why this design is efficient

| Approach | Data downloaded |
|---|---|
| Clone every repo | Full git history of every repo |
| DIVE's approach | Only the manifest files |

The scanner also monitors GitHub API rate limits and stops early with a warning rather than silently skipping repos.

---

## How the AI categorization works

The AI (a local [Ollama](https://ollama.com) model — no data leaves your machine) is used in two places.

### 1. Labelling security news

When new articles arrive, DIVE sends them to the model in batches of 10 with a plain-English prompt:

```
You are a security news classifier. Classify each item below.

Output ONLY a JSON array with exactly 3 objects in the same order as the items.
No explanation, no markdown, no code fences — only the JSON array.

Each object must have exactly these fields:
{
  "category": one of ["Vulnerability","Breach","Malware","Patch",...],
  "severity": one of ["Critical","High","Medium","Low","Info"],
  "affected_products": array of strings (max 5),
  "summary": string (one sentence, max 160 characters),
  "tags": array of strings (max 5)
}

Items:

<item id="1">
Title: OpenSSL Remote Code Execution Vulnerability
Content: A critical flaw in OpenSSL allows...
</item>
```

The model replies with raw JSON. DIVE parses it and saves the labels to the database.

### 2. Explaining a vulnerability in plain English

When a new Critical or High severity finding is discovered, DIVE asks the model for developer-friendly advice:

```
You are a security advisor helping a developer fix a vulnerability.

Output ONLY valid JSON with exactly these three fields:
{
  "impact": "one sentence — what an attacker could do if this is exploited",
  "fix": "the specific command or code change to fix this (be concrete)",
  "effort": "Low" or "Medium" or "High"
}

Vulnerability: CVE-2024-1234
Package: requests 2.28.0 (PyPI)
Fixed in: 2.32.0
Summary: Improper handling of redirects allows...
```

### Key things to understand about this approach

- **The model never touches your database or code directly.** The Python code queries the database, then pastes the relevant data into a prompt as plain text.
- **The output format is enforced by the prompt.** Telling the model "Output ONLY a JSON array" ensures the response can be parsed programmatically.
- **Low temperature (`0.1`)** makes the model less creative and more predictable — important when you need structured, consistent output.
- **Prompt injection defence.** Before inserting RSS feed content into a prompt, DIVE strips control characters so a malicious feed cannot sneak in fake instructions.

---

## How severity and priority are decided

This is the most important thing to understand: **severity for news and severity for findings are decided by completely different mechanisms.**

---

### News items — the AI decides

When a security article arrives, DIVE has no structured data to work with — just a title and some text. So it hands the content to the AI model and asks it to judge. The AI picks one of five labels:

| Label | Meaning |
|---|---|
| Critical | Widespread, actively exploited, or affects critical infrastructure |
| High | Serious risk but more limited in scope or exploitability |
| Medium | Noteworthy but requires specific conditions to exploit |
| Low | Minor or theoretical risk |
| Info | No direct risk — research, tool release, policy news |

There is no formula here. The AI reads the article and makes a judgment call, just like a human analyst would. That means it can be wrong, especially on ambiguous articles. If more than 20% of items in a batch come back as "Uncategorized", DIVE logs a warning suggesting you try a different model.

---

### Vulnerability findings — CVSS score decides

When DIVE finds a vulnerable package in your repos, the severity comes from the **CVSS score** attached to the CVE by the vulnerability database (OSV.dev). CVSS is an industry-standard scoring system, not an AI guess.

#### What is a CVSS score?

CVSS (Common Vulnerability Scoring System) is a number from 0 to 10 that captures how bad a vulnerability is. It is computed from a **vector string** — a compact notation that describes the vulnerability's characteristics. For example:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Each segment means something:

| Segment | Meaning | Value above |
|---|---|---|
| `AV:N` | Attack Vector: Network | Exploitable remotely |
| `AC:L` | Attack Complexity: Low | Easy to exploit |
| `PR:N` | Privileges Required: None | No login needed |
| `UI:N` | User Interaction: None | Victim doesn't need to click anything |
| `C:H` | Confidentiality impact: High | Data can be read |
| `I:H` | Integrity impact: High | Data can be modified |
| `A:H` | Availability impact: High | Service can be taken down |

DIVE uses the `cvss` library to calculate the numeric score from that string. If the library is not installed, it falls back to counting how many of the three impact metrics (C, I, A) are "High" as a rough approximation.

#### From score to label

Once DIVE has a numeric score, it maps it to a label:

| Score | Label |
|---|---|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.0 – 3.9 | Low |

If no CVSS vector is available, DIVE falls back to the text label that GitHub or OSV attached to the advisory (e.g. "HIGH") and uses a fixed approximate score for it.

#### What gets stored

DIVE only stores **Critical**, **High**, and **Unknown** findings. Medium and Low are silently discarded. This is intentional — on a busy codebase, low-severity findings would create too much noise.

---

### The priority score — beyond raw severity

After severity is determined, DIVE computes a **priority score** from 0 to 100 that helps you decide what to fix first. It combines three signals:

```
Priority = (CVSS score × 6) + KEV bonus − no-patch penalty
```

| Signal | Points | Why |
|---|---|---|
| CVSS score | up to 60 (score × 6) | Higher CVSS = higher risk |
| CISA KEV | +25 | The US government confirmed this CVE is being actively exploited in the wild |
| No patch available | −5 | If nothing can be done yet, slightly deprioritise |

**Example:** A CVSS 9.5 finding that is on the CISA KEV list with a patch available:

```
(9.5 × 6) + 25 − 0 = 57 + 25 = 82 out of 100
```

The CISA KEV bonus (+25) is large by design. A medium-severity CVE that real attackers are actively exploiting right now is more urgent than a theoretical Critical that no one has weaponised.

---

### Summary: two systems working together

| | News items | Vulnerability findings |
|---|---|---|
| Source of severity | AI model judgment | CVSS score from OSV.dev |
| Can be wrong? | Yes — AI makes mistakes | Rarely — it's a formula |
| Filtered? | No — all items are shown | Yes — only Critical/High/Unknown stored |
| Priority ranking | No | Yes — 0–100 score |

---

## Key files

| File | Plain-English role |
|---|---|
| `main.py` | Starts everything — the web server and the scheduler |
| `collector.py` | "Go fetch today's security news" |
| `categorizer.py` | "Ask the AI to label each news item" |
| `github_scanner.py` | "Check my repos for vulnerable packages" |
| `secrets_scanner.py` | "Check my repos for leaked secrets" |
| `lifecycle.py` | "Mark findings resolved when they disappear" |
| `notifier.py` | "Send me an alert" |
| `db.py` | All database read/write operations |
| `settings.py` | User preferences stored in the database |

---

## Further reading

- [Setup guide](setup.md) — get DIVE running
- [Docker setup](docker-setup.md) — recommended install path
- [Model selection](models.md) — choosing an Ollama model for your hardware
