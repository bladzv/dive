---
name: create-logs
description: Record all changes made in the current session into .github/actions.md. Compares the local codebase against the remote main branch and logs every action taken.
disable-model-invocation: true
---

Follow these steps exactly:

## Step 1 — Check and prepare the log file

Check whether `.github/actions.md` exists.
- If it does **not** exist: create a new blank file at `.github/actions.md`.
- If it **does** exist: read its entire content to understand which actions have already been logged, so you avoid duplicate entries.

## Step 2 — Compare with remote

Compare the local codebase with the remote repository `main` branch. Use the GitHub MCP to access the repository and retrieve the necessary information about what has changed.

## Step 3 — Write log entries

For every action taken in this session that has not yet been logged, append a new entry to `.github/actions.md` using the `printf` command. Do **not** use heredoc or `echo`.

Each entry must follow this exact format:

```
# Action: [Short descriptive title]
Timestamp: [YYYY-MM-DD HH:MM:SS UTC]

## Changes Made
- [Detailed description of changes]
- [Another change if applicable]

## Files Modified
- `path/to/file1.js` - [brief description]
- `path/to/file2.css` - [brief description]

## Rationale
[Why these changes were made — business/technical reasoning]

## Technical Notes
- [Important implementation details]
- [Security considerations]
- [Performance implications]
- [Dependencies or follow-up items]

---
```

Fetch the current UTC timestamp programmatically:
```bash
date -u +"%Y-%m-%d %H:%M:%S UTC"
```

The log must be **comprehensive** — cover all changes, fixes, and additions made during this session.
