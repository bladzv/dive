---
name: create-pr-description
description: Generate a complete PR description from the session action log. Derives a semantic branch name, conventional commit message, links related GitHub Issues, and writes the full description to .github/pr_description.md.
disable-model-invocation: true
---

Follow these steps exactly:

## Step 1 — Read session actions

Read the **entire** contents of `.github/actions.md`.

## Step 2 — Generate a semantic branch name

Analyze all logged actions and pick the appropriate prefix:

| Prefix | When to use |
|---|---|
| `feature/` | New functionality or capabilities |
| `fix/` | Bug fixes or corrections |
| `refactor/` | Code restructuring without feature changes |
| `chore/` | Maintenance tasks (dependencies, configs) |
| `docs/` | Documentation-only changes |
| `security/` | Security improvements or patches |

Format: `[prefix]/[kebab-case-description]`  
Rules: keep under 50 characters, be specific but concise, use descriptive verbs (add, implement, fix, improve), avoid articles (the, a, an).

## Step 3 — Generate a conventional commit message

One-line summary in the format: `[type]([scope]): [description]`

Types: `feat`, `fix`, `refactor`, `chore`, `docs`, `security`, `perf`, `test`

Rules: imperative mood ("Add" not "Added"), under 72 characters, no trailing period, lowercase description.

## Step 4 — Check GitHub Issues

Search the repository for existing GitHub Issues. Identify any issues addressed by the logged actions. Match action descriptions to issue titles and descriptions. Look for keywords: bug, feature request, enhancement, security.

## Step 5 — Create and write the PR description

Create the file if it does not exist:
```bash
touch .github/pr_description.md
```

**Always append** to the end of the file — never modify existing entries. Use the `printf` command. Do **not** use heredoc or `echo`.

Fetch the current UTC timestamp:
```bash
date -u +"%Y-%m-%d %H:%M:%S UTC"
```

Use this exact template:

```
# PR: [Descriptive title — short imperative summary of what this PR does]
Timestamp: [YYYY-MM-DD HH:MM:SS UTC]
Git Branch: [semantic-branch-name]
Git Commit Message: [conventional commit message]

---

## Summary
[2–4 sentence paragraph: what changed, why it matters, most important outcomes. No bullet points.]

---

## Related Issues
[List GitHub Issues this PR addresses. If none, write "None"]
- Closes #N
- Fixes #N
- Related to #N

---

## Added Features
[New functionality. If none, write "None"]

### [Feature Area / Component]
- **[Feature name]**: [Description of what it does and why it matters.]

---

## Changes
[Modifications to existing functionality or refactoring — not new features, not bug fixes. If none, write "None"]
- **[Component/area — change name]**: [What changed and why.]

---

## Fixes
[Bugs or issues resolved. If none, write "None"]
- **[Short fix name]**: [Root cause, what was broken, what the fix does.]

---

## Files Changed

| File | Change |
|---|---|
| `path/to/file.ext` | [One-line description] |
| `path/to/file.ext` | **NEW**: [Description] |

---

## Testing Notes
[Testing approach and verification steps]

**How to Test:**
1. [Step-by-step instruction]
2. [Expected result]

**Test Coverage:**
- [Browsers tested]
- [Scenarios validated]

---

## Security Considerations
[Security-related changes, OWASP categories addressed]

**Security Measures:**
- **[OWASP category or concern]**: [What was done.]

If no security changes: "No security changes in this PR"

---

## Performance Impact
[Improvements, trade-offs, bundle size, render, or runtime implications]

If no impact: "No significant performance impact"

---

## Breaking Changes
[List any breaking changes and migration path. If none, write "None"]

---

## Dependencies
[New or updated packages. If none, write "None"]
- `package@version` — [Why added/updated]

---

## Follow-up Items
[Tasks for future PRs. If none, write "None"]
- [ ] [Task description]

---
```

## Step 6 — Confirm and print next steps

After writing, output exactly:

```
✓ PR Description Generated

Branch: [semantic-branch-name]
Commit: [commit-message]
Issues: [count] related issue(s) found

PR description saved to .github/pr_description.md

Next Steps:
  1. Review the PR description
  2. Create branch: git checkout -b [branch-name]
  3. Stage changes: git add .
  4. Commit: git commit -m "[commit-message]"
  5. Push: git push origin [branch-name]
  6. Create PR using description from .github/pr_description.md
```
