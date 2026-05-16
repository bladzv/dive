# Integration Tests

These scripts run against **live external services** and require real credentials.
They are **not run in CI** — run them manually during development to validate
that the pipeline components work end-to-end before wiring logic together.

## When to use

| Script | Run when | What it validates |
|---|---|---|
| `test_collector.py` | After M2 — before wiring categorizer | RSS feeds return parseable items; NVD/CISA/OSV APIs return expected shapes |
| `test_scanner.py` | After M3 — before wiring lifecycle | OSV.dev returns parseable responses for real manifests; GitHub API reads repos |
| `test_notifier.py` | After M4 — before considering notifications done | Each configured channel (Slack/Discord/email) delivers a test message |

## Requirements

- `config.yaml` present and filled in with real credentials
- Ollama running (`docker compose up ollama -d` or bare-metal `ollama serve`)
- Internet access

## Running

```bash
# From the project root, with your venv active:
python tests/integration/test_collector.py
python tests/integration/test_scanner.py
python tests/integration/test_notifier.py
```

Each script prints a pass/fail summary. A failed check means the component
needs attention before the next milestone builds on top of it.

Scripts are added here in M2 and M3 alongside the components they test.
