"""
Integration test for notifier.py — live channel delivery.

Requires config.yaml with at least one notification channel configured
(slack.webhook_url, discord.webhook_url, or email settings).

Usage (from project root):
    python tests/integration/test_notifier.py

Exit code 0 = all checks passed.
Exit code 1 = one or more checks failed.

NOTE: This test WILL send real messages to your configured channels.
      Run it only when you want to verify end-to-end delivery.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import dive.config as cfg_module
import dive.notifier as notifier


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}" + (f": {detail}" if detail else ""))
    return condition


def _make_row(**kwargs) -> sqlite3.Row:
    """Build a sqlite3.Row from a dict."""
    defaults = {
        "id": 1,
        "repo_full_name": "user/test-repo",
        "cve_id": "CVE-2024-TEST-001",
        "ghsa_id": None,
        "package_name": "requests",
        "package_ecosystem": "PyPI",
        "installed_version": "2.28.0",
        "fixed_version": "2.32.0",
        "cvss_score": 9.1,
        "is_kev": 1,
        "patch_available": 1,
        "priority_score": 79.6,
        "state": "new",
        "manifest_path": "requirements.txt",
        "notified_at": None,
    }
    defaults.update(kwargs)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cols = list(defaults.keys())
    vals = list(defaults.values())
    placeholders = ", ".join("?" * len(cols))
    conn.execute(f"CREATE TABLE t ({', '.join(cols)})")
    conn.execute(f"INSERT INTO t VALUES ({placeholders})", vals)
    return conn.execute("SELECT * FROM t").fetchone()


def main() -> int:
    print("=" * 60)
    print("Notifier integration test — live channel delivery")
    print("=" * 60)

    print("\n[1] Loading config.yaml")
    try:
        config = cfg_module.load()
        print("  [PASS] config.yaml loaded")
    except Exception as exc:
        print(f"  [FAIL] Cannot load config.yaml: {exc}")
        return 1

    if not config.notifications.has_any_notification_channel:
        print("\n  [SKIP] No notification channels configured in config.yaml")
        print("  Add slack.webhook_url, discord.webhook_url, or email settings to test.")
        return 0

    failures = 0

    # ------------------------------------------------------------------
    # [2] Send a test findings alert
    # ------------------------------------------------------------------
    print("\n[2] Sending test findings alert (1 mock critical finding)")
    finding = _make_row()
    try:
        notifier.send_findings_alert(config, [finding])
        print("  [PASS] send_findings_alert completed without exception")
    except Exception as exc:
        print(f"  [FAIL] send_findings_alert raised: {exc}")
        failures += 1

    # ------------------------------------------------------------------
    # [3] Send a test failure alert
    # ------------------------------------------------------------------
    print("\n[3] Sending test failure alert")
    try:
        notifier.send_failure_alert(config, "Integration test — this is a synthetic error message")
        print("  [PASS] send_failure_alert completed without exception")
    except Exception as exc:
        print(f"  [FAIL] send_failure_alert raised: {exc}")
        failures += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if failures == 0:
        print("ALL CHECKS PASSED")
        print("\nCheck your Slack / Discord / email for two test messages.")
        print("If nothing arrived, check webhook URLs and SMTP settings in config.yaml.")
    else:
        print(f"{failures} CHECK(S) FAILED — review output above")
    print("=" * 60)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
