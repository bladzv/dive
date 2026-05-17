"""
Integration test for collector.py — M2 quality checkpoint.

Runs against live external services. Requires:
  - config.yaml with a valid GitHub token
  - Internet access

Usage (from project root):
    python tests/integration/test_collector.py

Exit code 0 = all checks passed.
Exit code 1 = one or more checks failed (see output).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Ensure project root is on the path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import collector
import config as cfg_module
import db


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}" + (f": {detail}" if detail else ""))
    return condition


def main() -> int:
    print("=" * 60)
    print("Collector integration test — M2 quality checkpoint")
    print("=" * 60)

    # --- Load config ---
    print("\n[1] Loading config.yaml")
    try:
        config = cfg_module.load()
        print("  [PASS] config.yaml loaded")
    except Exception as exc:
        print(f"  [FAIL] Cannot load config.yaml: {exc}")
        return 1

    failures = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_collector.db"
        db.init(db_path)

        with db.get_conn(db_path) as conn:
            # --- Run collector ---
            print("\n[2] Running collector (all sources)")
            stats = collector.run(conn, config)

            # --- Checks ---
            print("\n[3] Checking results")

            if not check(
                "Items fetched > 0", stats.items_fetched > 0, f"got {stats.items_fetched}"
            ):
                failures += 1

            if not check("New items inserted > 0", stats.items_new > 0, f"got {stats.items_new}"):
                failures += 1

            total_in_db = conn.execute("SELECT COUNT(*) FROM news_items").fetchone()[0]
            if not check("Database has items", total_in_db > 0, f"got {total_in_db}"):
                failures += 1

            # Check each source contributed something (or warn)
            sources = {
                row[0] for row in conn.execute("SELECT DISTINCT source FROM news_items").fetchall()
            }
            print(f"\n  Sources with data: {sorted(sources)}")

            expected_sources = {
                "Bleeping Computer",
                "Krebs on Security",
                "The Hacker News",
                "SANS ISC",
                "Cisco Talos",
                "Palo Alto Unit 42",
                "Google Mandiant",
                "CrowdStrike Blog",
                "Dark Reading",
                "NIST NVD",
                "CISA KEV",
                "GitHub Security Advisories",
            }
            missing = expected_sources - sources
            if missing:
                # Warn but don't fail — some feeds may be temporarily down
                print(f"  [WARN] Sources with no data: {sorted(missing)}")
                if stats.failed_sources:
                    print(f"  [WARN] Failed sources: {stats.failed_sources}")

            # Check field shapes for a sample item
            sample = conn.execute("SELECT * FROM news_items ORDER BY RANDOM() LIMIT 1").fetchone()
            if sample:
                if not check("Sample item has url", bool(sample["url"])):
                    failures += 1
                if not check("Sample item has title", bool(sample["title"])):
                    failures += 1
                if not check("Sample item has source", bool(sample["source"])):
                    failures += 1
                if not check("Sample item has fetched_at", bool(sample["fetched_at"])):
                    failures += 1

            # Check dedup — running again should add 0 new items
            print("\n[4] Checking deduplication (second run)")
            stats2 = collector.run(conn, config)
            if not check(
                "Second run adds 0 new items", stats2.items_new == 0, f"got {stats2.items_new}"
            ):
                failures += 1

    # --- Summary ---
    print("\n" + "=" * 60)
    if failures == 0:
        print("ALL CHECKS PASSED — collector is ready for M3")
        print("\nNext: open the database and spot-check a few items manually,")
        print("then run tests/integration/test_categorizer.py to validate")
        print("qwen2.5:3b output quality before building M3 on top.")
    else:
        print(f"{failures} CHECK(S) FAILED — review output above")
    print("=" * 60)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
