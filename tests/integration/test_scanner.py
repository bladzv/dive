"""
Integration test for github_scanner.py — M3 quality checkpoint.

Validates OSV.dev API shape and GitHub manifest scanning against real repos.
Requires config.yaml with a valid GitHub token and internet access.

Usage (from project root):
    python tests/integration/test_scanner.py

Exit code 0 = all checks passed.
Exit code 1 = one or more checks failed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import httpx

import config as cfg_module
import db
import github_scanner as gs
from github_scanner import (
    _extract_fixed_version,
    _extract_severity,
    _make_http_client,
    _parse_package_json,
    _parse_requirements_txt,
)


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}" + (f": {detail}" if detail else ""))
    return condition


def main() -> int:
    print("=" * 60)
    print("Scanner integration test — M3 quality checkpoint")
    print("=" * 60)

    print("\n[1] Loading config.yaml")
    try:
        config = cfg_module.load()
        print("  [PASS] config.yaml loaded")
    except Exception as exc:
        print(f"  [FAIL] Cannot load config.yaml: {exc}")
        return 1

    failures = 0

    # ------------------------------------------------------------------
    # [2] OSV.dev API smoke test — known vulnerable package
    # ------------------------------------------------------------------
    print("\n[2] OSV.dev API — querying a known-vulnerable package")
    try:
        with _make_http_client() as client:
            payload = {
                "queries": [
                    # requests 2.6.0 is known to be vulnerable (CVE-2023-32681)
                    {"version": "2.6.0", "package": {"name": "requests", "ecosystem": "PyPI"}},
                    # lodash 4.17.20 is known to be vulnerable
                    {"version": "4.17.20", "package": {"name": "lodash", "ecosystem": "npm"}},
                ]
            }
            resp = client.post("https://api.osv.dev/v1/querybatch", json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()

        results = data.get("results", [])
        if not check("OSV.dev returns results list", isinstance(results, list)):
            failures += 1
        if not check("Two results returned", len(results) == 2, f"got {len(results)}"):
            failures += 1

        if results:
            r0 = results[0]
            vulns = r0.get("vulns") or []
            if not check("requests 2.6.0 has vulns", len(vulns) > 0,
                         f"got {len(vulns)} vulns"):
                failures += 1
            if vulns:
                v = vulns[0]
                if not check("Vuln has 'id' field", "id" in v):
                    failures += 1
                if not check("Vuln has 'affected' field", "affected" in v):
                    failures += 1

                # Test our severity extractor on a real response
                text, score = _extract_severity(v)
                print(f"  Severity extracted: {text} (approx CVSS: {score})")
                if not check("Severity text not empty", bool(text)):
                    failures += 1

                # Test fixed version extractor
                fixed = _extract_fixed_version(v, "PyPI", "requests")
                print(f"  Fixed version: {fixed}")
                if not check("Fixed version extracted or None", fixed is None or "." in str(fixed)):
                    failures += 1

    except Exception as exc:
        print(f"  [FAIL] OSV.dev API call failed: {exc}")
        failures += 1

    # ------------------------------------------------------------------
    # [3] GitHub repo scan (first repo found)
    # ------------------------------------------------------------------
    print("\n[3] GitHub scanner — scanning your repositories")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_scanner.db"
        db.init(db_path)

        with db.get_conn(db_path) as conn:
            stats = gs.run(conn, config)

            if not check("Repos scanned > 0", stats.repos_scanned > 0,
                         f"got {stats.repos_scanned}"):
                failures += 1

            print(f"  Repos scanned:    {stats.repos_scanned}")
            print(f"  Packages checked: {stats.packages_checked}")
            print(f"  New findings:     {stats.findings_new}")
            print(f"  Updated findings: {stats.findings_updated}")
            print(f"  API requests used: {stats.api_requests_used}")
            if stats.failed_repos:
                print(f"  [WARN] Failed repos: {stats.failed_repos}")
            if stats.rate_limit_warning:
                print("  [WARN] Rate limit warning triggered")

            # Verify findings shape
            findings = db.get_findings(conn)
            if findings:
                f = findings[0]
                if not check("Finding has repo_full_name", bool(f["repo_full_name"])):
                    failures += 1
                if not check("Finding has package_name", bool(f["package_name"])):
                    failures += 1
                if not check("Finding state is 'new'", f["state"] == "new",
                             f"got '{f['state']}'"):
                    failures += 1
                print(f"\n  Sample finding:")
                print(f"    repo:     {f['repo_full_name']}")
                print(f"    package:  {f['package_name']} {f['installed_version']}")
                print(f"    cve:      {f['cve_id'] or f['ghsa_id']}")
                print(f"    severity: cvss={f['cvss_score']} kev={bool(f['is_kev'])}")
                print(f"    priority: {f['priority_score']}")
            else:
                print("  [INFO] No Critical/High findings — repo may be clean or have no scannable manifests")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if failures == 0:
        print("ALL CHECKS PASSED — scanner is ready for M4")
        print("\nNext: review findings above, then build lifecycle.py and notifier.py.")
    else:
        print(f"{failures} CHECK(S) FAILED — review output above")
    print("=" * 60)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
