#!/usr/bin/env python3
"""Populate a fresh development database with realistic dummy data.

Usage:
    DB_PATH=data/dev.db python scripts/seed_dev.py

Defaults to data/dev.db so it never touches the real database.
Run from the repo root with the venv active.
"""

import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Allow running from repo root without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent))

os.environ.setdefault("DB_PATH", "data/dev.db")

from dive import db  # noqa: E402


def _ago(days: float = 0, hours: float = 0) -> str:
    dt = datetime.now(UTC) - timedelta(days=days, hours=hours)
    return dt.isoformat()


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Bulk news — spread over 90 days to populate the activity heatmap
# ---------------------------------------------------------------------------


def _make_bulk_news() -> list[dict]:
    """Generate ~2 items per day over the past 90 days for heatmap coverage."""
    _sources = [
        "NVD",
        "The Hacker News",
        "Bleeping Computer",
        "Krebs on Security",
        "GitHub Security Advisories",
        "CISA KEV",
        "SANS ISC",
        "Cisco Talos",
    ]
    _categories = [
        "Vulnerability",
        "Vulnerability",
        "Patch Available",
        "Breach",
        "Malware",
        "Threat Intelligence",
    ]
    _severities = ["Critical", "High", "High", "Medium", "Medium", "Low"]
    _packages = [
        "nginx",
        "apache httpd",
        "openssl",
        "curl",
        "python",
        "node.js",
        "go runtime",
        "ruby",
        "mysql",
        "postgresql",
        "redis",
        "docker",
        "kubernetes",
        "terraform",
        "jenkins",
        "gitlab",
        "linux kernel",
        "glibc",
        "bash",
        "openssh",
        "git",
        "vim",
        "sudo",
        "wget",
        "php",
        "wordpress",
        "drupal",
        "rails",
    ]
    _title_templates = [
        "CVE-{year}-{n}: {sev} vulnerability in {pkg} allows remote code execution",
        "Security advisory: {sev} severity flaw in {pkg} (CVSS {cvss:.1f})",
        "Patch released for {sev} issue in {pkg} — upgrade immediately",
        "{sev} severity buffer overflow in {pkg} library discovered",
        "Researchers disclose {sev} vulnerability in {pkg}",
        "Emergency patch: {pkg} zero-day exploited in the wild",
        "{pkg} patched against {sev} injection flaw — CVE-{year}-{n}",
        "CERT advisory: {sev} {pkg} vulnerability affects enterprise deployments",
    ]

    items = []
    # Days 90 → 4 so we don't overlap with the curated fresh NEWS_ITEMS
    for day_offset in range(90, 3, -1):
        count = 1 + (day_offset % 3)  # 1, 2, or 3 items per day
        for j in range(count):
            hours_ago = day_offset * 24 + (j * 7 + day_offset % 11) % 23
            pub = _ago(hours=hours_ago)
            idx = day_offset * 17 + j * 31  # deterministic rotation
            sev = _severities[idx % len(_severities)]
            cat = _categories[idx % len(_categories)]
            src = _sources[idx % len(_sources)]
            pkg = _packages[idx % len(_packages)]
            tmpl = _title_templates[idx % len(_title_templates)]
            year = 2024 - (day_offset // 400)
            n = 10000 + day_offset * 3 + j
            cvss = 4.0 + (idx % 60) / 10.0
            url = f"https://example-infosec.com/feed/{day_offset}-{j}"
            title = tmpl.format(year=year, n=n, sev=sev.lower(), pkg=pkg, cvss=cvss)
            title = title[0].upper() + title[1:]
            items.append(
                {
                    "url": url,
                    "title": title,
                    "source": src,
                    "published_at": pub,
                    "fetched_at": pub,  # same-day fetch → correct heatmap distribution
                    "category": cat,
                    "severity": sev,
                    "summary": (
                        f"A {sev.lower()} severity security issue was identified affecting {pkg}. "
                        "Security teams are advised to review affected systems and apply the "
                        "available patch as soon as possible."
                    ),
                    "affected_products": json.dumps([pkg]),
                    "tags": json.dumps(["security", sev.lower(), pkg]),
                }
            )
    return items


BULK_NEWS = _make_bulk_news()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

NEWS_ITEMS = [
    # ── Very fresh items (< 24 h) — appear on the dashboard news feed ─────
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "title": "CVE-2024-6387: regreSSHion — RCE in OpenSSH server (CVSS 8.1)",
        "source": "NVD",
        "published_at": _ago(hours=1),
        "fetched_at": _ago(hours=1),
        "category": "Vulnerability",
        "severity": "Critical",
        "summary": "A race condition in OpenSSH's signal handler allows unauthenticated RCE "
        "on glibc-based Linux systems. Regression of a 2006 vulnerability.",
        "affected_products": str(["openssh"]),
        "tags": str(["rce", "ssh", "race-condition"]),
    },
    {
        "url": "https://example-infosec.com/advisory/pypi-malicious-packages-june",
        "title": "17 malicious PyPI packages caught stealing AWS credentials via env vars",
        "source": "The Hacker News",
        "published_at": _ago(hours=4),
        "fetched_at": _ago(hours=4),
        "category": "Malware",
        "severity": "High",
        "summary": "Security researchers found 17 typosquatting PyPI packages that exfiltrate "
        "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables to a "
        "remote attacker-controlled server.",
        "affected_products": str(["pypi"]),
        "tags": str(["malware", "pypi", "aws", "credential-theft"]),
    },
    {
        "url": "https://example-infosec.com/patch/chromium-june-2024",
        "title": "Chrome 126 fixes 21 vulnerabilities including 5 high-severity issues",
        "source": "The Hacker News",
        "published_at": _ago(hours=8),
        "fetched_at": _ago(hours=8),
        "category": "Patch Available",
        "severity": "High",
        "summary": "Google has released Chrome 126 addressing 21 security issues. Five are "
        "rated High severity, including use-after-free bugs in Dawn and V8.",
        "affected_products": str(["chrome", "chromium"]),
        "tags": str(["browser", "use-after-free", "v8"]),
    },
    {
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#CVE-2024-6387",
        "title": "CISA KEV: CVE-2024-6387 added — regreSSHion OpenSSH RCE",
        "source": "CISA KEV",
        "published_at": _ago(hours=16),
        "fetched_at": _ago(hours=16),
        "category": "Vulnerability",
        "severity": "Critical",
        "summary": "CISA has added the OpenSSH regreSSHion vulnerability to the KEV catalogue "
        "following confirmed in-the-wild exploitation.",
        "affected_products": str(["openssh"]),
        "tags": str(["kev", "cisa", "ssh"]),
    },
    # ── Critical ──────────────────────────────────────────────────────────
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "title": "CVE-2024-3094: XZ Utils backdoor in liblzma (CVSS 10.0)",
        "source": "NVD",
        "published_at": _ago(days=5),
        "fetched_at": _ago(days=5),
        "category": "Vulnerability",
        "severity": "Critical",
        "summary": "A supply-chain backdoor was discovered in XZ Utils 5.6.0 and 5.6.1. "
        "The malicious code targets systemd-based Linux systems and could allow "
        "an attacker to gain unauthorised remote access.",
        "affected_products": str(["xz-utils", "liblzma"]),
        "tags": str(["supply-chain", "backdoor", "linux"]),
    },
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "title": "CVE-2021-44228: Log4Shell — Remote Code Execution in Apache Log4j2 (CVSS 10.0)",
        "source": "NVD",
        "published_at": _ago(days=12),
        "fetched_at": _ago(days=12),
        "category": "Vulnerability",
        "severity": "Critical",
        "summary": "A critical RCE vulnerability in Apache Log4j2's JNDI lookup feature allows "
        "unauthenticated remote code execution. Affects versions 2.0-beta9 to 2.14.1.",
        "affected_products": str(["apache log4j2"]),
        "tags": str(["rce", "jndi", "java"]),
    },
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        "title": "CVE-2023-44487: HTTP/2 Rapid Reset Attack enables large-scale DDoS",
        "source": "NVD",
        "published_at": _ago(days=20),
        "fetched_at": _ago(days=20),
        "category": "Vulnerability",
        "severity": "High",
        "summary": "The HTTP/2 protocol allows a denial of service via rapid stream resets. "
        "Exploited in the wild to launch record-breaking DDoS campaigns.",
        "affected_products": str(["nginx", "apache httpd", "h2o"]),
        "tags": str(["ddos", "http2", "network"]),
    },
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
        "title": "CVE-2024-21626: runc container escape via /proc/self/cwd (CVSS 8.6)",
        "source": "NVD",
        "published_at": _ago(days=8),
        "fetched_at": _ago(days=8),
        "category": "Vulnerability",
        "severity": "High",
        "summary": "A file descriptor leak in runc allows a process inside a container to "
        "break out to the host filesystem. Affects Kubernetes, Docker, and containerd.",
        "affected_products": str(["runc", "docker", "containerd", "kubernetes"]),
        "tags": str(["container-escape", "kubernetes", "docker"]),
    },
    # ── High ──────────────────────────────────────────────────────────────
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0727",
        "title": "CVE-2024-0727: OpenSSL NULL pointer dereference in PKCS12 parsing",
        "source": "NVD",
        "published_at": _ago(days=15),
        "fetched_at": _ago(days=15),
        "category": "Vulnerability",
        "severity": "High",
        "summary": "Processing a maliciously crafted PKCS12 file may trigger an assertion "
        "failure and crash the application. Applications that handle untrusted "
        "PKCS12 files are most at risk.",
        "affected_products": str(["openssl"]),
        "tags": str(["crash", "openssl", "pkcs12"]),
    },
    {
        "url": "https://github.com/advisories/GHSA-v4w5-p2hm-jmhg",
        "title": "GHSA-v4w5-p2hm-jmhg: Requests library leaks credentials via redirect",
        "source": "GitHub Security Advisories",
        "published_at": _ago(days=7),
        "fetched_at": _ago(days=7),
        "category": "Vulnerability",
        "severity": "High",
        "summary": "The Python requests library forwards Authorization headers across redirects "
        "to different origins, potentially leaking credentials to a third-party host.",
        "affected_products": str(["requests"]),
        "tags": str(["python", "credential-leak", "redirect"]),
    },
    {
        "url": "https://github.com/advisories/GHSA-jfh8-c2jp-hdp8",
        "title": "GHSA-jfh8-c2jp-hdp8: Pillow heap buffer overflow in BLP image parsing",
        "source": "GitHub Security Advisories",
        "published_at": _ago(days=9),
        "fetched_at": _ago(days=9),
        "category": "Vulnerability",
        "severity": "High",
        "summary": "A heap buffer overflow in Pillow's BLP image decoder can lead to "
        "arbitrary code execution when processing untrusted image files.",
        "affected_products": str(["pillow"]),
        "tags": str(["python", "image-processing", "overflow"]),
    },
    # ── Medium ────────────────────────────────────────────────────────────
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5569",
        "title": "CVE-2024-5569: zipp infinite loop via crafted zip archive",
        "source": "NVD",
        "published_at": _ago(days=4),
        "fetched_at": _ago(days=4),
        "category": "Vulnerability",
        "severity": "Medium",
        "summary": "A maliciously crafted archive can cause zipp to enter an infinite loop, "
        "resulting in denial of service.",
        "affected_products": str(["zipp"]),
        "tags": str(["python", "dos", "zip"]),
    },
    {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-35255",
        "title": "CVE-2024-35255: Azure Identity elevation of privilege via token cache",
        "source": "NVD",
        "published_at": _ago(days=6),
        "fetched_at": _ago(days=6),
        "category": "Vulnerability",
        "severity": "Medium",
        "summary": "azure-identity may allow an unprivileged user to read tokens cached "
        "by another user on the same machine via a shared token cache file.",
        "affected_products": str(["azure-identity"]),
        "tags": str(["azure", "token", "privilege-escalation"]),
    },
    # ── CISA KEV ──────────────────────────────────────────────────────────
    {
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#CVE-2024-3094",
        "title": "CISA KEV: CVE-2024-3094 added — XZ Utils backdoor actively exploited",
        "source": "CISA KEV",
        "published_at": _ago(days=4),
        "fetched_at": _ago(days=4),
        "category": "Vulnerability",
        "severity": "Critical",
        "summary": "CISA has added CVE-2024-3094 (XZ Utils backdoor) to the Known Exploited "
        "Vulnerabilities catalogue. Federal agencies must remediate by 2024-04-12.",
        "affected_products": str(["xz-utils"]),
        "tags": str(["kev", "cisa", "mandate"]),
    },
    # ── Breach / Incident ─────────────────────────────────────────────────
    {
        "url": "https://example-infosec.com/breach/snowflake-2024",
        "title": "Snowflake credential-stuffing campaign exposes 165 customer tenants",
        "source": "The Hacker News",
        "published_at": _ago(days=18),
        "fetched_at": _ago(days=18),
        "category": "Breach",
        "severity": "High",
        "summary": "A threat actor obtained Snowflake credentials through infostealer malware "
        "and accessed data from at least 165 customer environments including "
        "Ticketmaster and Advance Auto Parts.",
        "affected_products": str(["snowflake"]),
        "tags": str(["breach", "credential-stuffing", "cloud"]),
    },
    {
        "url": "https://example-infosec.com/breach/change-healthcare-2024",
        "title": "Change Healthcare ransomware attack disrupts US prescription processing",
        "source": "Krebs on Security",
        "published_at": _ago(days=30),
        "fetched_at": _ago(days=30),
        "category": "Breach",
        "severity": "Critical",
        "summary": "ALPHV/BlackCat ransomware group attacked Change Healthcare, disrupting "
        "prescription processing for thousands of US pharmacies for weeks. "
        "Data of 100M+ patients potentially exposed.",
        "affected_products": str(["change healthcare"]),
        "tags": str(["ransomware", "healthcare", "blackcat"]),
    },
    # ── Malware ───────────────────────────────────────────────────────────
    {
        "url": "https://example-infosec.com/malware/polyfill-supply-chain",
        "title": "Polyfill.io supply-chain attack: 100k+ sites served malicious code",
        "source": "Bleeping Computer",
        "published_at": _ago(days=22),
        "fetched_at": _ago(days=22),
        "category": "Malware",
        "severity": "High",
        "summary": "After the polyfill.io domain was acquired by a Chinese company, the CDN "
        "began injecting malicious JavaScript into over 100,000 websites that "
        "embed the polyfill script.",
        "affected_products": str(["polyfill.io"]),
        "tags": str(["supply-chain", "javascript", "cdn"]),
    },
    # ── Patch Available ───────────────────────────────────────────────────
    {
        "url": "https://example-infosec.com/patch/git-2024-32002",
        "title": "Git 2.45.1 patches CVE-2024-32002: recursive clone RCE on Windows/macOS",
        "source": "Bleeping Computer",
        "published_at": _ago(days=11),
        "fetched_at": _ago(days=11),
        "category": "Patch Available",
        "severity": "Critical",
        "summary": "Git has released 2.45.1 to fix CVE-2024-32002, a critical vulnerability "
        "allowing RCE via a maliciously crafted repository during a recursive clone "
        "on case-insensitive filesystems.",
        "affected_products": str(["git"]),
        "tags": str(["rce", "git", "windows", "macos"]),
    },
    # ── Threat Intelligence ───────────────────────────────────────────────
    {
        "url": "https://example-infosec.com/intel/threat-landscape-q2-2024",
        "title": "Q2 2024 Threat Landscape: ransomware groups shift to data-theft-only extortion",
        "source": "Krebs on Security",
        "published_at": _ago(days=14),
        "fetched_at": _ago(days=14),
        "category": "Threat Intelligence",
        "severity": "Low",
        "summary": "Analysis shows ransomware groups increasingly skipping file encryption in "
        "favour of data exfiltration and extortion, reducing operational complexity "
        "and increasing victim pressure.",
        "affected_products": str([]),
        "tags": str(["ransomware", "threat-intel", "extortion"]),
    },
    {
        "url": "https://example-infosec.com/advisory/npm-manifest-confusion",
        "title": "npm manifest confusion: published metadata differs from installed package",
        "source": "Bleeping Computer",
        "published_at": _ago(days=25),
        "fetched_at": _ago(days=25),
        "category": "Vulnerability",
        "severity": "Medium",
        "summary": "A design flaw in npm allows the published manifest to differ from the "
        "tarball contents, enabling dependency confusion and typosquatting attacks "
        "that are invisible to audit tools.",
        "affected_products": str(["npm"]),
        "tags": str(["npm", "supply-chain", "package-manager"]),
    },
]

# News items to bookmark (looked up by URL after insertion)
BOOKMARK_URLS = [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    "https://example-infosec.com/breach/change-healthcare-2024",
    "https://example-infosec.com/advisory/pypi-malicious-packages-june",
    "https://example-infosec.com/patch/git-2024-32002",
]

KEYWORDS = [
    "ransomware",
    "CVE",
    "zero-day",
    "python",
    "docker",
    "OpenSSH",
    "supply-chain",
]

SETTINGS = {
    "active_model": "qwen2.5:3b",
    "run_interval_hours": "6",
}

WEEKLY_DIGEST = {
    "generated_at": _ago(days=2),
    "week_label": "Week of May 12, 2025",
    "items_collected": 312,
    "new_findings": 8,
    "resolved_count": 3,
    "top_findings": [
        {
            "repo": "bladzv/api-service",
            "id": "CVE-2021-44228",
            "package": "log4j-core",
            "cvss": 10.0,
            "priority": 10.0,
            "is_kev": True,
            "has_patch": True,
            "state": "new",
        },
        {
            "repo": "bladzv/data-pipeline",
            "id": "CVE-2022-22965",
            "package": "spring-beans",
            "cvss": 9.8,
            "priority": 9.8,
            "is_kev": True,
            "has_patch": True,
            "state": "new",
        },
        {
            "repo": "bladzv/dashboard-ui",
            "id": "CVE-2023-45133",
            "package": "@babel/traverse",
            "cvss": 9.3,
            "priority": 9.3,
            "is_kev": False,
            "has_patch": True,
            "state": "new",
        },
        {
            "repo": "bladzv/web-app",
            "id": "CVE-2024-6387",
            "package": "openssh-server",
            "cvss": 8.1,
            "priority": 9.1,
            "is_kev": True,
            "has_patch": True,
            "state": "new",
        },
        {
            "repo": "bladzv/ml-pipeline",
            "id": "CVE-2023-44271",
            "package": "Pillow",
            "cvss": 7.5,
            "priority": 7.5,
            "is_kev": False,
            "has_patch": True,
            "state": "new",
        },
    ],
    "top_repos": [
        {"repo": "bladzv/api-service", "finding_count": 5},
        {"repo": "bladzv/web-app", "finding_count": 5},
        {"repo": "bladzv/dashboard-ui", "finding_count": 4},
        {"repo": "bladzv/ml-pipeline", "finding_count": 4},
        {"repo": "bladzv/data-pipeline", "finding_count": 3},
    ],
}

FINDINGS = [
    # ── bladzv/api-service ────────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/api-service",
        "cve_id": "CVE-2021-44228",
        "ghsa_id": "GHSA-jfh8-c2jp-hdp8",
        "package_name": "log4j-core",
        "package_ecosystem": "Maven",
        "installed_version": "2.14.1",
        "fixed_version": "2.17.1",
        "affected_versions": ">= 2.0.0-beta9, < 2.17.1",
        "latest_version": "2.23.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 10.0,
        "is_kev": True,
        "patch_available": True,
        "priority_score": 10.0,
        "state": "new",
        "manifest_path": "pom.xml",
        "first_seen_at": _ago(days=12),
        "annotation": "Confirmed — we use JNDI lookups in logging. P0.",
        "github_issue_url": "https://github.com/bladzv/api-service/issues/12",
    },
    {
        "repo_full_name": "bladzv/api-service",
        "cve_id": "CVE-2023-45803",
        "ghsa_id": "GHSA-g4mx-q9vg-27p4",
        "package_name": "urllib3",
        "package_ecosystem": "pip",
        "installed_version": "1.26.17",
        "fixed_version": "1.26.18",
        "affected_versions": ">= 1.26.0, < 1.26.18",
        "latest_version": "2.2.2",
        "latest_version_vuln_count": 0,
        "cvss_score": 4.3,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 4.3,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=17),
        "annotation": None,
        "github_issue_url": "https://github.com/bladzv/api-service/issues/47",
    },
    {
        "repo_full_name": "bladzv/api-service",
        "cve_id": "CVE-2024-3651",
        "ghsa_id": None,
        "package_name": "idna",
        "package_ecosystem": "pip",
        "installed_version": "3.6",
        "fixed_version": "3.7",
        "affected_versions": "< 3.7",
        "latest_version": "3.7",
        "latest_version_vuln_count": 0,
        "cvss_score": 6.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 6.5,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=16),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/api-service",
        "cve_id": "CVE-2024-35255",
        "ghsa_id": None,
        "package_name": "azure-identity",
        "package_ecosystem": "pip",
        "installed_version": "1.15.0",
        "fixed_version": "1.16.1",
        "affected_versions": ">= 1.0.0, < 1.16.1",
        "latest_version": "1.17.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.5,
        "state": "acknowledged",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=6),
        "annotation": "Accepted risk — token cache is local-only in our deployment.",
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/api-service",
        "cve_id": "CVE-2023-28370",
        "ghsa_id": None,
        "package_name": "Tornado",
        "package_ecosystem": "pip",
        "installed_version": "6.2",
        "fixed_version": "6.3.2",
        "affected_versions": "< 6.3.2",
        "latest_version": "6.4.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "resolved",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=60),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/web-app ────────────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/web-app",
        "cve_id": "CVE-2024-6387",
        "ghsa_id": None,
        "package_name": "openssh-server",
        "package_ecosystem": "pip",
        "installed_version": "9.3p1",
        "fixed_version": "9.3p2",
        "affected_versions": ">= 8.5p1, < 9.3p2",
        "latest_version": "9.7p1",
        "latest_version_vuln_count": 0,
        "cvss_score": 8.1,
        "is_kev": True,
        "patch_available": True,
        "priority_score": 9.1,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=3),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/web-app",
        "cve_id": "CVE-2023-32681",
        "ghsa_id": "GHSA-v4w5-p2hm-jmhg",
        "package_name": "requests",
        "package_ecosystem": "pip",
        "installed_version": "2.28.1",
        "fixed_version": "2.31.0",
        "affected_versions": ">= 2.1.0, < 2.31.0",
        "latest_version": "2.32.2",
        "latest_version_vuln_count": 0,
        "cvss_score": 6.1,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 6.1,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=7),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/web-app",
        "cve_id": "CVE-2021-23337",
        "ghsa_id": "GHSA-35jh-r3h4-6jhm",
        "package_name": "lodash",
        "package_ecosystem": "npm",
        "installed_version": "4.17.20",
        "fixed_version": "4.17.21",
        "affected_versions": "< 4.17.21",
        "latest_version": "4.17.21",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.2,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.2,
        "state": "new",
        "manifest_path": "package.json",
        "first_seen_at": _ago(days=6),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/web-app",
        "cve_id": "CVE-2024-29415",
        "ghsa_id": None,
        "package_name": "ip",
        "package_ecosystem": "npm",
        "installed_version": "2.0.0",
        "fixed_version": "2.0.1",
        "affected_versions": ">= 2.0.0, < 2.0.1",
        "latest_version": "2.0.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 9.8,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 9.8,
        "state": "acknowledged",
        "manifest_path": "package-lock.json",
        "first_seen_at": _ago(days=8),
        "annotation": "Low actual risk — internal network only, not internet-facing.",
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/web-app",
        "cve_id": "CVE-2022-42969",
        "ghsa_id": None,
        "package_name": "py",
        "package_ecosystem": "pip",
        "installed_version": "1.11.0",
        "fixed_version": "1.11.1",
        "affected_versions": "< 1.11.1",
        "latest_version": "1.11.0",
        "latest_version_vuln_count": 1,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "resolved",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=45),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/web-app",
        "cve_id": "CVE-2022-40897",
        "ghsa_id": None,
        "package_name": "setuptools",
        "package_ecosystem": "pip",
        "installed_version": "65.5.0",
        "fixed_version": "65.5.1",
        "affected_versions": "< 65.5.1",
        "latest_version": "70.0.0",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.9,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.9,
        "state": "resolved",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=70),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/ml-pipeline ────────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/ml-pipeline",
        "cve_id": "CVE-2023-44271",
        "ghsa_id": "GHSA-jfh8-c2jp-hdp8",
        "package_name": "Pillow",
        "package_ecosystem": "pip",
        "installed_version": "9.5.0",
        "fixed_version": "10.0.1",
        "affected_versions": ">= 9.0.0, < 10.0.1",
        "latest_version": "10.3.0",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=9),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/ml-pipeline",
        "cve_id": "CVE-2023-36053",
        "ghsa_id": None,
        "package_name": "Django",
        "package_ecosystem": "pip",
        "installed_version": "4.1.9",
        "fixed_version": "4.1.10",
        "affected_versions": ">= 4.1.0, < 4.1.10",
        "latest_version": "5.0.6",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=11),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/ml-pipeline",
        "cve_id": "CVE-2023-50782",
        "ghsa_id": None,
        "package_name": "cryptography",
        "package_ecosystem": "pip",
        "installed_version": "41.0.5",
        "fixed_version": "42.0.0",
        "affected_versions": "< 42.0.0",
        "latest_version": "42.0.8",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=18),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/ml-pipeline",
        "cve_id": "CVE-2023-41105",
        "ghsa_id": None,
        "package_name": "cryptography",
        "package_ecosystem": "pip",
        "installed_version": "41.0.0",
        "fixed_version": "41.0.4",
        "affected_versions": ">= 41.0.0, < 41.0.4",
        "latest_version": "42.0.8",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "acknowledged",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=20),
        "annotation": "Scheduled for next sprint.",
        "github_issue_url": None,
    },
    # ── bladzv/infra-tools ────────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/infra-tools",
        "cve_id": "CVE-2024-5569",
        "ghsa_id": None,
        "package_name": "zipp",
        "package_ecosystem": "pip",
        "installed_version": "3.17.0",
        "fixed_version": "3.19.1",
        "affected_versions": ">= 3.17.0, < 3.19.1",
        "latest_version": "3.19.2",
        "latest_version_vuln_count": 0,
        "cvss_score": 6.2,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 6.2,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=4),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/infra-tools",
        "cve_id": "CVE-2023-32731",
        "ghsa_id": None,
        "package_name": "grpcio",
        "package_ecosystem": "pip",
        "installed_version": "1.54.0",
        "fixed_version": "1.54.2",
        "affected_versions": ">= 1.54.0, < 1.54.2",
        "latest_version": "1.64.0",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=22),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/dashboard-ui ───────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/dashboard-ui",
        "cve_id": "CVE-2023-45133",
        "ghsa_id": "GHSA-67hx-6x53-jw92",
        "package_name": "@babel/traverse",
        "package_ecosystem": "npm",
        "installed_version": "7.22.5",
        "fixed_version": "7.23.2",
        "affected_versions": "< 7.23.2",
        "latest_version": "7.24.6",
        "latest_version_vuln_count": 0,
        "cvss_score": 9.3,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 9.3,
        "state": "new",
        "manifest_path": "package.json",
        "first_seen_at": _ago(days=13),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/dashboard-ui",
        "cve_id": "CVE-2022-24999",
        "ghsa_id": "GHSA-qwcr-r2fm-qrc7",
        "package_name": "qs",
        "package_ecosystem": "npm",
        "installed_version": "6.5.2",
        "fixed_version": "6.9.7",
        "affected_versions": "< 6.9.7",
        "latest_version": "6.12.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "package-lock.json",
        "first_seen_at": _ago(days=10),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/dashboard-ui",
        "cve_id": "CVE-2023-42282",
        "ghsa_id": None,
        "package_name": "ip",
        "package_ecosystem": "npm",
        "installed_version": "1.1.8",
        "fixed_version": "2.0.1",
        "affected_versions": "< 2.0.1",
        "latest_version": "2.0.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 9.8,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 9.8,
        "state": "resolved",
        "manifest_path": "package-lock.json",
        "first_seen_at": _ago(days=40),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/dashboard-ui",
        "cve_id": "CVE-2023-26136",
        "ghsa_id": "GHSA-4q6p-r6v2-jvc5",
        "package_name": "tough-cookie",
        "package_ecosystem": "npm",
        "installed_version": "2.5.0",
        "fixed_version": "4.1.3",
        "affected_versions": "< 4.1.3",
        "latest_version": "4.1.4",
        "latest_version_vuln_count": 0,
        "cvss_score": 9.8,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 9.8,
        "state": "resolved",
        "manifest_path": "package.json",
        "first_seen_at": _ago(days=50),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/auth-service ───────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/auth-service",
        "cve_id": "CVE-2023-44487",
        "ghsa_id": "GHSA-qppj-fm56-g8dg",
        "package_name": "golang.org/x/net",
        "package_ecosystem": "Go",
        "installed_version": "0.13.0",
        "fixed_version": "0.17.0",
        "affected_versions": ">= 0.0.0, < 0.17.0",
        "latest_version": "0.25.0",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "go.mod",
        "first_seen_at": _ago(days=20),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/auth-service",
        "cve_id": "CVE-2024-24786",
        "ghsa_id": None,
        "package_name": "google.golang.org/protobuf",
        "package_ecosystem": "Go",
        "installed_version": "1.32.0",
        "fixed_version": "1.33.0",
        "affected_versions": "< 1.33.0",
        "latest_version": "1.34.1",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.9,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.9,
        "state": "new",
        "manifest_path": "go.mod",
        "first_seen_at": _ago(days=15),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/auth-service",
        "cve_id": "CVE-2023-46137",
        "ghsa_id": "GHSA-vg46-2rrj-3647",
        "package_name": "Twisted",
        "package_ecosystem": "pip",
        "installed_version": "22.10.0",
        "fixed_version": "23.10.0",
        "affected_versions": "< 23.10.0",
        "latest_version": "24.3.0",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.3,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.3,
        "state": "resolved",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=55),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/data-pipeline ──────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/data-pipeline",
        "cve_id": "CVE-2022-22965",
        "ghsa_id": "GHSA-36p3-wjmg-h94x",
        "package_name": "org.springframework:spring-beans",
        "package_ecosystem": "Maven",
        "installed_version": "5.3.14",
        "fixed_version": "5.3.18",
        "affected_versions": ">= 5.3.0, < 5.3.18",
        "latest_version": "6.1.8",
        "latest_version_vuln_count": 0,
        "cvss_score": 9.8,
        "is_kev": True,
        "patch_available": True,
        "priority_score": 9.8,
        "state": "new",
        "manifest_path": "pom.xml",
        "first_seen_at": _ago(days=25),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/data-pipeline",
        "cve_id": "CVE-2024-22190",
        "ghsa_id": None,
        "package_name": "gitpython",
        "package_ecosystem": "pip",
        "installed_version": "3.1.40",
        "fixed_version": "3.1.41",
        "affected_versions": "< 3.1.41",
        "latest_version": "3.1.43",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.8,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.8,
        "state": "acknowledged",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=30),
        "annotation": "Investigating impact on pipeline scripts.",
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/data-pipeline",
        "cve_id": "CVE-2023-48795",
        "ghsa_id": "GHSA-45x7-px36-x8w8",
        "package_name": "paramiko",
        "package_ecosystem": "pip",
        "installed_version": "3.3.1",
        "fixed_version": "3.4.0",
        "affected_versions": "< 3.4.0",
        "latest_version": "3.4.0",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.9,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.9,
        "state": "new",
        "manifest_path": "requirements.txt",
        "first_seen_at": _ago(days=19),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/mobile-app ─────────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/mobile-app",
        "cve_id": "CVE-2023-46234",
        "ghsa_id": "GHSA-cchq-frgv-rjh5",
        "package_name": "browserify-sign",
        "package_ecosystem": "npm",
        "installed_version": "4.2.1",
        "fixed_version": "4.2.2",
        "affected_versions": "< 4.2.2",
        "latest_version": "4.2.3",
        "latest_version_vuln_count": 0,
        "cvss_score": 7.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 7.5,
        "state": "new",
        "manifest_path": "package.json",
        "first_seen_at": _ago(days=10),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/mobile-app",
        "cve_id": "CVE-2024-28849",
        "ghsa_id": "GHSA-cxjh-pqwp-8mfp",
        "package_name": "follow-redirects",
        "package_ecosystem": "npm",
        "installed_version": "1.15.5",
        "fixed_version": "1.15.6",
        "affected_versions": "< 1.15.6",
        "latest_version": "1.15.6",
        "latest_version_vuln_count": 0,
        "cvss_score": 6.5,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 6.5,
        "state": "new",
        "manifest_path": "package-lock.json",
        "first_seen_at": _ago(days=14),
        "annotation": None,
        "github_issue_url": None,
    },
    # ── bladzv/admin-portal ───────────────────────────────────────────────
    {
        "repo_full_name": "bladzv/admin-portal",
        "cve_id": "CVE-2024-26141",
        "ghsa_id": "GHSA-xc64-yfmp-fgfm",
        "package_name": "rack",
        "package_ecosystem": "RubyGems",
        "installed_version": "3.0.8",
        "fixed_version": "3.0.9",
        "affected_versions": ">= 3.0.0, < 3.0.9",
        "latest_version": "3.0.11",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.3,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.3,
        "state": "new",
        "manifest_path": "Gemfile.lock",
        "first_seen_at": _ago(days=5),
        "annotation": None,
        "github_issue_url": None,
    },
    {
        "repo_full_name": "bladzv/admin-portal",
        "cve_id": "CVE-2024-26146",
        "ghsa_id": "GHSA-54rr-7fvw-6x8f",
        "package_name": "rack",
        "package_ecosystem": "RubyGems",
        "installed_version": "3.0.8",
        "fixed_version": "3.0.9",
        "affected_versions": ">= 3.0.0, < 3.0.9",
        "latest_version": "3.0.11",
        "latest_version_vuln_count": 0,
        "cvss_score": 5.3,
        "is_kev": False,
        "patch_available": True,
        "priority_score": 5.3,
        "state": "new",
        "manifest_path": "Gemfile.lock",
        "first_seen_at": _ago(days=5),
        "annotation": None,
        "github_issue_url": None,
    },
]

SECRET_FINDINGS = [
    {
        "repo_full_name": "bladzv/infra-tools",
        "file_path": "deploy/scripts/bootstrap.sh",
        "line_number": 14,
        "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "secret_type": "AWS Access Key ID",
        "rule_id": "aws-access-key-id",
        "fingerprint": "a1b2c3d4:deploy/scripts/bootstrap.sh:aws-access-key-id:14",
        "state": "new",
        "first_seen_at": _ago(days=2),
    },
    {
        "repo_full_name": "bladzv/web-app",
        "file_path": "config/staging.env",
        "line_number": 7,
        "commit_sha": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "secret_type": "GitHub Personal Access Token",
        "rule_id": "github-pat",
        "fingerprint": "b2c3d4e5:config/staging.env:github-pat:7",
        "state": "new",
        "first_seen_at": _ago(days=1),
    },
    {
        "repo_full_name": "bladzv/api-service",
        "file_path": ".env.example",
        "line_number": 22,
        "commit_sha": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "secret_type": "Slack Webhook URL",
        "rule_id": "slack-webhook-url",
        "fingerprint": "c3d4e5f6:.env.example:slack-webhook-url:22",
        "state": "new",
        "first_seen_at": _ago(days=5),
    },
    {
        "repo_full_name": "bladzv/ml-pipeline",
        "file_path": "notebooks/data_fetch.ipynb",
        "line_number": 41,
        "commit_sha": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
        "secret_type": "HuggingFace API Token",
        "rule_id": "huggingface-api-token",
        "fingerprint": "d4e5f6a1:notebooks/data_fetch.ipynb:huggingface-api-token:41",
        "state": "new",
        "first_seen_at": _ago(hours=18),
    },
    {
        "repo_full_name": "bladzv/dashboard-ui",
        "file_path": "src/api/client.ts",
        "line_number": 5,
        "commit_sha": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
        "secret_type": "Generic API Key",
        "rule_id": "generic-api-key",
        "fingerprint": "e5f6a1b2:src/api/client.ts:generic-api-key:5",
        "state": "false_positive",
        "first_seen_at": _ago(days=14),
    },
    {
        "repo_full_name": "bladzv/web-app",
        "file_path": "tests/fixtures/mock_creds.py",
        "line_number": 3,
        "commit_sha": "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
        "secret_type": "AWS Secret Access Key",
        "rule_id": "aws-secret-access-key",
        "fingerprint": "f6a1b2c3:tests/fixtures/mock_creds.py:aws-secret-access-key:3",
        "state": "false_positive",
        "first_seen_at": _ago(days=30),
    },
    {
        "repo_full_name": "bladzv/api-service",
        "file_path": "config/production.yaml",
        "line_number": 18,
        "commit_sha": "a2b3c4d5e6f7a2b3c4d5e6f7a2b3c4d5e6f7a2b3",
        "secret_type": "SendGrid API Key",
        "rule_id": "sendgrid-api-key",
        "fingerprint": "a2b3c4d5:config/production.yaml:sendgrid-api-key:18",
        "state": "resolved",
        "first_seen_at": _ago(days=45),
    },
    {
        "repo_full_name": "bladzv/infra-tools",
        "file_path": "terraform/variables.tf",
        "line_number": 31,
        "commit_sha": "b3c4d5e6f7a2b3c4d5e6f7a2b3c4d5e6f7a2b3c4",
        "secret_type": "Stripe Secret Key",
        "rule_id": "stripe-secret-key",
        "fingerprint": "b3c4d5e6:terraform/variables.tf:stripe-secret-key:31",
        "state": "resolved",
        "first_seen_at": _ago(days=60),
    },
]

RSS_FEEDS = [
    ("NVD Recent CVEs", "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz", True),
    (
        "CISA KEV",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        True,
    ),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", False),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", False),
    ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/", False),
    ("GitHub Security Blog", "https://github.blog/tag/security/feed/", False),
]

RUN_LOG = [
    {
        "started_at": _ago(hours=2),
        "completed_at": _ago(hours=1, days=0),
        "status": "success",
        "items_collected": 47,
        "items_categorized": 43,
        "findings_new": 3,
        "findings_total": 12,
    },
    {
        "started_at": _ago(hours=8),
        "completed_at": _ago(hours=7),
        "status": "success",
        "items_collected": 31,
        "items_categorized": 29,
        "findings_new": 0,
        "findings_total": 12,
    },
    {
        "started_at": _ago(days=1),
        "completed_at": _ago(days=1, hours=-1),
        "status": "success",
        "items_collected": 52,
        "items_categorized": 50,
        "findings_new": 5,
        "findings_total": 14,
    },
    {
        "started_at": _ago(days=2),
        "completed_at": _ago(days=2, hours=-0.5),
        "status": "error",
        "items_collected": 12,
        "items_categorized": 0,
        "findings_new": 0,
        "findings_total": 0,
        "error_message": "github_scanner: GitHub API rate limit exceeded (0 requests remaining)",
    },
    {
        "started_at": _ago(days=3),
        "completed_at": _ago(days=3, hours=-1),
        "status": "success",
        "items_collected": 68,
        "items_categorized": 65,
        "findings_new": 7,
        "findings_total": 18,
    },
    {
        "started_at": _ago(days=4),
        "completed_at": _ago(days=4, hours=-1),
        "status": "success",
        "items_collected": 44,
        "items_categorized": 42,
        "findings_new": 2,
        "findings_total": 16,
    },
    {
        "started_at": _ago(days=5),
        "completed_at": _ago(days=5, hours=-0.75),
        "status": "success",
        "items_collected": 59,
        "items_categorized": 57,
        "findings_new": 4,
        "findings_total": 15,
    },
    {
        "started_at": _ago(days=6),
        "completed_at": _ago(days=6, hours=-1),
        "status": "error",
        "items_collected": 0,
        "items_categorized": 0,
        "findings_new": 0,
        "findings_total": 0,
        "error_message": "collector: Connection timeout fetching NVD feed after 30s",
    },
    {
        "started_at": _ago(days=7),
        "completed_at": _ago(days=7, hours=-1.5),
        "status": "success",
        "items_collected": 73,
        "items_categorized": 70,
        "findings_new": 9,
        "findings_total": 22,
    },
    {
        "started_at": _ago(days=8),
        "completed_at": _ago(days=8, hours=-1),
        "status": "success",
        "items_collected": 38,
        "items_categorized": 36,
        "findings_new": 1,
        "findings_total": 13,
    },
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def seed(db_path_str: str) -> None:
    from pathlib import Path

    db_path = Path(db_path_str)
    if db_path.exists():
        print(f"Database already exists at {db_path} — delete it first to re-seed.")
        sys.exit(1)

    print(f"Seeding dev database at {db_path} …")
    db.init(db_path)

    now = _ago()

    with db.get_conn(db_path) as conn:
        # ── News items (curated, fetched_at matches published_at) ──────────
        for item in NEWS_ITEMS:
            fetched = item.get("fetched_at", item.get("published_at", now))
            conn.execute(
                """
                INSERT INTO news_items
                    (url, url_hash, title, source, published_at, fetched_at,
                     summary, category, severity, affected_products, tags)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    item["url"],
                    _url_hash(item["url"]),
                    item["title"],
                    item["source"],
                    item.get("published_at"),
                    fetched,
                    item.get("summary"),
                    item.get("category"),
                    item.get("severity"),
                    item.get("affected_products", str([])),
                    item.get("tags", str([])),
                ),
            )
        print(f"  {len(NEWS_ITEMS)} curated news items")

        # ── Bulk news items (heatmap coverage across 90 days) ──────────────
        bulk_inserted = 0
        for item in BULK_NEWS:
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO news_items
                        (url, url_hash, title, source, published_at, fetched_at,
                         summary, category, severity, affected_products, tags)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        item["url"],
                        _url_hash(item["url"]),
                        item["title"],
                        item["source"],
                        item.get("published_at"),
                        item["fetched_at"],
                        item.get("summary"),
                        item.get("category"),
                        item.get("severity"),
                        item.get("affected_products", "[]"),
                        item.get("tags", "[]"),
                    ),
                )
                bulk_inserted += 1
            except Exception:
                pass
        print(f"  {bulk_inserted} bulk news items (heatmap)")

        # ── Findings ───────────────────────────────────────────────────────
        for f in FINDINGS:
            conn.execute(
                """
                INSERT INTO findings (
                    repo_full_name, cve_id, ghsa_id,
                    package_name, package_ecosystem,
                    installed_version, fixed_version, affected_versions,
                    cvss_score, is_kev, patch_available, priority_score,
                    state, first_seen_at, last_seen_at,
                    manifest_path, annotation,
                    latest_version, latest_version_vuln_count,
                    github_issue_url
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    f["repo_full_name"],
                    f.get("cve_id"),
                    f.get("ghsa_id"),
                    f["package_name"],
                    f["package_ecosystem"],
                    f.get("installed_version"),
                    f.get("fixed_version"),
                    f.get("affected_versions"),
                    f.get("cvss_score"),
                    1 if f.get("is_kev") else 0,
                    1 if f.get("patch_available") else 0,
                    f.get("priority_score"),
                    f.get("state", "new"),
                    f.get("first_seen_at", now),
                    now,
                    f.get("manifest_path"),
                    f.get("annotation"),
                    f.get("latest_version"),
                    f.get("latest_version_vuln_count"),
                    f.get("github_issue_url"),
                ),
            )
        print(
            f"  {len(FINDINGS)} findings  "
            f"({sum(1 for f in FINDINGS if f['state']=='new')} new, "
            f"{sum(1 for f in FINDINGS if f['state']=='acknowledged')} acknowledged, "
            f"{sum(1 for f in FINDINGS if f['state']=='resolved')} resolved)"
        )

        # ── Secret findings ────────────────────────────────────────────────
        for s in SECRET_FINDINGS:
            conn.execute(
                """
                INSERT INTO secret_findings
                    (repo_full_name, file_path, line_number, commit_sha,
                     secret_type, rule_id, fingerprint, state,
                     first_seen_at, last_seen_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    s["repo_full_name"],
                    s["file_path"],
                    s.get("line_number"),
                    s["commit_sha"],
                    s["secret_type"],
                    s["rule_id"],
                    s["fingerprint"],
                    s.get("state", "new"),
                    s.get("first_seen_at", now),
                    now,
                ),
            )
        print(
            f"  {len(SECRET_FINDINGS)} secret findings  "
            f"({sum(1 for s in SECRET_FINDINGS if s['state']=='new')} new)"
        )

        # ── RSS feeds ──────────────────────────────────────────────────────
        feed_item_counts = {
            "NVD Recent CVEs": 1840,
            "CISA KEV": 423,
            "The Hacker News": 612,
            "Krebs on Security": 287,
            "Bleeping Computer": 934,
            "GitHub Security Blog": 156,
        }
        for name, url, is_default in RSS_FEEDS:
            conn.execute(
                """
                INSERT OR IGNORE INTO rss_feeds
                    (name, url, enabled, is_default, last_fetched_at, item_count, created_at)
                VALUES (?,?,1,?,?,?,?)
                """,
                (
                    name,
                    url,
                    1 if is_default else 0,
                    _ago(hours=2),
                    feed_item_counts.get(name, 0),
                    now,
                ),
            )
        print(f"  {len(RSS_FEEDS)} RSS feeds")

        # ── Run log ────────────────────────────────────────────────────────
        for run in RUN_LOG:
            conn.execute(
                """
                INSERT INTO run_log
                    (started_at, completed_at, status,
                     items_collected, items_categorized,
                     findings_new, findings_total, error_message)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    run["started_at"],
                    run.get("completed_at"),
                    run["status"],
                    run.get("items_collected", 0),
                    run.get("items_categorized", 0),
                    run.get("findings_new", 0),
                    run.get("findings_total", 0),
                    run.get("error_message"),
                ),
            )
        print(f"  {len(RUN_LOG)} run log entries")

        # ── Keywords ───────────────────────────────────────────────────────
        for kw in KEYWORDS:
            conn.execute(
                "INSERT OR IGNORE INTO keywords (keyword, created_at) VALUES (?,?)",
                (kw, now),
            )
        print(f"  {len(KEYWORDS)} keywords")

        # ── Bookmarks ──────────────────────────────────────────────────────
        bm_count = 0
        for url in BOOKMARK_URLS:
            row = conn.execute(
                "SELECT id FROM news_items WHERE url_hash = ?",
                (_url_hash(url),),
            ).fetchone()
            if row:
                conn.execute(
                    "INSERT OR IGNORE INTO bookmarks (news_item_id, created_at) VALUES (?,?)",
                    (row["id"], now),
                )
                bm_count += 1
        print(f"  {bm_count} bookmarks")

        # ── Settings (active model, interval, weekly digest) ───────────────
        for key, value in SETTINGS.items():
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?,?,?)",
                (key, value, now),
            )
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?,?,?)",
            ("weekly_digest.latest", json.dumps(WEEKLY_DIGEST), now),
        )
        print(f"  {len(SETTINGS) + 1} settings (incl. weekly digest)")

    print("\nDone. Start the dev server with:")
    print("  ./scripts/dev.sh run")
    print("  — or —")
    print(f"  DB_PATH={db_path} uvicorn dive.main:app --host 127.0.0.1 --port 8766 --reload")


if __name__ == "__main__":
    db_path = os.environ.get("DB_PATH", "data/dev.db")
    seed(db_path)
