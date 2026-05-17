"""
collector.py — Fetch security news from RSS feeds and structured APIs.

Each source is fetched independently. A failed source is logged and skipped —
the run continues regardless of individual failures.

Sources:
    RSS feeds  — 9 default blogs (Bleeping Computer, Krebs, THN, SANS ISC, etc.)
    NIST NVD   — CVEs published in the last N days
    CISA KEV   — Known Exploited Vulnerabilities (new entries only)
    GitHub SA  — GitHub Security Advisories (recent, via REST API)

All items are deduplicated by SHA-256 of the URL before insertion.
HTTP requests use: 30s timeout, up to 5 redirects, 10 MB response cap.
HTTP (non-TLS) source URLs are logged as warnings.
"""

from __future__ import annotations

import html
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import feedparser
import httpx

import db
import settings as settings_module
from config import AppConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_CONTENT_CHARS = 2000  # truncate article body before storing / sending to Ollama
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB hard cap on any HTTP response
_HTTP_TIMEOUT = 30.0
_COLLECTION_WINDOW_DAYS = 7  # how far back to fetch from structured APIs

_CVSS_SEVERITY_MAP = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.0, "Low"),
]
_GHSA_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _cvss_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    for threshold, label in _CVSS_SEVERITY_MAP:
        if score >= threshold:
            return label
    return None


_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_GHSA_URL = "https://api.github.com/advisories"

DEFAULT_RSS_FEEDS: list[tuple[str, str]] = [
    ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Google Mandiant", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss_simple.asp"),
]


# ---------------------------------------------------------------------------
# Stats dataclass
# ---------------------------------------------------------------------------


@dataclass
class CollectorStats:
    items_fetched: int = 0
    items_new: int = 0
    failed_sources: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(conn: sqlite3.Connection, config: AppConfig) -> CollectorStats:
    """Fetch all sources and insert new items into the database.

    Returns a CollectorStats summary. Never raises — individual source failures
    are captured in stats.failed_sources.
    """
    stats = CollectorStats()

    with _make_client() as client:
        _run_rss(client, conn, stats)
        _run_nvd(client, conn, config, stats)
        _run_kev(client, conn, stats)
        _run_github_advisories(client, conn, config, stats)

    if stats.failed_sources:
        logger.warning(
            "Collection complete: %d fetched, %d new, %d failed sources: %s",
            stats.items_fetched,
            stats.items_new,
            len(stats.failed_sources),
            ", ".join(stats.failed_sources),
        )
    else:
        logger.info(
            "Collection complete: %d fetched, %d new, 0 failed sources",
            stats.items_fetched,
            stats.items_new,
        )
    return stats


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def _make_client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=True,
        max_redirects=5,
        timeout=_HTTP_TIMEOUT,
        headers={"User-Agent": "dive/0.1 (self-hosted)"},
    )


def _safe_get(client: httpx.Client, url: str, **kwargs) -> httpx.Response | None:
    """GET with size cap, HTTP warning, and error logging. Returns None on failure."""
    if url.startswith("http://"):
        logger.warning("Fetching non-TLS URL: %s", url)
    try:
        response = client.get(url, **kwargs)
        response.raise_for_status()
        if len(response.content) > _MAX_RESPONSE_BYTES:
            logger.warning(
                "Response too large (%d bytes), truncating: %s", len(response.content), url
            )
        return response
    except httpx.HTTPStatusError as exc:
        logger.warning("HTTP %s from %s", exc.response.status_code, url)
        return None
    except httpx.RequestError as exc:
        logger.warning("Request failed for %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# RSS feeds
# ---------------------------------------------------------------------------


def _run_rss(
    client: httpx.Client,
    conn: sqlite3.Connection,
    stats: CollectorStats,
) -> None:
    feeds = settings_module.get_enabled_feeds(conn)
    for feed_row in feeds:
        name, url = feed_row["name"], feed_row["url"]
        try:
            _fetch_rss_feed(client, conn, name, url, stats)
        except Exception as exc:
            logger.exception("Unexpected error fetching RSS feed %s: %s", name, exc)
            stats.failed_sources.append(name)


def _fetch_rss_feed(
    client: httpx.Client,
    conn: sqlite3.Connection,
    name: str,
    url: str,
    stats: CollectorStats,
) -> None:
    response = _safe_get(client, url)
    if response is None:
        stats.failed_sources.append(name)
        return

    feed = feedparser.parse(response.text)
    if feed.bozo and not feed.entries:
        logger.warning("Feed parse error for %s: %s", name, feed.bozo_exception)
        stats.failed_sources.append(name)
        return

    for entry in feed.entries:
        item_url = entry.get("link", "").strip()
        title = _clean_text(entry.get("title", "")).strip()
        if not item_url or not title:
            continue

        content = _extract_rss_content(entry)
        published_at = _parse_rss_date(entry)

        item = {
            "url": item_url,
            "title": title,
            "source": name,
            "published_at": published_at,
            "fetched_at": _utcnow(),
            "content": _truncate(content, _MAX_CONTENT_CHARS),
            "raw_entry": {
                "id": entry.get("id"),
                "author": entry.get("author"),
            },
        }

        stats.items_fetched += 1
        if db.insert_news_item(conn, item):
            stats.items_new += 1

    settings_module.update_feed_stats(conn, url, _utcnow(), len(feed.entries))
    logger.debug("RSS %s: %d entries processed", name, len(feed.entries))


def _extract_rss_content(entry) -> str:
    """Extract plain text content from a feedparser entry."""
    # Try full content first, then summary
    if entry.get("content"):
        raw = entry["content"][0].get("value", "")
    else:
        raw = entry.get("summary", "")
    return _clean_text(raw)


def _parse_rss_date(entry) -> str | None:
    """Return ISO 8601 UTC string from a feedparser entry, or None."""
    # feedparser provides parsed_published as a time.struct_time tuple
    if entry.get("published_parsed"):
        try:
            dt = datetime(*entry["published_parsed"][:6], tzinfo=UTC)
            return dt.isoformat()
        except (TypeError, ValueError):
            pass
    if entry.get("published"):
        try:
            dt = parsedate_to_datetime(entry["published"])
            return dt.astimezone(UTC).isoformat()
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# NIST NVD
# ---------------------------------------------------------------------------


def _run_nvd(
    client: httpx.Client,
    conn: sqlite3.Connection,
    config: AppConfig,
    stats: CollectorStats,
) -> None:
    """Fetch CVEs published in the last COLLECTION_WINDOW_DAYS days from NVD."""
    try:
        _fetch_nvd(client, conn, config, stats)
    except Exception as exc:
        logger.exception("NVD collection failed: %s", exc)
        stats.failed_sources.append("NIST NVD")


def _fetch_nvd(
    client: httpx.Client,
    conn: sqlite3.Connection,
    config: AppConfig,
    stats: CollectorStats,
) -> None:
    now = datetime.now(UTC)
    start = now - timedelta(days=_COLLECTION_WINDOW_DAYS)

    params: dict = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }
    if config.nvd.api_key:
        params["apiKey"] = config.nvd.api_key

    # Delay between requests: NVD rate limits are 5/30s (no key) or 50/30s (with key)
    delay = 0.7 if config.nvd.api_key else 6.5
    start_index = 0

    while True:
        params["startIndex"] = start_index
        response = _safe_get(client, _NVD_BASE, params=params)
        if response is None:
            stats.failed_sources.append("NIST NVD")
            return

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            description = _nvd_description(cve)
            cvss = _nvd_cvss(cve)
            severity = _cvss_to_severity(cvss)
            item = {
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "title": cve_id,
                "source": "NIST NVD",
                "published_at": cve.get("published"),
                "fetched_at": _utcnow(),
                "content": _truncate(description, _MAX_CONTENT_CHARS),
                "raw_entry": {"cvss": cvss},
                # Pre-classified from NVD structured data — skips Ollama batch
                "category": "Vulnerability",
                "severity": severity,
                "summary": _truncate(description, 160),
                "affected_products": [],
                "tags": [cve_id],
                "cluster_id": cve_id,
            }
            stats.items_fetched += 1
            if db.insert_news_item(conn, item):
                stats.items_new += 1

        start_index += len(vulnerabilities)
        if start_index >= total:
            break

        time.sleep(delay)

    logger.debug("NVD: %d CVEs in window", total)


def _nvd_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _nvd_cvss(cve: dict) -> float | None:
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            return metrics[0].get("cvssData", {}).get("baseScore")
    return None


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------


def _run_kev(
    client: httpx.Client,
    conn: sqlite3.Connection,
    stats: CollectorStats,
) -> None:
    try:
        _fetch_kev(client, conn, stats)
    except Exception as exc:
        logger.exception("CISA KEV collection failed: %s", exc)
        stats.failed_sources.append("CISA KEV")


def _fetch_kev(
    client: httpx.Client,
    conn: sqlite3.Connection,
    stats: CollectorStats,
) -> None:
    response = _safe_get(client, _KEV_URL)
    if response is None:
        stats.failed_sources.append("CISA KEV")
        return

    data = response.json()
    cutoff = datetime.now(UTC) - timedelta(days=_COLLECTION_WINDOW_DAYS)
    new_kev = 0

    for vuln in data.get("vulnerabilities", []):
        date_added_str = vuln.get("dateAdded", "")
        try:
            date_added = datetime.fromisoformat(date_added_str).replace(tzinfo=UTC)
        except (ValueError, AttributeError):
            date_added = None

        # Only process KEVs added within the collection window
        if date_added and date_added < cutoff:
            continue

        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        title = f"{cve_id} — {vuln.get('vulnerabilityName', 'Known Exploited Vulnerability')}"
        content = (
            f"{vuln.get('shortDescription', '')}\n"
            f"Vendor: {vuln.get('vendorProject', '')} | "
            f"Product: {vuln.get('product', '')} | "
            f"Required action: {vuln.get('requiredAction', '')} | "
            f"Due date: {vuln.get('dueDate', '')}"
        )
        affected = [p for p in [vuln.get("vendorProject"), vuln.get("product")] if p]
        item = {
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}",
            "title": title,
            "source": "CISA KEV",
            "published_at": date_added.isoformat() if date_added else None,
            "fetched_at": _utcnow(),
            "content": _truncate(content, _MAX_CONTENT_CHARS),
            "raw_entry": {
                "ransomware": vuln.get("knownRansomwareCampaignUse"),
                "due_date": vuln.get("dueDate"),
            },
            # CISA KEV = actively exploited in the wild → always Critical
            "category": "Vulnerability",
            "severity": "Critical",
            "summary": _truncate(vuln.get("shortDescription") or title, 160),
            "affected_products": affected,
            "tags": [cve_id, "kev"],
            "cluster_id": cve_id,
        }
        stats.items_fetched += 1
        if db.insert_news_item(conn, item):
            stats.items_new += 1
            new_kev += 1

    logger.debug("CISA KEV: %d new entries in window", new_kev)


# ---------------------------------------------------------------------------
# GitHub Security Advisories
# ---------------------------------------------------------------------------


def _run_github_advisories(
    client: httpx.Client,
    conn: sqlite3.Connection,
    config: AppConfig,
    stats: CollectorStats,
) -> None:
    try:
        _fetch_github_advisories(client, conn, config, stats)
    except Exception as exc:
        logger.exception("GitHub Security Advisories collection failed: %s", exc)
        stats.failed_sources.append("GitHub Security Advisories")


def _fetch_github_advisories(
    client: httpx.Client,
    conn: sqlite3.Connection,
    config: AppConfig,
    stats: CollectorStats,
) -> None:
    headers = {
        "Authorization": f"Bearer {config.github.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "per_page": 100,
        "sort": "updated",
        "direction": "desc",
    }
    response = _safe_get(client, _GHSA_URL, headers=headers, params=params)
    if response is None:
        stats.failed_sources.append("GitHub Security Advisories")
        return

    advisories = response.json()
    if not isinstance(advisories, list):
        logger.warning("Unexpected GitHub SA response shape")
        stats.failed_sources.append("GitHub Security Advisories")
        return

    cutoff = datetime.now(UTC) - timedelta(days=_COLLECTION_WINDOW_DAYS)

    for adv in advisories:
        updated_str = adv.get("updated_at") or adv.get("published_at", "")
        try:
            updated = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            updated = None

        if updated and updated < cutoff:
            break  # results are sorted newest-first, so we can stop early

        adv_url = adv.get("html_url", "")
        ghsa_id = adv.get("ghsa_id", "")
        title = adv.get("summary") or ghsa_id or "GitHub Security Advisory"
        cve_ids = [c.get("cve_id") for c in adv.get("cve_ids", []) if c.get("cve_id")]
        content = (
            f"{adv.get('description', '')}\n"
            f"Severity: {adv.get('severity', '')} | "
            f"CVEs: {', '.join(cve_ids) if cve_ids else 'none'}"
        )

        if not adv_url or not title:
            continue

        sev = _GHSA_SEVERITY_MAP.get((adv.get("severity") or "").lower())
        cluster = cve_ids[0] if cve_ids else ghsa_id or None
        tags = ([ghsa_id] if ghsa_id else []) + cve_ids[:3]
        item = {
            "url": adv_url,
            "title": _truncate(title, 200),
            "source": "GitHub Security Advisories",
            "published_at": adv.get("published_at"),
            "fetched_at": _utcnow(),
            "content": _truncate(content, _MAX_CONTENT_CHARS),
            "raw_entry": {
                "ghsa_id": ghsa_id,
                "cve_ids": cve_ids,
                "severity": adv.get("severity"),
            },
            # Pre-classified from GitHub advisory structured data — skips Ollama
            "category": "Vulnerability",
            "severity": sev,  # None when severity field is absent → shows as Unknown
            "summary": _truncate(title, 160),
            "affected_products": [],
            "tags": tags,
            "cluster_id": cluster,
        }
        stats.items_fetched += 1
        if db.insert_news_item(conn, item):
            stats.items_new += 1

    logger.debug("GitHub SA: processed %d advisories", len(advisories))


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _clean_text(raw: str) -> str:
    """Strip HTML tags, decode entities, collapse whitespace."""
    text = _HTML_TAG_RE.sub(" ", raw)
    text = html.unescape(text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + "…"


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()
