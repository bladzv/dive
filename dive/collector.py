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
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import feedparser
import httpx

from . import db
from . import settings as settings_module
from .config import AppConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_CONTENT_CHARS = 2000  # truncate article body before storing / sending to Ollama
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB hard cap on any HTTP response
_HTTP_TIMEOUT = 30.0
_COLLECTION_WINDOW_DAYS = 7  # how far back to fetch from structured APIs
_NVD_MAX_PAGES = 50  # backstop against runaway pagination
_GHSA_MAX_PAGES = 10  # backstop against runaway pagination

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

# Default feeds live in settings.DEFAULT_FEEDS (single source of truth) and are
# read at runtime from the rss_feeds table via settings.get_enabled_feeds().


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


def run(
    conn: sqlite3.Connection,
    config: AppConfig,
    on_progress: Callable[[int, int], None] | None = None,
) -> CollectorStats:
    """Fetch all sources and insert new items into the database.

    Returns a CollectorStats summary. Never raises — individual source failures
    are captured in stats.failed_sources.
    """
    stats = CollectorStats()
    _sources_done = 0

    try:
        feeds = settings_module.get_enabled_feeds(conn)
    except Exception:
        logger.exception("Failed to load enabled feeds — proceeding with none")
        feeds = []
    total_sources = len(feeds) + 3  # RSS feeds + NVD + KEV + GHSA

    def _tick() -> None:
        nonlocal _sources_done
        _sources_done += 1
        if on_progress:
            on_progress(_sources_done, total_sources)

    if on_progress:
        on_progress(0, total_sources)

    with _make_client() as client:
        _run_rss(client, conn, stats, feeds=feeds, on_source_done=_tick)
        _run_nvd(client, conn, config, stats)
        _tick()
        _run_kev(client, conn, stats)
        _tick()
        _run_github_advisories(client, conn, config, stats)
        _tick()

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


# Identify honestly by default. A spoofed browser UA can backfire: some WAFs
# fingerprint the TLS handshake and flag a request claiming to be Chrome that
# doesn't match Chrome's real fingerprint as bot impersonation — this is
# exactly why Bleeping Computer's feed returned HTTP 403 while every other
# default feed (including Dark Reading, which this UA was originally added
# for) worked fine with an honest UA. Kept as a one-shot fallback in
# _safe_get for any host that genuinely rejects non-browser agents.
_DEFAULT_UA = "DIVE-security-monitor/1.0 (+https://github.com/bladzv/dive)"
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _make_client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=True,
        max_redirects=5,
        timeout=_HTTP_TIMEOUT,
        headers={
            "User-Agent": _DEFAULT_UA,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        },
    )


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_RETRY_BACKOFF_SECONDS = [1.0, 3.0]


def _safe_get(client: httpx.Client, url: str, **kwargs) -> httpx.Response | None:
    """GET with size cap, HTTP warning, retry-on-transient-error, and error logging.

    Returns None on failure. Retries on connection errors and on status codes
    that typically indicate a transient upstream issue (429/5xx) — not on 404,
    which means "not going to happen" regardless of retry. A single 403 is
    retried once with a browser User-Agent (some hosts, e.g. Bleeping Computer,
    block non-browser agents outright); a second 403 after that is treated the
    same as any other non-retryable failure. The browser-UA retry is tracked
    separately from the transient-error retry budget so it can fire
    regardless of how many transient retries have already happened.
    """
    if url.startswith("http://"):
        logger.warning("Fetching non-TLS URL: %s", url)

    tried_browser_ua = False
    retry_count = 0
    while True:
        try:
            response = client.get(url, **kwargs)
            response.raise_for_status()
            if len(response.content) > _MAX_RESPONSE_BYTES:
                logger.warning(
                    "Response too large (%d bytes), skipping: %s", len(response.content), url
                )
                return None
            return response
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in _RETRYABLE_STATUS_CODES and retry_count < len(_RETRY_BACKOFF_SECONDS):
                logger.debug(
                    "HTTP %s from %s — retrying in %.0fs",
                    status,
                    url,
                    _RETRY_BACKOFF_SECONDS[retry_count],
                )
                time.sleep(_RETRY_BACKOFF_SECONDS[retry_count])
                retry_count += 1
                continue
            if status == 403 and not tried_browser_ua:
                tried_browser_ua = True
                logger.debug("HTTP 403 from %s — retrying once with a browser User-Agent", url)
                kwargs["headers"] = {**(kwargs.get("headers") or {}), "User-Agent": _BROWSER_UA}
                continue
            logger.warning("HTTP %s from %s", status, url)
            return None
        except httpx.RequestError as exc:
            if retry_count < len(_RETRY_BACKOFF_SECONDS):
                logger.debug(
                    "Request failed for %s: %s — retrying in %.0fs",
                    url,
                    exc,
                    _RETRY_BACKOFF_SECONDS[retry_count],
                )
                time.sleep(_RETRY_BACKOFF_SECONDS[retry_count])
                retry_count += 1
                continue
            logger.warning("Request failed for %s: %s", url, exc)
            return None


# ---------------------------------------------------------------------------
# RSS feeds
# ---------------------------------------------------------------------------


def _run_rss(
    client: httpx.Client,
    conn: sqlite3.Connection,
    stats: CollectorStats,
    feeds: list | None = None,
    on_source_done: Callable[[], None] | None = None,
) -> None:
    if feeds is None:
        feeds = settings_module.get_enabled_feeds(conn)
    for feed_row in feeds:
        name, url = feed_row["name"], feed_row["url"]
        try:
            _fetch_rss_feed(client, conn, name, url, stats)
        except Exception as exc:
            logger.exception("Unexpected error fetching RSS feed %s: %s", name, exc)
            stats.failed_sources.append(name)
        if on_source_done:
            on_source_done()


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
    # NVD requires the API key as a request header, not a query parameter —
    # passing it as a query param returns HTTP 404 on every request (verified
    # against the live API). Header placement also keeps the key out of any
    # URL-based logging (e.g. httpx's own request-URL log line).
    nvd_headers = {"apiKey": config.nvd.api_key} if config.nvd.api_key else {}

    # Delay between requests: NVD rate limits are 5/30s (no key) or 50/30s (with key)
    delay = 0.7 if config.nvd.api_key else 6.5
    start_index = 0
    total = 0

    for page in range(_NVD_MAX_PAGES):
        params["startIndex"] = start_index
        response = _safe_get(client, _NVD_BASE, params=params, headers=nvd_headers)
        if response is None:
            stats.failed_sources.append("NIST NVD")
            return

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        if not vulnerabilities:
            # NVD can return an empty page while totalResults > 0 under load.
            # There's nothing left to advance on, so stop rather than spin.
            break

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
    else:
        logger.warning(
            "NVD: hit the %d-page pagination cap with %d/%d results fetched — "
            "remaining CVEs will be picked up on a later run",
            _NVD_MAX_PAGES,
            start_index,
            total,
        )

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

    # The persistent kev_entries table is the source of truth for is_kev
    # scoring, so it's populated from the FULL catalog every run — independent
    # of the news collection window below, which only controls what shows up
    # as a news item (we don't want to flood the feed with years of history).
    all_entries = [
        (vuln.get("cveID", ""), vuln.get("dateAdded") or None)
        for vuln in data.get("vulnerabilities", [])
        if vuln.get("cveID")
    ]
    if all_entries:
        db.upsert_kev_entries(conn, all_entries)

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
    params: dict | None = {
        "per_page": 100,
        "sort": "updated",
        "direction": "desc",
    }
    cutoff = datetime.now(UTC) - timedelta(days=_COLLECTION_WINDOW_DAYS)

    url = _GHSA_URL
    total_processed = 0
    stopped_early = False

    for page in range(_GHSA_MAX_PAGES):
        response = _safe_get(client, url, headers=headers, params=params)
        if response is None:
            stats.failed_sources.append("GitHub Security Advisories")
            return

        advisories = response.json()
        if not isinstance(advisories, list):
            logger.warning("Unexpected GitHub SA response shape")
            stats.failed_sources.append("GitHub Security Advisories")
            return

        for adv in advisories:
            updated_str = adv.get("updated_at") or adv.get("published_at", "")
            try:
                updated = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                updated = None

            if updated and updated < cutoff:
                # Results are sorted newest-first, so we can stop entirely —
                # every advisory on later pages would also be out of window.
                stopped_early = True
                break

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
            total_processed += 1

        if stopped_early:
            break

        next_link = response.links.get("next")
        if not next_link:
            break
        # The "next" Link URL already carries its own query string.
        url = next_link["url"]
        params = None
    else:
        logger.info(
            "GitHub SA: hit the %d-page pagination cap — older advisories in "
            "this window will be picked up on a later run",
            _GHSA_MAX_PAGES,
        )

    logger.info("GitHub SA: processed %d advisories across %d page(s)", total_processed, page + 1)


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
