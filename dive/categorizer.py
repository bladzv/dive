"""
categorizer.py — AI-powered news categorization via Ollama.

Reads uncategorized news items from the database, sends them to the local Ollama
model in batches of 10, validates the JSON response, and writes results back.

Fallback: items that fail schema validation after MAX_RETRIES attempts are stored
as category="Uncategorized" / severity="Unknown" so they still appear in the feed.

If the uncategorized rate exceeds UNCATEGORIZED_WARNING_THRESHOLD, a warning is
logged — a signal to evaluate a different model (see MODELS.md).

Clustering: items mentioning the same CVE ID are assigned the same cluster_id,
so the dashboard can group them into a single story card.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from . import db
from .config import AppConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BATCH_SIZE = 10
MAX_RETRIES = 2
HTTP_TIMEOUT = 120.0  # Ollama on Pi 4 can be slow — 2 min budget per batch
UNCATEGORIZED_WARNING_THRESHOLD = 0.20  # warn if >20% of items fall back

VALID_CATEGORIES = {
    "Vulnerability",
    "Breach",
    "Malware",
    "Patch",
    "Research",
    "Tool",
    "Policy",
    "Other",
}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@dataclass
class CategorizerStats:
    total_processed: int = 0
    categorized: int = 0
    uncategorized: int = 0

    @property
    def uncategorized_rate(self) -> float:
        if self.total_processed == 0:
            return 0.0
        return self.uncategorized / self.total_processed


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(
    conn: sqlite3.Connection,
    config: AppConfig,
    on_progress: Callable[[int, int], None] | None = None,
) -> CategorizerStats:
    """Categorize all pending news items and write results to the database.

    Processes items in batches of BATCH_SIZE. Never raises — individual batch
    failures fall back to Uncategorized/Unknown.

    on_progress(done, total) is called after each batch so callers can track
    real-time progress (e.g. to update the pipeline drawer).
    """
    stats = CategorizerStats()
    items = db.get_uncategorized_items(conn, limit=500)

    if not items:
        logger.info("No uncategorized items — nothing to do")
        return stats

    total = len(items)
    # Prefer the model set via the Settings UI over the config.yaml default.
    active_model = db.get_setting(conn, "active_model") or config.ollama.model
    logger.info(
        "Categorizing %d items in batches of %d (model: %s)", total, BATCH_SIZE, active_model
    )

    if on_progress:
        on_progress(0, total)

    with _make_client() as client:
        for batch_start in range(0, total, BATCH_SIZE):
            batch = items[batch_start : batch_start + BATCH_SIZE]
            _process_batch(conn, client, config, batch, stats, active_model)
            if on_progress:
                on_progress(min(batch_start + len(batch), total), total)

    stats.total_processed = stats.categorized + stats.uncategorized

    if stats.uncategorized_rate > UNCATEGORIZED_WARNING_THRESHOLD:
        logger.warning(
            "High uncategorized rate: %.0f%% of items fell back to Uncategorized/Unknown. "
            "Consider evaluating a different model — see MODELS.md.",
            stats.uncategorized_rate * 100,
        )

    logger.info(
        "Categorization complete: %d categorized, %d uncategorized (%.0f%%)",
        stats.categorized,
        stats.uncategorized,
        stats.uncategorized_rate * 100,
    )
    return stats


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------


def _process_batch(
    conn: sqlite3.Connection,
    client: httpx.Client,
    config: AppConfig,
    batch: list[sqlite3.Row],
    stats: CategorizerStats,
    model: str,
) -> None:
    results: list[dict] | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        raw_response = _call_ollama(client, config, batch, model)
        if raw_response is None:
            logger.warning("Ollama call failed (attempt %d/%d)", attempt, MAX_RETRIES)
            continue

        results = _parse_response(raw_response, expected_count=len(batch))
        if results is not None:
            break
        logger.warning("Response failed validation (attempt %d/%d)", attempt, MAX_RETRIES)

    for i, row in enumerate(batch):
        r = _normalize_result(results[i]) if results and i < len(results) else None
        if r and _is_valid(r):
            cluster_id = _assign_cluster(row["title"], row["content"] or "")
            db.update_item_categorization(
                conn,
                row["id"],
                summary=str(r.get("summary") or "")[:160],
                category=r["category"],
                severity=r["severity"],
                affected_products=r.get("affected_products") or [],
                tags=r.get("tags") or [],
                cluster_id=cluster_id,
            )
            stats.categorized += 1
        else:
            # Fallback: store item as Uncategorized so it still appears in the feed
            cluster_id = _assign_cluster(row["title"], row["content"] or "")
            db.update_item_categorization(
                conn,
                row["id"],
                summary="",
                category="Uncategorized",
                severity="Unknown",
                affected_products=[],
                tags=[],
                cluster_id=cluster_id,
            )
            stats.uncategorized += 1


# ---------------------------------------------------------------------------
# Ollama HTTP call
# ---------------------------------------------------------------------------


def _normalize_result(r: dict) -> dict:
    """Normalise model output casing so exact-match validation doesn't fail on
    variants like 'vulnerability' or 'HIGH' returned by smaller models."""
    if isinstance(r.get("category"), str):
        r["category"] = r["category"].strip().capitalize()
    if isinstance(r.get("severity"), str):
        r["severity"] = r["severity"].strip().capitalize()
    return r


def _call_ollama(
    client: httpx.Client,
    config: AppConfig,
    batch: list[sqlite3.Row],
    model: str,
) -> str | None:
    """Send a batch to Ollama. Returns the raw response text, or None on error."""
    prompt = _build_prompt(batch)
    url = f"{config.ollama.host.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",  # Ollama JSON mode — constrains output to valid JSON
        "options": {"temperature": 0.1},  # low temperature for deterministic output
    }

    try:
        response = client.post(url, json=payload, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")
    except httpx.TimeoutException:
        logger.warning("Ollama request timed out after %.0fs", HTTP_TIMEOUT)
        return None
    except httpx.HTTPStatusError as exc:
        logger.warning("Ollama returned HTTP %s", exc.response.status_code)
        return None
    except (httpx.RequestError, ValueError) as exc:
        logger.warning("Ollama call failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def _build_prompt(batch: list[sqlite3.Row]) -> str:
    """Build the classification prompt for a batch of items."""
    items_block = ""
    for i, row in enumerate(batch, start=1):
        title = _sanitize_field(row["title"], 200)
        content = _sanitize_field(row["content"] or "", 500)
        items_block += f'<item id="{i}">\nTitle: {title}\nContent: {content}\n</item>\n\n'

    return f"""You are a security news classifier. Classify each item below.

Output ONLY a JSON array with exactly {len(batch)} objects in the same order as the items.
No explanation, no markdown, no code fences — only the JSON array.

Each object must have exactly these fields:
{{
  "category": one of ["Vulnerability","Breach","Malware","Patch","Research","Tool","Policy","Other"],
  "severity": one of ["Critical","High","Medium","Low","Info"],
  "affected_products": array of strings (product or vendor names, max 5, empty array if none),
  "summary": string (one sentence describing the item, max 160 characters),
  "tags": array of strings (relevant keywords, max 5, empty array if none)
}}

Items:

{items_block}"""


# ---------------------------------------------------------------------------
# Response parsing and validation
# ---------------------------------------------------------------------------


def _parse_response(raw: str, expected_count: int) -> list[dict] | None:
    """Parse and basic-validate the Ollama JSON response.

    Returns a list of dicts on success. Accepts partial results when the model
    returns fewer items than expected rather than discarding everything.
    """
    if not raw or not raw.strip():
        return None

    text = raw.strip()

    # If the model wrapped the array in an object, extract the first list value.
    # Models use wildly different wrapper keys ("results", "output", "answer", etc.)
    # so we accept any list value rather than checking a hardcoded set.
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            for val in obj.values():
                if isinstance(val, list) and val:
                    text = json.dumps(val)
                    break
        except (json.JSONDecodeError, AttributeError):
            pass

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("Ollama JSON parse error: %s | raw: %.200s", exc, raw)
        return None

    if not isinstance(parsed, list):
        logger.warning(
            "Ollama returned %s instead of a JSON array | raw: %.200s",
            type(parsed).__name__,
            raw[:200],
        )
        return None

    if not parsed:
        return None

    if len(parsed) != expected_count:
        logger.warning(
            "Ollama response count mismatch: expected %d, got %d — using partial results",
            expected_count,
            len(parsed),
        )

    return parsed


def _is_valid(item: Any) -> bool:
    """Return True if an item dict has the required fields with valid values."""
    if not isinstance(item, dict):
        return False
    if item.get("category") not in VALID_CATEGORIES:
        return False
    if item.get("severity") not in VALID_SEVERITIES:
        return False
    if not isinstance(item.get("summary"), str):
        return False
    return True


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------


def _assign_cluster(title: str, content: str) -> str | None:
    """Return the first CVE ID mentioned in the title or first 500 chars of content.

    Items sharing a CVE ID are shown as a single story card in the dashboard.
    Returns None if no CVE ID is found.
    """
    text = f"{title} {content[:500]}"
    match = _CVE_RE.search(text)
    return match.group(0).upper() if match else None


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_field(text: str, max_chars: int) -> str:
    """Strip control characters and truncate. Prevents prompt injection via feed content."""
    text = _CONTROL_RE.sub(" ", text)
    if len(text) > max_chars:
        text = text[:max_chars].rsplit(" ", 1)[0] + "…"
    return text


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def _make_client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=False,
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": "dive/0.1"},
    )
