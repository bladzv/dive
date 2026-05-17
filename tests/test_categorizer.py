"""
Unit tests for categorizer.py — prompt building, response parsing,
validation, fallback, batch splitting, and clustering.

No Ollama connection is used — Ollama calls are mocked.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import categorizer
import db
from categorizer import (
    BATCH_SIZE,
    VALID_CATEGORIES,
    VALID_SEVERITIES,
    _assign_cluster,
    _build_prompt,
    _is_valid,
    _parse_response,
    _sanitize_field,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_row(
    item_id: int = 1,
    title: str = "CVE-2024-1234 Remote Code Execution in Example",
    content: str = "An attacker can exploit this to execute arbitrary code.",
    source: str = "Test Feed",
    url: str = "https://example.com/cve-2024-1234",
) -> sqlite3.Row:
    """Build a sqlite3.Row-compatible dict for testing."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE t (id INTEGER, title TEXT, content TEXT, source TEXT, url TEXT)"
    )
    conn.execute("INSERT INTO t VALUES (?,?,?,?,?)", (item_id, title, content, source, url))
    conn.commit()
    return conn.execute("SELECT * FROM t").fetchone()


def _make_batch(count: int) -> list[sqlite3.Row]:
    return [
        _make_row(
            item_id=i,
            title=f"Security item {i}",
            content=f"Description of security issue {i}.",
            url=f"https://example.com/item{i}",
        )
        for i in range(1, count + 1)
    ]


def _valid_result() -> dict:
    return {
        "category": "Vulnerability",
        "severity": "High",
        "affected_products": ["ExampleLib"],
        "summary": "Remote code execution vulnerability in ExampleLib.",
        "tags": ["rce"],
    }


# ---------------------------------------------------------------------------
# _build_prompt
# ---------------------------------------------------------------------------


def test_build_prompt_contains_all_items():
    batch = _make_batch(3)
    prompt = _build_prompt(batch)
    assert 'id="1"' in prompt
    assert 'id="2"' in prompt
    assert 'id="3"' in prompt


def test_build_prompt_mentions_expected_count():
    batch = _make_batch(5)
    prompt = _build_prompt(batch)
    assert "5" in prompt  # "exactly 5 objects"


def test_build_prompt_includes_valid_categories():
    prompt = _build_prompt(_make_batch(1))
    for cat in ["Vulnerability", "Breach", "Malware", "Patch"]:
        assert cat in prompt


def test_build_prompt_includes_item_title():
    batch = [_make_row(title="Log4Shell Critical Vulnerability")]
    prompt = _build_prompt(batch)
    assert "Log4Shell Critical Vulnerability" in prompt


def test_build_prompt_sanitizes_content():
    """Control characters must be stripped from prompt content."""
    batch = [_make_row(content="Malicious\x00content\x1fwith\x08controls")]
    prompt = _build_prompt(batch)
    assert "\x00" not in prompt
    assert "\x1f" not in prompt
    assert "\x08" not in prompt


# ---------------------------------------------------------------------------
# _parse_response
# ---------------------------------------------------------------------------


def test_parse_response_valid_array():
    data = [_valid_result()]
    result = _parse_response(json.dumps(data), expected_count=1)
    assert result is not None
    assert len(result) == 1
    assert result[0]["category"] == "Vulnerability"


def test_parse_response_wrong_count_returns_partial():
    # Count mismatch: return what the model gave us rather than discarding everything.
    data = [_valid_result(), _valid_result()]
    result = _parse_response(json.dumps(data), expected_count=1)
    assert result == data


def test_parse_response_invalid_json_returns_none():
    assert _parse_response("not json at all", expected_count=1) is None


def test_parse_response_empty_string_returns_none():
    assert _parse_response("", expected_count=1) is None


def test_parse_response_object_instead_of_array_returns_none():
    assert _parse_response(json.dumps({"category": "Vulnerability"}), expected_count=1) is None


def test_parse_response_handles_wrapped_array():
    """Model sometimes wraps array in {results: [...]} — we unwrap it."""
    data = {"results": [_valid_result()]}
    result = _parse_response(json.dumps(data), expected_count=1)
    assert result is not None
    assert result[0]["category"] == "Vulnerability"


def test_parse_response_batch_of_ten():
    data = [_valid_result() for _ in range(10)]
    result = _parse_response(json.dumps(data), expected_count=10)
    assert result is not None
    assert len(result) == 10


# ---------------------------------------------------------------------------
# _is_valid
# ---------------------------------------------------------------------------


def test_is_valid_passes_good_item():
    assert _is_valid(_valid_result()) is True


def test_is_valid_rejects_invalid_category():
    item = {**_valid_result(), "category": "NotACategory"}
    assert _is_valid(item) is False


def test_is_valid_rejects_invalid_severity():
    item = {**_valid_result(), "severity": "Extreme"}
    assert _is_valid(item) is False


def test_is_valid_rejects_missing_summary():
    item = {k: v for k, v in _valid_result().items() if k != "summary"}
    assert _is_valid(item) is False


def test_is_valid_rejects_non_string_summary():
    item = {**_valid_result(), "summary": 42}
    assert _is_valid(item) is False


def test_is_valid_rejects_non_dict():
    assert _is_valid("string") is False
    assert _is_valid(None) is False
    assert _is_valid([]) is False


def test_all_valid_categories_accepted():
    for cat in VALID_CATEGORIES:
        item = {**_valid_result(), "category": cat}
        assert _is_valid(item) is True, f"Expected {cat} to be valid"


def test_all_valid_severities_accepted():
    for sev in VALID_SEVERITIES:
        item = {**_valid_result(), "severity": sev}
        assert _is_valid(item) is True, f"Expected {sev} to be valid"


# ---------------------------------------------------------------------------
# _assign_cluster
# ---------------------------------------------------------------------------


def test_assign_cluster_extracts_cve_from_title():
    assert _assign_cluster("CVE-2024-44000 in Apache", "") == "CVE-2024-44000"


def test_assign_cluster_extracts_cve_from_content():
    assert _assign_cluster("Critical bug found", "See CVE-2023-1234 for details") == "CVE-2023-1234"


def test_assign_cluster_title_takes_precedence():
    result = _assign_cluster("CVE-2024-0001 headline", "Also related to CVE-2024-9999")
    assert result == "CVE-2024-0001"


def test_assign_cluster_uppercases_cve():
    assert _assign_cluster("cve-2024-1234 vulnerability", "") == "CVE-2024-1234"


def test_assign_cluster_no_cve_returns_none():
    assert _assign_cluster("General security news", "No CVE mentioned here") is None


def test_assign_cluster_only_searches_first_500_chars_of_content():
    content = "x" * 600 + " CVE-2024-9999"
    assert _assign_cluster("No title CVE", content) is None


# ---------------------------------------------------------------------------
# _sanitize_field
# ---------------------------------------------------------------------------


def test_sanitize_field_strips_control_chars():
    assert "\x00" not in _sanitize_field("bad\x00field", 200)
    assert "\x1f" not in _sanitize_field("bad\x1ffield", 200)


def test_sanitize_field_truncates():
    result = _sanitize_field("word " * 100, 20)
    assert len(result) <= 21  # 20 + possible ellipsis char


def test_sanitize_field_preserves_short_text():
    text = "Short safe text"
    assert _sanitize_field(text, 200) == text


# ---------------------------------------------------------------------------
# Batch splitting (integration with mocked Ollama)
# ---------------------------------------------------------------------------


@pytest.fixture
def db_conn(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init(db_path)
    with db.get_conn(db_path) as conn:
        yield conn


def test_run_splits_into_correct_batches(db_conn):
    """11 items should produce 2 Ollama calls (10 + 1)."""
    for i in range(11):
        db.insert_news_item(
            db_conn,
            {
                "url": f"https://example.com/item{i}",
                "title": f"Security item {i}",
                "source": "Test",
                "fetched_at": "2024-01-15T00:00:00+00:00",
                "content": f"Description {i}",
            },
        )

    call_count = 0

    def fake_call_ollama(client, config, batch, model):
        nonlocal call_count
        call_count += 1
        return json.dumps([_valid_result() for _ in batch])

    config = MagicMock()
    config.ollama.host = "http://localhost:11434"
    config.ollama.model = "qwen2.5:3b"

    with patch("categorizer._call_ollama", side_effect=fake_call_ollama):
        stats = categorizer.run(db_conn, config)

    assert call_count == 2  # ceil(11 / 10) = 2
    assert stats.categorized == 11
    assert stats.uncategorized == 0


def test_run_falls_back_on_ollama_failure(db_conn):
    """When Ollama fails all retries, items should be stored as Uncategorized."""
    db.insert_news_item(
        db_conn,
        {
            "url": "https://example.com/item1",
            "title": "Some security news",
            "source": "Test",
            "fetched_at": "2024-01-15T00:00:00+00:00",
            "content": "Something happened.",
        },
    )

    config = MagicMock()
    config.ollama.host = "http://localhost:11434"
    config.ollama.model = "qwen2.5:3b"

    with patch("categorizer._call_ollama", return_value=None):
        stats = categorizer.run(db_conn, config)

    assert stats.uncategorized == 1
    assert stats.categorized == 0
    row = db_conn.execute("SELECT category, severity FROM news_items").fetchone()
    assert row["category"] == "Uncategorized"
    assert row["severity"] == "Unknown"
