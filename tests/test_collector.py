"""
Unit tests for collector.py — _safe_get retry-on-transient-error behavior.

No real network calls are made — httpx.Client is mocked throughout.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx

import dive.db as db
from dive.collector import CollectorStats, _fetch_github_advisories, _fetch_nvd, _safe_get


def _response(status_code=200, content=b"ok"):
    response = MagicMock()
    response.status_code = status_code
    response.content = content
    if status_code >= 400:
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"{status_code}", request=MagicMock(), response=response
        )
    else:
        response.raise_for_status.return_value = None
    return response


@patch("dive.collector.time.sleep")
def test_safe_get_retries_on_503_then_succeeds(mock_sleep):
    client = MagicMock()
    client.get.side_effect = [_response(503), _response(200)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is not None
    assert result.status_code == 200
    assert client.get.call_count == 2
    mock_sleep.assert_called_once()


@patch("dive.collector.time.sleep")
def test_safe_get_gives_up_after_max_retries(mock_sleep):
    client = MagicMock()
    client.get.side_effect = [_response(503), _response(503), _response(503)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is None
    assert client.get.call_count == 3
    assert mock_sleep.call_count == 2


@patch("dive.collector.time.sleep")
def test_safe_get_does_not_retry_on_404(mock_sleep):
    client = MagicMock()
    client.get.side_effect = [_response(404)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is None
    assert client.get.call_count == 1
    mock_sleep.assert_not_called()


@patch("dive.collector.time.sleep")
def test_safe_get_retries_once_with_browser_ua_on_403(mock_sleep):
    """A 403 gets exactly one retry with a browser User-Agent (some hosts,
    e.g. Bleeping Computer, block non-browser agents outright)."""
    client = MagicMock()
    client.get.side_effect = [_response(403), _response(200)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is not None
    assert result.status_code == 200
    assert client.get.call_count == 2
    mock_sleep.assert_not_called()  # the browser-UA retry is immediate, not backed off
    # the second call must carry the browser UA
    second_call_kwargs = client.get.call_args_list[1].kwargs
    from dive.collector import _BROWSER_UA

    assert second_call_kwargs["headers"]["User-Agent"] == _BROWSER_UA


@patch("dive.collector.time.sleep")
def test_safe_get_gives_up_after_browser_ua_retry_also_403s(mock_sleep):
    client = MagicMock()
    client.get.side_effect = [_response(403), _response(403)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is None
    assert client.get.call_count == 2
    mock_sleep.assert_not_called()


@patch("dive.collector.time.sleep")
def test_safe_get_403_retry_preserves_existing_headers(mock_sleep):
    """The browser-UA fallback must merge into existing headers (e.g. GHSA's
    Authorization), not replace them — losing Authorization would turn an
    authenticated request into an anonymous (and likely still-failing) one."""
    client = MagicMock()
    client.get.side_effect = [_response(403), _response(200)]

    result = _safe_get(
        client, "https://api.github.com/advisories", headers={"Authorization": "Bearer tok"}
    )

    assert result is not None
    second_call_kwargs = client.get.call_args_list[1].kwargs
    assert second_call_kwargs["headers"]["Authorization"] == "Bearer tok"
    from dive.collector import _BROWSER_UA

    assert second_call_kwargs["headers"]["User-Agent"] == _BROWSER_UA


@patch("dive.collector.time.sleep")
def test_safe_get_403_fallback_available_after_transient_retries(mock_sleep):
    """The browser-UA retry must not be starved by the transient-retry budget:
    a 503 retry followed by a 403 must still get its one browser-UA retry."""
    client = MagicMock()
    client.get.side_effect = [_response(503), _response(403), _response(200)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is not None
    assert client.get.call_count == 3


@patch("dive.collector.time.sleep")
def test_safe_get_retries_on_connection_error_then_succeeds(mock_sleep):
    client = MagicMock()
    client.get.side_effect = [
        httpx.ConnectError("connection reset", request=MagicMock()),
        _response(200),
    ]

    result = _safe_get(client, "https://example.com/feed")

    assert result is not None
    assert client.get.call_count == 2
    mock_sleep.assert_called_once()


def _nvd_response(vulnerabilities, total_results):
    response = MagicMock()
    response.json.return_value = {
        "vulnerabilities": vulnerabilities,
        "totalResults": total_results,
    }
    return response


@patch("dive.collector.time.sleep")
@patch("dive.collector._safe_get")
def test_fetch_nvd_stops_on_empty_page_instead_of_looping_forever(
    mock_safe_get, mock_sleep, tmp_db
):
    """NVD can return an empty vulnerabilities page while totalResults > 0.

    start_index only advances by len(vulnerabilities), so without a guard
    the pagination loop never terminates. This must return promptly.
    """
    mock_safe_get.return_value = _nvd_response([], 5000)
    config = MagicMock()
    config.nvd.api_key = ""
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_nvd(MagicMock(), conn, config, stats)

    assert mock_safe_get.call_count == 1


@patch("dive.collector.time.sleep")
@patch("dive.collector._safe_get")
def test_fetch_nvd_respects_page_cap(mock_safe_get, mock_sleep, tmp_db):
    """A page that never reaches totalResults must not paginate forever."""
    # Each page returns 1 result out of a much larger total — start_index
    # advances but never catches up to totalResults within the page cap.
    mock_safe_get.return_value = _nvd_response(
        [{"cve": {"id": "CVE-2024-0001", "published": "2024-01-01T00:00:00"}}],
        100_000,
    )
    config = MagicMock()
    config.nvd.api_key = ""
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_nvd(MagicMock(), conn, config, stats)

    from dive.collector import _NVD_MAX_PAGES

    assert mock_safe_get.call_count == _NVD_MAX_PAGES


@patch("dive.collector.time.sleep")
@patch("dive.collector._safe_get")
def test_fetch_nvd_stops_normally_when_total_reached(mock_safe_get, mock_sleep, tmp_db):
    mock_safe_get.return_value = _nvd_response(
        [{"cve": {"id": "CVE-2024-0002", "published": "2024-01-01T00:00:00"}}],
        1,
    )
    config = MagicMock()
    config.nvd.api_key = ""
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_nvd(MagicMock(), conn, config, stats)

    assert mock_safe_get.call_count == 1
    assert stats.items_fetched == 1


@patch("dive.collector.time.sleep")
@patch("dive.collector._safe_get")
def test_fetch_nvd_sends_api_key_as_header_not_query_param(mock_safe_get, mock_sleep, tmp_db):
    """NVD returns HTTP 404 if apiKey is passed as a query param — it must be
    a request header instead (verified against the live NVD API)."""
    mock_safe_get.return_value = _nvd_response([], 0)
    config = MagicMock()
    config.nvd.api_key = "test-nvd-key-12345"
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_nvd(MagicMock(), conn, config, stats)

    call_kwargs = mock_safe_get.call_args.kwargs
    assert call_kwargs["headers"] == {"apiKey": "test-nvd-key-12345"}
    assert "apiKey" not in call_kwargs["params"]


@patch("dive.collector.time.sleep")
@patch("dive.collector._safe_get")
def test_fetch_nvd_no_api_key_sends_empty_headers(mock_safe_get, mock_sleep, tmp_db):
    mock_safe_get.return_value = _nvd_response([], 0)
    config = MagicMock()
    config.nvd.api_key = ""
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_nvd(MagicMock(), conn, config, stats)

    call_kwargs = mock_safe_get.call_args.kwargs
    assert call_kwargs["headers"] == {}


def _ghsa_advisory(ghsa_id, updated_at=None):
    if updated_at is None:
        updated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "ghsa_id": ghsa_id,
        "summary": f"{ghsa_id} summary",
        "updated_at": updated_at,
        "published_at": updated_at,
        "severity": "high",
        "cve_ids": [],
        "description": "desc",
    }


def _ghsa_response(advisories, next_url=None):
    response = MagicMock()
    response.json.return_value = advisories
    response.links = {"next": {"url": next_url}} if next_url else {}
    return response


@patch("dive.collector._safe_get")
def test_fetch_github_advisories_follows_next_link(mock_safe_get, tmp_db):
    """A page full of in-window advisories must fetch the next page too."""
    page1 = [_ghsa_advisory(f"GHSA-{i:04d}") for i in range(100)]
    page2 = [_ghsa_advisory("GHSA-page2")]
    mock_safe_get.side_effect = [
        _ghsa_response(page1, next_url="https://api.github.com/advisories?page=2"),
        _ghsa_response(page2),
    ]
    config = MagicMock()
    config.github.token = "tok"
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_github_advisories(MagicMock(), conn, config, stats)

    assert mock_safe_get.call_count == 2
    assert stats.items_fetched == 101


@patch("dive.collector._safe_get")
def test_fetch_github_advisories_stops_at_cutoff_without_following_next(mock_safe_get, tmp_db):
    """Once we cross the collection window we must not fetch further pages."""
    old_advisory = _ghsa_advisory("GHSA-old", updated_at="2000-01-01T00:00:00Z")
    mock_safe_get.return_value = _ghsa_response(
        [old_advisory], next_url="https://api.github.com/advisories?page=2"
    )
    config = MagicMock()
    config.github.token = "tok"
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_github_advisories(MagicMock(), conn, config, stats)

    assert mock_safe_get.call_count == 1
    assert stats.items_fetched == 0


@patch("dive.collector._safe_get")
def test_fetch_github_advisories_respects_page_cap(mock_safe_get, tmp_db):
    """A next link that never ends must not paginate forever."""
    mock_safe_get.return_value = _ghsa_response(
        [_ghsa_advisory("GHSA-loop")], next_url="https://api.github.com/advisories?page=next"
    )
    config = MagicMock()
    config.github.token = "tok"
    stats = CollectorStats()

    with db.get_conn(tmp_db) as conn:
        _fetch_github_advisories(MagicMock(), conn, config, stats)

    from dive.collector import _GHSA_MAX_PAGES

    assert mock_safe_get.call_count == _GHSA_MAX_PAGES
