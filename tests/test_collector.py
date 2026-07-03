"""
Unit tests for collector.py — _safe_get retry-on-transient-error behavior.

No real network calls are made — httpx.Client is mocked throughout.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from dive.collector import _safe_get


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
def test_safe_get_does_not_retry_on_403(mock_sleep):
    client = MagicMock()
    client.get.side_effect = [_response(403)]

    result = _safe_get(client, "https://example.com/feed")

    assert result is None
    assert client.get.call_count == 1
    mock_sleep.assert_not_called()


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
