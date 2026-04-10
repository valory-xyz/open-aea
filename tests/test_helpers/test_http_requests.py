# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""Tests for aea.helpers.http_requests module."""

import http.client
import io
import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aea.helpers import http_requests


def _mock_urlopen(status: int = 200, body: bytes = b"{}") -> MagicMock:
    """Create a mock context manager for urlopen."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    resp.url = "http://example.com"
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestHTTPResponse:
    """Tests for HTTPResponse."""

    def test_text(self) -> None:
        """Test text property."""
        resp = http_requests.HTTPResponse(200, b"hello")
        assert resp.text == "hello"

    def test_content(self) -> None:
        """Test content property."""
        resp = http_requests.HTTPResponse(200, b"\x00\x01")
        assert resp.content == b"\x00\x01"

    def test_json(self) -> None:
        """Test json parsing."""
        resp = http_requests.HTTPResponse(200, b'{"key": "val"}')
        assert resp.json() == {"key": "val"}

    def test_json_empty_raises(self) -> None:
        """Test json on empty body raises."""
        resp = http_requests.HTTPResponse(200, b"")
        with pytest.raises(json.JSONDecodeError):
            resp.json()

    def test_read(self) -> None:
        """Test read method."""
        resp = http_requests.HTTPResponse(200, b"data")
        assert resp.read() == b"data"


class TestRequest:
    """Tests for request function."""

    @patch("aea.helpers.http_requests._opener.open")
    def test_get(self, mock_open: MagicMock) -> None:
        """Test basic GET request."""
        mock_open.return_value = _mock_urlopen(200, b'{"ok": true}')
        resp = http_requests.get("http://example.com")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    @patch("aea.helpers.http_requests._opener.open")
    def test_post(self, mock_open: MagicMock) -> None:
        """Test basic POST request."""
        mock_open.return_value = _mock_urlopen(201, b"created")
        resp = http_requests.post("http://example.com")
        assert resp.status_code == 201
        assert resp.text == "created"

    @patch("aea.helpers.http_requests._opener.open")
    def test_params_encoding(self, mock_open: MagicMock) -> None:
        """Test query params are URL-encoded."""
        mock_open.return_value = _mock_urlopen()
        http_requests.get("http://example.com", params={"a": "1", "b": "2"})
        req = mock_open.call_args[0][0]
        assert "a=1" in req.full_url
        assert "b=2" in req.full_url
        assert "?" in req.full_url

    @patch("aea.helpers.http_requests._opener.open")
    def test_params_with_existing_query(self, mock_open: MagicMock) -> None:
        """Test params appended with & when URL already has query string."""
        mock_open.return_value = _mock_urlopen()
        http_requests.get("http://example.com?x=0", params={"a": "1"})
        req = mock_open.call_args[0][0]
        assert "?x=0&a=1" in req.full_url

    @patch("aea.helpers.http_requests._opener.open")
    def test_dict_data_form_encoded(self, mock_open: MagicMock) -> None:
        """Test dict data is form-encoded."""
        mock_open.return_value = _mock_urlopen()
        http_requests.post("http://example.com", data={"key": "val"})
        req = mock_open.call_args[0][0]
        assert req.data == b"key=val"
        assert "application/x-www-form-urlencoded" in req.headers.get(
            "Content-type", ""
        )

    @patch("aea.helpers.http_requests._opener.open")
    def test_bytes_data_passthrough(self, mock_open: MagicMock) -> None:
        """Test bytes data passed as-is."""
        mock_open.return_value = _mock_urlopen()
        http_requests.post("http://example.com", data=b"raw")
        req = mock_open.call_args[0][0]
        assert req.data == b"raw"

    @patch("aea.helpers.http_requests._opener.open")
    def test_multipart_files(self, mock_open: MagicMock) -> None:
        """Test multipart file upload."""
        mock_open.return_value = _mock_urlopen()
        f = io.BytesIO(b"file content")
        f.name = "/home/user/secret/file.txt"
        http_requests.post("http://example.com", files={"upload": f})
        req = mock_open.call_args[0][0]
        assert b"file content" in req.data
        assert b"multipart/form-data" in req.headers.get("Content-type", "").encode()
        # filename should be basename only, not full path
        assert b"file.txt" in req.data
        assert b"/home/user/secret" not in req.data


class TestErrorHandling:
    """Tests for error handling."""

    @patch("aea.helpers.http_requests._opener.open")
    def test_http_error_returns_response(self, mock_open: MagicMock) -> None:
        """Test HTTPError is caught and returned as HTTPResponse."""
        mock_open.side_effect = urllib.error.HTTPError(
            url="",
            code=404,
            msg="",
            hdrs=None,  # type: ignore
            fp=io.BytesIO(b"not found"),
        )
        resp = http_requests.get("http://example.com")
        assert resp.status_code == 404
        assert resp.text == "not found"

    @patch("aea.helpers.http_requests._opener.open")
    def test_url_error_raises_connection_error(self, mock_open: MagicMock) -> None:
        """Test URLError maps to ConnectionError."""
        mock_open.side_effect = urllib.error.URLError("Connection refused")
        with pytest.raises(http_requests.ConnectionError):
            http_requests.get("http://example.com")

    @patch("aea.helpers.http_requests._opener.open")
    def test_os_error_raises_connection_error(self, mock_open: MagicMock) -> None:
        """Test OSError maps to ConnectionError."""
        mock_open.side_effect = OSError("Network unreachable")
        with pytest.raises(http_requests.ConnectionError):
            http_requests.get("http://example.com")

    @patch("aea.helpers.http_requests._opener.open")
    def test_http_exception_raises_connection_error(self, mock_open: MagicMock) -> None:
        """Test http.client.HTTPException maps to ConnectionError."""
        mock_open.side_effect = http.client.IncompleteRead(b"partial")
        with pytest.raises(http_requests.ConnectionError):
            http_requests.get("http://example.com")

    @patch("aea.helpers.http_requests._opener.open")
    def test_http_error_safe_read_on_read_failure(self, mock_open: MagicMock) -> None:
        """Test that a failing e.read() inside HTTPError handler doesn't crash."""
        exc = urllib.error.HTTPError(
            url="",
            code=500,
            msg="",
            hdrs=None,  # type: ignore
            fp=io.BytesIO(b""),
        )
        exc.read = MagicMock(side_effect=OSError("read failed"))  # type: ignore[method-assign]
        mock_open.side_effect = exc
        resp = http_requests.get("http://example.com")
        assert resp.status_code == 500
        assert resp.content == b""


class TestSchemeValidation:
    """Tests for URL scheme validation."""

    def test_file_scheme_rejected(self) -> None:
        """Test file:// URLs are rejected."""
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            http_requests.get("file:///etc/passwd")

    def test_ftp_scheme_rejected(self) -> None:
        """Test ftp:// URLs are rejected."""
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            http_requests.get("ftp://example.com/file")

    @patch("aea.helpers.http_requests._opener.open")
    def test_http_scheme_allowed(self, mock_open: MagicMock) -> None:
        """Test http:// URLs are allowed."""
        mock_open.return_value = _mock_urlopen()
        resp = http_requests.get("http://example.com")
        assert resp.status_code == 200

    @patch("aea.helpers.http_requests._opener.open")
    def test_https_scheme_allowed(self, mock_open: MagicMock) -> None:
        """Test https:// URLs are allowed."""
        mock_open.return_value = _mock_urlopen()
        resp = http_requests.get("https://example.com")
        assert resp.status_code == 200


class TestRedirectBehaviour:
    """Tests for method-specific redirect handling (matches requests library)."""

    @patch("aea.helpers.http_requests._opener.open")
    def test_post_redirect_returned_as_response(self, mock_open: MagicMock) -> None:
        """POST 301/302 should NOT be followed, match requests default."""
        mock_open.side_effect = urllib.error.HTTPError(
            url="",
            code=301,
            msg="",
            hdrs=None,  # type: ignore
            fp=io.BytesIO(b"redirect"),
        )
        resp = http_requests.post("http://example.com/api")
        assert resp.status_code == 301

    def test_get_follows_redirect_via_conditional_handler(self) -> None:
        """GET requests should follow redirects (match requests default)."""
        handler = http_requests._ConditionalNoRedirectHandler()
        # Simulate a GET request receiving a 302 redirect
        req = urllib.request.Request("http://example.com/a", method="GET")
        result = handler.redirect_request(
            req,
            io.BytesIO(b""),
            302,
            "Found",
            {"location": "http://example.com/b"},
            "http://example.com/b",
        )
        # For GET, should return a new Request (to follow the redirect)
        assert result is not None
        assert isinstance(result, urllib.request.Request)

    def test_post_suppresses_redirect_via_conditional_handler(self) -> None:
        """POST requests should NOT follow redirects."""
        handler = http_requests._ConditionalNoRedirectHandler()
        req = urllib.request.Request("http://example.com/a", data=b"x", method="POST")
        result = handler.redirect_request(
            req,
            io.BytesIO(b""),
            302,
            "Found",
            {"location": "http://example.com/b"},
            "http://example.com/b",
        )
        assert result is None

    @pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
    def test_other_unsafe_methods_suppress_redirects(self, method: str) -> None:
        """PUT/DELETE/PATCH should not follow redirects either."""
        handler = http_requests._ConditionalNoRedirectHandler()
        req = urllib.request.Request("http://example.com/a", data=b"x", method=method)
        result = handler.redirect_request(
            req,
            io.BytesIO(b""),
            302,
            "Found",
            {"location": "http://example.com/b"},
            "http://example.com/b",
        )
        assert result is None


class TestBackwardsCompatShims:
    """Tests for backwards-compatible re-exports."""

    def test_response_alias(self) -> None:
        """Response is an alias for HTTPResponse."""
        assert http_requests.Response is http_requests.HTTPResponse

    def test_exceptions_connection_error(self) -> None:
        """exceptions.ConnectionError is our ConnectionError."""
        assert http_requests.exceptions.ConnectionError is http_requests.ConnectionError

    def test_exceptions_request_exception(self) -> None:
        """exceptions.RequestException maps to ConnectionError."""
        assert (
            http_requests.exceptions.RequestException is http_requests.ConnectionError
        )

    def test_json_decode_error(self) -> None:
        """Verify JSONDecodeError re-exports the stdlib one."""
        assert http_requests.JSONDecodeError is json.JSONDecodeError

    def test_head_function(self) -> None:
        """head() is a thin wrapper over request('HEAD', ...)."""
        assert callable(http_requests.head)

    @patch("aea.helpers.http_requests._opener.open")
    def test_head_makes_head_request(self, mock_open: MagicMock) -> None:
        """head() actually sends a HEAD request."""
        mock_open.return_value = _mock_urlopen(200, b"")
        http_requests.head("http://example.com")
        req = mock_open.call_args[0][0]
        assert req.get_method() == "HEAD"


class TestDownloadToFile:
    """Tests for download_to_file streaming helper."""

    @patch("aea.helpers.http_requests._opener.open")
    def test_streams_chunks_to_file(self, mock_open: MagicMock, tmp_path: Path) -> None:
        """Test response body is streamed to file in chunks."""
        # Mock urlopen with a response that returns chunks then EOF
        chunks = [b"chunk1", b"chunk2", b"chunk3", b""]
        resp = MagicMock()
        resp.status = 200
        resp.read = MagicMock(side_effect=chunks)
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = resp

        target = tmp_path / "out.bin"
        status = http_requests.download_to_file("http://example.com/file", str(target))
        assert status == 200
        assert target.read_bytes() == b"chunk1chunk2chunk3"

    @patch("aea.helpers.http_requests._opener.open")
    def test_http_error_returns_status(
        self, mock_open: MagicMock, tmp_path: Path
    ) -> None:
        """Test HTTP error returns status code without raising."""
        mock_open.side_effect = urllib.error.HTTPError(
            url="",
            code=404,
            msg="",
            hdrs=None,  # type: ignore
            fp=io.BytesIO(b""),
        )
        target = tmp_path / "out.bin"
        status = http_requests.download_to_file(
            "http://example.com/missing", str(target)
        )
        assert status == 404

    def test_rejects_non_http_scheme(self, tmp_path: Path) -> None:
        """Test non-http scheme is rejected."""
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            http_requests.download_to_file("file:///etc/passwd", str(tmp_path / "out"))

    @patch("aea.helpers.http_requests._opener.open")
    def test_url_error_raises(self, mock_open: MagicMock, tmp_path: Path) -> None:
        """Test URLError maps to ConnectionError."""
        mock_open.side_effect = urllib.error.URLError("refused")
        with pytest.raises(http_requests.ConnectionError):
            http_requests.download_to_file(
                "http://example.com/file", str(tmp_path / "out")
            )
