# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2026 Valory AG
#   Copyright 2018-2019 Fetch.AI Limited
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

"""
Minimal HTTP helpers backed by :mod:`urllib` from the standard library.

Replaces the ``requests`` package for the few HTTP calls the core
framework needs (registry API, package downloads, GitHub tag fetches).
"""

import http.client
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from json import loads as json_loads
from typing import Any, Dict, Optional, Tuple, Union

from aea.helpers.constants import NETWORK_REQUEST_DEFAULT_TIMEOUT

DEFAULT_TIMEOUT = NETWORK_REQUEST_DEFAULT_TIMEOUT
_ALLOWED_SCHEMES = ("http", "https")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirect following to match requests behaviour."""

    def redirect_request(  # pylint: disable=too-many-positional-arguments
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        """Disable redirects.

        :param req: the original request.
        :param fp: the response file-like object.
        :param code: HTTP status code.
        :param msg: HTTP status message.
        :param headers: response headers.
        :param newurl: the redirect target URL.
        :return: None (suppresses redirect).
        """
        return None  # type: ignore[return-value]


_opener = urllib.request.build_opener(_NoRedirectHandler)


class HTTPResponse:
    """Lightweight response wrapper matching the subset of requests.Response used in aea."""

    def __init__(self, status_code: int, data: bytes, url: str = "") -> None:
        """Initialize HTTPResponse.

        :param status_code: HTTP status code.
        :param data: response body bytes.
        :param url: request URL.
        """
        self.status_code = status_code
        self._data = data
        self.url = url

    @property
    def text(self) -> str:
        """Response body as string."""
        return self._data.decode("utf-8", errors="replace")

    @property
    def content(self) -> bytes:
        """Response body as bytes."""
        return self._data

    def json(self) -> Any:
        """Parse response body as JSON."""
        return json_loads(self._data)

    def read(self) -> bytes:
        """Read response body (for compatibility with file-like usage)."""
        return self._data


class ConnectionError(OSError):  # noqa: A001  # pylint: disable=redefined-builtin
    """HTTP connection error."""


def _safe_read(exc: urllib.error.HTTPError) -> bytes:
    """Read error body, returning empty bytes on failure.

    :param exc: the HTTPError to read from.
    :return: body bytes.
    """
    try:
        return exc.read()
    except Exception:  # pylint: disable=broad-except
        return b""


def request(  # pylint: disable=too-many-positional-arguments
    method: str,
    url: str,
    params: Optional[Dict[str, str]] = None,
    data: Optional[Union[bytes, Dict[str, str]]] = None,
    headers: Optional[Dict[str, str]] = None,
    files: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> HTTPResponse:
    """
    Perform an HTTP request using urllib.

    :param method: HTTP method (GET, POST, PUT, etc.).
    :param url: the URL.
    :param params: optional query parameters.
    :param data: optional body data (bytes or dict for form-encoded).
    :param headers: optional headers dict.
    :param files: optional dict of {field: file_obj} for multipart upload.
    :param timeout: request timeout in seconds.
    :return: HTTPResponse.
    :raises ValueError: if the URL scheme is not http or https.
    :raises ConnectionError: on connection failure.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")

    if params:
        sep = "&" if parsed.query else "?"
        url = url + sep + urllib.parse.urlencode(params)

    headers = dict(headers) if headers else {}
    body: Optional[bytes] = None

    if files:
        fields = data if isinstance(data, dict) else {}
        body, content_type = _encode_multipart(fields, files)
        headers["Content-Type"] = content_type
    elif isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, bytes):
        body = data

    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())

    try:
        with _opener.open(req, timeout=timeout) as resp:  # nosec
            return HTTPResponse(resp.status, resp.read(), url=resp.url)
    except urllib.error.HTTPError as e:
        return HTTPResponse(e.code, _safe_read(e), url=url)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise ConnectionError(str(e)) from e


def get(url: str, timeout: float = DEFAULT_TIMEOUT, **kwargs: Any) -> HTTPResponse:
    """HTTP GET.

    :param url: the URL.
    :param timeout: request timeout in seconds.
    :param kwargs: additional keyword arguments passed to request().
    :return: HTTPResponse.
    """
    return request("GET", url, timeout=timeout, **kwargs)


def post(url: str, timeout: float = DEFAULT_TIMEOUT, **kwargs: Any) -> HTTPResponse:
    """HTTP POST.

    :param url: the URL.
    :param timeout: request timeout in seconds.
    :param kwargs: additional keyword arguments passed to request().
    :return: HTTPResponse.
    """
    return request("POST", url, timeout=timeout, **kwargs)


def _encode_multipart(
    fields: Dict[str, str], files: Dict[str, Any]
) -> Tuple[bytes, str]:
    """
    Encode multipart/form-data body for file uploads.

    :param fields: form field key-value pairs.
    :param files: dict of {field_name: file_obj} for multipart upload.
    :return: tuple of (body_bytes, content_type).
    """
    boundary = uuid.uuid4().hex
    parts: list = []

    for key, value in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        parts.append(f"{value}\r\n".encode())

    for field_name, file_obj in files.items():
        filename = os.path.basename(getattr(file_obj, "name", field_name))
        file_data = file_obj.read()
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\n'.encode()
        )
        parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
        parts.append(file_data)
        parts.append(b"\r\n")

    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type
