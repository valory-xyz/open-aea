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

# pylint: disable=protected-access,unused-argument,redefined-builtin,too-many-positional-arguments,import-outside-toplevel,cyclic-import

"""
Lightweight IPFS HTTP API client.

Replaces the ``ipfshttpclient`` package. Talks directly to the IPFS
daemon's HTTP API (``/api/v0/*``) using ``urllib``.
"""

import http.client
import json
import mimetypes
import os
import socket
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Exceptions (mirrors ipfshttpclient.exceptions hierarchy)
# ---------------------------------------------------------------------------


class IPFSError(Exception):
    """Base IPFS client error."""


class CommunicationError(IPFSError):
    """Could not communicate with the IPFS daemon."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize, accepting optional ``original`` for compat."""
        kwargs.pop("original", None)
        super().__init__(*args, **kwargs)


class TimeoutError(CommunicationError):  # noqa: A001
    """Request to the IPFS daemon timed out."""


class StatusError(CommunicationError):
    """IPFS daemon returned an unexpected HTTP status."""


class ErrorResponse(StatusError):
    """IPFS daemon returned a JSON error message."""


# ---------------------------------------------------------------------------
# Multipart encoding for the IPFS /api/v0/add endpoint
# ---------------------------------------------------------------------------


def _multipart_boundary() -> str:
    """Generate a random multipart boundary."""
    return uuid.uuid4().hex


def _quote_filename(filename: str) -> str:
    """URL-encode a filename for use in Content-Disposition headers."""
    return urllib.parse.quote(filename, safe="")


def _guess_content_type(filename: str) -> str:
    """Guess MIME type for a filename, defaulting to application/octet-stream."""
    ctype, _ = mimetypes.guess_type(filename)
    return ctype or "application/octet-stream"


def _multipart_file_header(
    boundary: str,
    field_name: str,
    filename: str,
    content_type: str = "application/octet-stream",
    abspath: Optional[str] = None,
) -> bytes:
    """Encode the header portion of a file part (before the data)."""
    quoted = _quote_filename(filename)
    # Headers sorted alphabetically to match ipfshttpclient behavior
    header = f"--{boundary}\r\n"
    if abspath:
        header += f"Abspath: {abspath}\r\n"
    header += (
        f'Content-Disposition: form-data; name="{field_name}"; filename="{quoted}"\r\n'
        f"Content-Type: {content_type}\r\n"
        f"\r\n"
    )
    return header.encode()


def _multipart_file_part(
    boundary: str,
    field_name: str,
    filename: str,
    data: bytes,
    content_type: str = "application/octet-stream",
    abspath: Optional[str] = None,
) -> bytes:
    """Encode a single file part in multipart form-data (header + data)."""
    return (
        _multipart_file_header(boundary, field_name, filename, content_type, abspath)
        + data
        + b"\r\n"
    )


def _multipart_dir_part(boundary: str, dirname: str) -> bytes:
    """Encode a directory marker in multipart form-data."""
    quoted = _quote_filename(dirname)
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{quoted}"\r\n'
        f"Content-Type: application/x-directory\r\n"
        f"\r\n"
    )
    return header.encode() + b"\r\n"


def _multipart_end(boundary: str) -> bytes:
    """Encode the multipart terminator."""
    return f"--{boundary}--\r\n".encode()


def _stream_directory(
    dir_path: str,
    boundary: str,
    recursive: bool = True,
) -> Generator[bytes, None, None]:
    """
    Yield multipart form-data chunks for IPFS /api/v0/add.

    Streams file contents in 256KB chunks to avoid loading entire
    directories into memory.

    :param dir_path: path to directory or file.
    :param boundary: multipart boundary string.
    :param recursive: include subdirectories.
    :yield: bytes chunks of multipart body.
    """
    root = Path(dir_path)
    base_name = root.name

    # Use os.path.abspath (not Path.resolve) to avoid macOS /private prefix
    abs_root = os.path.abspath(root)

    if root.is_file():
        ctype = _guess_content_type(base_name)
        yield _multipart_file_header(boundary, "file", base_name, ctype, abs_root)
        with open(root, "rb") as f:
            while True:
                chunk = f.read(262144)  # 256KB chunks
                if not chunk:
                    break
                yield chunk
        yield b"\r\n"
    else:
        # Walk directory, emitting subdirs before files at each level
        # to match ipfshttpclient's filescanner ordering
        for dirpath_str, dirnames, filenames in os.walk(root):
            dirpath = Path(dirpath_str)
            rel = dirpath.relative_to(root)
            dir_label = str(Path(base_name) / rel).replace(os.sep, "/")

            yield _multipart_dir_part(boundary, dir_label)

            if not recursive:
                dirnames.clear()
            else:
                dirnames.sort()

            for fname in sorted(filenames):
                fpath = dirpath / fname
                file_label = str(Path(base_name) / rel / fname).replace(os.sep, "/")
                abs_file = os.path.normpath(os.path.join(abs_root, str(rel), fname))
                ctype = _guess_content_type(fname)
                yield _multipart_file_header(
                    boundary, "file", file_label, ctype, abs_file
                )
                with open(fpath, "rb") as f:
                    while True:
                        chunk = f.read(262144)  # 256KB chunks
                        if not chunk:
                            break
                        yield chunk
                yield b"\r\n"

    yield _multipart_end(boundary)


def _encode_bytes(data: bytes, boundary: str) -> Tuple[bytes, str]:
    """Encode bytes as multipart form-data for IPFS /api/v0/add."""
    parts = [
        _multipart_file_part(boundary, "file", "bytes", data),
        _multipart_end(boundary),
    ]
    body = b"".join(parts)
    content_type = f'multipart/form-data; boundary="{boundary}"'
    return body, content_type


# ---------------------------------------------------------------------------
# Subsections: pin, name, repo
# ---------------------------------------------------------------------------


class _PinSection:
    """Pin management commands."""

    def __init__(self, client: "IPFSHTTPClient") -> None:
        self._client = client

    def ls(self, type: str = "all") -> Dict:  # noqa: A002
        """List pinned objects."""
        return self._client._api_post("/pin/ls", params={"type": type})

    def add(self, cid: str, recursive: bool = True) -> Dict:
        """Pin an object."""
        return self._client._api_post(
            "/pin/add", params={"arg": cid, "recursive": str(recursive).lower()}
        )

    def rm(self, cid: str, recursive: bool = True) -> Dict:
        """Unpin an object."""
        return self._client._api_post(
            "/pin/rm", params={"arg": cid, "recursive": str(recursive).lower()}
        )


class _NameSection:
    """IPNS name commands."""

    def __init__(self, client: "IPFSHTTPClient") -> None:
        self._client = client

    def publish(self, ipfs_path: str, **kwargs: Any) -> Dict:
        """Publish an IPNS name."""
        params: Dict[str, str] = {"arg": ipfs_path}
        params["resolve"] = str(kwargs.get("resolve", True)).lower()
        params["lifetime"] = str(kwargs.get("lifetime", "24h"))
        if kwargs.get("allow_offline"):
            params["allow-offline"] = "true"
        return self._client._api_post("/name/publish", params=params)


class _RepoSection:
    """Repository commands."""

    def __init__(self, client: "IPFSHTTPClient") -> None:
        self._client = client

    def gc(self, quiet: bool = False) -> List[Dict]:
        """Run garbage collection."""
        resp = self._client._api_post(
            "/repo/gc", params={"quiet": str(quiet).lower()}, stream=True
        )
        # /repo/gc returns newline-delimited JSON
        if isinstance(resp, list):
            return resp
        return [resp]


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------


class IPFSHTTPClient:
    """
    Lightweight IPFS HTTP API client.

    Replaces ``ipfshttpclient.Client``. Communicates with the IPFS daemon
    via its HTTP API at ``/api/v0/*``.
    """

    def __init__(self, addr: str, base: str = "api/v0") -> None:
        """
        Initialize client.

        :param addr: multiaddr string (e.g. ``/dns/host/tcp/443/https``).
        :param base: API base path.
        """
        from aea_cli_ipfs.ipfs_utils import addr_to_url

        self._base_url = addr_to_url(addr).rstrip("/") + "/" + base.strip("/")
        self._timeout = 120

        # Subsections
        self.pin = _PinSection(self)
        self.name = _NameSection(self)
        self.repo = _RepoSection(self)

    def _post(
        self,
        endpoint: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[bytes, Iterable[bytes]]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, bytes]:
        """
        POST to the IPFS API and return (status_code, body_bytes).

        :param endpoint: API endpoint path.
        :param params: optional query parameters.
        :param data: optional request body. Either bytes (sent with
            Content-Length) or an iterable of bytes (sent with chunked
            Transfer-Encoding for streaming uploads).
        :param headers: optional headers.
        :return: tuple of (status_code, body_bytes).
        :raises CommunicationError: on connection failure.
        :raises TimeoutError: on timeout.
        """
        url = self._base_url + endpoint
        if params:
            url = url + "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(
            url,
            data=data if data is not None else b"",
            headers=headers or {},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:  # pylint: disable=broad-except
                body = b""
            return e.code, body
        except socket.timeout as e:
            raise TimeoutError(str(e)) from e
        except urllib.error.URLError as e:
            if "timed out" in str(e):
                raise TimeoutError(str(e)) from e
            raise CommunicationError(str(e)) from e
        except (http.client.HTTPException, OSError) as e:
            raise CommunicationError(str(e)) from e

    def _api_post(
        self,
        endpoint: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        stream: bool = False,
    ) -> Any:
        """Make a POST request to the IPFS API, parse JSON response."""
        status, body = self._post(endpoint, params=params, data=data, headers=headers)
        text = body.decode("utf-8", errors="replace")

        if status != 200:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict) and "Message" in parsed:
                    raise ErrorResponse(parsed["Message"])
            except (ValueError, KeyError):
                pass
            raise StatusError(f"IPFS API returned status {status}: {text}")

        if stream:
            results = []
            for line in text.strip().split("\n"):
                line = line.strip()
                if line:
                    results.append(json.loads(line))
            return results

        return json.loads(body)

    def id(self, peer: Optional[str] = None) -> Dict:
        """Get node identity info."""
        params: Dict[str, str] = {}
        if peer is not None:
            params["arg"] = peer
        return self._api_post("/id", params=params or None)

    def add(
        self,
        file_or_dir: str,
        pin: bool = True,
        recursive: bool = True,
        wrap_with_directory: bool = True,
    ) -> Union[Dict, List[Dict]]:
        """
        Add file or directory to IPFS.

        :param file_or_dir: path to file or directory.
        :param pin: whether to pin the content.
        :param recursive: whether to add recursively.
        :param wrap_with_directory: whether to wrap with directory.
        :return: list of dicts with 'Name' and 'Hash' keys.
        """
        boundary = _multipart_boundary()
        content_type = f'multipart/form-data; boundary="{boundary}"'
        body_stream = _stream_directory(
            file_or_dir,
            boundary,
            recursive=recursive,
        )
        params = {
            "pin": str(pin).lower(),
            "recursive": str(recursive).lower(),
            "wrap-with-directory": str(wrap_with_directory).lower(),
        }
        status, resp_body = self._post(
            "/add",
            params=params,
            data=body_stream,
            headers={"Content-Type": content_type},
        )
        text = resp_body.decode("utf-8", errors="replace")

        if status != 200:
            try:
                err = json.loads(resp_body)
                if isinstance(err, dict) and "Message" in err:
                    raise ErrorResponse(err["Message"])
            except (ValueError, KeyError):
                pass
            raise StatusError(f"IPFS API returned status {status}: {text}")

        # /add returns newline-delimited JSON
        results = []
        for line in text.strip().split("\n"):
            line = line.strip()
            if line:
                results.append(json.loads(line))

        # Match ipfshttpclient behavior: single-item result returns a dict,
        # multi-item result returns a list
        if len(results) == 1:
            return results[0]
        return results

    def add_bytes(self, data: bytes, **kwargs: Any) -> str:
        """
        Add bytes to IPFS.

        :param data: bytes to add.
        :param kwargs: additional keyword arguments.
        :return: hash string.
        """
        boundary = _multipart_boundary()
        body, content_type = _encode_bytes(data, boundary)
        status, resp_body = self._post(
            "/add", data=body, headers={"Content-Type": content_type}
        )

        if status != 200:
            text = resp_body.decode("utf-8", errors="replace")
            try:
                err = json.loads(resp_body)
                if isinstance(err, dict) and "Message" in err:
                    raise ErrorResponse(err["Message"])
            except (ValueError, KeyError):
                pass
            raise StatusError(f"IPFS API returned status {status}: {text}")
        result = json.loads(resp_body)
        if "Hash" not in result:
            raise StatusError(f"IPFS API response missing 'Hash' key: {result}")
        return result["Hash"]

    def get(self, cid: str, target: str = ".") -> None:
        """
        Download a file or directory from IPFS.

        The IPFS ``/api/v0/get`` endpoint returns a tar archive.

        :param cid: IPFS CID to download.
        :param target: local directory to extract into.
        """
        url = (
            self._base_url
            + "/get?"
            + urllib.parse.urlencode(
                {"arg": cid, "archive": "true", "compress": "false"}
            )
        )
        req = urllib.request.Request(url, data=b"", method="POST")

        try:
            resp = urllib.request.urlopen(req, timeout=self._timeout)  # nosec
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:  # pylint: disable=broad-except
                body = b""
            try:
                err = json.loads(body)
                if isinstance(err, dict) and "Message" in err:
                    raise ErrorResponse(err["Message"])
            except (ValueError, KeyError):
                pass
            raise StatusError(f"IPFS API returned status {e.code}") from e
        except socket.timeout as e:
            raise TimeoutError(str(e)) from e
        except urllib.error.URLError as e:
            if "timed out" in str(e):
                raise TimeoutError(str(e)) from e
            raise CommunicationError(str(e)) from e
        except (http.client.HTTPException, OSError) as e:
            raise CommunicationError(str(e)) from e

        if resp.status != 200:
            raise StatusError(f"IPFS API returned status {resp.status}")

        # Stream tar extraction with path traversal prevention (CVE-2007-4559)
        abs_target = os.path.abspath(target)
        with tarfile.open(fileobj=resp, mode="r|") as tar:
            for member in tar:
                member_path = os.path.normpath(member.name)
                if member_path.startswith("/") or ".." in member_path.split(os.sep):
                    continue
                full_path = os.path.normpath(os.path.join(abs_target, member_path))
                if not full_path.startswith(abs_target):
                    continue
                # filter="data" is the safe default on 3.14+; explicit
                # here to silence the DeprecationWarning on 3.12/3.13.
                tar.extract(
                    member, path=target, set_attrs=False, filter="data"
                )  # nosec
