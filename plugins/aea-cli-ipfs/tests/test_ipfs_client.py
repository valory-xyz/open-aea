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

"""Tests for the inlined IPFS HTTP client."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from aea_cli_ipfs.ipfs_client import (
    CommunicationError,
    ErrorResponse,
    IPFSHTTPClient,
    StatusError,
    TimeoutError,
    _encode_bytes,
    _multipart_boundary,
    _quote_filename,
    _stream_directory,
)

# ---------------------------------------------------------------------------
# Multipart encoding tests
# ---------------------------------------------------------------------------


class TestMultipartEncoding:
    """Tests for multipart encoding functions."""

    def test_encode_bytes(self) -> None:
        """Test encoding bytes as multipart."""
        boundary = "test-boundary"
        body, content_type = _encode_bytes(b"hello world", boundary)
        assert b"hello world" in body
        assert b"--test-boundary" in body
        assert b"--test-boundary--" in body
        assert 'boundary="test-boundary"' in content_type

    def test_encode_single_file(self) -> None:
        """Test encoding a single file."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.txt"
            p.write_text("hello")
            boundary = "test-boundary"
            body = b"".join(_stream_directory(str(p), boundary))
            assert b"hello" in body
            assert b"test.txt" in body
            assert b"--test-boundary--" in body

    def test_encode_directory(self) -> None:
        """Test encoding a directory with files."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mydir"
            root.mkdir()
            (root / "a.txt").write_text("aaa")
            (root / "b.txt").write_text("bbb")
            sub = root / "sub"
            sub.mkdir()
            (sub / "c.txt").write_text("ccc")

            boundary = "test-boundary"
            body = b"".join(_stream_directory(str(root), boundary, recursive=True))

            assert b"aaa" in body
            assert b"bbb" in body
            assert b"ccc" in body
            assert b"mydir%2Fa.txt" in body
            assert b"mydir%2Fsub%2Fc.txt" in body
            # Directory markers
            assert b"application/x-directory" in body

    def test_boundary_uniqueness(self) -> None:
        """Test that boundaries are unique."""
        b1 = _multipart_boundary()
        b2 = _multipart_boundary()
        assert b1 != b2

    def test_filename_url_encoding(self) -> None:
        """Test that filenames with special chars are URL-encoded."""
        assert _quote_filename("simple.txt") == "simple.txt"
        assert _quote_filename("dir/file.txt") == "dir%2Ffile.txt"
        assert _quote_filename("has space.txt") == "has%20space.txt"
        assert _quote_filename("special&char=yes") == "special%26char%3Dyes"

    def test_encode_directory_non_recursive(self) -> None:
        """Test encoding directory with recursive=False skips subdirs."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mydir"
            root.mkdir()
            (root / "a.txt").write_text("aaa")
            sub = root / "sub"
            sub.mkdir()
            (sub / "b.txt").write_text("bbb")

            boundary = "test-boundary"
            body = b"".join(_stream_directory(str(root), boundary, recursive=False))
            assert b"aaa" in body
            assert b"bbb" not in body  # subdirectory content excluded


# ---------------------------------------------------------------------------
# Client construction
# ---------------------------------------------------------------------------


class TestClientConstruction:
    """Tests for IPFSHTTPClient construction."""

    def test_default_construction(self) -> None:
        """Test client builds correct base URL from multiaddr."""
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        assert "http://127.0.0.1:5001/api/v0" in client._base_url

    def test_https_construction(self) -> None:
        """Test client with HTTPS multiaddr."""
        client = IPFSHTTPClient("/dns/registry.autonolas.tech/tcp/443/https")
        assert "https://registry.autonolas.tech:443/api/v0" in client._base_url


# ---------------------------------------------------------------------------
# API methods (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_response(status_code=200, json_data=None, text="", content=b""):
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text or json.dumps(json_data or {})
    resp.content = content
    return resp


class TestId:
    """Tests for id() method."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_id(self, mock_post: MagicMock) -> None:
        """Test id returns node info."""
        mock_post.return_value = _mock_response(
            json_data={"ID": "Qm123", "AgentVersion": "go-ipfs/0.6.0"}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.id()
        assert result["ID"] == "Qm123"

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_id_connection_error(self, mock_post: MagicMock) -> None:
        """Test id raises CommunicationError on connection failure."""
        mock_post.side_effect = requests.exceptions.ConnectionError("refused")
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(CommunicationError):
            client.id()


class TestAdd:
    """Tests for add() and add_bytes() methods."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_bytes(self, mock_post: MagicMock) -> None:
        """Test add_bytes returns hash."""
        mock_post.return_value = _mock_response(
            json_data={"Hash": "QmTest123", "Name": "bytes"}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.add_bytes(b"test data")
        assert result == "QmTest123"

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_directory(self, mock_post: MagicMock) -> None:
        """Test add returns list of items."""
        ndjson = (
            '{"Name":"mydir/a.txt","Hash":"Qm1"}\n'
            '{"Name":"mydir","Hash":"Qm2"}\n'
            '{"Name":"","Hash":"QmWrapped"}\n'
        )
        mock_post.return_value = _mock_response(text=ndjson, status_code=200)
        mock_post.return_value.json.side_effect = ValueError("ndjson")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mydir"
            root.mkdir()
            (root / "a.txt").write_text("aaa")

            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            result = client.add(str(root))
            assert isinstance(result, list)
            assert len(result) == 3

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_single_file_returns_dict(self, mock_post: MagicMock) -> None:
        """Test add returns dict for single file (matches ipfshttpclient)."""
        ndjson = '{"Name":"test.txt","Hash":"QmSingle"}\n'
        mock_post.return_value = _mock_response(text=ndjson, status_code=200)
        mock_post.return_value.json.side_effect = ValueError("ndjson")

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.txt"
            p.write_text("hello")
            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            result = client.add(str(p))
            assert isinstance(result, dict)
            assert result["Hash"] == "QmSingle"

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_error_response(self, mock_post: MagicMock) -> None:
        """Test add raises ErrorResponse on IPFS error."""
        mock_post.return_value = _mock_response(
            status_code=500, json_data={"Message": "something broke"}
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mydir"
            root.mkdir()
            (root / "a.txt").write_text("aaa")

            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            with pytest.raises(ErrorResponse, match="something broke"):
                client.add(str(root))


class TestGet:
    """Tests for get() method."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_get_extracts_tar(self, mock_post: MagicMock) -> None:
        """Test get downloads and extracts tar archive."""
        import io
        import tarfile

        # Create a tar archive in memory
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            data = b"file contents"
            info = tarfile.TarInfo(name="QmTest/file.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_bytes = buf.getvalue()

        resp = _mock_response(status_code=200, content=tar_bytes)
        resp.raw = io.BytesIO(tar_bytes)
        resp.raw.decode_content = True
        mock_post.return_value = resp

        with tempfile.TemporaryDirectory() as tmp:
            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            client.get("QmTest", tmp)
            extracted = Path(tmp) / "QmTest" / "file.txt"
            assert extracted.read_bytes() == b"file contents"

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_get_status_error(self, mock_post: MagicMock) -> None:
        """Test get raises StatusError on bad status."""
        mock_post.return_value = _mock_response(status_code=504, text="timeout")
        mock_post.return_value.json.side_effect = ValueError("not json")
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(StatusError):
            client.get("QmBad", "/tmp")


class TestTimeout:
    """Tests for timeout handling."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_timeout(self, mock_post: MagicMock) -> None:
        """Test add raises TimeoutError on timeout."""
        mock_post.side_effect = requests.exceptions.Timeout("timed out")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "f.txt").write_text("x")
            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            with pytest.raises(TimeoutError):
                client.add(str(Path(tmp) / "f.txt"))

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_bytes_timeout(self, mock_post: MagicMock) -> None:
        """Test add_bytes raises TimeoutError on timeout."""
        mock_post.side_effect = requests.exceptions.Timeout("timed out")
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(TimeoutError):
            client.add_bytes(b"data")

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_get_timeout(self, mock_post: MagicMock) -> None:
        """Test get raises TimeoutError on timeout."""
        mock_post.side_effect = requests.exceptions.Timeout("timed out")
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(TimeoutError):
            client.get("QmBad", "/tmp")


class TestAddBytesErrorHandling:
    """Tests for add_bytes error handling."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_bytes_error_response(self, mock_post: MagicMock) -> None:
        """Test add_bytes raises ErrorResponse on IPFS error."""
        mock_post.return_value = _mock_response(
            status_code=500, json_data={"Message": "add failed"}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(ErrorResponse, match="add failed"):
            client.add_bytes(b"data")

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_add_bytes_missing_hash(self, mock_post: MagicMock) -> None:
        """Test add_bytes raises StatusError when Hash key missing."""
        mock_post.return_value = _mock_response(
            status_code=200, json_data={"Name": "bytes"}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(StatusError, match="missing.*Hash"):
            client.add_bytes(b"data")


class TestTarSafety:
    """Tests for tar extraction safety."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_path_traversal_filtered(self, mock_post: MagicMock) -> None:
        """Test that tar members with path traversal are filtered out."""
        import io as _io
        import tarfile as _tarfile

        buf = _io.BytesIO()
        with _tarfile.open(fileobj=buf, mode="w") as tar:
            # Safe member
            safe_data = b"safe content"
            safe_info = _tarfile.TarInfo(name="QmTest/safe.txt")
            safe_info.size = len(safe_data)
            tar.addfile(safe_info, _io.BytesIO(safe_data))
            # Malicious member with path traversal
            bad_data = b"malicious"
            bad_info = _tarfile.TarInfo(name="../../../etc/passwd")
            bad_info.size = len(bad_data)
            tar.addfile(bad_info, _io.BytesIO(bad_data))
        tar_bytes = buf.getvalue()

        resp = _mock_response(status_code=200, content=tar_bytes)
        resp.raw = _io.BytesIO(tar_bytes)
        resp.raw.decode_content = True
        mock_post.return_value = resp

        with tempfile.TemporaryDirectory() as tmp:
            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            client.get("QmTest", tmp)
            # Safe file extracted
            assert (Path(tmp) / "QmTest" / "safe.txt").read_bytes() == b"safe content"
            # Only the safe file was extracted — no other files in the temp dir
            all_files = list(Path(tmp).rglob("*"))
            assert sorted(str(f.relative_to(tmp)) for f in all_files) == [
                "QmTest",
                str(Path("QmTest") / "safe.txt"),
            ]


class TestEmptyDirAdd:
    """Tests for empty directory add handling."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_empty_dir_returns_dict(self, mock_post: MagicMock) -> None:
        """Test add with empty dir (single IPFS response item) returns correctly."""
        ndjson = '{"Name":"emptydir","Hash":"QmEmpty"}\n'
        mock_post.return_value = _mock_response(text=ndjson, status_code=200)
        mock_post.return_value.json.side_effect = ValueError("ndjson")

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "emptydir"
            d.mkdir()
            client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
            result = client.add(str(d))
            # Single item -> dict
            assert isinstance(result, dict)
            assert result["Hash"] == "QmEmpty"


class TestPin:
    """Tests for pin operations."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_pin_ls(self, mock_post: MagicMock) -> None:
        """Test pin.ls returns pinned keys."""
        mock_post.return_value = _mock_response(
            json_data={"Keys": {"Qm1": {"Type": "recursive"}}}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.pin.ls(type="recursive")
        assert "Qm1" in result["Keys"]

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_pin_add(self, mock_post: MagicMock) -> None:
        """Test pin.add."""
        mock_post.return_value = _mock_response(json_data={"Pins": ["Qm1"]})
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.pin.add("Qm1")
        assert "Qm1" in result["Pins"]

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_pin_rm(self, mock_post: MagicMock) -> None:
        """Test pin.rm."""
        mock_post.return_value = _mock_response(json_data={"Pins": ["Qm1"]})
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.pin.rm("Qm1")
        assert "Qm1" in result["Pins"]

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_pin_add_error(self, mock_post: MagicMock) -> None:
        """Test pin.add raises ErrorResponse."""
        mock_post.return_value = _mock_response(
            status_code=500, json_data={"Message": "pin error"}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        with pytest.raises(ErrorResponse):
            client.pin.add("QmBad")


class TestNamePublish:
    """Tests for name.publish."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_publish(self, mock_post: MagicMock) -> None:
        """Test name.publish."""
        mock_post.return_value = _mock_response(
            json_data={"Name": "Qm123", "Value": "/ipfs/QmHash"}
        )
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.name.publish("/ipfs/QmHash")
        assert result["Value"] == "/ipfs/QmHash"


class TestRepoGc:
    """Tests for repo.gc."""

    @patch("aea_cli_ipfs.ipfs_client.requests.post")
    def test_gc(self, mock_post: MagicMock) -> None:
        """Test repo.gc returns list of removed objects."""
        ndjson = '{"Key":"Qm1"}\n{"Key":"Qm2"}\n'
        resp = _mock_response(status_code=200, text=ndjson)
        resp.json.side_effect = ValueError("ndjson")
        mock_post.return_value = resp
        client = IPFSHTTPClient("/ip4/127.0.0.1/tcp/5001")
        result = client.repo.gc()
        assert len(result) == 2
