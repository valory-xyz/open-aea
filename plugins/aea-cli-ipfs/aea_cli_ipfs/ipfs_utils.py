# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2025 Valory AG
#   Copyright 2018-2020 Fetch.AI Limited
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
"""Ipfs utils for `ipfs cli command`."""

import logging
import os
import shutil
import signal
import subprocess  # nosec
import tempfile
import time
from pathlib import Path
from typing import Dict, IO, List, Optional, Set, Tuple, Union, cast

import ipfshttpclient  # type: ignore
import requests
from aea_cli_ipfs.exceptions import (
    DownloadError,
    NodeError,
    PinError,
    PublishError,
    RemoveError,
)


DEFAULT_IPFS_URI_BASE = str(os.environ.get("OPEN_AEA_IPFS_ADDR_BASE", "api/v0"))
DEFAULT_IPFS_URL = "/dns/registry.autonolas.tech/tcp/443/https"
DEFAULT_IPFS_URL_LOCAL = "/ip4/127.0.0.1/tcp/5001"
ALLOWED_CONNECTION_TYPES = ("tcp",)
ALLOWED_ADDR_TYPES = ("ip4", "dns")
ALLOWED_PROTOCOL_TYPES = ("http", "https")
MULTIADDR_FORMAT = "/{dns,dns4,dns6,ip4}/<host>/tcp/<port>/protocol"
IPFS_NODE_CHECK_ENDPOINT = "/api/v0/id"
IPFS_VERSION = "0.6.0"


def _verify_attr(name: str, attr: str, allowed: Tuple[str, ...]) -> None:
    """Varify various attributes of ipfs address."""

    if attr not in allowed:
        raise ValueError(f"{name} should be one of the {allowed}, provided: {attr}")


def resolve_addr(addr: str) -> Tuple[str, ...]:
    """
    Multiaddr resolver.

    :param addr: multiaddr string.
    :return: http URL
    """
    _, addr_scheme, host, conn_type, *extra_data = addr.split("/")

    if len(extra_data) > 2:  # pylint: disable=no-else-raise
        raise ValueError(
            f"Invalid multiaddr string provided, valid format: {MULTIADDR_FORMAT}. Provided: {addr}"
        )
    elif len(extra_data) == 2:
        port, protocol, *_ = extra_data
    elif len(extra_data) == 1:
        (port,) = extra_data
        protocol = "http"
    else:
        port = "5001"
        protocol = "http"

    _verify_attr("Address type", addr_scheme, ALLOWED_ADDR_TYPES)
    _verify_attr("Connection", conn_type, ALLOWED_CONNECTION_TYPES)
    _verify_attr("Protocol", protocol, ALLOWED_PROTOCOL_TYPES)

    return addr_scheme, host, conn_type, port, protocol


def addr_to_url(addr: str) -> str:
    """Convert address to url."""

    _, host, _, port, protocol = resolve_addr(addr)
    return f"{protocol}://{host}:{port}"


def is_remote_addr(host: str) -> bool:
    """Check if addr is remote or local."""
    return host not in ("localhost", "127.0.0.1", "0.0.0.0")  # nosec


class IPFSDaemon:
    """
    Set up the IPFS daemon.

    :raises Exception: if IPFS is not installed.
    """

    api_url: str
    node_url: str
    is_remote: bool
    process: Optional[subprocess.Popen]

    def __init__(
        self, node_url: str = "http://127.0.0.1:5001", is_remote: bool = False
    ):
        """Initialise IPFS daemon."""

        if node_url.endswith("/"):
            node_url = node_url[:-1]

        self.node_url = node_url
        self.api_url = node_url + IPFS_NODE_CHECK_ENDPOINT
        self.process = None
        self.is_remote = is_remote

        if not is_remote:
            self._check_ipfs()

    @staticmethod
    def _check_ipfs() -> None:
        """Check if IPFS node is running."""
        res = shutil.which("ipfs")
        if res is None:
            raise RuntimeError("Please install IPFS first!")
        process = subprocess.Popen(  # nosec
            ["ipfs", "--version"],
            stdout=subprocess.PIPE,
            env=os.environ.copy(),
        )
        output, _ = process.communicate()
        if b"0.6.0" not in output:
            raise RuntimeError(
                "Please ensure you have version 0.6.0 of IPFS daemon installed."
            )

    def is_started_externally(self) -> bool:
        """Check daemon was started externally."""
        try:
            x = requests.post(self.api_url, timeout=30)
            return x.status_code == 200
        except requests.exceptions.ConnectionError:
            return False

    def is_started_internally(self) -> bool:
        """Check daemon was started internally."""
        return bool(self.process)

    def is_started(self) -> bool:
        """Check daemon was started."""
        return self.is_started_externally() or self.is_started_internally()

    def start(self) -> None:
        """Run the ipfs daemon."""
        cmd = ["ipfs", "daemon", "--offline"]
        self.process = subprocess.Popen(  # nosec
            cmd,
            stdout=subprocess.PIPE,
            env=os.environ.copy(),
        )
        empty_outputs = 0

        if self.process.stdout is None:
            raise RuntimeError("Could not start IPFS daemon.")

        for stdout_line in iter(cast(IO[bytes], self.process.stdout).readline, ""):
            if b"Daemon is ready" in stdout_line:
                break
            if stdout_line == b"":
                empty_outputs += 1
                if empty_outputs >= 5:
                    raise RuntimeError("Could not start IPFS daemon.")

    def stop(self) -> None:  # pragma: nocover
        """Terminate the ipfs daemon if it was started internally."""
        if self.process is None:
            return

        if self.process.stdout is not None:
            self.process.stdout.close()

        self.process.send_signal(signal.SIGTERM)
        self.process.wait(timeout=30)
        poll = self.process.poll()
        if poll is None:
            self.process.terminate()
            self.process.wait(2)
        self.process = None

    def __enter__(self) -> None:
        """Run the ipfs daemon."""
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore
        """Terminate the ipfs daemon."""
        self.stop()


class IPFSTool:
    """IPFS tool to add, publish, remove, download directories."""

    _addr: Optional[str] = None

    def __init__(
        self,
        addr: Optional[str] = None,
        base: str = DEFAULT_IPFS_URI_BASE,
    ):
        """
        Init tool.

        :param addr: multiaddr string for IPFS client.
        :param base: API base for IPFS client.
        """

        if addr is None:
            addr = os.environ.get("OPEN_AEA_IPFS_ADDR", DEFAULT_IPFS_URL)

        _, host, *_ = resolve_addr(cast(str, addr))  # verify addr

        self._addr = addr
        self.is_remote = is_remote_addr(host)
        self.client = ipfshttpclient.Client(addr=self.addr, base=base)
        self.daemon = IPFSDaemon(
            node_url=addr_to_url(self.addr), is_remote=self.is_remote
        )

    @property
    def addr(
        self,
    ) -> str:
        """Node address"""
        return cast(str, self._addr)

    def is_a_package(self, package_hash: str) -> bool:
        """Checks if a package with `package_hash` is pinned or not"""
        return package_hash in self.all_pins()

    def all_pins(self, recursive_only: bool = True) -> Set[str]:
        """Returns a list of all pins."""
        pinned_hashes = self.client.pin.ls(
            type="recursive" if recursive_only else "all"
        )
        return set(pinned_hashes["Keys"])

    def add_bytes(self, data: bytes, **kwargs) -> str:
        """
        Add bytes data to ipfs.

        :param data: bytes
        :param kwargs: options passed to request library

        :return: hash
        """
        response = self.client.add_bytes(data, **kwargs)
        return response

    def add(
        self,
        dir_path: str,
        pin: bool = True,
        recursive: bool = True,
        wrap_with_directory: bool = True,
    ) -> Tuple[str, str, List]:
        """
        Add directory to ipfs.

        It wraps into directory.

        :param dir_path: str, path to dir to publish
        :param pin: bool, pin object or not
        :param recursive: bool, publish dierctory recursively or not
        :param wrap_with_directory: bool, wrap object with directory or not

        :return: dir name published, hash, list of items processed
        """
        response = self.client.add(
            dir_path,
            pin=pin,
            recursive=recursive,
            wrap_with_directory=wrap_with_directory,
        )
        if wrap_with_directory:
            return response[-2]["Name"], response[-1]["Hash"], response[:-1]

        if Path(dir_path).is_dir():
            return response[-1]["Name"], response[-1]["Hash"], response[:-1]

        return response["Name"], response["Hash"], []

    def pin(self, hash_id: str) -> Dict:
        """Pin content with hash_id"""

        try:
            return self.client.pin.add(hash_id, recursive=True)
        except ipfshttpclient.exceptions.ErrorResponse as e:
            raise PinError(f"Error on while pinning {hash_id}: {str(e)}") from e

    def remove(self, hash_id: str) -> Dict:
        """
        Remove dir added by it's hash.

        :param hash_id: str. hash of dir to remove

        :return: dict with unlinked items.
        """
        try:
            return self.client.pin.rm(hash_id, recursive=True)
        except ipfshttpclient.exceptions.ErrorResponse as e:
            raise RemoveError(f"Error on {hash_id} remove: {str(e)}") from e

    def remove_unpinned_files(self) -> None:
        """Remove dir added by it's hash."""
        try:
            return self.client.repo.gc()
        except ipfshttpclient.exceptions.ErrorResponse as e:
            raise RemoveError(
                f"Error while performing garbage collection: {str(e)}"
            ) from e

    def download(
        self,
        hash_id: str,
        target_dir: Union[str, Path],
        fix_path: bool = True,
        attempts: int = 5,
    ) -> str:
        """
        Download dir by its hash.

        :param hash_id: str. hash of file or package to download
        :param target_dir: Union[str, Path]. directory to place downloaded
        :param fix_path: bool. default True. on download don't wrap result in to hash_id directory.
        :param attempts: int. default 5. How often to attempt the download.
        :return: downloaded path
        """

        def move_to_target_dir(download_tmp_path: Path) -> str:
            """Move downloaded content to target directory"""
            if download_tmp_path.is_file():
                # Downloaded object is a file and can be moved easily
                shutil.move(str(download_tmp_path), str(target_dir))
                return str(target_dir)

            if fix_path:
                # identify name of package
                paths = list(download_tmp_path.glob("*"))
                if len(paths) == 1:
                    (package_path,) = paths
                else:
                    package_path = download_tmp_path

                # move content of directory with hashid to target dir
                shutil.move(str(package_path), str(target_dir))
                return str(Path(target_dir, package_path.name))

            # move directory with hash id to target dir
            shutil.move(str(download_tmp_path), str(target_dir))
            return str(Path(target_dir, download_tmp_path.name))

        target_dir = Path(target_dir)
        target_dir.mkdir(exist_ok=True, parents=True)

        while attempts:
            attempts -= 1
            try:  # download to tmp_dir in case of midway download failure
                with tempfile.TemporaryDirectory() as tmp_dir:
                    self.client.get(hash_id, tmp_dir)
                    return move_to_target_dir(Path(tmp_dir) / hash_id)
            except ipfshttpclient.exceptions.StatusError as e:
                logging.error(f"error on download of {hash_id}: {e}")
                time.sleep(1)

        raise DownloadError(f"Failed to download: {hash_id}")

    def publish(self, hash_id: str) -> Dict:
        """
        Publish directory by it's hash id.

        :param hash_id: hash of the directory to publish.

        :return: dict of names it was publish for.
        """
        try:
            return self.client.name.publish(hash_id)
        except ipfshttpclient.exceptions.TimeoutError as e:  # pragma: nocover
            raise PublishError(
                "can not publish within timeout, check internet connection!"
            ) from e

    def check_ipfs_node_running(self) -> None:
        """Check ipfs node running."""
        try:
            self.client.id()
        except ipfshttpclient.exceptions.CommunicationError as e:
            raise NodeError(f"Can not connect to node. Is node running?:\n{e}") from e
