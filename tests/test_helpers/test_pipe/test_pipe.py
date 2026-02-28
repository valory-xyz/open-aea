# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2026 Valory AG
#   Copyright 2018-2021 Fetch.AI Limited
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
"""Tests for the pipe module."""

import asyncio
import errno
from threading import Thread
from unittest import mock
from unittest.mock import Mock, patch

import pytest

from aea.helpers.pipe import (
    IPCChannelClient,
    PosixNamedPipeChannel,
    PosixNamedPipeChannelClient,
    PosixNamedPipeProtocol,
    TCPSocketChannel,
    TCPSocketChannelClient,
    TCPSocketProtocol,
    make_ipc_channel,
    make_ipc_channel_client,
)

from tests.conftest import skip_test_windows


def _run_echo_service(client: IPCChannelClient):
    async def echo_service(client: IPCChannelClient):
        try:
            await client.connect()
            while True:
                data = await client.read()
                if not data:
                    break
                await client.write(data)
        except (asyncio.IncompleteReadError, asyncio.CancelledError, OSError):
            pass
        finally:
            await client.close()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(echo_service(client))


@pytest.mark.asyncio
class TestAEAHelperMakePipe:
    """Test that make_ipc_channel utility and abstract class IPCChannel work properly"""

    @pytest.mark.asyncio
    async def test_connection_communication(self):
        """Test connection communication."""
        pipe = make_ipc_channel()
        assert (
            pipe.in_path is not None and pipe.out_path is not None
        ), "Pipe not properly setup"

        connected = asyncio.ensure_future(pipe.connect())

        client_pipe = make_ipc_channel_client(pipe.out_path, pipe.in_path)

        client = Thread(target=_run_echo_service, args=[client_pipe])
        client.start()

        try:
            assert await asyncio.wait_for(
                connected, timeout=5.0
            ), "Failed to connect pipe"

            message = b"hello"
            await pipe.write(message)
            received = await asyncio.wait_for(pipe.read(), timeout=5.0)

            assert received == message, "Echoed message differs"

        except Exception:
            raise
        finally:
            await pipe.close()
            client.join(timeout=5.0)
            assert not client.is_alive(), "Echo thread did not terminate in time"


@pytest.mark.asyncio
class TestAEAHelperTCPSocketChannel:
    """Test that TCPSocketChannel work properly"""

    @pytest.mark.asyncio
    async def test_connection_communication(self):
        """Test connection communication."""
        pipe = TCPSocketChannel()
        assert (
            pipe.in_path is not None and pipe.out_path is not None
        ), "TCPSocketChannel not properly setup"

        connected = asyncio.ensure_future(pipe.connect())

        client_pipe = TCPSocketChannelClient(pipe.out_path, pipe.in_path)

        client = Thread(target=_run_echo_service, args=[client_pipe])
        client.start()

        try:
            assert await asyncio.wait_for(
                connected, timeout=5.0
            ), "Failed to connect pipe"

            message = b"hello"
            await pipe.write(message)
            received = await asyncio.wait_for(pipe.read(), timeout=5.0)

            assert received == message, "Echoed message differs"

        except Exception:
            raise
        finally:
            await pipe.close()
            client.join(timeout=5.0)
            assert not client.is_alive(), "Echo thread did not terminate in time"

    @pytest.mark.asyncio
    async def test_connection_refused(self):
        """Test connection refused."""
        pipe = TCPSocketChannel()
        assert (
            pipe.in_path is not None and pipe.out_path is not None
        ), "TCPSocketChannel not properly setup"

        client_pipe = TCPSocketChannelClient(pipe.out_path, pipe.in_path)

        connected = await client_pipe.connect()
        assert connected is False

    def test_tcp_socket_channel_protocol_writer_property(self):
        """Test that TCP socket channel protocol write not set raises"""

        pipe = TCPSocketChannel()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            reader = asyncio.StreamReader()
            writer = asyncio.StreamWriter(mock.Mock(), mock.Mock(), reader, mock.Mock())
            pipe._sock = TCPSocketProtocol(reader, writer)
            assert pipe._sock.writer is writer
        finally:
            asyncio.set_event_loop(None)
            loop.close()


def make_future(result) -> asyncio.Future:
    """Make future for value."""
    f = asyncio.Future()  # type: ignore
    f.set_result(result)
    return f


@skip_test_windows
@pytest.mark.asyncio
async def test_posix_pipe_closes_prev_in_fd_on_retry():
    """Test that the previous input fd is closed when a new one is opened on retry."""
    pipe = PosixNamedPipeProtocol(
        in_path="/tmp/test_in", out_path="/tmp/test_out"  # nosec
    )
    pipe._loop = asyncio.get_event_loop()
    pipe._connection_attempts = 3

    first_in_fd = 42
    second_in_fd = 43
    out_fd = 44
    enxio_error = OSError(errno.ENXIO, "No such device or address")

    # First attempt: open in (42), open out fails ENXIO, sleep, retry
    # Second attempt: open in (43) — should close prev (42), open out (44) — success
    with patch(
        "os.open", side_effect=[first_in_fd, enxio_error, second_in_fd, out_fd]
    ), patch("os.close") as mock_close, patch(
        "asyncio.sleep", return_value=None
    ), patch(
        "os.fdopen"
    ), patch.object(
        pipe._loop, "connect_read_pipe", return_value=(Mock(), Mock())
    ):
        pipe._connection_attempts = 3
        await pipe.connect(timeout=1.0)

    # The first input fd should have been closed when the second was opened
    mock_close.assert_any_call(first_in_fd)


@skip_test_windows
@pytest.mark.asyncio
class TestAEAHelperPosixNamedPipeChannel:
    """Test that TCPSocketChannel work properly"""

    @pytest.mark.asyncio
    async def test_connection_communication(self):
        """Test connection communication."""
        pipe = PosixNamedPipeChannel()
        assert (
            pipe.in_path is not None and pipe.out_path is not None
        ), "PosixNamedPipeChannel not properly setup"

        connected = asyncio.ensure_future(pipe.connect())

        client_pipe = PosixNamedPipeChannelClient(pipe.out_path, pipe.in_path)

        client = Thread(target=_run_echo_service, args=[client_pipe])
        client.start()

        try:
            assert await asyncio.wait_for(
                connected, timeout=5.0
            ), "Failed to connect pipe"

            message = b"hello"
            await pipe.write(message)
            received = await asyncio.wait_for(pipe.read(), timeout=5.0)

            assert received == message, "Echoed message differs"

        except Exception:
            raise
        finally:
            await pipe.close()
            client.join(timeout=5.0)
            assert not client.is_alive(), "Echo thread did not terminate in time"
