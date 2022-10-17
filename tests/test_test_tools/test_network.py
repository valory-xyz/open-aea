# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022 Valory AG
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

"""Test helper utils."""

import socket
from unittest import mock

from aea.test_tools.network import get_host, get_unused_tcp_port


def is_port_in_use(port: int) -> bool:
    """Check if port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


def test_get_unused_tcp_port() -> None:
    """Test get_unused_tcp_port"""

    n_ports = 100
    for _ in range(n_ports):
        assert not is_port_in_use(get_unused_tcp_port())


def test_get_host():
    """Test get_host"""

    assert get_host()
    with mock.patch("socket.socket.connect", side_effect=Exception):
        get_host()