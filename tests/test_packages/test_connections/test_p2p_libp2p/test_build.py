# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022 Valory AG
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
"""Test P2PLibp2p connection build."""
import os
import tempfile
from io import StringIO
from unittest import mock

import pytest

from aea.exceptions import AEAException

from packages.open_aea.connections.p2p_libp2p import check_dependencies
from packages.open_aea.connections.p2p_libp2p.check_dependencies import (
    ERROR_MESSAGE_TEMPLATE_BINARY_NOT_FOUND,
    ERROR_MESSAGE_TEMPLATE_VERSION_TOO_LOW,
    MINIMUM_GCC_VERSION,
    MINIMUM_GO_VERSION,
    build_node,
    check_versions,
    version_to_string,
)
from packages.open_aea.connections.p2p_libp2p.connection import LIBP2P_NODE_MODULE_NAME


def test_check_versions():
    """Test check_versions - positive case."""
    with mock.patch("sys.stdout", new_callable=StringIO) as mock_stdout:
        check_versions()
        stdout = mock_stdout.getvalue()
    assert f"check 'go'>={version_to_string(MINIMUM_GO_VERSION)}, found: " in stdout
    assert f"check 'gcc'>={version_to_string(MINIMUM_GCC_VERSION)}, found: " in stdout


def test_check_versions_negative_binary_not_found():
    """Test check_versions - negative case, binary not found."""
    with mock.patch("shutil.which", return_value=None):
        with pytest.raises(
            AEAException,
            match=ERROR_MESSAGE_TEMPLATE_BINARY_NOT_FOUND.format(command="go"),
        ):
            check_versions()


def test_check_versions_negative_version_too_low():
    """Test check_versions - negative case, version too low."""
    with mock.patch.object(
        check_dependencies, "get_version", return_value=(0, 0, 0),
    ):
        minimal = version_to_string(MINIMUM_GO_VERSION)
        with pytest.raises(
            AEAException,
            match=ERROR_MESSAGE_TEMPLATE_VERSION_TOO_LOW.format(
                command="go", minimal=minimal, current="0.0.0"
            ),
        ):
            check_versions()


def test_check_versions_negative_cannot_parse_version():
    """Test the check_versions - negative case, cannot parse version."""
    with mock.patch("sys.stdout", new_callable=StringIO) as mock_stdout:
        with mock.patch("subprocess.check_output", return_value=b""):
            check_versions()
        stdout = mock_stdout.getvalue()
    go_msg = "Warning: cannot parse 'go' version from command: ['go', 'version']."
    gcc_msg = "Warning: cannot parse 'gcc' version from command: ['gcc', '--version']."
    assert go_msg in stdout and gcc_msg in stdout


def test_build_node():
    """Test build node function."""
    with tempfile.TemporaryDirectory() as build_dir:
        build_node(build_dir)
        assert os.path.exists(os.path.join(build_dir, LIBP2P_NODE_MODULE_NAME))
