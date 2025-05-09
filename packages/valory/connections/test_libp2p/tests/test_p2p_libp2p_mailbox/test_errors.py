# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2024 Valory AG
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

"""This test module contains negative tests for Libp2p tcp client connection."""
from unittest.mock import Mock, patch

import pytest

from packages.valory.connections.p2p_libp2p_mailbox.connection import (
    P2PLibp2pMailboxConnection,
)
from packages.valory.connections.test_libp2p.tests.base import (
    BaseP2PLibp2pTest,
    _make_libp2p_mailbox_connection,
)
from packages.valory.connections.test_libp2p.tests.test_p2p_libp2p_client.test_errors import (
    DONE_FUTURE,
)
from packages.valory.connections.test_libp2p.tests.test_p2p_libp2p_client.test_errors import (
    TestLibp2pClientConnectionFailureConnectionSetup as BaseFailureConnectionSetup,
)
from packages.valory.connections.test_libp2p.tests.test_p2p_libp2p_client.test_errors import (
    TestLibp2pClientConnectionFailureNodeNotConnected as BaseFailureNodeNotConnected,
)


# pylint: skip-file


@pytest.mark.asyncio
class TestLibp2pMailboxConnectionFailureNodeNotConnected(BaseFailureNodeNotConnected):
    """Test that connection fails when node not running"""

    public_key = BaseP2PLibp2pTest.default_crypto.public_key
    connection = _make_libp2p_mailbox_connection(peer_public_key=public_key)  # type: ignore
    # overwrite, no mailbox equivalent of P2PLibp2pClientConnection (TCPSocketChannelClient)
    test_connect_attempts = None

    @pytest.mark.asyncio
    async def test_reconnect_on_send_fail(self):
        """Test reconnect on send fails."""

        self.connection._node_client = Mock()
        self.connection._node_client.send_envelope.side_effect = Exception("oops")
        with patch.object(
            self.connection, "_perform_connection_to_node", return_value=DONE_FUTURE
        ) as connect_mock, patch.object(
            self.connection, "_ensure_valid_envelope_for_external_comms"
        ):
            with pytest.raises(Exception, match="oops"):
                await self.connection._send_envelope_with_node_client(Mock())
                connect_mock.assert_called()


class TestLibp2pMailboxConnectionFailureConnectionSetup(BaseFailureConnectionSetup):
    """Test that connection fails when setup incorrectly"""

    connection_cls = P2PLibp2pMailboxConnection  # type: ignore
