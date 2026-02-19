# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2024-2026 Valory AG
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

"""Tests for the RPC rotation module (no Ganache required)."""

import time
from unittest.mock import MagicMock, patch

import pytest
from aea_ledger_ethereum.rpc_rotation import (
    CONNECTION_ERROR_BACKOFF,
    QUOTA_EXCEEDED_BACKOFF,
    RATE_LIMIT_BACKOFF,
    RPCRotationMixin,
    SERVER_ERROR_BACKOFF,
    classify_error,
    parse_rpc_urls,
)


# ---------------------------------------------------------------------------
# parse_rpc_urls
# ---------------------------------------------------------------------------


class TestParseRpcUrls:
    """Tests for parse_rpc_urls."""

    def test_single_url(self) -> None:
        """Single URL returns a one-element list."""
        result = parse_rpc_urls("http://localhost:8545")
        assert result == ["http://localhost:8545"]

    def test_single_url_with_whitespace(self) -> None:
        """Whitespace is stripped."""
        result = parse_rpc_urls("  http://localhost:8545  ")
        assert result == ["http://localhost:8545"]

    def test_multiple_urls(self) -> None:
        """Comma-separated URLs are split correctly."""
        result = parse_rpc_urls("http://rpc1.example.com,http://rpc2.example.com")
        assert result == ["http://rpc1.example.com", "http://rpc2.example.com"]

    def test_multiple_urls_with_whitespace(self) -> None:
        """Whitespace around each URL is stripped."""
        result = parse_rpc_urls(" http://a , http://b , http://c ")
        assert result == ["http://a", "http://b", "http://c"]

    def test_empty_segments_are_ignored(self) -> None:
        """Empty segments from trailing commas are dropped."""
        result = parse_rpc_urls("http://a,,http://b,")
        assert result == ["http://a", "http://b"]

    def test_all_empty_segments_fallback(self) -> None:
        """If all segments are empty after split, return original string."""
        result = parse_rpc_urls(",,,")
        assert result == [",,,"]


# ---------------------------------------------------------------------------
# classify_error
# ---------------------------------------------------------------------------


class TestClassifyError:
    """Tests for classify_error."""

    @pytest.mark.parametrize(
        "msg,expected",
        [
            ("HTTP 429 Too Many Requests", "rate_limit"),
            ("rate limit exceeded", "rate_limit"),
            ("ratelimit reached", "rate_limit"),
            ("connection refused", "connection"),
            ("read timeout", "connection"),
            ("Name resolution failed", "connection"),
            ("max retries exceeded", "connection"),
            ("404 not found", "connection"),
            ("exceeded the quota for today", "quota"),
            ("quota exceeded", "quota"),
            ("allowance exceeded", "quota"),
            ("HTTP 502 Bad Gateway", "server"),
            ("503 Service Unavailable", "server"),
            ("internal server error", "server"),
            (
                "gateway timeout",
                "connection",
            ),  # "timeout" matches connection before server
            ("too many open files", "fd_exhaustion"),
            ("OSError(24, 'Too many open files')", "fd_exhaustion"),
            ("errno 24", "fd_exhaustion"),
            ("some random error", "unknown"),
        ],
    )
    def test_classification(self, msg: str, expected: str) -> None:
        """Error messages are classified correctly."""
        assert classify_error(Exception(msg)) == expected

    def test_case_insensitive(self) -> None:
        """Classification is case-insensitive."""
        assert classify_error(Exception("RATE LIMIT")) == "rate_limit"

    def test_fd_exhaustion_priority_over_connection(self) -> None:
        """FD exhaustion is checked before connection signals."""
        # "too many open files" could also match other patterns
        assert classify_error(Exception("too many open files")) == "fd_exhaustion"


# ---------------------------------------------------------------------------
# RPCRotationMixin — unit tests with a mock Web3 instance
# ---------------------------------------------------------------------------


class FakeApi(RPCRotationMixin):
    """Minimal class using the mixin for testing."""

    def __init__(self, rpc_urls, request_kwargs=None):
        """Initialise with mock API and rotation."""
        self._api = MagicMock()
        self._init_rotation(rpc_urls, request_kwargs or {})


class TestRPCRotationMixinInit:
    """Tests for _init_rotation and properties."""

    def test_single_rpc_disables_rotation(self) -> None:
        """With one RPC, rotation is disabled."""
        api = FakeApi(["http://rpc1"])
        assert api.rpc_count == 1
        assert api.current_rpc_url == "http://rpc1"
        assert api._rotation_enabled is False

    def test_multiple_rpcs_enables_rotation(self) -> None:
        """With multiple RPCs, rotation is enabled."""
        api = FakeApi(["http://rpc1", "http://rpc2", "http://rpc3"])
        assert api.rpc_count == 3
        assert api._rotation_enabled is True


class TestHealthTracking:
    """Tests for _mark_rpc_backoff and _is_rpc_healthy."""

    def test_healthy_by_default(self) -> None:
        """All RPCs start as healthy."""
        api = FakeApi(["http://a", "http://b"])
        assert api._is_rpc_healthy(0) is True
        assert api._is_rpc_healthy(1) is True

    def test_backoff_marks_unhealthy(self) -> None:
        """After marking backoff, RPC is unhealthy."""
        api = FakeApi(["http://a", "http://b"])
        api._mark_rpc_backoff(0, 100.0)
        assert api._is_rpc_healthy(0) is False
        assert api._is_rpc_healthy(1) is True

    def test_backoff_expires(self) -> None:
        """After backoff expires, RPC is healthy again."""
        api = FakeApi(["http://a", "http://b"])
        api._mark_rpc_backoff(0, 0.01)
        time.sleep(0.02)
        assert api._is_rpc_healthy(0) is True


class TestRotateProvider:
    """Tests for _rotate_provider."""

    def test_no_rotation_with_single_rpc(self) -> None:
        """Single RPC never rotates."""
        api = FakeApi(["http://only"])
        assert api._rotate_provider() is False

    def test_rotation_selects_next_healthy(self) -> None:
        """Rotation picks the next healthy RPC in round-robin."""
        api = FakeApi(["http://a", "http://b", "http://c"])
        assert api._current_rpc_index == 0

        rotated = api._rotate_provider()
        assert rotated is True
        assert api._current_rpc_index == 1
        assert api.current_rpc_url == "http://b"

    def test_rotation_skips_unhealthy(self) -> None:
        """Rotation skips RPCs in backoff."""
        api = FakeApi(["http://a", "http://b", "http://c"])
        api._mark_rpc_backoff(1, 300.0)  # b is unhealthy

        api._rotate_provider()
        assert api._current_rpc_index == 2  # skipped 1, went to 2

    def test_rotation_cooldown(self) -> None:
        """Cannot rotate again within cooldown period."""
        api = FakeApi(["http://a", "http://b"])
        api._rotate_provider()  # first rotation OK
        assert api._rotate_provider() is False  # cooldown blocks

    def test_all_in_backoff_picks_soonest_expiry(self) -> None:
        """When all RPCs are in backoff, picks the one expiring soonest."""
        api = FakeApi(["http://a", "http://b", "http://c"])
        now = time.monotonic()
        api._rpc_backoff_until[1] = now + 100
        api._rpc_backoff_until[2] = now + 10  # expires sooner

        api._rotate_provider()
        assert api._current_rpc_index == 2

    def test_rotation_swaps_provider(self) -> None:
        """Rotation actually sets a new HTTPProvider on self._api."""
        api = FakeApi(["http://a", "http://b"], {"timeout": 10})
        api._rotate_provider()
        # Check that provider was reassigned
        assert api._api.provider is not None


class TestHandleErrorAndRotate:
    """Tests for _handle_rpc_error_and_maybe_rotate."""

    def test_unknown_error_no_retry(self) -> None:
        """Unknown errors don't trigger retry."""
        api = FakeApi(["http://a", "http://b"])
        should_retry = api._handle_rpc_error_and_maybe_rotate(
            Exception("something weird"), "test_op"
        )
        assert should_retry is False

    def test_rate_limit_triggers_backoff_and_rotation(self) -> None:
        """Rate limit error backs off current RPC and rotates."""
        api = FakeApi(["http://a", "http://b"])
        should_retry = api._handle_rpc_error_and_maybe_rotate(
            Exception("429 Too Many Requests"), "test_op"
        )
        assert should_retry is True
        assert api._is_rpc_healthy(0) is False  # original RPC backed off
        assert api._current_rpc_index == 1  # rotated to b

    def test_connection_error_triggers_rotation(self) -> None:
        """Connection error triggers rotation."""
        api = FakeApi(["http://a", "http://b"])
        should_retry = api._handle_rpc_error_and_maybe_rotate(
            Exception("connection refused"), "test_op"
        )
        assert should_retry is True
        assert api._current_rpc_index == 1

    def test_fd_exhaustion_backs_off_all_rpcs(self) -> None:
        """FD exhaustion marks ALL RPCs as unhealthy."""
        api = FakeApi(["http://a", "http://b", "http://c"])
        should_retry = api._handle_rpc_error_and_maybe_rotate(
            Exception("too many open files"), "test_op"
        )
        assert should_retry is True
        assert api._is_rpc_healthy(0) is False
        assert api._is_rpc_healthy(1) is False
        assert api._is_rpc_healthy(2) is False


class TestExecuteWithRpcRotation:
    """Tests for _execute_with_rpc_rotation."""

    def test_single_rpc_no_rotation_just_calls(self) -> None:
        """With single RPC, operation is called directly without retry wrapper."""
        api = FakeApi(["http://only"])
        result = api._execute_with_rpc_rotation(lambda: 42, "test")
        assert result == 42

    def test_single_rpc_propagates_exception(self) -> None:
        """With single RPC, exceptions propagate immediately."""
        api = FakeApi(["http://only"])
        with pytest.raises(ValueError, match="boom"):
            api._execute_with_rpc_rotation(
                lambda: (_ for _ in ()).throw(ValueError("boom")),
                "test",
            )

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_retries_on_rate_limit(self, mock_sleep: MagicMock) -> None:
        """Rate limit errors are retried with rotation."""
        api = FakeApi(["http://a", "http://b"])

        call_count = 0

        def _op():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("429 rate limit")
            return "success"

        result = api._execute_with_rpc_rotation(_op, "test_retry")
        assert result == "success"
        assert call_count == 3
        assert mock_sleep.call_count >= 1

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_raises_after_max_retries(self, mock_sleep: MagicMock) -> None:
        """After exhausting retries, the last exception is raised."""
        api = FakeApi(["http://a", "http://b"])

        def _always_fail():
            raise Exception("connection refused forever")

        with pytest.raises(Exception, match="connection refused"):
            api._execute_with_rpc_rotation(_always_fail, "test_exhaust")

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_unknown_error_not_retried(self, mock_sleep: MagicMock) -> None:
        """Unknown errors are raised immediately, not retried."""
        api = FakeApi(["http://a", "http://b"])

        call_count = 0

        def _op():
            nonlocal call_count
            call_count += 1
            raise TypeError("unexpected")

        with pytest.raises(TypeError):
            api._execute_with_rpc_rotation(_op, "test_unknown")
        assert call_count == 1  # no retries

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_write_only_retries_connection_errors(self, mock_sleep: MagicMock) -> None:
        """Write operations only retry on connection errors, not rate limits."""
        api = FakeApi(["http://a", "http://b"])

        call_count = 0

        def _op():
            nonlocal call_count
            call_count += 1
            raise Exception("429 rate limit")

        with pytest.raises(Exception, match="rate limit"):
            api._execute_with_rpc_rotation(_op, "test_write", is_write=True)
        assert call_count == 1  # not retried for write

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_write_retries_connection_error(self, mock_sleep: MagicMock) -> None:
        """Write operations DO retry on clear connection errors."""
        api = FakeApi(["http://a", "http://b"])

        call_count = 0

        def _op():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("connection refused")
            return "tx_hash"

        result = api._execute_with_rpc_rotation(_op, "test_write_conn", is_write=True)
        assert result == "tx_hash"
        assert call_count == 3

    def test_success_on_first_try(self) -> None:
        """Successful call on first try returns immediately."""
        api = FakeApi(["http://a", "http://b", "http://c"])
        result = api._execute_with_rpc_rotation(lambda: 123, "test_ok")
        assert result == 123


# ---------------------------------------------------------------------------
# Integration: EthereumApi.__init__ with multi-RPC
# ---------------------------------------------------------------------------


class TestEthereumApiMultiRpc:
    """Test that EthereumApi correctly parses multi-RPC address."""

    @patch("aea_ledger_ethereum.ethereum.Web3")
    @patch("aea_ledger_ethereum.ethereum.HTTPProvider")
    def test_single_rpc_backward_compatible(
        self, mock_provider_cls: MagicMock, mock_web3_cls: MagicMock
    ) -> None:
        """Single RPC URL: rotation is disabled, same behavior as before."""
        from aea_ledger_ethereum.ethereum import EthereumApi

        mock_web3 = MagicMock()
        mock_web3_cls.return_value = mock_web3
        mock_web3.middleware_onion = MagicMock()

        api = EthereumApi(address="http://localhost:8545")
        assert api._rotation_enabled is False
        assert api.rpc_count == 1
        mock_provider_cls.assert_called_once()

    @patch("aea_ledger_ethereum.ethereum.Web3")
    @patch("aea_ledger_ethereum.ethereum.HTTPProvider")
    def test_multi_rpc_enables_rotation(
        self, mock_provider_cls: MagicMock, mock_web3_cls: MagicMock
    ) -> None:
        """Comma-separated RPC URLs enable rotation."""
        from aea_ledger_ethereum.ethereum import EthereumApi

        mock_web3 = MagicMock()
        mock_web3_cls.return_value = mock_web3
        mock_web3.middleware_onion = MagicMock()

        api = EthereumApi(address="http://rpc1.example.com,http://rpc2.example.com")
        assert api._rotation_enabled is True
        assert api.rpc_count == 2
        assert api.current_rpc_url == "http://rpc1.example.com"


# ---------------------------------------------------------------------------
# Backoff duration verification
# ---------------------------------------------------------------------------


class TestBackoffDurations:
    """Verify correct backoff is applied per error category."""

    @pytest.mark.parametrize(
        "error_msg,expected_backoff",
        [
            ("429 rate limit", RATE_LIMIT_BACKOFF),
            ("connection refused", CONNECTION_ERROR_BACKOFF),
            ("quota exceeded", QUOTA_EXCEEDED_BACKOFF),
            ("502 Bad Gateway", SERVER_ERROR_BACKOFF),
        ],
    )
    def test_correct_backoff_per_category(
        self, error_msg: str, expected_backoff: float
    ) -> None:
        """Each error category applies the correct backoff duration."""
        api = FakeApi(["http://a", "http://b"])
        api._handle_rpc_error_and_maybe_rotate(Exception(error_msg), "test")
        # RPC #0 should be in backoff for approximately expected_backoff seconds
        backoff_until = api._rpc_backoff_until.get(0, 0.0)
        remaining = backoff_until - time.monotonic()
        assert remaining > 0
        assert remaining <= expected_backoff + 1.0  # allow 1s tolerance


# ---------------------------------------------------------------------------
# Integration: _try_* methods with rotation
# ---------------------------------------------------------------------------


class TestTryMethodsWithRotation:
    """Test that wrapped _try_* methods trigger rotation on RPC errors."""

    def _make_api(self):
        """Create an EthereumApi with mocked Web3 and 2 RPCs."""
        from aea_ledger_ethereum.ethereum import EthereumApi

        with patch("aea_ledger_ethereum.ethereum.Web3") as mock_web3_cls, patch(
            "aea_ledger_ethereum.ethereum.HTTPProvider"
        ):
            mock_web3 = MagicMock()
            mock_web3_cls.return_value = mock_web3
            mock_web3.middleware_onion = MagicMock()

            api = EthereumApi(address="http://rpc1.example.com,http://rpc2.example.com")
        return api

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_get_balance_rotates_on_rate_limit(self, mock_sleep: MagicMock) -> None:
        """_try_get_balance rotates to next RPC on rate limit error."""
        api = self._make_api()
        call_count = 0

        def mock_get_balance(addr):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("429 Too Many Requests")
            return 1000

        api._api.eth.get_balance = mock_get_balance
        api._api.to_checksum_address = lambda x: x

        result = api._try_get_balance("0x1234")
        assert result == 1000
        assert call_count == 3

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_get_transaction_count_rotates(self, mock_sleep: MagicMock) -> None:
        """_try_get_transaction_count rotates on connection error."""
        api = self._make_api()
        call_count = 0

        def mock_get_tx_count(addr):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("connection refused")
            return 42

        api._api.eth.get_transaction_count = mock_get_tx_count
        api._api.to_checksum_address = lambda x: x

        result = api._try_get_transaction_count("0x1234")
        assert result == 42
        assert call_count == 2

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_send_signed_transaction_no_retry_on_rate_limit(
        self, mock_sleep: MagicMock
    ) -> None:
        """_try_send_signed_transaction does NOT retry rate limit (write safety).

        :param mock_sleep: patch fixture for time.sleep.

        Note: try_decorator catches the exception and returns None instead of
        raising, so we check the call count and None return value.
        """
        api = self._make_api()
        call_count = 0

        def mock_send_raw(raw_tx):
            nonlocal call_count
            call_count += 1
            raise Exception("429 rate limit")

        api._api.eth.send_raw_transaction = mock_send_raw

        with patch(
            "aea_ledger_ethereum.ethereum.SignedTransactionTranslator"
        ) as mock_translator:
            mock_signed = MagicMock()
            mock_signed.raw_transaction = b"\x00"
            mock_translator.from_dict.return_value = mock_signed

            # try_decorator catches the exception — returns None
            result = api._try_send_signed_transaction({"some": "tx"})
            assert result is None
            assert call_count == 1  # NOT retried (write safety)

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_send_signed_transaction_retries_connection_error(
        self, mock_sleep: MagicMock
    ) -> None:
        """_try_send_signed_transaction DOES retry on connection errors."""
        api = self._make_api()
        call_count = 0

        def mock_send_raw(raw_tx):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("connection refused")
            result = MagicMock()
            result.to_0x_hex.return_value = "0xabc123"
            return result

        api._api.eth.send_raw_transaction = mock_send_raw

        with patch(
            "aea_ledger_ethereum.ethereum.SignedTransactionTranslator"
        ) as mock_translator:
            mock_signed = MagicMock()
            mock_signed.raw_transaction = b"\x00"
            mock_translator.from_dict.return_value = mock_signed

            result = api._try_send_signed_transaction({"some": "tx"})
            assert result == "0xabc123"
            assert call_count == 3

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_get_transaction_receipt_rotates(self, mock_sleep: MagicMock) -> None:
        """_try_get_transaction_receipt rotates on server error."""
        api = self._make_api()
        call_count = 0

        def mock_get_receipt(tx_hash):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("502 Bad Gateway")
            # Return an AttributeDict-like object
            return {"status": 1, "blockNumber": 100}

        api._api.eth.get_transaction_receipt = mock_get_receipt

        with patch(
            "aea_ledger_ethereum.ethereum.AttributeDictTranslator"
        ) as mock_translator:
            mock_translator.to_dict.return_value = {"status": 1, "blockNumber": 100}
            result = api._try_get_transaction_receipt("0xabc")
            assert result == {"status": 1, "blockNumber": 100}
            assert call_count == 2

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_get_state_rotates(self, mock_sleep: MagicMock) -> None:
        """_try_get_state rotates on quota error."""
        api = self._make_api()
        call_count = 0

        def mock_get_block(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("quota exceeded")
            return 12345

        api._api.eth.get_block = mock_get_block

        result = api._try_get_state("get_block", "latest")
        assert result == {"get_block_result": 12345}
        assert call_count == 2

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_get_gas_estimate_rotates(self, mock_sleep: MagicMock) -> None:
        """_try_get_gas_estimate rotates on connection error."""
        api = self._make_api()
        call_count = 0

        def mock_estimate_gas(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("connection refused")
            return 21000

        api._api.eth.estimate_gas = mock_estimate_gas

        result = api._try_get_gas_estimate({"gas": 0, "to": "0x1"})
        assert result == 21000
        assert call_count == 2

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_try_get_gas_pricing_rotates(self, mock_sleep: MagicMock) -> None:
        """try_get_gas_pricing rotates on rate limit error."""
        api = self._make_api()
        call_count = 0

        def mock_generate_gas_price():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("429 rate limit")
            return {"maxFeePerGas": 100, "maxPriorityFeePerGas": 10}

        # Mock the gas strategy retrieval
        api._api.eth._gas_price_strategy = None
        api._api.eth.set_gas_price_strategy = MagicMock()
        api._api.eth.generate_gas_price = mock_generate_gas_price

        with patch.object(api, "_get_gas_price_strategy") as mock_get_strategy:
            mock_get_strategy.return_value = ("eip1559", lambda **kw: None)
            result = api.try_get_gas_pricing(gas_price_strategy="eip1559")
            assert result == {"maxFeePerGas": 100, "maxPriorityFeePerGas": 10}
            assert call_count == 2
