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

"""Tests for the RPC rotation middleware (no Ganache required)."""

import time
from unittest.mock import MagicMock, patch

import pytest
from aea_ledger_ethereum.rpc_rotation import (
    CONNECTION_ERROR_BACKOFF,
    QUOTA_EXCEEDED_BACKOFF,
    RATE_LIMIT_BACKOFF,
    RPCRotationMiddleware,
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
        assert classify_error(Exception("too many open files")) == "fd_exhaustion"


# ---------------------------------------------------------------------------
# RPCRotationMiddleware helpers to build test instances
# ---------------------------------------------------------------------------


def _make_middleware(rpc_urls, request_kwargs=None):
    """Build an RPCRotationMiddleware with a mock web3 instance."""
    mock_w3 = MagicMock()
    with patch(
        "aea_ledger_ethereum.rpc_rotation.enrich_rpc_urls",
        side_effect=lambda urls, **kw: urls,
    ):
        mw = RPCRotationMiddleware.build(
            mock_w3,
            rpc_urls=rpc_urls,
            request_kwargs=request_kwargs or {},
        )
    return mw


# ---------------------------------------------------------------------------
# Build + introspection
# ---------------------------------------------------------------------------


class TestRPCRotationMiddlewareBuild:
    """Tests for build() and introspection properties."""

    def test_single_rpc_disables_rotation(self) -> None:
        """With one RPC, rotation is disabled."""
        mw = _make_middleware(["http://rpc1"])
        assert mw.rpc_count == 1
        assert mw.current_rpc_url == "http://rpc1"
        assert mw._rotation_enabled is False

    def test_multiple_rpcs_enables_rotation(self) -> None:
        """With multiple RPCs, rotation is enabled."""
        mw = _make_middleware(["http://rpc1", "http://rpc2", "http://rpc3"])
        assert mw.rpc_count == 3
        assert mw._rotation_enabled is True

    def test_providers_created_per_url(self) -> None:
        """One HTTPProvider is created per URL."""
        mw = _make_middleware(["http://a", "http://b"])
        assert len(mw._providers) == 2


# ---------------------------------------------------------------------------
# Health tracking
# ---------------------------------------------------------------------------


class TestHealthTracking:
    """Tests for _mark_rpc_backoff and _is_rpc_healthy."""

    def test_healthy_by_default(self) -> None:
        """All RPCs start as healthy."""
        mw = _make_middleware(["http://a", "http://b"])
        assert mw._is_rpc_healthy(0) is True
        assert mw._is_rpc_healthy(1) is True

    def test_backoff_marks_unhealthy(self) -> None:
        """After marking backoff, RPC is unhealthy."""
        mw = _make_middleware(["http://a", "http://b"])
        mw._mark_rpc_backoff(0, 100.0)
        assert mw._is_rpc_healthy(0) is False
        assert mw._is_rpc_healthy(1) is True

    def test_backoff_expires(self) -> None:
        """After backoff expires, RPC is healthy again."""
        mw = _make_middleware(["http://a", "http://b"])
        mw._mark_rpc_backoff(0, 0.01)
        time.sleep(0.02)
        assert mw._is_rpc_healthy(0) is True


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestRotate:
    """Tests for _rotate."""

    def test_no_rotation_with_single_rpc(self) -> None:
        """Single RPC never rotates."""
        mw = _make_middleware(["http://only"])
        assert mw._rotate() is False

    def test_rotation_selects_next_healthy(self) -> None:
        """Rotation picks the next healthy RPC in round-robin."""
        mw = _make_middleware(["http://a", "http://b", "http://c"])
        assert mw._current_index == 0
        assert mw._rotate() is True
        assert mw._current_index == 1
        assert mw.current_rpc_url == "http://b"

    def test_rotation_skips_unhealthy(self) -> None:
        """Rotation skips RPCs in backoff."""
        mw = _make_middleware(["http://a", "http://b", "http://c"])
        mw._mark_rpc_backoff(1, 300.0)
        mw._rotate()
        assert mw._current_index == 2

    def test_rotation_cooldown(self) -> None:
        """Cannot rotate again within cooldown period."""
        mw = _make_middleware(["http://a", "http://b"])
        mw._rotate()
        assert mw._rotate() is False

    def test_all_in_backoff_picks_soonest_expiry(self) -> None:
        """When all RPCs are in backoff, picks the one expiring soonest."""
        mw = _make_middleware(["http://a", "http://b", "http://c"])
        now = time.monotonic()
        mw._backoff_until[1] = now + 100
        mw._backoff_until[2] = now + 10
        mw._rotate()
        assert mw._current_index == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestHandleErrorAndRotate:
    """Tests for _handle_error_and_rotate."""

    def test_unknown_error_no_retry(self) -> None:
        """Unknown errors don't trigger retry."""
        mw = _make_middleware(["http://a", "http://b"])
        assert mw._handle_error_and_rotate(Exception("something weird"), "op") is False

    def test_rate_limit_triggers_backoff_and_rotation(self) -> None:
        """Rate limit backs off current RPC and rotates."""
        mw = _make_middleware(["http://a", "http://b"])
        assert (
            mw._handle_error_and_rotate(Exception("429 Too Many Requests"), "op")
            is True
        )
        assert mw._is_rpc_healthy(0) is False
        assert mw._current_index == 1

    def test_fd_exhaustion_backs_off_all_rpcs(self) -> None:
        """FD exhaustion marks ALL RPCs as unhealthy."""
        mw = _make_middleware(["http://a", "http://b", "http://c"])
        mw._handle_error_and_rotate(Exception("too many open files"), "op")
        assert mw._is_rpc_healthy(0) is False
        assert mw._is_rpc_healthy(1) is False
        assert mw._is_rpc_healthy(2) is False


# ---------------------------------------------------------------------------
# wrap_make_request — single RPC (pass-through)
# ---------------------------------------------------------------------------


class TestWrapMakeRequestSingleRpc:
    """Tests for wrap_make_request with a single RPC (rotation disabled)."""

    def test_passes_through_to_make_request(self) -> None:
        """Single-RPC: calls make_request directly."""
        mw = _make_middleware(["http://only"])
        inner = MagicMock(return_value={"result": 42})
        middleware_fn = mw.wrap_make_request(inner)
        result = middleware_fn("eth_blockNumber", [])
        inner.assert_called_once_with("eth_blockNumber", [])
        assert result == {"result": 42}

    def test_propagates_exception(self) -> None:
        """Single-RPC: exceptions propagate immediately."""
        mw = _make_middleware(["http://only"])
        inner = MagicMock(side_effect=ConnectionError("refused"))
        middleware_fn = mw.wrap_make_request(inner)
        with pytest.raises(ConnectionError):
            middleware_fn("eth_blockNumber", [])


# ---------------------------------------------------------------------------
# wrap_make_request — multi-RPC (rotation enabled)
# ---------------------------------------------------------------------------


class TestWrapMakeRequestMultiRpc:
    """Tests for wrap_make_request with multiple RPCs."""

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_retries_on_rate_limit(self, mock_sleep: MagicMock) -> None:
        """Rate-limit errors are retried with rotation."""
        mw = _make_middleware(["http://a", "http://b"])
        call_count = 0

        def _make_request(method, params):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("429 rate limit")
            return {"result": "ok"}

        for provider in mw._providers:
            provider.make_request = _make_request

        middleware_fn = mw.wrap_make_request(MagicMock())
        result = middleware_fn("eth_blockNumber", [])
        assert result == {"result": "ok"}
        assert call_count == 3
        assert mock_sleep.call_count >= 1

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_raises_after_max_retries(self, mock_sleep: MagicMock) -> None:
        """Raises last exception after exhausting retries."""
        mw = _make_middleware(["http://a", "http://b"])
        for provider in mw._providers:
            provider.make_request = MagicMock(
                side_effect=Exception("connection refused")
            )
        middleware_fn = mw.wrap_make_request(MagicMock())
        with pytest.raises(Exception, match="connection refused"):
            middleware_fn("eth_blockNumber", [])

    def test_unknown_error_not_retried(self) -> None:
        """Unknown errors raise immediately without retry."""
        mw = _make_middleware(["http://a", "http://b"])
        call_count = 0

        def _fail(method, params):
            nonlocal call_count
            call_count += 1
            raise TypeError("unexpected type")

        for provider in mw._providers:
            provider.make_request = _fail

        middleware_fn = mw.wrap_make_request(MagicMock())
        with pytest.raises(TypeError):
            middleware_fn("eth_blockNumber", [])
        assert call_count == 1

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_write_not_retried_on_rate_limit(self, mock_sleep: MagicMock) -> None:
        """eth_sendRawTransaction is NOT retried on rate limit (write safety)."""
        mw = _make_middleware(["http://a", "http://b"])
        call_count = 0

        def _fail(method, params):
            nonlocal call_count
            call_count += 1
            raise Exception("429 rate limit")

        for provider in mw._providers:
            provider.make_request = _fail

        middleware_fn = mw.wrap_make_request(MagicMock())
        with pytest.raises(Exception, match="rate limit"):
            middleware_fn("eth_sendRawTransaction", [])
        assert call_count == 1

    @patch("aea_ledger_ethereum.rpc_rotation.time.sleep")
    def test_write_retried_on_connection_error(self, mock_sleep: MagicMock) -> None:
        """eth_sendRawTransaction IS retried on connection errors."""
        mw = _make_middleware(["http://a", "http://b"])
        call_count = 0

        def _make_request(method, params):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("connection refused")
            return {"result": "0xtxhash"}

        for provider in mw._providers:
            provider.make_request = _make_request

        middleware_fn = mw.wrap_make_request(MagicMock())
        result = middleware_fn("eth_sendRawTransaction", [])
        assert result == {"result": "0xtxhash"}
        assert call_count == 3

    def test_success_on_first_try(self) -> None:
        """Successful first call returns immediately."""
        mw = _make_middleware(["http://a", "http://b"])
        for provider in mw._providers:
            provider.make_request = MagicMock(return_value={"result": 123})
        middleware_fn = mw.wrap_make_request(MagicMock())
        assert middleware_fn("eth_blockNumber", []) == {"result": 123}


# ---------------------------------------------------------------------------
# Integration: EthereumApi uses middleware correctly
# ---------------------------------------------------------------------------


class TestEthereumApiMultiRpc:
    """Test that EthereumApi correctly sets up RPCRotationMiddleware."""

    @patch("aea_ledger_ethereum.ethereum.Web3")
    @patch("aea_ledger_ethereum.ethereum.HTTPProvider")
    @patch(
        "aea_ledger_ethereum.rpc_rotation.enrich_rpc_urls",
        side_effect=lambda urls, **kw: urls,
    )
    def test_single_rpc_rotation_disabled(
        self, _mock_enrich, mock_provider_cls: MagicMock, mock_web3_cls: MagicMock
    ) -> None:
        """Single RPC: rotation middleware is disabled."""
        from aea_ledger_ethereum.ethereum import EthereumApi

        mock_web3 = MagicMock()
        mock_web3_cls.return_value = mock_web3
        mock_web3.middleware_onion = MagicMock()

        api = EthereumApi(address="http://localhost:8545")
        assert api._rpc_rotation._rotation_enabled is False
        assert api._rpc_rotation.rpc_count == 1
        assert api._rpc_rotation.current_rpc_url == "http://localhost:8545"

    @patch("aea_ledger_ethereum.ethereum.Web3")
    @patch("aea_ledger_ethereum.ethereum.HTTPProvider")
    @patch(
        "aea_ledger_ethereum.rpc_rotation.enrich_rpc_urls",
        side_effect=lambda urls, **kw: urls,
    )
    def test_multi_rpc_rotation_enabled(
        self, _mock_enrich, mock_provider_cls: MagicMock, mock_web3_cls: MagicMock
    ) -> None:
        """Comma-separated RPCs: rotation middleware is enabled."""
        from aea_ledger_ethereum.ethereum import EthereumApi

        mock_web3 = MagicMock()
        mock_web3_cls.return_value = mock_web3
        mock_web3.middleware_onion = MagicMock()

        api = EthereumApi(address="http://rpc1.example.com,http://rpc2.example.com")
        assert api._rpc_rotation._rotation_enabled is True
        assert api._rpc_rotation.rpc_count == 2
        assert api._rpc_rotation.current_rpc_url == "http://rpc1.example.com"

    @patch("aea_ledger_ethereum.ethereum.Web3")
    @patch("aea_ledger_ethereum.ethereum.HTTPProvider")
    @patch(
        "aea_ledger_ethereum.rpc_rotation.enrich_rpc_urls",
        side_effect=lambda urls, **kw: urls,
    )
    def test_middleware_added_to_onion(
        self, _mock_enrich, mock_provider_cls: MagicMock, mock_web3_cls: MagicMock
    ) -> None:
        """Test that RPCRotationMiddleware is added to the middleware onion."""
        from aea_ledger_ethereum.ethereum import EthereumApi

        mock_web3 = MagicMock()
        mock_web3_cls.return_value = mock_web3
        mock_web3.middleware_onion = MagicMock()

        EthereumApi(address="http://rpc1.example.com,http://rpc2.example.com")
        # middleware_onion.add should be called at least twice
        # (once for RPCRotation, once for CachedChainId)
        assert mock_web3.middleware_onion.add.call_count >= 2


# ---------------------------------------------------------------------------
# Backoff durations
# ---------------------------------------------------------------------------


class TestBackoffDurations:
    """Verify correct backoff per error category."""

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
        mw = _make_middleware(["http://a", "http://b"])
        mw._handle_error_and_rotate(Exception(error_msg), "test")
        backoff_until = mw._backoff_until.get(0, 0.0)
        remaining = backoff_until - time.monotonic()
        assert remaining > 0
        assert remaining <= expected_backoff + 1.0
