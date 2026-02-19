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

"""RPC rotation support for EthereumApi with automatic failover and backoff.

When multiple RPC endpoints are provided (comma-separated), the plugin
automatically rotates to healthy endpoints on rate-limit, connection,
or quota errors.  With a single RPC URL the mixin is effectively a no-op.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, TypeVar

from web3 import HTTPProvider


_logger = logging.getLogger("aea.ledger_apis.ethereum.rpc_rotation")

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Error classification signals
# ---------------------------------------------------------------------------

RATE_LIMIT_SIGNALS = ("429", "rate limit", "too many requests", "ratelimit")

CONNECTION_SIGNALS = (
    "timeout",
    "timed out",
    "connection refused",
    "connection reset",
    "connection error",
    "connection aborted",
    "name resolution",
    "dns",
    "no route to host",
    "network unreachable",
    "max retries exceeded",
    "read timeout",
    "connect timeout",
    "remote end closed",
    "broken pipe",
    "404",
    "not found",
)

QUOTA_SIGNALS = (
    "exceeded the quota",
    "exceeded quota",
    "quota usage",
    "quota exceeded",
    "allowance exceeded",
)

SERVER_ERROR_SIGNALS = (
    "500",
    "502",
    "503",
    "504",
    "internal server error",
    "bad gateway",
    "service unavailable",
    "gateway timeout",
)

FD_EXHAUSTION_SIGNALS = ("too many open files", "oserror(24", "errno 24")

# ---------------------------------------------------------------------------
# Backoff durations (seconds)
# ---------------------------------------------------------------------------

RATE_LIMIT_BACKOFF = 10.0
QUOTA_EXCEEDED_BACKOFF = 300.0
CONNECTION_ERROR_BACKOFF = 30.0
SERVER_ERROR_BACKOFF = 15.0
FD_EXHAUSTION_BACKOFF = 60.0

_BACKOFF_MAP: Dict[str, float] = {
    "rate_limit": RATE_LIMIT_BACKOFF,
    "connection": CONNECTION_ERROR_BACKOFF,
    "quota": QUOTA_EXCEEDED_BACKOFF,
    "server": SERVER_ERROR_BACKOFF,
    "fd_exhaustion": FD_EXHAUSTION_BACKOFF,
}

# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------

MAX_RETRIES = 6
RETRY_DELAY = 1.0  # base delay between retries (exponential backoff)
MAX_RETRY_DELAY = 5.0  # cap on retry delay
ROTATION_COOLDOWN = 2.0  # min time between rotations to prevent cascade


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def parse_rpc_urls(address: str) -> List[str]:
    """Parse RPC URL(s) from an *address* string.

    Supports a single URL or a comma-separated list.
    Returns a list with at least one URL.
    """
    if "," in address:
        urls = [url.strip() for url in address.split(",") if url.strip()]
        return urls if urls else [address]
    return [address.strip()]


def classify_error(error: Exception) -> str:
    """Classify an RPC error into a category.

    Returns one of:
    ``"rate_limit"``, ``"connection"``, ``"quota"``, ``"server"``,
    ``"fd_exhaustion"``, or ``"unknown"``.
    """
    err_text = str(error).lower()

    if any(s in err_text for s in FD_EXHAUSTION_SIGNALS):
        return "fd_exhaustion"
    if any(s in err_text for s in RATE_LIMIT_SIGNALS):
        return "rate_limit"
    if any(s in err_text for s in QUOTA_SIGNALS):
        return "quota"
    if any(s in err_text for s in CONNECTION_SIGNALS):
        return "connection"
    if any(s in err_text for s in SERVER_ERROR_SIGNALS):
        return "server"
    return "unknown"


# ---------------------------------------------------------------------------
# Mixin
# ---------------------------------------------------------------------------


class RPCRotationMixin:
    """Mixin providing RPC rotation capabilities for EthereumApi.

    Manages a pool of RPC endpoints with per-endpoint health tracking,
    automatic failover on errors, and exponential-backoff retry logic.

    When a single RPC URL is provided the mixin is effectively a no-op:
    ``_rotation_enabled`` is ``False`` and ``_execute_with_rpc_rotation``
    simply calls the operation once.
    """

    # ------------------------------------------------------------------
    # Initialisation (called from EthereumApi.__init__)
    # ------------------------------------------------------------------

    def _init_rotation(
        self,
        rpc_urls: List[str],
        request_kwargs: Dict[str, Any],
        chain_id: Optional[int] = None,
    ) -> None:
        """Initialise rotation state.

        If *chain_id* is provided, enriches *rpc_urls* with validated
        public RPCs from Chainlist.org as fallback endpoints.
        """
        from aea_ledger_ethereum.chainlist import (  # pylint: disable=import-outside-toplevel
            enrich_rpc_urls,
        )

        rpc_urls = enrich_rpc_urls(rpc_urls, chain_id=chain_id)
        self._rpc_urls: List[str] = rpc_urls
        self._rpc_request_kwargs: Dict[str, Any] = request_kwargs
        self._current_rpc_index: int = 0
        self._rpc_backoff_until: Dict[int, float] = {}
        self._last_rotation_time: float = 0.0
        self._rotation_lock: threading.Lock = threading.Lock()
        self._rotation_enabled: bool = len(rpc_urls) > 1

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------

    @property
    def current_rpc_url(self) -> str:
        """Return the currently active RPC URL."""
        return self._rpc_urls[self._current_rpc_index]

    @property
    def rpc_count(self) -> int:
        """Return the number of configured RPC endpoints."""
        return len(self._rpc_urls)

    # ------------------------------------------------------------------
    # Per-RPC health tracking
    # ------------------------------------------------------------------

    def _mark_rpc_backoff(self, index: int, seconds: float) -> None:
        """Mark an RPC as temporarily unavailable for *seconds*."""
        self._rpc_backoff_until[index] = time.monotonic() + seconds

    def _is_rpc_healthy(self, index: int) -> bool:
        """Return ``True`` if the RPC at *index* is not in backoff."""
        return time.monotonic() >= self._rpc_backoff_until.get(index, 0.0)

    # ------------------------------------------------------------------
    # Provider rotation
    # ------------------------------------------------------------------

    def _rotate_provider(self) -> bool:
        """Rotate to the next healthy RPC endpoint.

        Swaps ``self._api.provider`` to the new endpoint, preserving
        all Web3 middleware.  Returns ``True`` if a rotation occurred.
        """
        with self._rotation_lock:
            n = len(self._rpc_urls)
            if n <= 1:
                return False

            now = time.monotonic()
            if now - self._last_rotation_time < ROTATION_COOLDOWN:
                return False  # cooldown: prevent cascade rotations

            # Find next healthy RPC (round-robin)
            best: Optional[int] = None
            for offset in range(1, n):
                candidate = (self._current_rpc_index + offset) % n
                if self._is_rpc_healthy(candidate):
                    best = candidate
                    break

            if best is None:
                # All in backoff — pick the one expiring soonest
                best = min(
                    (i for i in range(n) if i != self._current_rpc_index),
                    key=lambda i: self._rpc_backoff_until.get(i, 0.0),
                )

            self._current_rpc_index = best
            # Hot-swap the provider (middleware stack is preserved)
            self._api.provider = HTTPProvider(  # type: ignore[attr-defined]
                endpoint_uri=self._rpc_urls[best],
                request_kwargs=self._rpc_request_kwargs,
            )
            self._last_rotation_time = now

            _logger.info("Rotated RPC to #%d: %s", best, self._rpc_urls[best])
            return True

    # ------------------------------------------------------------------
    # Error handling + rotation trigger
    # ------------------------------------------------------------------

    def _handle_rpc_error_and_maybe_rotate(
        self,
        error: Exception,
        operation_name: str = "",
    ) -> bool:
        """Classify *error*, backoff the failing RPC, and rotate.

        Returns ``True`` if the caller should retry the operation.
        """
        category = classify_error(error)

        if category == "fd_exhaustion":
            _logger.error(
                "FD exhaustion detected — pausing ALL RPCs for %ds.",
                int(FD_EXHAUSTION_BACKOFF),
            )
            for i in range(len(self._rpc_urls)):
                self._mark_rpc_backoff(i, FD_EXHAUSTION_BACKOFF)
            return True

        if category == "unknown":
            return False  # don't retry unknown errors

        backoff = _BACKOFF_MAP.get(category, 0.0)
        self._mark_rpc_backoff(self._current_rpc_index, backoff)
        _logger.warning(
            "RPC #%d %s error (backoff %ds) during %s: %.120s",
            self._current_rpc_index,
            category.upper(),
            int(backoff),
            operation_name,
            str(error),
        )
        self._rotate_provider()
        return True

    # ------------------------------------------------------------------
    # Retry wrapper
    # ------------------------------------------------------------------

    def _execute_with_rpc_rotation(
        self,
        operation: Callable[[], T],
        operation_name: str = "rpc_call",
        is_write: bool = False,
    ) -> T:
        """Execute *operation* with RPC rotation and retry logic.

        For **read** operations: retries across RPCs on recoverable errors.

        For **write** operations (``is_write=True``): retries only on
        clear connection failures that occurred *before* the request
        reached the node.  Ambiguous timeouts are never retried to
        avoid double-submission.

        Raises the last exception if all retries are exhausted.
        """
        if not self._rotation_enabled:
            return operation()

        max_retries = min(MAX_RETRIES, len(self._rpc_urls) * 2)
        last_error: Optional[Exception] = None

        for attempt in range(max_retries + 1):
            try:
                return operation()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                last_error = exc
                category = classify_error(exc)

                # Write safety: only retry on clear pre-send failures
                if is_write and category not in ("connection", "fd_exhaustion"):
                    raise

                should_retry = self._handle_rpc_error_and_maybe_rotate(
                    exc, operation_name
                )
                if not should_retry or attempt >= max_retries:
                    raise

                delay = min(RETRY_DELAY * (2**attempt), MAX_RETRY_DELAY)
                _logger.info(
                    "%s attempt %d failed, retrying in %.1fs …",
                    operation_name,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)

        raise last_error  # type: ignore[misc]  # unreachable but keeps mypy happy
