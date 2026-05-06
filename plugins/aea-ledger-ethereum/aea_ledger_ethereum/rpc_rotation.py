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

"""RPC rotation support for EthereumApi as a web3 middleware.

When multiple RPC endpoints are provided (comma-separated), the
:class:`RPCRotationMiddleware` automatically fails over to healthy
endpoints on rate-limit, connection, or quota errors.  With a single
RPC URL the middleware retries on transport failures without rotation.
"""

import logging
import ssl
import threading
import time
from typing import Any, Dict, FrozenSet, List, Optional, Union

from aea_ledger_ethereum.chainlist import enrich_rpc_urls
from web3 import AsyncWeb3, HTTPProvider, Web3
from web3.middleware.base import Web3MiddlewareBuilder
from web3.types import RPCEndpoint, RPCResponse

_logger = logging.getLogger("aea.ledger_apis.ethereum.rpc_rotation")

MakeRequestFn = Any  # web3 typing alias

# ---------------------------------------------------------------------------
# Write RPC methods — retried only on clear pre-send failures
# ---------------------------------------------------------------------------

WRITE_RPC_METHODS: FrozenSet[str] = frozenset(
    {"eth_sendRawTransaction", "eth_sendTransaction"}
)

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

    :param address: single RPC URL or comma-separated list of URLs.
    :return: list of parsed RPC URL strings.
    """
    if "," in address:
        urls = [url.strip() for url in address.split(",") if url.strip()]
        return urls if urls else [address]
    return [address.strip()]


def _is_connection_reset(error: BaseException) -> bool:
    """Return ``True`` if *error* (or its cause chain) is a connection-reset.

    Checks exception type and ``errno`` so locale-specific OS error messages
    (e.g. Chinese or Spanish WSAECONNRESET text) do not cause misses.
    Walks ``__cause__`` / ``__context__`` chains for wrapped exceptions.

    :param error: exception to inspect.
    :return: ``True`` if the error indicates a connection reset.
    """
    seen: set = set()
    candidate: Optional[BaseException] = error
    while candidate is not None and id(candidate) not in seen:
        seen.add(id(candidate))
        if isinstance(candidate, (ConnectionResetError, ssl.SSLEOFError)):
            return True
        if getattr(candidate, "errno", None) == 10054:  # WSAECONNRESET on Windows
            return True
        cause = getattr(candidate, "__cause__", None)
        context = getattr(candidate, "__context__", None)
        candidate = cause if cause is not None else context
    return False


def classify_error(error: Exception) -> str:
    """Classify an RPC error into a category.

    Returns one of:
    ``"rate_limit"``, ``"connection"``, ``"quota"``, ``"server"``,
    ``"fd_exhaustion"``, or ``"unknown"``.

    :param error: the exception raised by the RPC call.
    :return: error category string.
    """
    # Locale-safe class-based checks first — English-only string matching
    # misses localized OS error messages (Spanish, Chinese WSAECONNRESET text).
    if _is_connection_reset(error):
        return "connection"

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
# Middleware
# ---------------------------------------------------------------------------


class RPCRotationMiddleware(Web3MiddlewareBuilder):
    """Web3 middleware that rotates RPC endpoints on transport failures.

    Manages a pool of :class:`~web3.HTTPProvider` instances with
    per-endpoint health tracking, automatic failover, and
    exponential-backoff retry logic.

    For **write** operations (``eth_sendRawTransaction``,
    ``eth_sendTransaction``) only clear pre-send connection failures are
    retried to prevent double-submission.

    Usage::

        rpc_rotation = RPCRotationMiddleware.build(
            w3,
            rpc_urls=["https://rpc1.example.com", "https://rpc2.example.com"],
            request_kwargs={"timeout": 10},
            chain_id=100,
        )
        web3.middleware_onion.add(rpc_rotation)
    """

    # Set by build()
    _rpc_urls: List[str]
    _request_kwargs: Dict[str, Any]
    _providers: List[HTTPProvider]
    _current_index: int
    _backoff_until: Dict[int, float]
    _lock: threading.Lock
    _last_rotation_time: float

    @classmethod
    def build(  # pylint: disable=arguments-differ
        cls,
        w3: Union[AsyncWeb3, Web3],
        rpc_urls: List[str],
        request_kwargs: Optional[Dict[str, Any]] = None,
        chain_id: Optional[int] = None,
    ) -> "RPCRotationMiddleware":
        """Build the middleware.

        :param w3: the Web3 instance.
        :param rpc_urls: list of RPC endpoint URL strings (required).
        :param request_kwargs: dict forwarded to each HTTPProvider.
        :param chain_id: optional chain ID for Chainlist fallback enrichment.
        :return: configured :class:`RPCRotationMiddleware` instance.
        """
        if request_kwargs is None:
            request_kwargs = {}

        rpc_urls = enrich_rpc_urls(rpc_urls, chain_id=chain_id)

        mw = cls(w3)
        mw._rpc_urls = rpc_urls  # pylint: disable=protected-access
        mw._request_kwargs = request_kwargs  # pylint: disable=protected-access
        mw._providers = [  # pylint: disable=protected-access
            HTTPProvider(endpoint_uri=url, request_kwargs=request_kwargs)
            for url in rpc_urls
        ]
        mw._current_index = 0  # pylint: disable=protected-access
        mw._backoff_until = {}  # pylint: disable=protected-access
        mw._lock = threading.Lock()  # pylint: disable=protected-access
        mw._last_rotation_time = 0.0  # pylint: disable=protected-access
        return mw

    def __call__(self, w3: Any = None) -> "RPCRotationMiddleware":
        """Allow this pre-built instance to be stored directly in the middleware onion.

        web3's ``combine_middleware`` calls ``mw(w3)`` on each entry; returning
        ``self`` ensures the already-initialised instance is reused unchanged.

        :param w3: web3 instance (ignored — already set on build).
        :return: this middleware instance.
        """
        return self

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------

    @property
    def current_rpc_url(self) -> str:
        """Return the currently active RPC URL."""
        return self._rpc_urls[self._current_index]

    @property
    def rpc_count(self) -> int:
        """Return the number of configured RPC endpoints."""
        return len(self._rpc_urls)

    # ------------------------------------------------------------------
    # Per-RPC health tracking
    # ------------------------------------------------------------------

    def _mark_rpc_backoff(self, index: int, seconds: float) -> None:
        """Mark an RPC as temporarily unavailable for *seconds*."""
        self._backoff_until[index] = time.monotonic() + seconds

    def _is_rpc_healthy(self, index: int) -> bool:
        """Return ``True`` if the RPC at *index* is not in backoff."""
        return time.monotonic() >= self._backoff_until.get(index, 0.0)

    # ------------------------------------------------------------------
    # Provider rotation
    # ------------------------------------------------------------------

    def _rotate(self) -> bool:
        """Rotate to the next healthy RPC endpoint.

        :return: ``True`` if a rotation occurred, ``False`` otherwise.
        """
        with self._lock:
            n = len(self._rpc_urls)
            if n <= 1:
                return False

            now = time.monotonic()
            if now - self._last_rotation_time < ROTATION_COOLDOWN:
                return False

            best: Optional[int] = None
            for offset in range(1, n):
                candidate = (self._current_index + offset) % n
                if self._is_rpc_healthy(candidate):
                    best = candidate
                    break

            if best is None:
                best = min(
                    (i for i in range(n) if i != self._current_index),
                    key=lambda i: self._backoff_until.get(i, 0.0),
                )

            self._current_index = best
            self._last_rotation_time = now
            _logger.info("Rotated RPC to #%d: %s", best, self._rpc_urls[best])
            return True

    # ------------------------------------------------------------------
    # Session eviction
    # ------------------------------------------------------------------

    def _evict_provider_session(self, index: int) -> None:
        """Evict the cached ``requests.Session`` for the provider at *index*.

        On a connection reset (WSAECONNRESET / errno 10054) the HTTP keep-alive
        pool holds a stale socket.  Clearing the session cache forces a fresh
        TCP/TLS handshake on the next retry rather than reusing the broken
        connection.  The ``lru_cache``-backed pool cannot evict individual
        entries, so the whole cache is cleared — the overhead of re-establishing
        connections is negligible compared to the cost of a stuck withdrawal.

        This is best-effort: if the internal attribute layout of the web3
        ``HTTPProvider`` differs across versions, a warning is logged and the
        eviction is skipped — the retry still proceeds (with the stale socket).

        :param index: index into ``self._providers``.
        """
        try:
            provider = self._providers[index]
            session_mgr = getattr(provider, "_request_session_manager", None)
            if session_mgr is not None:
                cache = getattr(session_mgr, "session_cache", None)
                if cache is not None:
                    lock = getattr(session_mgr, "_lock", None)
                    if lock is not None:
                        with lock:
                            cache.clear()
                    else:
                        cache.clear()
                else:
                    _logger.warning(
                        "Provider #%d: session_mgr has no 'session_cache'; skipping session eviction.",
                        index,
                    )
            else:
                _logger.warning(
                    "Provider #%d: HTTPProvider has no '_request_session_manager'; skipping session eviction.",
                    index,
                )
        except Exception:  # pylint: disable=broad-exception-caught  # nosec B110
            pass  # Never mask the original error

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def _handle_error_and_rotate(self, error: Exception, operation: str) -> bool:
        """Classify *error*, apply backoff, and rotate.

        :param error: the transport-level exception.
        :param operation: human-readable label for log messages.
        :return: ``True`` if the caller should retry.
        """
        category = classify_error(error)

        if category == "fd_exhaustion":
            _logger.error(
                "FD exhaustion detected — pausing ALL RPCs for %ds.",
                int(FD_EXHAUSTION_BACKOFF),
            )
            for i in range(len(self._rpc_urls)):
                self._mark_rpc_backoff(i, FD_EXHAUSTION_BACKOFF)
            self._rotate()
            return True

        if category == "unknown":
            return False

        if category == "connection":
            # Evict the stale session so the retry gets a fresh TCP/TLS handshake.
            self._evict_provider_session(self._current_index)

        backoff = _BACKOFF_MAP.get(category, 0.0)
        self._mark_rpc_backoff(self._current_index, backoff)
        _logger.warning(
            "RPC #%d %s error (backoff %ds) during %s: %.120s",
            self._current_index,
            category.upper(),
            int(backoff),
            operation,
            str(error),
        )
        self._rotate()
        return True

    # ------------------------------------------------------------------
    # wrap_make_request
    # ------------------------------------------------------------------

    def wrap_make_request(self, make_request: MakeRequestFn) -> MakeRequestFn:  # pylint: disable=unused-argument
        """Wrap the JSON-RPC make_request with retry and rotation logic.

        :param make_request: the next function in the middleware chain.
        :return: wrapped make_request function.
        """

        def middleware(method: RPCEndpoint, params: Any) -> RPCResponse:
            """Middleware function to override the request with."""
            is_write = method in WRITE_RPC_METHODS
            max_retries = min(MAX_RETRIES, len(self._rpc_urls) * 2)
            last_error: Optional[Exception] = None

            for attempt in range(max_retries + 1):
                try:
                    return self._providers[self._current_index].make_request(
                        method, params
                    )
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    last_error = exc
                    category = classify_error(exc)

                    # Write safety: only retry on clear pre-send failures
                    if is_write and category not in ("connection", "fd_exhaustion"):
                        raise

                    should_retry = self._handle_error_and_rotate(exc, str(method))
                    if not should_retry or attempt >= max_retries:
                        raise

                    delay = min(RETRY_DELAY * (2**attempt), MAX_RETRY_DELAY)
                    _logger.info(
                        "%s attempt %d failed, retrying in %.1fs …",
                        method,
                        attempt + 1,
                        delay,
                    )
                    time.sleep(delay)

            raise last_error  # type: ignore[misc]

        return middleware
