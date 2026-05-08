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

"""RPC rotation support for EthereumApi as a Web3 ``HTTPProvider`` subclass.

When multiple RPC endpoints are provided (comma-separated), the
:class:`RotatingHTTPProvider` automatically fails over to healthy
endpoints on rate-limit, connection, or quota errors.  With a single
RPC URL the provider retries on transport failures without rotation.

Implementing rotation as a provider (rather than a middleware) keeps
the standard web3 middleware chain intact: every request runs through
the full chain — defaults plus any user-injected middleware — and only
the underlying transport changes when rotation occurs.
"""

import logging
import ssl
import threading
import time
from contextlib import nullcontext
from typing import Any, Dict, FrozenSet, List, Literal, Optional

from aea_ledger_ethereum.chainlist import enrich_rpc_urls
from web3 import HTTPProvider
from web3.types import RPCEndpoint, RPCResponse

# Closed set of error categories returned by :func:`classify_error`.  Using a
# ``Literal`` keeps the stringly-typed switches in ``make_request`` and
# ``_handle_error_and_rotate`` checkable by mypy and prevents future
# maintainers from adding a category without updating every call site.
ErrorCategory = Literal[
    "rate_limit", "connection", "quota", "server", "fd_exhaustion", "unknown"
]

_logger = logging.getLogger("aea.ledger_apis.ethereum.rpc_rotation")

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
        if isinstance(candidate, ConnectionResetError):
            return True
        if isinstance(candidate, ssl.SSLError) and not isinstance(
            candidate, ssl.SSLCertVerificationError
        ):
            return True
        if getattr(candidate, "errno", None) == 10054:  # WSAECONNRESET on Windows
            return True
        cause = getattr(candidate, "__cause__", None)
        context = getattr(candidate, "__context__", None)
        candidate = cause if cause is not None else context
    return False


def classify_error(error: Exception) -> ErrorCategory:
    """Classify an RPC error into a category.

    :param error: the exception raised by the RPC call.
    :return: one of ``"rate_limit"``, ``"connection"``, ``"quota"``,
        ``"server"``, ``"fd_exhaustion"``, ``"unknown"``.
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
# Provider
# ---------------------------------------------------------------------------


class RotatingHTTPProvider(HTTPProvider):
    """:class:`~web3.HTTPProvider` that rotates RPC endpoints on transport failures.

    Manages a pool of :class:`~web3.HTTPProvider` instances with
    per-endpoint health tracking, automatic failover, and
    exponential-backoff retry logic.  Because rotation happens at the
    transport layer (inside :meth:`make_request`) rather than as a web3
    middleware, the standard middleware chain — defaults plus any
    user-injected middleware — runs untouched on every call.

    For **write** operations (``eth_sendRawTransaction``,
    ``eth_sendTransaction``) only clear pre-send connection failures are
    retried to prevent double-submission.

    Usage::

        provider = RotatingHTTPProvider(
            rpc_urls=["https://rpc1.example.com", "https://rpc2.example.com"],
            request_kwargs={"timeout": 10},
            chain_id=100,
        )
        w3 = Web3(provider)
    """

    def __init__(
        self,
        rpc_urls: List[str],
        request_kwargs: Optional[Dict[str, Any]] = None,
        chain_id: Optional[int] = None,
    ) -> None:
        """Initialize the rotating provider.

        :param rpc_urls: list of RPC endpoint URL strings (required, non-empty).
        :param request_kwargs: dict forwarded to each pooled :class:`HTTPProvider`.
        :param chain_id: optional chain ID for Chainlist fallback enrichment.
        :raises ValueError: if ``rpc_urls`` (after Chainlist enrichment) is empty.
        """
        if request_kwargs is None:
            request_kwargs = {}

        rpc_urls = enrich_rpc_urls(rpc_urls, chain_id=chain_id)
        if not rpc_urls:
            raise ValueError("RotatingHTTPProvider requires at least one RPC URL.")

        # Set the attributes the ``endpoint_uri`` getter reads *before*
        # calling ``super().__init__``.  The parent constructor writes to
        # ``self.endpoint_uri`` (which our no-op setter absorbs); some web3
        # code paths read ``endpoint_uri`` from within the parent init —
        # hoisting these assignments keeps the getter defensible regardless
        # of which parent code paths are taken on a future web3 upgrade.
        # When upgrading web3.py: re-verify ``HTTPProvider.__init__`` still
        # does not read ``self.endpoint_uri`` after assignment, and that
        # the rotating provider is never constructed with ``session=...``
        # passed through (parent reads ``endpoint_uri`` in that branch).
        self._rpc_urls: List[str] = rpc_urls
        self._current_index: int = 0

        # ``isinstance(self, HTTPProvider)`` must hold so web3 treats us
        # as a proper provider; the parent's session/transport machinery
        # is otherwise unused since every request is delegated to one of
        # ``self._providers``.
        super().__init__(endpoint_uri=rpc_urls[0], request_kwargs=request_kwargs)

        self._providers: List[HTTPProvider] = [
            HTTPProvider(endpoint_uri=url, request_kwargs=request_kwargs)
            for url in rpc_urls
        ]
        self._backoff_until: Dict[int, float] = {}
        # Reentrant so health-tracking helpers can be called both directly
        # (from ``_handle_error_and_rotate``) and from inside ``_rotate``,
        # which already holds the lock when iterating candidates.
        self._lock: threading.RLock = threading.RLock()
        self._last_rotation_time: float = 0.0

        # Surface that the configured MAX_RETRIES is being clamped by the
        # (small) provider pool — common for single-URL deployments.  Logged
        # once at construction rather than per-request to avoid log spam.
        uncapped_retries = len(rpc_urls) * 2
        if uncapped_retries < MAX_RETRIES:
            _logger.info(
                "RotatingHTTPProvider: retry budget capped at %d "
                "(RPC count=%d, MAX_RETRIES=%d)",
                uncapped_retries,
                len(rpc_urls),
                MAX_RETRIES,
            )

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

    @property  # type: ignore[override]
    def endpoint_uri(self) -> str:  # type: ignore[override]
        """Return the URL of the currently active RPC endpoint.

        Overrides :attr:`HTTPProvider.endpoint_uri` so that diagnostic tooling
        (metrics, logging, request IDs) reading ``w3.provider.endpoint_uri``
        observes the URL we are *currently* dispatching to rather than the
        URL passed to ``super().__init__``.

        :return: the active RPC URL.
        """
        return self._rpc_urls[self._current_index]

    @endpoint_uri.setter
    def endpoint_uri(self, value: str) -> None:
        """No-op setter retained for parent-class compatibility.

        :param value: ignored.  ``HTTPProvider.__init__`` assigns to
            ``endpoint_uri`` once at construction; we accept the write so the
            parent constructor does not raise, but the active endpoint is
            always derived from ``self._rpc_urls[self._current_index]``.
        """
        # Surface the no-op so a future caller doing
        # ``provider.endpoint_uri = "https://override"`` can see at DEBUG
        # level that the assignment did not change the active endpoint.
        _logger.debug(
            "RotatingHTTPProvider ignores endpoint_uri assignment to %r; "
            "active URL is derived from self._rpc_urls[self._current_index]",
            value,
        )

    # ------------------------------------------------------------------
    # Per-RPC health tracking
    # ------------------------------------------------------------------

    def _mark_rpc_backoff(self, index: int, seconds: float) -> None:
        """Mark an RPC as temporarily unavailable for *seconds*.

        :param index: provider index in ``self._providers``.
        :param seconds: backoff duration in seconds.
        """
        with self._lock:
            self._backoff_until[index] = time.monotonic() + seconds

    def _is_rpc_healthy(self, index: int) -> bool:
        """Return ``True`` if the RPC at *index* is not in backoff.

        :param index: provider index in ``self._providers``.
        :return: ``True`` if not in backoff (or never marked).
        """
        with self._lock:
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
            if session_mgr is None:
                _logger.warning(
                    "Provider #%d: HTTPProvider has no '_request_session_manager'; skipping session eviction.",
                    index,
                )
                return

            # Read session_cache and clear it under the lock when one exists,
            # so both the reference and the mutation are protected. Fall back
            # to a nullcontext when the session manager doesn't expose a lock.
            lock = getattr(session_mgr, "_lock", None)
            with lock if lock is not None else nullcontext():
                cache = getattr(session_mgr, "session_cache", None)
                if cache is None:
                    _logger.warning(
                        "Provider #%d: session_mgr has no 'session_cache'; skipping session eviction.",
                        index,
                    )
                    return
                cache.clear()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            _logger.warning(
                "Session eviction failed for provider #%d: %s",
                index,
                exc,
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def _handle_error_and_rotate(
        self,
        error: Exception,
        operation: str,
        index: int,
        category: Optional[ErrorCategory] = None,
    ) -> bool:
        """Apply backoff and rotation for an error.

        :param error: the transport-level exception.
        :param operation: human-readable label for log messages.
        :param index: provider index that was active when the error occurred.
        :param category: optional pre-computed result of :func:`classify_error`.
            Pass-through when the caller has already classified the error to
            avoid a redundant string scan; defaults to running the classifier.
        :return: ``True`` if the caller should retry.
        """
        if category is None:
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
            # Surface the unclassified error so operators can spot novel
            # transport issues; the caller will re-raise without retry.
            _logger.warning(
                "RPC #%d unclassified error during %s (will not retry): %.120s",
                index,
                operation,
                str(error),
            )
            return False

        if category == "connection":
            # Evict the stale session so the retry gets a fresh TCP/TLS handshake.
            self._evict_provider_session(index)

        backoff = _BACKOFF_MAP.get(category, 0.0)
        self._mark_rpc_backoff(index, backoff)
        _logger.warning(
            "RPC #%d %s error (backoff %ds) during %s: %.120s",
            index,
            category.upper(),
            int(backoff),
            operation,
            str(error),
        )
        self._rotate()
        return True

    # ------------------------------------------------------------------
    # make_request — the rotation/retry loop
    # ------------------------------------------------------------------

    def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        """Dispatch a JSON-RPC call with rotation and retry across the pool.

        Each attempt routes to the currently-active pooled provider.  On a
        retryable transport failure the offending provider is marked unhealthy,
        rotation advances to the next healthy peer, and the call is retried
        (with exponential backoff) until the per-call retry budget is
        exhausted.  Write methods are retried only on clear pre-send failures
        so a partially-submitted transaction is never re-broadcast.

        :param method: JSON-RPC method name.
        :param params: JSON-RPC parameters.
        :return: the JSON-RPC response.
        """
        is_write = method in WRITE_RPC_METHODS
        url_count = len(self._rpc_urls)
        max_retries = min(MAX_RETRIES, url_count * 2)

        for attempt in range(max_retries + 1):
            used_index = self._current_index  # snapshot before the call
            try:
                return self._providers[used_index].make_request(method, params)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                category = classify_error(exc)

                # Write safety: only retry on clear pre-send failures
                if is_write and category not in ("connection", "fd_exhaustion"):
                    raise

                should_retry = self._handle_error_and_rotate(
                    exc, str(method), used_index, category
                )
                if not should_retry:
                    raise
                if attempt >= max_retries:
                    # All retries used up across the provider pool: surface
                    # a single summary so a systemic outage is distinguishable
                    # from a one-off transient failure.
                    _logger.warning(
                        "%s: exhausted %d retries across %d provider(s); "
                        "last error category=%s, last error=%.120s",
                        method,
                        max_retries,
                        url_count,
                        category,
                        str(exc),
                    )
                    raise

                delay = min(RETRY_DELAY * (2**attempt), MAX_RETRY_DELAY)
                _logger.info(
                    "%s attempt %d failed, retrying in %.1fs …",
                    method,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)

        # Unreachable: ``range(max_retries + 1)`` always yields at least one
        # iteration which either returns successfully or re-raises above.
        raise AssertionError(  # pragma: no cover
            "unreachable: retry loop exited without returning"
        )
