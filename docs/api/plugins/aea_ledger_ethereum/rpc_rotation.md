<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation"></a>

# plugins.aea-ledger-ethereum.aea`_`ledger`_`ethereum.rpc`_`rotation

RPC rotation support for EthereumApi as a Web3 ``HTTPProvider`` subclass.

When multiple RPC endpoints are provided (comma-separated), the
:class:`RotatingHTTPProvider` automatically fails over to healthy
endpoints on rate-limit, connection, or quota errors.  With a single
RPC URL the provider retries on transport failures without rotation.

Implementing rotation as a provider (rather than a middleware) keeps
the standard web3 middleware chain intact: every request runs through
the full chain — defaults plus any user-injected middleware — and only
the underlying transport changes when rotation occurs.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RETRY_DELAY"></a>

#### RETRY`_`DELAY

base delay between retries (exponential backoff)

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.MAX_RETRY_DELAY"></a>

#### MAX`_`RETRY`_`DELAY

cap on retry delay

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.ROTATION_COOLDOWN"></a>

#### ROTATION`_`COOLDOWN

min time between rotations to prevent cascade

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.parse_rpc_urls"></a>

#### parse`_`rpc`_`urls

```python
def parse_rpc_urls(address: str) -> List[str]
```

Parse RPC URL(s) from an *address* string.

Supports a single URL or a comma-separated list.
Returns a list with at least one URL.

**Arguments**:

- `address`: single RPC URL or comma-separated list of URLs.

**Returns**:

list of parsed RPC URL strings.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.classify_error"></a>

#### classify`_`error

```python
def classify_error(error: Exception) -> ErrorCategory
```

Classify an RPC error into a category.

**Arguments**:

- `error`: the exception raised by the RPC call.

**Returns**:

one of ``"rate_limit"``, ``"connection"``, ``"quota"``,
``"server"``, ``"fd_exhaustion"``, ``"unknown"``.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider"></a>

## RotatingHTTPProvider Objects

```python
class RotatingHTTPProvider(HTTPProvider)
```

:class:`~web3.HTTPProvider` that rotates RPC endpoints on transport failures.

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

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider.__init__"></a>

#### `__`init`__`

```python
def __init__(rpc_urls: List[str],
             request_kwargs: Optional[Dict[str, Any]] = None,
             chain_id: Optional[int] = None) -> None
```

Initialize the rotating provider.

**Arguments**:

- `rpc_urls`: list of RPC endpoint URL strings (required, non-empty).
- `request_kwargs`: dict forwarded to each pooled :class:`HTTPProvider`.
- `chain_id`: optional chain ID for Chainlist fallback enrichment.

**Raises**:

- `ValueError`: if ``rpc_urls`` (after Chainlist enrichment) is empty.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider.current_rpc_url"></a>

#### current`_`rpc`_`url

```python
@property
def current_rpc_url() -> str
```

Return the currently active RPC URL.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider.rpc_count"></a>

#### rpc`_`count

```python
@property
def rpc_count() -> int
```

Return the number of configured RPC endpoints.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider.endpoint_uri"></a>

#### endpoint`_`uri

```python
@property
def endpoint_uri() -> str
```

Return the URL of the currently active RPC endpoint.

Overrides :attr:`HTTPProvider.endpoint_uri` so that diagnostic tooling
(metrics, logging, request IDs) reading ``w3.provider.endpoint_uri``
observes the URL we are *currently* dispatching to rather than the
URL passed to ``super().__init__``.

**Returns**:

the active RPC URL.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider.endpoint_uri"></a>

#### endpoint`_`uri

```python
@endpoint_uri.setter
def endpoint_uri(value: str) -> None
```

No-op setter retained for parent-class compatibility.

**Arguments**:

- `value`: ignored.  ``HTTPProvider.__init__`` assigns to
``endpoint_uri`` once at construction; we accept the write so the
parent constructor does not raise, but the active endpoint is
always derived from ``self._rpc_urls[self._current_index]``.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RotatingHTTPProvider.make_request"></a>

#### make`_`request

```python
def make_request(method: RPCEndpoint, params: Any) -> RPCResponse
```

Dispatch a JSON-RPC call with rotation and retry across the pool.

Each attempt routes to the currently-active pooled provider.  On a
retryable transport failure the offending provider is marked unhealthy,
rotation advances to the next healthy peer, and the call is retried
(with exponential backoff) until the per-call retry budget is
exhausted.  Write methods are retried only on clear pre-send failures
so a partially-submitted transaction is never re-broadcast.

**Arguments**:

- `method`: JSON-RPC method name.
- `params`: JSON-RPC parameters.

**Returns**:

the JSON-RPC response.

