<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation"></a>

# plugins.aea-ledger-ethereum.aea`_`ledger`_`ethereum.rpc`_`rotation

RPC rotation support for EthereumApi as a web3 middleware.

When multiple RPC endpoints are provided (comma-separated), the
:class:`RPCRotationMiddleware` automatically fails over to healthy
endpoints on rate-limit, connection, or quota errors.  With a single
RPC URL the middleware retries on transport failures without rotation.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.MakeRequestFn"></a>

#### MakeRequestFn

web3 typing alias

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
def classify_error(error: Exception) -> str
```

Classify an RPC error into a category.

Returns one of:
``"rate_limit"``, ``"connection"``, ``"quota"``, ``"server"``,
``"fd_exhaustion"``, or ``"unknown"``.

**Arguments**:

- `error`: the exception raised by the RPC call.

**Returns**:

error category string.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMiddleware"></a>

## RPCRotationMiddleware Objects

```python
class RPCRotationMiddleware(Web3MiddlewareBuilder)
```

Web3 middleware that rotates RPC endpoints on transport failures.

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

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMiddleware.build"></a>

#### build

```python
@classmethod
def build(cls,
          w3: Union[AsyncWeb3, Web3],
          rpc_urls: List[str],
          request_kwargs: Optional[Dict[str, Any]] = None,
          chain_id: Optional[int] = None) -> "RPCRotationMiddleware"
```

Build the middleware.

**Arguments**:

- `w3`: the Web3 instance.
- `rpc_urls`: list of RPC endpoint URL strings (required).
- `request_kwargs`: dict forwarded to each HTTPProvider.
- `chain_id`: optional chain ID for Chainlist fallback enrichment.

**Returns**:

configured :class:`RPCRotationMiddleware` instance.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMiddleware.__call__"></a>

#### `__`call`__`

```python
def __call__(w3: Any = None) -> "RPCRotationMiddleware"
```

Allow this pre-built instance to be stored directly in the middleware onion.

web3's ``combine_middleware`` calls ``mw(w3)`` on each entry; returning
``self`` ensures the already-initialised instance is reused unchanged.

**Arguments**:

- `w3`: web3 instance (ignored — already set on build).

**Returns**:

this middleware instance.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMiddleware.current_rpc_url"></a>

#### current`_`rpc`_`url

```python
@property
def current_rpc_url() -> str
```

Return the currently active RPC URL.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMiddleware.rpc_count"></a>

#### rpc`_`count

```python
@property
def rpc_count() -> int
```

Return the number of configured RPC endpoints.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMiddleware.wrap_make_request"></a>

#### wrap`_`make`_`request

```python
def wrap_make_request(make_request: MakeRequestFn) -> MakeRequestFn
```

Wrap the JSON-RPC make_request with retry and rotation logic.

**Arguments**:

- `make_request`: the next function in the middleware chain.

**Returns**:

wrapped make_request function.

