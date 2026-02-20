<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation"></a>

# plugins.aea-ledger-ethereum.aea`_`ledger`_`ethereum.rpc`_`rotation

RPC rotation support for EthereumApi with automatic failover and backoff.

When multiple RPC endpoints are provided (comma-separated), the plugin
automatically rotates to healthy endpoints on rate-limit, connection,
or quota errors.  With a single RPC URL the mixin is effectively a no-op.

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

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMixin"></a>

## RPCRotationMixin Objects

```python
class RPCRotationMixin()
```

Mixin providing RPC rotation capabilities for EthereumApi.

Manages a pool of RPC endpoints with per-endpoint health tracking,
automatic failover on errors, and exponential-backoff retry logic.

When a single RPC URL is provided the mixin is effectively a no-op:
``_rotation_enabled`` is ``False`` and ``_execute_with_rpc_rotation``
simply calls the operation once.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMixin.current_rpc_url"></a>

#### current`_`rpc`_`url

```python
@property
def current_rpc_url() -> str
```

Return the currently active RPC URL.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.rpc_rotation.RPCRotationMixin.rpc_count"></a>

#### rpc`_`count

```python
@property
def rpc_count() -> int
```

Return the number of configured RPC endpoints.

