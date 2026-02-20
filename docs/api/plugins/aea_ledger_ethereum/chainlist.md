<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist"></a>

# plugins.aea-ledger-ethereum.aea`_`ledger`_`ethereum.chainlist

Chainlist RPC enrichment — fetch, probe, and rank public RPCs.

Optional module that downloads public RPC endpoints from chainlist.org,
validates them with ``eth_blockNumber`` probes, filters stale ones, and
returns the best candidates sorted by latency.  Used as fallback RPCs
for the RPC rotation system.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.CACHE_TTL"></a>

#### CACHE`_`TTL

24 hours

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.PROBE_TIMEOUT"></a>

#### PROBE`_`TIMEOUT

seconds per probe

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.MAX_BLOCK_LAG"></a>

#### MAX`_`BLOCK`_`LAG

blocks behind median → stale

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.MAX_RPCS"></a>

#### MAX`_`RPCS

don't enrich beyond this

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.probe_rpc"></a>

#### probe`_`rpc

```python
def probe_rpc(
        url: str,
        timeout: float = PROBE_TIMEOUT) -> Optional[Tuple[str, float, int]]
```

Probe *url* with ``eth_blockNumber``.

Returns ``(url, latency_ms, block_number)`` on success, ``None`` on
failure.

**Arguments**:

- `url`: RPC endpoint URL to probe.
- `timeout`: request timeout in seconds.

**Returns**:

tuple of (url, latency_ms, block_number) or None on failure.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.RPCNode"></a>

## RPCNode Objects

```python
@dataclass
class RPCNode()
```

A single RPC entry from Chainlist.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.RPCNode.is_tracking"></a>

#### is`_`tracking

```python
@property
def is_tracking() -> bool
```

True if the RPC is known to track user data.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.ChainlistRPC"></a>

## ChainlistRPC Objects

```python
class ChainlistRPC()
```

Fetcher and parser for Chainlist RPC data with local caching.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.ChainlistRPC.__init__"></a>

#### `__`init`__`

```python
def __init__() -> None
```

Initialise with empty RPC data.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.ChainlistRPC.fetch_data"></a>

#### fetch`_`data

```python
def fetch_data(force_refresh: bool = False) -> None
```

Fetch RPC data from chainlist.org (cached for 24h).

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.ChainlistRPC.get_rpcs"></a>

#### get`_`rpcs

```python
def get_rpcs(chain_id: int) -> List[RPCNode]
```

Return parsed RPC nodes for *chain_id*.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.ChainlistRPC.get_validated_rpcs"></a>

#### get`_`validated`_`rpcs

```python
def get_validated_rpcs(chain_id: int,
                       existing_rpcs: List[str],
                       max_results: int = 5) -> List[str]
```

Return Chainlist RPCs filtered, probed, and sorted by quality.

Pipeline:
1. Fetch HTTPS RPCs from Chainlist for *chain_id*.
2. Filter out template URLs, duplicates, and non-HTTPS.
3. Probe top candidates in parallel with ``eth_blockNumber``.
4. Discard stale RPCs (block number lagging behind median).
5. Return up to *max_results* URLs sorted by latency.

**Arguments**:

- `chain_id`: numeric EVM chain identifier.
- `existing_rpcs`: URLs already known, used for deduplication.
- `max_results`: maximum number of validated RPCs to return.

**Returns**:

list of validated RPC URLs sorted by latency.

<a id="plugins.aea-ledger-ethereum.aea_ledger_ethereum.chainlist.enrich_rpc_urls"></a>

#### enrich`_`rpc`_`urls

```python
def enrich_rpc_urls(rpc_urls: List[str],
                    chain_id: Optional[int] = None,
                    max_rpcs: int = MAX_RPCS) -> List[str]
```

Enrich *rpc_urls* with validated public RPCs from Chainlist.

This is the main entry point for the RPC rotation system.
Returns the original URLs followed by any Chainlist fallbacks.

If *chain_id* is ``None`` or enrichment fails, returns *rpc_urls*
unchanged.

**Arguments**:

- `rpc_urls`: existing RPC URLs to enrich.
- `chain_id`: numeric EVM chain identifier, or None to skip enrichment.
- `max_rpcs`: upper bound on total RPC URLs to return.

**Returns**:

original URLs followed by any validated Chainlist fallbacks.

