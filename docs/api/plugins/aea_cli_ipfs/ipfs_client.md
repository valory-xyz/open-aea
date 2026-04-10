<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client"></a>

# plugins.aea-cli-ipfs.aea`_`cli`_`ipfs.ipfs`_`client

Lightweight IPFS HTTP API client.

Replaces the ``ipfshttpclient`` package. Talks directly to the IPFS
daemon's HTTP API (``/api/v0/*``) using ``urllib``.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSError"></a>

## IPFSError Objects

```python
class IPFSError(Exception)
```

Base IPFS client error.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.CommunicationError"></a>

## CommunicationError Objects

```python
class CommunicationError(IPFSError)
```

Could not communicate with the IPFS daemon.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.CommunicationError.__init__"></a>

#### `__`init`__`

```python
def __init__(*args: Any, **kwargs: Any) -> None
```

Initialize, accepting optional ``original`` for compat.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.TimeoutError"></a>

## TimeoutError Objects

```python
class TimeoutError(CommunicationError)
```

Request to the IPFS daemon timed out.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.StatusError"></a>

## StatusError Objects

```python
class StatusError(CommunicationError)
```

IPFS daemon returned an unexpected HTTP status.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.ErrorResponse"></a>

## ErrorResponse Objects

```python
class ErrorResponse(StatusError)
```

IPFS daemon returned a JSON error message.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._PinSection"></a>

## `_`PinSection Objects

```python
class _PinSection()
```

Pin management commands.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._PinSection.ls"></a>

#### ls

```python
def ls(type: str = "all") -> Dict
```

List pinned objects.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._PinSection.add"></a>

#### add

```python
def add(cid: str, recursive: bool = True) -> Dict
```

Pin an object.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._PinSection.rm"></a>

#### rm

```python
def rm(cid: str, recursive: bool = True) -> Dict
```

Unpin an object.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._NameSection"></a>

## `_`NameSection Objects

```python
class _NameSection()
```

IPNS name commands.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._NameSection.publish"></a>

#### publish

```python
def publish(ipfs_path: str, **kwargs: Any) -> Dict
```

Publish an IPNS name.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._RepoSection"></a>

## `_`RepoSection Objects

```python
class _RepoSection()
```

Repository commands.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client._RepoSection.gc"></a>

#### gc

```python
def gc(quiet: bool = False) -> List[Dict]
```

Run garbage collection.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSHTTPClient"></a>

## IPFSHTTPClient Objects

```python
class IPFSHTTPClient()
```

Lightweight IPFS HTTP API client.

Replaces ``ipfshttpclient.Client``. Communicates with the IPFS daemon
via its HTTP API at ``/api/v0/*``.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSHTTPClient.__init__"></a>

#### `__`init`__`

```python
def __init__(addr: str, base: str = "api/v0") -> None
```

Initialize client.

**Arguments**:

- `addr`: multiaddr string (e.g. ``/dns/host/tcp/443/https``).
- `base`: API base path.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSHTTPClient.id"></a>

#### id

```python
def id(peer: Optional[str] = None) -> Dict
```

Get node identity info.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSHTTPClient.add"></a>

#### add

```python
def add(file_or_dir: str,
        pin: bool = True,
        recursive: bool = True,
        wrap_with_directory: bool = True) -> Union[Dict, List[Dict]]
```

Add file or directory to IPFS.

**Arguments**:

- `file_or_dir`: path to file or directory.
- `pin`: whether to pin the content.
- `recursive`: whether to add recursively.
- `wrap_with_directory`: whether to wrap with directory.

**Returns**:

list of dicts with 'Name' and 'Hash' keys.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSHTTPClient.add_bytes"></a>

#### add`_`bytes

```python
def add_bytes(data: bytes, **kwargs: Any) -> str
```

Add bytes to IPFS.

**Arguments**:

- `data`: bytes to add.
- `kwargs`: additional keyword arguments.

**Returns**:

hash string.

<a id="plugins.aea-cli-ipfs.aea_cli_ipfs.ipfs_client.IPFSHTTPClient.get"></a>

#### get

```python
def get(cid: str, target: str = ".") -> None
```

Download a file or directory from IPFS.

The IPFS ``/api/v0/get`` endpoint returns a tar archive.

**Arguments**:

- `cid`: IPFS CID to download.
- `target`: local directory to extract into.

