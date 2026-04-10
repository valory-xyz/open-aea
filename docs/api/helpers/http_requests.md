<a id="aea.helpers.http_requests"></a>

# aea.helpers.http`_`requests

Minimal HTTP helpers backed by :mod:`urllib` from the standard library.

Replaces the ``requests`` package for the few HTTP calls the core
framework needs (registry API, package downloads, GitHub tag fetches).

<a id="aea.helpers.http_requests._ConditionalNoRedirectHandler"></a>

## `_`ConditionalNoRedirectHandler Objects

```python
class _ConditionalNoRedirectHandler(urllib.request.HTTPRedirectHandler)
```

Match requests' default redirect behaviour per HTTP method.

requests.get() follows redirects by default (allow_redirects=True),
while requests.post()/put()/delete()/patch() do NOT follow redirects
(allow_redirects=False). urllib.request's default follows everything
— including silently turning POST→GET on 30x, which is a silent
behaviour change. This handler suppresses redirects only for unsafe
methods and lets the default HTTPRedirectHandler follow them for
safe methods like GET/HEAD.

Also backports 308 (Permanent Redirect) handling: Python 3.11+
handles 308 natively in HTTPRedirectHandler, but 3.10 is missing
``http_error_308`` AND ``redirect_request`` does not include 308
in its allowed-codes tuple. Without this backport, a CDN returning
308 on a GET would surface as ``HTTPResponse(308, ...)`` and break
downstream callers like ``download_file``.

<a id="aea.helpers.http_requests._ConditionalNoRedirectHandler.redirect_request"></a>

#### redirect`_`request

```python
def redirect_request(req: urllib.request.Request, fp: Any, code: int, msg: str,
                     headers: Any,
                     newurl: str) -> Optional[urllib.request.Request]
```

Suppress redirects for unsafe methods, follow for safe ones.

**Arguments**:

- `req`: the original request.
- `fp`: the response file-like object.
- `code`: HTTP status code.
- `msg`: HTTP status message.
- `headers`: response headers.
- `newurl`: the redirect target URL.

**Returns**:

a new Request to follow, or None to suppress.

<a id="aea.helpers.http_requests._ConditionalNoRedirectHandler.http_error_308"></a>

#### http`_`error`_`308

```python
def http_error_308(req: urllib.request.Request, fp: Any, code: int, msg: str,
                   headers: Any) -> Optional[Any]
```

Treat 308 the same as 301 (permanent redirect).

Python 3.11+ provides this natively; this backport makes 308
work on 3.10.

**Arguments**:

- `req`: the original request.
- `fp`: the response file-like object.
- `code`: HTTP status code (308).
- `msg`: HTTP status message.
- `headers`: response headers.

**Returns**:

redirected response or None.

<a id="aea.helpers.http_requests.HTTPResponse"></a>

## HTTPResponse Objects

```python
class HTTPResponse()
```

Lightweight response wrapper matching the subset of requests.Response used in aea.

<a id="aea.helpers.http_requests.HTTPResponse.__init__"></a>

#### `__`init`__`

```python
def __init__(status_code: int, data: bytes, url: str = "") -> None
```

Initialize HTTPResponse.

**Arguments**:

- `status_code`: HTTP status code.
- `data`: response body bytes.
- `url`: request URL.

<a id="aea.helpers.http_requests.HTTPResponse.text"></a>

#### text

```python
@property
def text() -> str
```

Response body as string.

<a id="aea.helpers.http_requests.HTTPResponse.content"></a>

#### content

```python
@property
def content() -> bytes
```

Response body as bytes.

<a id="aea.helpers.http_requests.HTTPResponse.json"></a>

#### json

```python
def json() -> Any
```

Parse response body as JSON.

<a id="aea.helpers.http_requests.HTTPResponse.read"></a>

#### read

```python
def read() -> bytes
```

Read response body (for compatibility with file-like usage).

<a id="aea.helpers.http_requests.ConnectionError"></a>

## ConnectionError Objects

```python
class ConnectionError(OSError)
```

HTTP connection error.

<a id="aea.helpers.http_requests.request"></a>

#### request

```python
def request(method: str,
            url: str,
            params: Optional[Dict[str, str]] = None,
            data: Optional[Union[bytes, Dict[str, str]]] = None,
            headers: Optional[Dict[str, str]] = None,
            files: Optional[Dict[str, Any]] = None,
            timeout: float = DEFAULT_TIMEOUT) -> HTTPResponse
```

Perform an HTTP request using urllib.

**Arguments**:

- `method`: HTTP method (GET, POST, PUT, etc.).
- `url`: the URL.
- `params`: optional query parameters.
- `data`: optional body data (bytes or dict for form-encoded).
- `headers`: optional headers dict.
- `files`: optional dict of {field: file_obj} for multipart upload.
- `timeout`: request timeout in seconds.

**Raises**:

- `ValueError`: if the URL scheme is not http or https.
- `ConnectionError`: on connection failure.

**Returns**:

HTTPResponse.

<a id="aea.helpers.http_requests.get"></a>

#### get

```python
def get(url: str,
        timeout: float = DEFAULT_TIMEOUT,
        **kwargs: Any) -> HTTPResponse
```

HTTP GET.

**Arguments**:

- `url`: the URL.
- `timeout`: request timeout in seconds.
- `kwargs`: additional keyword arguments passed to request().

**Returns**:

HTTPResponse.

<a id="aea.helpers.http_requests.post"></a>

#### post

```python
def post(url: str,
         timeout: float = DEFAULT_TIMEOUT,
         **kwargs: Any) -> HTTPResponse
```

HTTP POST.

**Arguments**:

- `url`: the URL.
- `timeout`: request timeout in seconds.
- `kwargs`: additional keyword arguments passed to request().

**Returns**:

HTTPResponse.

<a id="aea.helpers.http_requests.head"></a>

#### head

```python
def head(url: str,
         timeout: float = DEFAULT_TIMEOUT,
         **kwargs: Any) -> HTTPResponse
```

HTTP HEAD.

**Arguments**:

- `url`: the URL.
- `timeout`: request timeout in seconds.
- `kwargs`: additional keyword arguments passed to request().

**Returns**:

HTTPResponse.

<a id="aea.helpers.http_requests._ExceptionsShim"></a>

## `_`ExceptionsShim Objects

```python
class _ExceptionsShim()
```

Namespace shim exposing the old requests.exceptions.* names.

Provides ConnectionError and RequestException as aliases of our
ConnectionError for backwards compatibility with code that catches
``requests.exceptions.ConnectionError`` via the old wrapper.

<a id="aea.helpers.http_requests._ExceptionsShim.ConnectionError"></a>

#### ConnectionError

noqa: A003

<a id="aea.helpers.http_requests.download_to_file"></a>

#### download`_`to`_`file

```python
def download_to_file(url: str,
                     filepath: str,
                     timeout: float = DEFAULT_TIMEOUT,
                     chunk_size: int = 262144) -> int
```

Stream the response body to a file in fixed-size chunks.

Avoids buffering large downloads in memory.

**Arguments**:

- `url`: the URL to download.
- `filepath`: local file path to write the response body to.
- `timeout`: request timeout in seconds.
- `chunk_size`: read chunk size in bytes (default 256KB).

**Raises**:

- `ValueError`: if the URL scheme is not http or https.
- `ConnectionError`: on connection failure.

**Returns**:

HTTP status code.

