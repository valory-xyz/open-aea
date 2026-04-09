<a id="aea.helpers.multiformat"></a>

# aea.helpers.multiformat

Inlined multiformat helpers: base58, multibase, multicodec, multihash.

Replaces external packages: base58, py-multibase, py-multicodec, pymultihash.
Only implements the subset of functionality used within the AEA framework.

<a id="aea.helpers.multiformat.b58encode"></a>

#### b58encode

```python
def b58encode(data: bytes) -> bytes
```

Encode bytes to base58 (Bitcoin alphabet).

**Arguments**:

- `data`: bytes to encode.

**Returns**:

base58-encoded bytes.

<a id="aea.helpers.multiformat.b58decode"></a>

#### b58decode

```python
def b58decode(data: Union[bytes, str]) -> bytes
```

Decode base58 (Bitcoin alphabet) to bytes.

**Arguments**:

- `data`: base58-encoded bytes or string.

**Returns**:

decoded bytes.

<a id="aea.helpers.multiformat.multibase_encode"></a>

#### multibase`_`encode

```python
def multibase_encode(encoding: str, data: bytes) -> bytes
```

Encode data with a multibase prefix.

Supports: base32, base32upper, base58btc, base16, base16upper.

**Arguments**:

- `encoding`: the encoding name.
- `data`: bytes to encode.

**Raises**:

- `ValueError`: if encoding is not supported.

**Returns**:

multibase-encoded bytes (prefix + encoded data).

<a id="aea.helpers.multiformat.multibase_decode"></a>

#### multibase`_`decode

```python
def multibase_decode(data: bytes) -> bytes
```

Decode multibase-encoded data.

**Arguments**:

- `data`: multibase-encoded bytes.

**Raises**:

- `ValueError`: if the multibase prefix is not recognized.

**Returns**:

decoded bytes.

<a id="aea.helpers.multiformat.multibase_is_encoded"></a>

#### multibase`_`is`_`encoded

```python
def multibase_is_encoded(data: bytes) -> bool
```

Check if data is multibase-encoded.

**Arguments**:

- `data`: bytes to check.

**Returns**:

True if the first byte is a recognized multibase prefix.

<a id="aea.helpers.multiformat.multicodec_is_codec"></a>

#### multicodec`_`is`_`codec

```python
def multicodec_is_codec(name: str) -> bool
```

Check if a codec name is valid.

**Arguments**:

- `name`: the codec name.

**Returns**:

True if the name is in the multicodec table.

<a id="aea.helpers.multiformat.multicodec_add_prefix"></a>

#### multicodec`_`add`_`prefix

```python
def multicodec_add_prefix(codec: str, data: bytes) -> bytes
```

Add a multicodec varint prefix to data.

**Arguments**:

- `codec`: the codec name.
- `data`: the data to prefix.

**Raises**:

- `ValueError`: if the codec is unknown.

**Returns**:

prefixed data.

<a id="aea.helpers.multiformat.multicodec_get_codec"></a>

#### multicodec`_`get`_`codec

```python
def multicodec_get_codec(data: bytes) -> str
```

Get the codec name from multicodec-prefixed data.

**Arguments**:

- `data`: multicodec-prefixed data.

**Raises**:

- `ValueError`: if the prefix is not in the lookup table.

**Returns**:

the codec name.

<a id="aea.helpers.multiformat.multicodec_remove_prefix"></a>

#### multicodec`_`remove`_`prefix

```python
def multicodec_remove_prefix(data: bytes) -> bytes
```

Remove the multicodec varint prefix from data.

**Arguments**:

- `data`: multicodec-prefixed data.

**Returns**:

data without the prefix.

<a id="aea.helpers.multiformat.multihash_digest"></a>

#### multihash`_`digest

```python
def multihash_digest(data: bytes, func_code: int) -> Tuple[int, bytes]
```

Compute a multihash digest.

**Arguments**:

- `data`: the data to hash.
- `func_code`: the hash function code (SHA2_256_CODE or IDENTITY_HASH_CODE).

**Raises**:

- `ValueError`: if the function code is unsupported.

**Returns**:

tuple of (func_code, digest_bytes).

<a id="aea.helpers.multiformat.multihash_encode"></a>

#### multihash`_`encode

```python
def multihash_encode(func_code: int, digest: bytes) -> bytes
```

Encode a multihash: [varint(func_code), varint(digest_length), digest].

**Arguments**:

- `func_code`: the hash function code.
- `digest`: the hash digest bytes.

**Returns**:

encoded multihash bytes.

<a id="aea.helpers.multiformat.multihash_decode"></a>

#### multihash`_`decode

```python
def multihash_decode(data: bytes) -> Tuple[int, bytes]
```

Decode a multihash.

**Arguments**:

- `data`: encoded multihash bytes.

**Raises**:

- `ValueError`: if the data is malformed.

**Returns**:

tuple of (func_code, digest_bytes).

