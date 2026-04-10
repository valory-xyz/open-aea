<a id="aea.helpers.secp256k1"></a>

# aea.helpers.secp256k1

secp256k1 compressed public key validation.

Replaces the ``ecdsa`` package for the single use case in
``aea.helpers.multiaddr.base``: validating that a 33-byte compressed
secp256k1 public key encodes a point on the curve.

Curve equation: y² = x³ + 7 (mod p)

<a id="aea.helpers.secp256k1.validate_secp256k1_compressed_pubkey"></a>

#### validate`_`secp256k1`_`compressed`_`pubkey

```python
def validate_secp256k1_compressed_pubkey(compressed: bytes) -> None
```

Validate a compressed secp256k1 public key.

A compressed key is 33 bytes: a 0x02 or 0x03 prefix byte followed
by the 32-byte big-endian x coordinate. The prefix indicates the
parity of the y coordinate. This function verifies that the x
coordinate corresponds to a point on the secp256k1 curve.

**Arguments**:

- `compressed`: 33-byte compressed public key.

**Raises**:

- `ValueError`: if the key is malformed or not on the curve.

