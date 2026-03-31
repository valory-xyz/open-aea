# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
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

"""
secp256k1 compressed public key validation.

Replaces the ``ecdsa`` package for the single use case in
``aea.helpers.multiaddr.base``: validating that a 33-byte compressed
secp256k1 public key encodes a point on the curve.

Curve equation: y² = x³ + 7 (mod p)
"""

# secp256k1 field prime
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def validate_secp256k1_compressed_pubkey(compressed: bytes) -> None:
    """
    Validate a compressed secp256k1 public key.

    A compressed key is 33 bytes: a 0x02 or 0x03 prefix byte followed
    by the 32-byte big-endian x coordinate. The prefix indicates the
    parity of the y coordinate. This function verifies that the x
    coordinate corresponds to a point on the secp256k1 curve.

    :param compressed: 33-byte compressed public key.
    :raises ValueError: if the key is malformed or not on the curve.
    """
    if len(compressed) != 33:
        raise ValueError(
            f"Expected 33 bytes for compressed secp256k1 key, got {len(compressed)}"
        )

    prefix = compressed[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"Invalid compressed key prefix: {hex(prefix)}")

    x = int.from_bytes(compressed[1:33], "big")

    # y² = x³ + 7 (mod p)  — secp256k1 has a=0, b=7
    y_sq = (pow(x, 3, _P) + 7) % _P

    # Compute candidate square root. For secp256k1, p ≡ 3 (mod 4),
    # so y = y_sq^((p+1)/4) mod p gives a square root when one exists.
    y = pow(y_sq, (_P + 1) // 4, _P)

    # Verify the candidate is actually a square root
    if (y * y) % _P != y_sq:
        raise ValueError(
            f"Encoding does not correspond to a point on the secp256k1 curve "
            f"(x={hex(x)} is not on the curve)"
        )
