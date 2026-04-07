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
Inlined multiformat helpers: base58, multibase, multicodec, multihash.

Replaces external packages: base58, py-multibase, py-multicodec, pymultihash.
Only implements the subset of functionality used within the AEA framework.
"""

import base64
import hashlib
from typing import Tuple, Union

from aea.helpers.multiformat_codecs import CODE_TABLE, NAME_TABLE

# --- Constants ---

IDENTITY_HASH_CODE = 0x00
SHA2_256_CODE = 0x12

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_BASE = len(_B58_ALPHABET)
_B58_CHAR_TO_INT = {char: index for index, char in enumerate(_B58_ALPHABET)}

# Multibase prefix -> (encoding_name, encoder, decoder)
_MULTIBASE_PREFIXES = {
    b"b": "base32",
    b"B": "base32upper",
    b"z": "base58btc",
    b"f": "base16",
    b"F": "base16upper",
}
_MULTIBASE_NAMES = {v: k for k, v in _MULTIBASE_PREFIXES.items()}


# --- Base58 (Bitcoin alphabet) ---


def b58encode(data: bytes) -> bytes:
    """
    Encode bytes to base58 (Bitcoin alphabet).

    :param data: bytes to encode.
    :return: base58-encoded bytes.
    """
    # Count leading zero bytes
    n_leading = 0
    for byte in data:
        if byte == 0:
            n_leading += 1
        else:
            break

    # Convert to big integer
    acc = int.from_bytes(data, "big")

    # Encode
    result = bytearray()
    while acc > 0:
        acc, remainder = divmod(acc, _B58_BASE)
        result.append(_B58_ALPHABET[remainder])

    # Add leading '1' for each leading zero byte
    result.extend([_B58_ALPHABET[0]] * n_leading)
    result.reverse()
    return bytes(result)


def b58decode(data: Union[bytes, str]) -> bytes:
    """
    Decode base58 (Bitcoin alphabet) to bytes.

    :param data: base58-encoded bytes or string.
    :return: decoded bytes.
    """
    if isinstance(data, str):
        data = data.encode("ascii")

    # Count leading '1' characters
    n_leading = 0
    for byte in data:
        if byte == _B58_ALPHABET[0]:
            n_leading += 1
        else:
            break

    # Convert from base58 to integer
    acc = 0
    for byte in data:
        if byte not in _B58_CHAR_TO_INT:
            raise ValueError(f"Invalid base58 character: {chr(byte)!r}")
        acc = acc * _B58_BASE + _B58_CHAR_TO_INT[byte]

    # Convert to bytes
    if acc == 0:
        result = b""
    else:
        result = acc.to_bytes((acc.bit_length() + 7) // 8, "big")

    return b"\x00" * n_leading + result


# --- Multibase ---


def multibase_encode(encoding: str, data: bytes) -> bytes:
    """
    Encode data with a multibase prefix.

    Supports: base32, base32upper, base58btc, base16, base16upper.

    :param encoding: the encoding name.
    :param data: bytes to encode.
    :return: multibase-encoded bytes (prefix + encoded data).
    :raises ValueError: if encoding is not supported.
    """
    prefix = _MULTIBASE_NAMES.get(encoding)
    if prefix is None:
        raise ValueError(f"Unsupported multibase encoding: {encoding}")

    if encoding == "base32":
        encoded = base64.b32encode(data).lower().rstrip(b"=")
    elif encoding == "base32upper":
        encoded = base64.b32encode(data).rstrip(b"=")
    elif encoding == "base58btc":
        encoded = b58encode(data)
    elif encoding == "base16":
        encoded = data.hex().encode("ascii")
    elif encoding == "base16upper":
        encoded = data.hex().upper().encode("ascii")
    else:
        raise ValueError(f"Unsupported multibase encoding: {encoding}")

    return prefix + encoded


def multibase_decode(data: bytes) -> bytes:
    """
    Decode multibase-encoded data.

    :param data: multibase-encoded bytes.
    :return: decoded bytes.
    :raises ValueError: if the multibase prefix is not recognized.
    """
    prefix = data[0:1]
    encoding = _MULTIBASE_PREFIXES.get(prefix)
    if encoding is None:
        raise ValueError(f"Unrecognized multibase prefix: {prefix!r}")

    payload = data[1:]

    if encoding in ("base32", "base32upper"):
        # Add back padding for base64.b32decode
        upper_payload = payload.upper() if encoding == "base32" else payload
        padding = (8 - len(upper_payload) % 8) % 8
        try:
            return base64.b32decode(upper_payload + b"=" * padding, casefold=True)
        except Exception as e:
            raise ValueError("Invalid base32 multibase payload") from e
    if encoding == "base58btc":
        return b58decode(payload)
    if encoding == "base16":
        return bytes.fromhex(payload.decode("ascii"))
    if encoding == "base16upper":
        return bytes.fromhex(payload.decode("ascii"))

    raise ValueError(f"Unsupported multibase encoding: {encoding}")  # pragma: no cover


def multibase_is_encoded(data: bytes) -> bool:
    """
    Check if data is multibase-encoded.

    :param data: bytes to check.
    :return: True if the first byte is a recognized multibase prefix.
    """
    if len(data) < 2:
        return False
    prefix = data[0:1]
    return prefix in _MULTIBASE_PREFIXES


# --- Varint (unsigned LEB128) ---


def _varint_encode(number: int) -> bytes:
    """Encode an integer as an unsigned varint (LEB128)."""
    buf = bytearray()
    while True:
        towrite = number & 0x7F
        number >>= 7
        if number:
            buf.append(towrite | 0x80)
        else:
            buf.append(towrite)
            break
    return bytes(buf)


def _varint_decode(data: bytes) -> Tuple[int, int]:
    """
    Decode an unsigned varint from the start of data.

    :param data: bytes to decode.
    :return: (value, number_of_bytes_consumed).
    """
    result = 0
    shift = 0
    for i, byte in enumerate(data):
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i + 1
        shift += 7
    raise ValueError("varint is truncated")


# --- Multicodec ---


def multicodec_is_codec(name: str) -> bool:
    """
    Check if a codec name is valid.

    :param name: the codec name.
    :return: True if the name is in the multicodec table.
    """
    return name in NAME_TABLE


def multicodec_add_prefix(codec: str, data: bytes) -> bytes:
    """
    Add a multicodec varint prefix to data.

    :param codec: the codec name.
    :param data: the data to prefix.
    :return: prefixed data.
    :raises ValueError: if the codec is unknown.
    """
    if codec not in NAME_TABLE:
        raise ValueError(f"Unknown codec: {codec}")
    code = NAME_TABLE[codec]
    return _varint_encode(code) + data


def multicodec_get_codec(data: bytes) -> str:
    """
    Get the codec name from multicodec-prefixed data.

    :param data: multicodec-prefixed data.
    :return: the codec name.
    :raises ValueError: if the prefix is not in the lookup table.
    """
    code, _ = _varint_decode(data)
    if code not in CODE_TABLE:
        raise ValueError(f"Prefix {code} not present in the lookup table")
    return CODE_TABLE[code]


def multicodec_remove_prefix(data: bytes) -> bytes:
    """
    Remove the multicodec varint prefix from data.

    :param data: multicodec-prefixed data.
    :return: data without the prefix.
    """
    _, consumed = _varint_decode(data)
    return data[consumed:]


# --- Multihash ---

# Recognized multihash function codes (matching pymultihash.Func + identity)
_MULTIHASH_CODES = {
    IDENTITY_HASH_CODE,  # 0x00 identity
    0x11,  # sha1
    SHA2_256_CODE,  # 0x12 sha2-256
    0x13,  # sha2-512
    0x14,  # sha3-512
    0x15,  # sha3-384
    0x16,  # sha3-256
    0x17,  # sha3-224
    0x18,  # shake-128
    0x19,  # shake-256
    0x40,  # blake2b
    0x41,  # blake2s
}


def multihash_digest(data: bytes, func_code: int) -> Tuple[int, bytes]:
    """
    Compute a multihash digest.

    :param data: the data to hash.
    :param func_code: the hash function code (SHA2_256_CODE or IDENTITY_HASH_CODE).
    :return: tuple of (func_code, digest_bytes).
    :raises ValueError: if the function code is unsupported.
    """
    if func_code == SHA2_256_CODE:
        digest = hashlib.sha256(data).digest()
    elif func_code == IDENTITY_HASH_CODE:
        digest = data
    else:
        raise ValueError(f"Unsupported hash function code: {func_code}")
    return func_code, digest


def multihash_encode(func_code: int, digest: bytes) -> bytes:
    """
    Encode a multihash: [varint(func_code), varint(digest_length), digest].

    :param func_code: the hash function code.
    :param digest: the hash digest bytes.
    :return: encoded multihash bytes.
    """
    return _varint_encode(func_code) + _varint_encode(len(digest)) + digest


def multihash_decode(data: bytes) -> Tuple[int, bytes]:
    """
    Decode a multihash.

    :param data: encoded multihash bytes.
    :return: tuple of (func_code, digest_bytes).
    :raises ValueError: if the data is malformed.
    """
    if len(data) < 2:
        raise ValueError("multihash is too short")
    func_code, consumed_func = _varint_decode(data)
    if func_code not in _MULTIHASH_CODES:
        raise ValueError(f"unknown hash function code: {func_code}")
    length, consumed_len = _varint_decode(data[consumed_func:])
    offset = consumed_func + consumed_len
    digest = data[offset:]
    if length != len(digest):
        raise ValueError("multihash length field does not match digest field length")
    return func_code, digest
