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

"""Tests for the inlined multiformat helpers (base58, multibase, multicodec, multihash)."""

import hashlib

import pytest

from aea.helpers.multiformat import (
    IDENTITY_HASH_CODE,
    SHA2_256_CODE,
    b58decode,
    b58encode,
    multibase_decode,
    multibase_encode,
    multibase_is_encoded,
    multicodec_add_prefix,
    multicodec_get_codec,
    multicodec_is_codec,
    multicodec_remove_prefix,
    multihash_decode,
    multihash_digest,
    multihash_encode,
)

# --- base58 ---


class TestBase58:
    """Tests for base58 encode/decode."""

    def test_encode_empty(self) -> None:
        """Test encoding empty bytes."""
        assert b58encode(b"") == b""

    def test_decode_empty(self) -> None:
        """Test decoding empty bytes."""
        assert b58decode(b"") == b""

    def test_roundtrip(self) -> None:
        """Test encode/decode roundtrip."""
        for data in [b"hello", b"\x00\x00\x01", b"\xff" * 32, bytes(10)]:
            assert b58decode(b58encode(data)) == data

    def test_known_vector(self) -> None:
        """Test against known base58 vectors."""
        # "Hello World" in base58btc
        assert b58encode(b"Hello World") == b"JxF12TrwUP45BMd"
        assert b58decode(b"JxF12TrwUP45BMd") == b"Hello World"

    def test_leading_zeros(self) -> None:
        """Test that leading zero bytes map to leading '1' chars."""
        encoded = b58encode(b"\x00\x00\x00hello")
        assert encoded.startswith(b"111")
        assert b58decode(encoded) == b"\x00\x00\x00hello"

    def test_accepts_str_input(self) -> None:
        """Test that decode accepts string input."""
        assert b58decode("JxF12TrwUP45BMd") == b"Hello World"

    def test_returns_bytes(self) -> None:
        """Test that encode always returns bytes."""
        result = b58encode(b"test")
        assert isinstance(result, bytes)


# --- multibase ---


class TestMultibase:
    """Tests for multibase encode/decode/is_encoded."""

    def test_base32_encode_decode_roundtrip(self) -> None:
        """Test base32 roundtrip."""
        data = b"\x01\x70\x12\x20" + b"\xab" * 32
        encoded = multibase_encode("base32", data)
        assert encoded[0:1] == b"b"
        decoded = multibase_decode(encoded)
        assert decoded == data

    def test_base58btc_encode_decode_roundtrip(self) -> None:
        """Test base58btc roundtrip."""
        data = b"\x01\x70\x12\x20" + b"\xab" * 32
        encoded = multibase_encode("base58btc", data)
        assert encoded[0:1] == b"z"
        decoded = multibase_decode(encoded)
        assert decoded == data

    def test_is_encoded_base32(self) -> None:
        """Test is_encoded for base32."""
        data = b"\x01\x70\x12\x20" + bytes(32)
        encoded = multibase_encode("base32", data)
        assert multibase_is_encoded(encoded) is True

    def test_is_encoded_base58btc(self) -> None:
        """Test is_encoded for base58btc."""
        data = b"\x01\x70" + bytes(10)
        encoded = multibase_encode("base58btc", data)
        assert multibase_is_encoded(encoded) is True

    def test_is_not_encoded(self) -> None:
        """Test is_encoded returns False for non-multibase data."""
        # CIDv0 base58-encoded hashes are NOT multibase-encoded
        assert (
            multibase_is_encoded(b"QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR")
            is False
        )

    def test_unsupported_encoding_raises(self) -> None:
        """Test that unsupported encoding raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported multibase encoding"):
            multibase_encode("base2", b"data")

    def test_invalid_base32_raises(self) -> None:
        """Test that invalid base32 payload raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base32"):
            multibase_decode(b"bb")  # 'b' prefix + invalid single-char payload


# --- multicodec ---


class TestMulticodec:
    """Tests for multicodec functions."""

    def test_is_codec_valid(self) -> None:
        """Test is_codec for known codecs."""
        assert multicodec_is_codec("dag-pb") is True
        assert multicodec_is_codec("dag-cbor") is True
        assert multicodec_is_codec("raw") is True
        assert multicodec_is_codec("protobuf") is True

    def test_is_codec_invalid(self) -> None:
        """Test is_codec for unknown codec."""
        assert multicodec_is_codec("bogus") is False

    def test_add_prefix_dag_pb(self) -> None:
        """Test add_prefix for dag-pb codec."""
        result = multicodec_add_prefix("dag-pb", b"hello")
        # dag-pb code is 0x70, varint for 0x70 is a single byte
        assert result == b"\x70hello"

    def test_get_codec(self) -> None:
        """Test get_codec extracts codec name."""
        data = b"\x70hello"
        assert multicodec_get_codec(data) == "dag-pb"

    def test_remove_prefix(self) -> None:
        """Test remove_prefix strips the codec prefix."""
        data = b"\x70hello"
        assert multicodec_remove_prefix(data) == b"hello"

    def test_roundtrip(self) -> None:
        """Test add/remove prefix roundtrip."""
        original = b"test data"
        prefixed = multicodec_add_prefix("dag-pb", original)
        assert multicodec_get_codec(prefixed) == "dag-pb"
        assert multicodec_remove_prefix(prefixed) == original

    def test_unknown_codec_prefix_raises(self) -> None:
        """Test that unknown codec prefix raises ValueError."""
        with pytest.raises(ValueError):
            multicodec_get_codec(b"\xff\xff\xff\xff\x0f")


# --- multihash ---


class TestMultihash:
    """Tests for multihash functions."""

    def test_digest_sha256(self) -> None:
        """Test sha256 multihash digest."""
        data = b"hello"
        mh = multihash_digest(data, SHA2_256_CODE)
        expected_digest = hashlib.sha256(data).digest()
        assert mh == (SHA2_256_CODE, expected_digest)

    def test_encode_sha256(self) -> None:
        """Test multihash encoding for sha256."""
        data = b"hello"
        func_code, digest = multihash_digest(data, SHA2_256_CODE)
        encoded = multihash_encode(func_code, digest)
        assert encoded[0] == 0x12  # sha2-256
        assert encoded[1] == 32  # digest length
        assert encoded[2:] == hashlib.sha256(data).digest()

    def test_digest_identity(self) -> None:
        """Test identity multihash digest."""
        data = b"test_data"
        func_code, digest = multihash_digest(data, IDENTITY_HASH_CODE)
        assert func_code == 0x00
        assert digest == data

    def test_encode_identity(self) -> None:
        """Test multihash encoding for identity hash."""
        data = b"test"
        func_code, digest = multihash_digest(data, IDENTITY_HASH_CODE)
        encoded = multihash_encode(func_code, digest)
        assert encoded[0] == 0x00  # identity
        assert encoded[1] == 4  # length of "test"
        assert encoded[2:] == b"test"

    def test_decode_sha256(self) -> None:
        """Test multihash decoding."""
        digest = b"\xab" * 32
        encoded = bytes([0x12, 32]) + digest
        func_code, decoded_digest = multihash_decode(encoded)
        assert func_code == 0x12
        assert decoded_digest == digest

    def test_decode_too_short(self) -> None:
        """Test decoding too-short multihash raises."""
        with pytest.raises(ValueError, match="multihash is too short"):
            multihash_decode(b"\x12")

    def test_decode_length_mismatch(self) -> None:
        """Test decoding with wrong length field raises."""
        with pytest.raises(
            ValueError,
            match="multihash length field does not match digest field length",
        ):
            multihash_decode(b"\x12\x03\xab\xab")

    def test_decode_empty(self) -> None:
        """Test decoding empty bytes raises."""
        with pytest.raises(ValueError, match="multihash is too short"):
            multihash_decode(b"")

    def test_encode_decode_varint_roundtrip(self) -> None:
        """Test that encode/decode uses varints correctly."""
        # Test with all recognized codes
        for func_code in (SHA2_256_CODE, IDENTITY_HASH_CODE, 0x11, 0x40):
            digest = b"\xab" * 32
            encoded = multihash_encode(func_code, digest)
            decoded_code, decoded_digest = multihash_decode(encoded)
            assert decoded_code == func_code
            assert decoded_digest == digest

    def test_decode_unknown_func_code(self) -> None:
        """Test that unknown hash function codes are rejected."""
        # 0x99 is not a recognized multihash code
        from aea.helpers.multiformat import _varint_encode

        bad_data = _varint_encode(0x99) + _varint_encode(1) + b"\xAA"
        with pytest.raises(ValueError, match="unknown hash function"):
            multihash_decode(bad_data)


# --- Integration: CID-like operations ---


class TestIntegration:
    """Integration tests combining multiple multiformat operations."""

    HASH_V0 = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
    HASH_V1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

    def test_cidv0_roundtrip(self) -> None:
        """Test CIDv0 base58 decode then re-encode."""
        decoded = b58decode(self.HASH_V0.encode())
        re_encoded = b58encode(decoded)
        assert re_encoded == self.HASH_V0.encode()

    def test_cidv1_multibase_roundtrip(self) -> None:
        """Test CIDv1 multibase decode then re-encode."""
        cid_bytes = self.HASH_V1.encode()
        assert multibase_is_encoded(cid_bytes) is True
        decoded = multibase_decode(cid_bytes)
        codec = multicodec_get_codec(decoded[1:])
        assert codec == "dag-pb"
        data = multicodec_remove_prefix(decoded[1:])
        # data should be a valid multihash
        func_code, digest = multihash_decode(data)
        assert func_code == SHA2_256_CODE
        assert len(digest) == 32

    def test_multihash_for_peer_id(self) -> None:
        """Test multihash digest + encode + base58 for peer ID computation."""
        key_data = b"some_serialized_key"
        func_code, digest = multihash_digest(key_data, IDENTITY_HASH_CODE)
        encoded = multihash_encode(func_code, digest)
        peer_id = b58encode(encoded).decode()
        assert isinstance(peer_id, str)
        # Decode back
        decoded_mh = b58decode(peer_id.encode())
        fc, d = multihash_decode(decoded_mh)
        assert fc == IDENTITY_HASH_CODE
        assert d == key_data
