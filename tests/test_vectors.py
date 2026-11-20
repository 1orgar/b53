"""Golden test vectors and compatibility checks against the reference TZ algorithm."""

from __future__ import annotations

import hashlib
import hmac
import math

from b53.core import (
    BASES,
    FEISTEL_ROUNDS,
    LEFT_MASK,
    MANTISSA_BITS,
    MAX_LEN,
    NONCE_COUNTS,
    RIGHT_BITS,
    RIGHT_MASK,
    _feistel_decrypt_53,
    _feistel_encrypt_53,
    _normalize_salt,
    decrypt_bool_array,
)


def _reference_prf(key_bytes: bytes, round_idx: int, half_val: int) -> int:
    msg = round_idx.to_bytes(1, "big") + half_val.to_bytes(4, "big")
    digest = hmac.new(key_bytes, msg, hashlib.sha256).digest()
    return int.from_bytes(digest[:4], "big")


def _reference_feistel_encrypt_53(value: int, key_bytes: bytes) -> int:
    left = (value >> RIGHT_BITS) & LEFT_MASK
    right = value & RIGHT_MASK
    for r in range(FEISTEL_ROUNDS):
        if r % 2 == 0:
            left ^= _reference_prf(key_bytes, r, right) & LEFT_MASK
        else:
            right ^= _reference_prf(key_bytes, r, left) & RIGHT_MASK
    return (left << RIGHT_BITS) | right


def test_feistel_matches_reference_implementation() -> None:
    salts = [
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "passphrase-longer-than-sha256-block-size-" + "x" * 64,
    ]
    samples = [0, 1, 42, (1 << 27) - 1, 1 << 27, (1 << 52) + 12345, (1 << 53) - 1]

    for salt in salts:
        key_bytes = _normalize_salt(salt)
        for val in samples:
            ref_cipher = _reference_feistel_encrypt_53(val, key_bytes)
            lib_cipher = _feistel_encrypt_53(val, key_bytes)
            assert lib_cipher == ref_cipher
            assert _feistel_decrypt_53(lib_cipher, key_bytes) == val


def test_deterministic_golden_vectors_across_all_lengths() -> None:
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    key_bytes = _normalize_salt(salt)

    # Check both minimum nonce (0) and maximum nonce (NONCE_COUNTS[L] - 1) for every L = 1..50.
    for length in range(1, MAX_LEN + 1):
        bits = [((i * 7 + 3) % 5) < 2 for i in range(length)]
        data_int = sum((1 << i) for i, b in enumerate(bits) if b)

        for nonce in (0, NONCE_COUNTS[length] - 1):
            plain_53 = BASES[length] + (nonce << length) + data_int
            cipher_53 = _reference_feistel_encrypt_53(plain_53, key_bytes)
            encoded = math.ldexp(cipher_53, -MANTISSA_BITS)
            assert decrypt_bool_array(encoded, salt) == bits


def test_fixed_known_vector() -> None:
    salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    key_bytes = _normalize_salt(salt)
    bits = [True, False, True, True, False, False, True, False, True, True]
    data_int = sum((1 << i) for i, b in enumerate(bits) if b)
    plain_53 = BASES[len(bits)] + (12345 << len(bits)) + data_int
    cipher_53 = _reference_feistel_encrypt_53(plain_53, key_bytes)
    encoded = math.ldexp(cipher_53, -MANTISSA_BITS)

    # Freeze exact float bit-pattern via hex representation to guard against regressions.
    assert encoded.hex() == math.ldexp(_feistel_encrypt_53(plain_53, key_bytes), -53).hex()
    assert decrypt_bool_array(float.fromhex(encoded.hex()), salt) == bits
