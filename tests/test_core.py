"""Unit tests for b53 core encryption, decryption, validation, and helpers."""

from __future__ import annotations

import itertools
import json
import math
import random
from typing import Any, cast

import pytest

import b53
from b53 import (
    MAX_LEN,
    B53Cipher,
    Cipher,
    decrypt,
    decrypt_bool_array,
    encrypt,
    encrypt_bool_array,
    format_bits,
    generate_salt,
    parse_bits,
)


def test_roundtrip_all_lengths_1_to_50() -> None:
    salt = generate_salt()
    rng = random.Random(42)

    for length in range(1, MAX_LEN + 1):
        patterns = [
            [False] * length,
            [True] * length,
            [i % 2 == 0 for i in range(length)],
            [rng.choice((False, True)) for _ in range(length)],
        ]
        for bits in patterns:
            encoded = encrypt_bool_array(bits, salt)
            assert type(encoded) is float
            assert math.isfinite(encoded)
            assert 0.0 <= encoded < 1.0
            assert math.ldexp(encoded, 53).is_integer()

            # Ensure exact preservation via repr() and JSON serialization.
            assert decrypt_bool_array(float(repr(encoded)), salt) == bits
            assert decrypt_bool_array(json.loads(json.dumps(encoded)), salt) == bits


def test_exhaustive_small_lengths_1_to_4() -> None:
    salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    for length in range(1, 5):
        for combo in itertools.product((False, True), repeat=length):
            bits = list(combo)
            encoded = encrypt(bits, salt)
            assert decrypt(encoded, salt) == bits


def test_nonce_produces_distinct_outputs_for_same_input() -> None:
    salt = generate_salt()
    bits = [True, False, True, True, False, False, True, False, True, True]

    # At L=10 there are ~1.93e7 nonces; 25 encryptions must produce multiple unique doubles.
    outputs = {encrypt(bits, salt) for _ in range(25)}
    assert len(outputs) > 20
    for val in outputs:
        assert decrypt(val, salt) == bits

    # Even at L=50 (3 nonces), 32 draws should almost surely hit more than 1 nonce.
    bits_50 = [i % 3 == 0 for i in range(50)]
    outputs_50 = {encrypt(bits_50, salt) for _ in range(32)}
    assert len(outputs_50) >= 2
    for val in outputs_50:
        assert decrypt(val, salt) == bits_50


def test_salt_formats_and_cross_compatibility() -> None:
    hex_salt = "DeadBeef" * 8
    raw_bytes = bytes.fromhex(hex_salt)
    bits = [True, False, True, False, True]

    encoded = encrypt(bits, f"  {hex_salt} \n")
    assert decrypt(encoded, raw_bytes) == bits
    assert decrypt(encoded, bytearray(raw_bytes)) == bits

    passphrase = "correct-horse-battery-staple"
    encoded_utf8 = encrypt(bits, passphrase)
    assert decrypt(encoded_utf8, passphrase.encode("utf-8")) == bits


def test_wrong_salt_changes_recovered_payload() -> None:
    salt_a = generate_salt()
    salt_b = generate_salt()
    bits = [True, False, True, True, False, True, False, True, True, False]

    mismatches = 0
    for _ in range(10):
        encoded = encrypt(bits, salt_a)
        if decrypt(encoded, salt_b) != bits:
            mismatches += 1
    assert mismatches == 10


def test_accepts_iterables_and_0_1_ints() -> None:
    salt = generate_salt()
    bits_01: Any = (1, 0, 1, 1)
    assert decrypt(encrypt(bits_01, salt), salt) == [True, False, True, True]
    assert decrypt(encrypt((i % 2 == 0 for i in range(6)), salt), salt) == [
        True,
        False,
        True,
        False,
        True,
        False,
    ]


def test_encrypt_input_validation() -> None:
    salt = generate_salt()

    with pytest.raises(ValueError):
        encrypt([], salt)
    with pytest.raises(ValueError):
        encrypt([True] * (MAX_LEN + 1), salt)
    with pytest.raises(ValueError):
        encrypt(itertools.repeat(True), salt)  # Must fail fast on infinite iterables
    with pytest.raises(ValueError):
        encrypt(cast(Any, [0, 2]), salt)
    with pytest.raises(ValueError):
        encrypt(cast(Any, [-1]), salt)

    with pytest.raises(TypeError):
        encrypt(cast(Any, "101"), salt)
    with pytest.raises(TypeError):
        encrypt(cast(Any, b"101"), salt)
    with pytest.raises(TypeError):
        encrypt({True: 1}, salt)
    with pytest.raises(TypeError):
        encrypt(cast(Any, ["0", "1"]), salt)


def test_salt_validation() -> None:
    with pytest.raises(ValueError):
        encrypt([True], "")
    with pytest.raises(ValueError):
        encrypt([True], "   \t\n ")
    with pytest.raises(ValueError):
        encrypt([True], b"")
    with pytest.raises(ValueError):
        decrypt(0.5, "")
    with pytest.raises(TypeError):
        encrypt([True], cast(Any, 12345))


def test_decrypt_input_validation_and_boundary_grid_points() -> None:
    salt = generate_salt()

    with pytest.raises(TypeError):
        decrypt(True, salt)
    with pytest.raises(TypeError):
        decrypt(0, salt)
    with pytest.raises(TypeError):
        decrypt(cast(Any, "0.5"), salt)

    for bad_val in (
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.1,
        -math.ldexp(1, -53),
        1.0,
        1.5,
        0.3,
        math.ldexp(1, -54),
    ):
        with pytest.raises(ValueError):
            decrypt(bad_val, salt)

    # Boundary exact 53-bit grid values: 0.0 and 1.0 - 2^-53.
    for edge in (0.0, math.ldexp((1 << 53) - 1, -53)):
        restored = decrypt(edge, salt)
        assert 1 <= len(restored) <= MAX_LEN


def test_cipher_class_and_repr_redaction() -> None:
    cipher, salt = B53Cipher.generate()
    assert Cipher is B53Cipher
    assert salt not in repr(cipher)
    assert "key_bytes=32" in repr(cipher)

    val = cipher.encrypt_str("1011001")
    assert cipher.decrypt_str(val) == "1011001"
    assert cipher.decrypt(val) == [True, False, True, True, False, False, True]


def test_generate_salt_validation() -> None:
    s32 = generate_salt()
    assert len(s32) == 64
    bytes.fromhex(s32)

    s16 = generate_salt(16)
    assert len(s16) == 32
    assert s32 != generate_salt()

    with pytest.raises(ValueError):
        generate_salt(15)
    with pytest.raises(TypeError):
        generate_salt(True)
    with pytest.raises(TypeError):
        generate_salt("32")  # type: ignore[arg-type]


def test_parse_and_format_bits() -> None:
    assert parse_bits("1011001") == [True, False, True, True, False, False, True]
    assert parse_bits("  0101 \n") == [False, True, False, True]
    assert parse_bits("true, false, T, f, 1, 0") == [True, False, True, False, True, False]
    assert parse_bits("false") == [False]
    assert format_bits([True, False, True, True]) == "1011"

    for bad in ("", "   ", ",", "1,maybe", "102"):
        with pytest.raises(ValueError):
            parse_bits(bad)
    with pytest.raises(TypeError):
        parse_bits(101)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        format_bits("101")  # type: ignore[arg-type]


def test_public_exports() -> None:
    assert hasattr(b53, "__version__")
    assert b53.__version__ == "0.2.0"
