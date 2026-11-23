"""Tests for scrypt-based password key stretching."""

from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest

from b53 import (
    DEFAULT_SCRYPT_MAXMEM,
    DEFAULT_SCRYPT_N,
    DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R,
    B53Cipher,
    decrypt,
    derive_salt,
    deserialize,
    encrypt,
    serialize,
)


def test_default_scrypt_constants() -> None:
    assert DEFAULT_SCRYPT_N == 1 << 15
    assert DEFAULT_SCRYPT_R == 8
    assert DEFAULT_SCRYPT_P == 1
    assert DEFAULT_SCRYPT_MAXMEM == 128 * 1024 * 1024


def test_derive_salt_matches_scrypt_and_roundtrips() -> None:
    password = "correct-horse-battery-staple"
    salt_hex = derive_salt(password)

    assert len(salt_hex) == 64
    expected = hashlib.scrypt(
        password.encode("utf-8"),
        salt=b"b53:scrypt:v1",
        n=DEFAULT_SCRYPT_N,
        r=DEFAULT_SCRYPT_R,
        p=DEFAULT_SCRYPT_P,
        maxmem=DEFAULT_SCRYPT_MAXMEM,
        dklen=32,
    ).hex()
    assert salt_hex == expected

    bits = [True, False, True, True, False, False, True]
    encoded = encrypt(bits, salt_hex)
    assert decrypt(encoded, salt_hex) == bits

    many = [i % 2 == 0 for i in range(42)]
    doubles = serialize(many, salt_hex)
    assert deserialize(doubles, salt_hex) == many


def test_derive_salt_context_and_whitespace_sensitivity() -> None:
    # Use fast n=16 only for parameter-sensitivity checks.
    k1 = derive_salt("secret", n=16, r=1, p=1)
    k2 = derive_salt(" secret", n=16, r=1, p=1)
    k3 = derive_salt("secret", context="user:1", n=16, r=1, p=1)
    k4 = derive_salt(b"secret", context=b"user:1", n=16, r=1, p=1)
    k5 = derive_salt("secret", context="user:2", n=16, r=1, p=1)

    assert k1 != k2
    assert k1 != k3
    assert k3 == k4
    assert k3 != k5

    k16 = derive_salt("secret", num_bytes=16, n=16, r=1, p=1)
    assert len(k16) == 32


def test_cipher_from_password_interoperates_with_derive_salt() -> None:
    salt = derive_salt("my-password", context="tenant-a", n=16, r=1, p=1)
    cipher = B53Cipher.from_password("my-password", context="tenant-a", n=16, r=1, p=1)

    bits = [i % 3 == 0 for i in range(35)]
    doubles = cipher.serialize(bits)
    assert deserialize(doubles, salt) == bits
    assert cipher.deserialize(serialize(bits, salt)) == bits


def test_derive_salt_validation() -> None:
    with pytest.raises(ValueError):
        derive_salt("")
    with pytest.raises(ValueError):
        derive_salt(b"")
    with pytest.raises(ValueError):
        derive_salt(bytearray())
    with pytest.raises(ValueError):
        derive_salt("pw", context="")
    with pytest.raises(ValueError):
        derive_salt("pw", context=b"")
    with pytest.raises(ValueError):
        derive_salt("pw", num_bytes=15)

    for bad_n in (0, 1, 3, 12, -16):
        with pytest.raises(ValueError):
            derive_salt("pw", n=bad_n, r=1, p=1)

    with pytest.raises(ValueError):
        derive_salt("pw", n=16, r=0, p=1)
    with pytest.raises(ValueError):
        derive_salt("pw", n=16, r=1, p=0)
    with pytest.raises(ValueError):
        derive_salt("pw", n=16, r=1, p=1, maxmem=-1)

    with pytest.raises(TypeError):
        derive_salt(cast(Any, None))
    with pytest.raises(TypeError):
        derive_salt("pw", context=cast(Any, 123))
    with pytest.raises(TypeError):
        derive_salt("pw", num_bytes=True)
    with pytest.raises(TypeError):
        derive_salt("pw", n=True)
    with pytest.raises(TypeError):
        derive_salt("pw", r=False)
    with pytest.raises(TypeError):
        derive_salt("pw", p=True)
    with pytest.raises(TypeError):
        derive_salt("pw", maxmem=True)
