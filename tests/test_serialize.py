"""Tests for arbitrary-length boolean array serialization and deserialization."""

from __future__ import annotations

import math
import random
from typing import Any, cast

import pytest

from b53 import (
    DEFAULT_CHUNK_MAX,
    DEFAULT_CHUNK_MIN,
    B53Cipher,
    decrypt,
    deserialize,
    deserialize_bool_array,
    generate_salt,
    serialize,
    serialize_bool_array,
)


def test_default_bounds_constants() -> None:
    assert DEFAULT_CHUNK_MIN == 10
    assert DEFAULT_CHUNK_MAX == 30


def test_serialize_deserialize_various_lengths() -> None:
    salt = generate_salt()
    rng = random.Random(12345)

    for length in (0, 1, 5, 10, 29, 30, 31, 50, 51, 137, 1000):
        bits = [rng.choice((False, True)) for _ in range(length)]
        doubles = serialize_bool_array(bits, salt)
        assert isinstance(doubles, list)
        for val in doubles:
            assert type(val) is float
            assert 0.0 <= val < 1.0
            assert math.ldexp(val, 53).is_integer()

        assert deserialize_bool_array(doubles, salt) == bits
        assert deserialize(serialize(bits, salt), salt) == bits


def test_chunk_sizes_are_random_within_bounds() -> None:
    salt = generate_salt()
    bits = [i % 2 == 0 for i in range(600)]

    doubles = serialize(bits, salt, min_size=10, max_size=30)
    chunk_lengths = [len(decrypt(d, salt)) for d in doubles]

    assert sum(chunk_lengths) == len(bits)
    assert all(10 <= n <= 30 for n in chunk_lengths[:-1])
    assert 1 <= chunk_lengths[-1] <= 30
    # Across ~30 chunks drawn from [10, 30], sizes must vary randomly.
    assert len(set(chunk_lengths[:-1])) > 1

    # Full allowed boundary range [1, 50].
    doubles_full = serialize(bits, salt, min_size=1, max_size=50)
    full_lengths = [len(decrypt(d, salt)) for d in doubles_full]
    assert sum(full_lengths) == len(bits)
    assert all(1 <= n <= 50 for n in full_lengths)
    assert deserialize(doubles_full, salt) == bits


def test_equal_bounds_produce_fixed_chunk_sizes() -> None:
    salt = generate_salt()
    bits = [True, False] * 17 + [True]  # 35 elements

    doubles = serialize(bits, salt, min_size=10, max_size=10)
    assert [len(decrypt(d, salt)) for d in doubles] == [10, 10, 10, 5]
    assert deserialize(doubles, salt) == bits

    bits_5 = [True, False, True, False, True]
    doubles_one_by_one = serialize(bits_5, salt, min_size=1, max_size=1)
    assert [len(decrypt(d, salt)) for d in doubles_one_by_one] == [1, 1, 1, 1, 1]
    assert deserialize(doubles_one_by_one, salt) == bits_5

    bits_120 = [i % 3 == 0 for i in range(120)]
    doubles_50 = serialize(bits_120, salt, min_size=50, max_size=50)
    assert [len(decrypt(d, salt)) for d in doubles_50] == [50, 50, 20]
    assert deserialize(doubles_50, salt) == bits_120


def test_cipher_methods_and_generators() -> None:
    cipher, _ = B53Cipher.generate()
    expected = [i % 4 == 0 for i in range(95)]

    doubles = cipher.serialize((i % 4 == 0 for i in range(95)), min_size=8, max_size=16)
    assert cipher.deserialize(d for d in doubles) == expected


@pytest.mark.parametrize(
    ("min_size", "max_size"),
    [
        (0, 30),
        (-1, 10),
        (10, 51),
        (1, 100),
        (31, 30),
        (20, 10),
        (50, 1),
        (60, 70),
    ],
)
def test_invalid_bounds_raise_value_error(min_size: int, max_size: int) -> None:
    salt = generate_salt()
    with pytest.raises(ValueError):
        serialize([True, False], salt, min_size=min_size, max_size=max_size)
    # Must validate bounds even when input array is empty.
    with pytest.raises(ValueError):
        serialize([], salt, min_size=min_size, max_size=max_size)


def test_invalid_bound_types_raise_type_error() -> None:
    salt = generate_salt()
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=True, max_size=30)
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=10, max_size=False)
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=cast(Any, 10.0), max_size=30)
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=10, max_size=cast(Any, "30"))


def test_serialize_and_deserialize_input_and_salt_validation() -> None:
    salt = generate_salt()

    with pytest.raises(ValueError):
        serialize([], "")
    with pytest.raises(ValueError):
        deserialize([], "")
    with pytest.raises(TypeError):
        serialize(cast(Any, "1010"), salt)
    with pytest.raises(ValueError):
        serialize(cast(Any, [0, 1, 2]), salt)
    with pytest.raises(TypeError):
        deserialize(cast(Any, "0.5"), salt)
    with pytest.raises(ValueError):
        deserialize([0.5, 1.0], salt)
    with pytest.raises(TypeError):
        deserialize(cast(Any, [True]), salt)
