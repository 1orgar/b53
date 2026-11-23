"""Tests for chained arbitrary-length boolean array serialization and deserialization."""

from __future__ import annotations

import math
import random
import secrets
from typing import Any, cast

import pytest

import b53.core as core_mod
from b53 import (
    DEFAULT_CHUNK_MIN,
    MAX_LEN,
    MIN_SPLIT_SIZE,
    B53Cipher,
    decrypt,
    deserialize,
    deserialize_bool_array,
    generate_salt,
    serialize,
    serialize_bool_array,
)
from b53.core import (
    _decrypt_with_key,
    _derive_initial_seed,
    _derive_next_seed,
    _normalize_salt,
    _plan_chunk_sizes,
)


def _chained_chunk_lengths(doubles: list[float], salt: str) -> list[int]:
    """Helper verifying chunk lengths by stepping through the seed chain."""
    key_bytes = _normalize_salt(salt)
    seed = _derive_initial_seed(key_bytes, len(doubles))
    lengths: list[int] = []
    prev_len = 0
    for idx, val in enumerate(doubles):
        if idx > 0:
            seed = _derive_next_seed(key_bytes, seed, idx, prev_len)
        bits = _decrypt_with_key(val, seed)
        prev_len = len(bits)
        lengths.append(prev_len)
    return lengths


def test_default_constants() -> None:
    assert DEFAULT_CHUNK_MIN == 10
    assert MIN_SPLIT_SIZE == 2


def test_csprng_used_exclusively_in_package() -> None:
    assert isinstance(core_mod._CSPRNG, secrets.SystemRandom)
    assert "random" not in vars(core_mod)


def test_serialize_deserialize_various_lengths() -> None:
    salt = generate_salt()
    rng = random.Random(12345)

    for length in (0, 1, 5, 9, 10, 11, 12, 19, 20, 30, 50, 51, 137, 1000):
        bits = [rng.choice((False, True)) for _ in range(length)]
        doubles = serialize_bool_array(bits, salt)
        assert isinstance(doubles, list)
        expected_chunks = 0 if length == 0 else (length // DEFAULT_CHUNK_MIN) + 1
        assert len(doubles) == expected_chunks

        for val in doubles:
            assert type(val) is float
            assert 0.0 <= val < 1.0
            assert math.ldexp(val, 53).is_integer()

        assert deserialize_bool_array(doubles, salt) == bits
        assert deserialize(serialize(bits, salt), salt) == bits


def test_planner_fixed_count_and_first_chunk_bound() -> None:
    for min_size in (2, 3, 10, 50):
        for total in range(1, 105):
            sizes = _plan_chunk_sizes(total, min_size)
            assert len(sizes) == (total // min_size) + 1
            assert sum(sizes) == total
            assert 1 <= sizes[0] < min_size
            assert all(1 <= size <= min_size for size in sizes[1:])


def test_twelve_elements_with_min_size_10_example() -> None:
    salt = generate_salt()
    bits = [i % 3 == 0 for i in range(12)]

    seen_splits: set[tuple[int, ...]] = set()
    for _ in range(40):
        doubles = serialize(bits, salt, min_size=10)
        lengths = tuple(_chained_chunk_lengths(doubles, salt))
        assert len(lengths) == 2
        assert sum(lengths) == 12
        assert 1 <= lengths[0] < 10
        assert 1 <= lengths[1] <= 10
        assert deserialize(doubles, salt) == bits
        seen_splits.add(lengths)

    assert len(seen_splits) > 1


def test_divisible_lengths_add_extra_chunk_with_random_sizes() -> None:
    salt = generate_salt()

    for total in (10, 20, 30):
        bits = [i % 2 == 1 for i in range(total)]
        seen_splits: set[tuple[int, ...]] = set()
        for _ in range(30):
            doubles = serialize(bits, salt, min_size=10)
            lengths = tuple(_chained_chunk_lengths(doubles, salt))
            assert len(lengths) == (total // 10) + 1
            assert sum(lengths) == total
            assert 1 <= lengths[0] < 10
            assert all(1 <= size <= 10 for size in lengths[1:])
            assert deserialize(doubles, salt) == bits
            seen_splits.add(lengths)

        assert len(seen_splits) > 1


def test_cannot_decrypt_individual_chunks_or_tampered_sequences() -> None:
    salt = generate_salt()

    # Even for a single-chunk array (K=1), seed_0 differs from raw salt.
    short_bits = [True, False, True, True, False]
    mismatches_single = sum(
        1
        for _ in range(10)
        if decrypt(serialize(short_bits, salt, min_size=10)[0], salt) != short_bits
    )
    assert mismatches_single == 10

    # Multi-chunk array: cannot decrypt any chunk alone, nor truncate, drop, or reorder.
    bits = [i % 3 == 0 for i in range(45)]
    doubles = serialize(bits, salt, min_size=10)
    assert len(doubles) == 5

    # Partition original bits using the real chunk lengths for negative assertions.
    chunk_lens = _chained_chunk_lengths(doubles, salt)
    chunks: list[list[bool]] = []
    pos = 0
    for size in chunk_lens:
        chunks.append(bits[pos : pos + size])
        pos += size

    for idx, d in enumerate(doubles):
        assert decrypt(d, salt) != chunks[idx]
        assert deserialize([d], salt) != chunks[idx]

    # Truncation changes total_chunks -> breaks seed_0 and all subsequent chunks.
    assert deserialize(doubles[:-1], salt) != bits[: sum(chunk_lens[:-1])]
    # Dropping chunk 0 shifts indices and breaks the seed chain.
    assert deserialize(doubles[1:], salt) != bits[chunk_lens[0] :]
    # Swapping chunks breaks chaining.
    swapped = list(doubles)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    assert deserialize(swapped, salt) != bits


def test_cipher_methods_and_generators() -> None:
    cipher, _ = B53Cipher.generate()
    expected = [i % 4 == 0 for i in range(95)]

    doubles = cipher.serialize((i % 4 == 0 for i in range(95)), min_size=8)
    assert len(doubles) == (95 // 8) + 1
    assert cipher.deserialize(d for d in doubles) == expected


@pytest.mark.parametrize("bad_min_size", [-5, 0, 1, MAX_LEN + 1, 100])
def test_invalid_min_size_raises_value_error(bad_min_size: int) -> None:
    salt = generate_salt()
    with pytest.raises(ValueError):
        serialize([True, False], salt, min_size=bad_min_size)
    with pytest.raises(ValueError):
        serialize([], salt, min_size=bad_min_size)


def test_invalid_min_size_type_raises_type_error() -> None:
    salt = generate_salt()
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=True)
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=False)
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=cast(Any, 10.0))
    with pytest.raises(TypeError):
        serialize([True], salt, min_size=cast(Any, "10"))


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
