"""Tests for the exact 53-bit mantissa partition tables."""

from __future__ import annotations

from b53.core import BASES, MANTISSA_BITS, MAX_LEN, MIN_LEN, NONCE_COUNTS, SIZES, STATE_SPACE


def test_partition_covers_entire_53_bit_space() -> None:
    total = sum(NONCE_COUNTS[length] * (1 << length) for length in range(MIN_LEN, MAX_LEN + 1))
    assert total == STATE_SPACE == (1 << MANTISSA_BITS)


def test_partition_ranges_are_contiguous_and_disjoint() -> None:
    assert set(NONCE_COUNTS.keys()) == set(range(MIN_LEN, MAX_LEN + 1))
    assert set(BASES.keys()) == set(range(MIN_LEN, MAX_LEN + 1))
    assert set(SIZES.keys()) == set(range(MIN_LEN, MAX_LEN + 1))

    assert BASES[1] == 0
    for length in range(MIN_LEN, MAX_LEN + 1):
        assert NONCE_COUNTS[length] >= 3
        assert SIZES[length] == (NONCE_COUNTS[length] << length)
        if length < MAX_LEN:
            assert BASES[length] + SIZES[length] == BASES[length + 1]

    assert BASES[MAX_LEN] + SIZES[MAX_LEN] == STATE_SPACE


def test_partition_matches_specification_reference_values() -> None:
    expected = {
        50: 3,
        49: 3,
        48: 3,
        47: 5,
        45: 13,
        40: 100,
        30: 5_811,
        20: 335_103,
        10: 19_323_738,
        1: 2_971_477_630,
    }
    for length, count in expected.items():
        assert NONCE_COUNTS[length] == count
