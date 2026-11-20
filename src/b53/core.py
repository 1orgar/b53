"""Core 53-bit reversible boolean-array packing and Feistel cipher."""

from __future__ import annotations

import hmac
import math
import secrets
from bisect import bisect_right
from collections.abc import Iterable, Mapping

MANTISSA_BITS = 53
MIN_LEN = 1
MAX_LEN = 50
STATE_SPACE = 1 << MANTISSA_BITS

LEFT_BITS = 26
RIGHT_BITS = 27  # 26 + 27 = 53 bits
LEFT_MASK = (1 << LEFT_BITS) - 1
RIGHT_MASK = (1 << RIGHT_BITS) - 1
FEISTEL_ROUNDS = 8

MIN_SALT_BYTES = 16
DEFAULT_SALT_BYTES = 32

SaltType = str | bytes | bytearray


def _build_partition_tables() -> tuple[dict[int, int], dict[int, int], dict[int, int]]:
    """Build exact partition tables splitting ``2^53`` states across ``L = 1..50``."""
    nonce_counts: dict[int, int] = {}
    remaining = STATE_SPACE

    for length in range(MAX_LEN, 1, -1):
        unit = 1 << length
        count = max(3, remaining // (4 * unit))
        nonce_counts[length] = count
        remaining -= count * unit

    # Remaining budget at L = 1 is guaranteed even and absorbed completely.
    if remaining <= 0 or remaining % 2 != 0:
        raise RuntimeError("53-bit partition integrity check failed at L=1.")
    nonce_counts[1] = remaining // 2

    bases: dict[int, int] = {}
    sizes: dict[int, int] = {}
    cursor = 0
    for length in range(MIN_LEN, MAX_LEN + 1):
        size = nonce_counts[length] << length
        bases[length] = cursor
        sizes[length] = size
        cursor += size

    if cursor != STATE_SPACE:
        raise RuntimeError("53-bit partition does not sum to 2^53.")

    return nonce_counts, bases, sizes


NONCE_COUNTS, BASES, SIZES = _build_partition_tables()
_BASE_LIST: tuple[int, ...] = tuple(BASES[length] for length in range(MIN_LEN, MAX_LEN + 1))


def _normalize_salt(salt: SaltType) -> bytes:
    """Validate and normalize a hex string, UTF-8 passphrase, or raw byte key."""
    if isinstance(salt, (bytes, bytearray)):
        key = bytes(salt)
        if not key:
            raise ValueError("Salt must not be empty.")
        return key
    if not isinstance(salt, str):
        raise TypeError(f"Salt must be str or bytes, got {type(salt).__name__}.")

    cleaned = salt.strip()
    if not cleaned:
        raise ValueError("Salt must not be empty.")

    try:
        decoded = bytes.fromhex(cleaned)
    except ValueError:
        return cleaned.encode("utf-8")

    if not decoded:
        raise ValueError("Salt must not be empty.")
    return decoded


def _coerce_bits(bits: Iterable[bool], *, max_items: int | None = None) -> list[bool]:
    """Convert an iterable of bool or 0/1 ints to ``list[bool]`` safely."""
    if isinstance(bits, (str, bytes, bytearray, memoryview, Mapping)):
        raise TypeError(
            "bits must be a sequence or iterable of booleans (not str, bytes, or mapping); "
            "use parse_bits() to parse a bit string."
        )

    result: list[bool] = []
    for item in bits:
        if max_items is not None and len(result) >= max_items:
            raise ValueError(
                f"Array length must be between {MIN_LEN} and {MAX_LEN} elements."
            )
        if isinstance(item, bool):
            result.append(item)
        elif isinstance(item, int):
            if item not in (0, 1):
                raise ValueError(f"Integer bit elements must be 0 or 1, got {item!r}.")
            result.append(bool(item))
        elif type(item).__name__ == "bool_" and hasattr(item, "__bool__"):
            # Support numpy.bool_ without taking a runtime dependency on numpy.
            result.append(bool(item))
        else:
            raise TypeError(
                f"Bit elements must be bool (or 0/1 int), got {type(item).__name__}."
            )
    return result


def _prf(key_bytes: bytes, round_idx: int, half_val: int) -> int:
    """Compute a 32-bit keyed round output via HMAC-SHA256."""
    msg = round_idx.to_bytes(1, "big") + half_val.to_bytes(4, "big")
    digest = hmac.digest(key_bytes, msg, "sha256")
    return int.from_bytes(digest[:4], "big")


def _feistel_encrypt_53(value: int, key_bytes: bytes) -> int:
    """Bijective 53-bit encryption via an 8-round unbalanced Feistel network (26 + 27)."""
    left = (value >> RIGHT_BITS) & LEFT_MASK
    right = value & RIGHT_MASK
    for r in range(FEISTEL_ROUNDS):
        if r % 2 == 0:
            left ^= _prf(key_bytes, r, right) & LEFT_MASK
        else:
            right ^= _prf(key_bytes, r, left) & RIGHT_MASK
    return (left << RIGHT_BITS) | right


def _feistel_decrypt_53(value: int, key_bytes: bytes) -> int:
    """Inverse 8-round unbalanced Feistel permutation over 53-bit integers."""
    left = (value >> RIGHT_BITS) & LEFT_MASK
    right = value & RIGHT_MASK
    for r in reversed(range(FEISTEL_ROUNDS)):
        if r % 2 == 0:
            left ^= _prf(key_bytes, r, right) & LEFT_MASK
        else:
            right ^= _prf(key_bytes, r, left) & RIGHT_MASK
    return (left << RIGHT_BITS) | right


def _encrypt_with_key(bits: Iterable[bool], key_bytes: bytes) -> float:
    bools = _coerce_bits(bits, max_items=MAX_LEN)
    length = len(bools)
    if not (MIN_LEN <= length <= MAX_LEN):
        raise ValueError(
            f"Array length must be between {MIN_LEN} and {MAX_LEN} elements, got {length}."
        )

    data_int = 0
    for idx, bit in enumerate(bools):
        if bit:
            data_int |= 1 << idx

    nonce = secrets.randbelow(NONCE_COUNTS[length])
    plain_53 = BASES[length] + (nonce << length) + data_int
    cipher_53 = _feistel_encrypt_53(plain_53, key_bytes)
    return math.ldexp(cipher_53, -MANTISSA_BITS)


def _decrypt_with_key(double_val: float, key_bytes: bytes) -> list[bool]:
    if isinstance(double_val, bool) or not isinstance(double_val, float):
        raise TypeError("Expected a float (IEEE 754 binary64 double).")
    if not math.isfinite(double_val) or not (0.0 <= double_val < 1.0):
        raise ValueError("Double value must be finite and in the half-open interval [0.0, 1.0).")

    scaled = math.ldexp(double_val, MANTISSA_BITS)
    if not scaled.is_integer():
        raise ValueError("Double value does not lie on the exact 53-bit IEEE 754 grid.")

    cipher_53 = int(scaled)
    plain_53 = _feistel_decrypt_53(cipher_53, key_bytes)

    length = bisect_right(_BASE_LIST, plain_53)
    base = BASES[length]
    if not (base <= plain_53 < base + SIZES[length]):
        raise ValueError("Failed to decode 53-bit state.")

    offset = plain_53 - base
    data_int = offset & ((1 << length) - 1)
    return [((data_int >> idx) & 1) == 1 for idx in range(length)]


def generate_salt(num_bytes: int = DEFAULT_SALT_BYTES) -> str:
    """Generate a cryptographically secure hex-encoded salt (default 32 bytes / 256 bits)."""
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise TypeError(f"num_bytes must be int, got {type(num_bytes).__name__}.")
    if num_bytes < MIN_SALT_BYTES:
        raise ValueError(
            f"Salt size must be at least {MIN_SALT_BYTES} bytes (128 bits), got {num_bytes}."
        )
    return secrets.token_hex(num_bytes)


def parse_bits(raw: str) -> list[bool]:
    """Parse a bit string (e.g. ``'1011001'``) or comma-separated booleans into ``list[bool]``."""
    if not isinstance(raw, str):
        raise TypeError(f"Expected str, got {type(raw).__name__}.")

    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("Bit string must not be empty.")

    if all(ch in "01" for ch in cleaned):
        return [ch == "1" for ch in cleaned]

    tokens = [token.strip().lower() for token in cleaned.split(",") if token.strip()]
    if not tokens:
        raise ValueError("Bit string must not be empty.")

    result: list[bool] = []
    for token in tokens:
        if token in ("1", "true", "t"):
            result.append(True)
        elif token in ("0", "false", "f"):
            result.append(False)
        else:
            raise ValueError(f"Unrecognized boolean token: {token!r}.")
    return result


def format_bits(bits: Iterable[bool]) -> str:
    """Format an iterable of booleans as a ``'0'``/``'1'`` bit string."""
    return "".join("1" if bit else "0" for bit in _coerce_bits(bits))


def encrypt_bool_array(bits: Iterable[bool], salt: SaltType) -> float:
    """Encrypt 1..50 booleans with hidden length and random nonce into [0.0, 1.0)."""
    key_bytes = _normalize_salt(salt)
    return _encrypt_with_key(bits, key_bytes)


def decrypt_bool_array(double_val: float, salt: SaltType) -> list[bool]:
    """Recover the original boolean list and its hidden length from a double and salt."""
    key_bytes = _normalize_salt(salt)
    return _decrypt_with_key(double_val, key_bytes)


def encrypt(bits: Iterable[bool], salt: SaltType) -> float:
    """Alias for :func:`encrypt_bool_array`."""
    return encrypt_bool_array(bits, salt)


def decrypt(double_val: float, salt: SaltType) -> list[bool]:
    """Alias for :func:`decrypt_bool_array`."""
    return decrypt_bool_array(double_val, salt)


class B53Cipher:
    """Reusable cipher bound to a normalized secret salt."""

    def __init__(self, salt: SaltType) -> None:
        self._key_bytes = _normalize_salt(salt)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_bytes={len(self._key_bytes)})"

    @classmethod
    def generate(cls, num_bytes: int = DEFAULT_SALT_BYTES) -> tuple[B53Cipher, str]:
        """Generate a new random salt and return ``(cipher, salt_hex)``."""
        salt = generate_salt(num_bytes)
        return cls(salt), salt

    def encrypt(self, bits: Iterable[bool]) -> float:
        """Encrypt 1..50 booleans into a double in ``[0.0, 1.0)``."""
        return _encrypt_with_key(bits, self._key_bytes)

    def decrypt(self, double_val: float) -> list[bool]:
        """Decrypt a double in ``[0.0, 1.0)`` back into the original ``list[bool]``."""
        return _decrypt_with_key(double_val, self._key_bytes)

    def encrypt_str(self, raw_bits: str) -> float:
        """Parse a bit string (e.g. ``'10110'``) and encrypt it."""
        return self.encrypt(parse_bits(raw_bits))

    def decrypt_str(self, double_val: float) -> str:
        """Decrypt a double and format the result as a ``'0'``/``'1'`` bit string."""
        return format_bits(self.decrypt(double_val))


Cipher = B53Cipher
