# b53

**English** | [🇷🇺 Русская версия](https://github.com/1orgar/b53/blob/main/README_RU.md)

[![PyPI version](https://img.shields.io/pypi/v/b53.svg)](https://pypi.org/project/b53/)
[![Python versions](https://img.shields.io/pypi/pyversions/b53.svg)](https://pypi.org/project/b53/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/1orgar/b53/actions/workflows/ci.yml/badge.svg)](https://github.com/1orgar/b53/actions/workflows/ci.yml)

**`b53`** is a zero-dependency Python library for reversible cryptographic packing of boolean arrays of arbitrary length `L ∈ [1, 50]` into a single standard IEEE 754 `binary64` (`double` / Python `float`) in the half-open interval `[0.0, 1.0)`.

## Key Properties

- **Hidden length inside the float:** the original array length `L ∈ [1, 50]` is encoded directly inside the 53-bit mantissa space—no external length metadata is required.
- **Randomized output (nonce) per encryption:** encrypting the same boolean array with the same salt produces different pseudorandom doubles in `[0.0, 1.0)`.
- **Bijective 53-bit permutation:** uses an 8-round unbalanced Feistel network (`26 + 27 = 53` bits) keyed by `HMAC-SHA256` with your secret salt.
- **Chained arbitrary-length serialization:** splits arrays of any length into a fixed number of random-size chunks with per-chunk salt chaining so individual doubles cannot be decrypted in isolation.
- **Password key stretching (`scrypt`):** derives strong 256-bit salts from human passwords via standard-library `hashlib.scrypt` (`RFC 7914`).
- **Pure Python standard library:** zero runtime dependencies, typed (`py.typed`), Python 3.10+.

## Installation

```bash
pip install b53

# Optional: asymmetric X25519 extension (b53a / b53.asymmetric)
pip install "b53[asymmetric]"
```

## Quick Start

### Python API

```python
import b53

# 1. Generate a 256-bit secret salt (or stretch a password with scrypt)
salt = b53.generate_salt()
# salt = b53.derive_salt("my-passphrase", context="user:42")

# 2. Encrypt a boolean array (1..50 elements) into a float in [0.0, 1.0)
bits = [True, False, True, True, False, False, True, False, True, True]
x1 = b53.encrypt(bits, salt)
x2 = b53.encrypt(bits, salt)  # different float due to random nonce
assert x1 != x2

# 3. Decrypt back to the exact original list[bool] and length
assert b53.decrypt(x1, salt) == bits
assert b53.decrypt(x2, salt) == bits

# 4. Serialize/deserialize an arbitrary-length boolean array into list[float]
many_bits = [i % 3 == 0 for i in range(250)]
doubles = b53.serialize(many_bits, salt, min_size=10)
assert b53.deserialize(doubles, salt) == many_bits
```

For repeated operations with the same salt (or directly from a password), use `B53Cipher` (alias `Cipher`):

```python
from b53 import B53Cipher

cipher = B53Cipher(salt)
# or: cipher = B53Cipher.from_password("my-passphrase", context="user:42")

encoded = cipher.encrypt_str("1011001011")
print(repr(encoded))
print(cipher.decrypt_str(encoded))  # "1011001011"

doubles = cipher.serialize(many_bits)  # default min_size=10
assert cipher.deserialize(doubles) == many_bits
```

### Asymmetric Mode (`b53a` / `b53.asymmetric`)

Requires `pip install "b53[asymmetric]"`. Uses `X25519` + `HKDF-SHA256` without embedding keys into the `double` output:

```python
import b53a  # or: from b53 import b53a

bob = b53a.generate_keypair()

# 1. One-way sealed session: encryptor only needs bob.public_key;
#    capsule is stored separately from the double payloads.
enc, capsule = b53a.seal_session(bob.public_key, context="table:flags")
d = enc.encrypt([True, False, True, True])        # 1 exact double in [0.0, 1.0)
ds = enc.serialize([True, False] * 15)            # fixed-count list[float]

dec = b53a.open_session(capsule, bob.private_key, context="table:flags")
assert dec.decrypt(d) == [True, False, True, True]
assert dec.deserialize(ds) == [True, False] * 15

# 2. Pairwise X25519 (no capsule needed when both sides hold keypairs)
alice = b53a.generate_keypair()
x = b53a.encrypt([True, False, True], alice.private_key, bob.public_key)
assert b53a.decrypt(x, bob.private_key, alice.public_key) == [True, False, True]
```

### Command-Line Interface

```bash
# 1. Generate a 256-bit hex salt
SALT=$(b53 generate-salt)

# 2. Encrypt the same bit string 3 times
b53 encrypt 1011001011 --salt "$SALT" --count 3

# 3. Decrypt any generated double back to the original array
b53 decrypt 0.7419283058129402 --salt "$SALT"
```

You can also run via `python -m b53 ...`, pass `--salt-file path/to/salt`, or set the `B53_SALT` environment variable.

## How It Works

An IEEE 754 `binary64` float on the uniform `2⁻⁵³` grid represents `x = C · 2⁻⁵³` for `C ∈ {0, 1, ..., 2⁵³ - 1}`.

The entire 53-bit state space (`2⁵³ = 9,007,199,254,740,992` states) is partitioned without gaps or overlaps across all 50 lengths `L ∈ [1, 50]` so that:

<p align="center">
  <code>&sum;<sub>L=1..50</sub> M<sub>L</sub> &middot; 2<sup>L</sup> = 2<sup>53</sup></code>
</p>

Space is allocated top-down from `L = 50` to `L = 1`, reserving ~25% of the remaining budget at each step (at least `M_L ≥ 3` nonces even at `L = 50`):

| Length `L` | Data combinations (`2^L`) | Nonces per array (`M_L`) | Segment size (`M_L · 2^L`) |
|---:|---:|---:|---:|
| 50 | `2^50` | 3 | `3 × 2^50` |
| 49 | `2^49` | 3 | `3 × 2^49` |
| 48 | `2^48` | 3 | `3 × 2^48` |
| 47 | `2^47` | 5 | `5 × 2^47` |
| 45 | `2^45` | 13 | `13 × 2^45` |
| 40 | `2^40` | 100 | `100 × 2^40` |
| 30 | `2^30` | 5,811 | `5,811 × 2^30` |
| 20 | `2^20` | 335,103 | `335,103 × 2^20` |
| 10 | `2^10` | 19,323,738 | `~1.98 × 10^10` |
| 1 | `2^1` | 2,971,477,630 | `~5.94 × 10^9` |

1. **Pack:** encode `bits` as `D ∈ [0, 2^L - 1]`, pick `r ∈ [0, M_L - 1]` via `secrets.randbelow`, and compute `P = BASES[L] + r * 2^L + D`.
2. **Permute:** apply an 8-round unbalanced Feistel network (`26 + 27` bits) with `HMAC-SHA256` keyed by the normalized salt to obtain `C ∈ [0, 2^53 - 1]`.
3. **Float conversion:** return `math.ldexp(C, -53)` (`C · 2⁻⁵³`).
4. **Decrypt:** verify `x ∈ [0.0, 1.0)` lies exactly on the `2⁻⁵³` grid, invert the Feistel permutation to recover `P`, find the unique range `L`, discard `r`, and unpack the lower `L` bits of `P - BASES[L]`.

## Precision Requirements

When serializing the encrypted `double` to text, JSON, CSV, or CLI arguments, always preserve all significant binary64 digits using `repr(x)` / `f"{x:.17g}"` (or native `DOUBLE PRECISION` / `FLOAT8` in databases). Rounding even the least significant digit alters the lower bits of the 53-bit ciphertext and breaks decryption.

When using `serialize()` / `deserialize()`, keep the full list of doubles in its original order: chunk 0 derives its seed from the total chunk count, and each subsequent chunk derives a modified salt from the root salt, previous seed, index, and previous chunk length—so individual doubles cannot be decrypted in isolation.

## API Reference

- `generate_salt(num_bytes: int = 32) -> str` — generate a cryptographically random hex salt (≥ 16 bytes).
- `derive_salt(password, context=None, *, num_bytes=32, n=32768, r=8, p=1, maxmem=...) -> str` — stretch a human password/passphrase into a hex salt via stdlib `hashlib.scrypt` (`RFC 7914`).
- `encrypt(bits, salt) -> float` / `encrypt_bool_array(bits, salt) -> float` — encrypt `1..50` booleans (or `0`/`1` ints) into a double in `[0.0, 1.0)`.
- `decrypt(double_val, salt) -> list[bool]` / `decrypt_bool_array(double_val, salt) -> list[bool]` — recover the exact boolean list and length.
- `serialize(bits, salt, min_size=10) -> list[float]` / `serialize_bool_array(...)` — split an arbitrary-length boolean sequence into a fixed number of chunks `(len(bits) // min_size) + 1` of random sizes in `[1, min_size]` (first chunk strictly `< min_size`, `2 <= min_size <= 50`) and encrypt them using a chained per-chunk salt (`HMAC-SHA256` over total chunk count for chunk 0, then previous seed + index + previous chunk size).
- `deserialize(values, salt) -> list[bool]` / `deserialize_bool_array(values, salt)` — verify and restore the full boolean list from chained doubles.
- `parse_bits(raw: str) -> list[bool]` — parse `"10110"` or `"true,false,1,0"`.
- `format_bits(bits) -> str` — format booleans as `"10110"`.
- `B53Cipher(salt)` (alias `Cipher`) — reusable cipher object with `.encrypt()`, `.decrypt()`, `.serialize()`, `.deserialize()`, `.encrypt_str()`, `.decrypt_str()`, `B53Cipher.generate()`, and `B53Cipher.from_password(password, context=...)`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## License

[MIT](https://github.com/1orgar/b53/blob/main/LICENSE)
