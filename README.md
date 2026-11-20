# b53

**English** | [🇷🇺 Русская версия](README_RU.md)

[![PyPI version](https://img.shields.io/pypi/v/b53.svg)](https://pypi.org/project/b53/)
[![Python versions](https://img.shields.io/pypi/pyversions/b53.svg)](https://pypi.org/project/b53/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/1orgar/b53/actions/workflows/ci.yml/badge.svg)](https://github.com/1orgar/b53/actions/workflows/ci.yml)

**`b53`** is a zero-dependency Python library for reversible cryptographic packing of boolean arrays of arbitrary length $L \in [1, 50]$ into a single standard IEEE 754 `binary64` (`double` / Python `float`) in the half-open interval $[0.0, 1.0)$.

## Key Properties

- **Hidden length inside the float:** the original array length $L \in [1, 50]$ is encoded directly inside the 53-bit mantissa space—no external length metadata is required.
- **Randomized output (nonce) per encryption:** encrypting the same boolean array with the same salt produces different pseudorandom doubles in $[0.0, 1.0)$.
- **Bijective 53-bit permutation:** uses an 8-round unbalanced Feistel network ($26 + 27 = 53$ bits) keyed by `HMAC-SHA256` with your secret salt.
- **Pure Python standard library:** zero runtime dependencies, typed (`py.typed`), Python 3.10+.

## Installation

```bash
pip install b53
```

## Quick Start

### Python API

```python
import b53

# 1. Generate a 256-bit secret salt (store securely)
salt = b53.generate_salt()

# 2. Encrypt a boolean array (1..50 elements) into a float in [0.0, 1.0)
bits = [True, False, True, True, False, False, True, False, True, True]
x1 = b53.encrypt(bits, salt)
x2 = b53.encrypt(bits, salt)  # different float due to random nonce
assert x1 != x2

# 3. Decrypt back to the exact original list[bool] and length
assert b53.decrypt(x1, salt) == bits
assert b53.decrypt(x2, salt) == bits
```

For repeated operations with the same salt, use `B53Cipher` (alias `Cipher`):

```python
from b53 import B53Cipher

cipher = B53Cipher(salt)
encoded = cipher.encrypt_str("1011001011")
print(repr(encoded))
print(cipher.decrypt_str(encoded))  # "1011001011"
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

An IEEE 754 `binary64` float on the uniform $2^{-53}$ grid represents $x = C \cdot 2^{-53}$ for $C \in \{0, 1, \dots, 2^{53} - 1\}$.

The entire 53-bit state space ($2^{53} = 9\,007\,199\,254\,740\,992$ states) is partitioned without gaps or overlaps across all 50 lengths $L \in [1, 50]$ so that:

$$\sum_{L=1}^{50} M_L \cdot 2^L = 2^{53}$$

Space is allocated top-down from $L = 50$ to $L = 1$, reserving $\approx 25\%$ of the remaining budget at each step (at least $M_L \ge 3$ nonces even at $L = 50$):

| Length $L$ | Data combinations ($2^L$) | Nonces per array ($M_L$) | Segment size ($M_L \cdot 2^L$) |
|---:|---:|---:|---:|
| 50 | $2^{50}$ | 3 | $3 \times 2^{50}$ |
| 49 | $2^{49}$ | 3 | $3 \times 2^{49}$ |
| 48 | $2^{48}$ | 3 | $3 \times 2^{48}$ |
| 47 | $2^{47}$ | 5 | $5 \times 2^{47}$ |
| 45 | $2^{45}$ | 13 | $13 \times 2^{45}$ |
| 40 | $2^{40}$ | 100 | $100 \times 2^{40}$ |
| 30 | $2^{30}$ | 5,811 | $5{,}811 \times 2^{30}$ |
| 20 | $2^{20}$ | 335,103 | $335{,}103 \times 2^{20}$ |
| 10 | $2^{10}$ | 19,323,738 | $\approx 1.98 \times 10^{10}$ |
| 1 | $2^1$ | 2,971,477,630 | $\approx 5.94 \times 10^{9}$ |

1. **Pack:** encode `bits` as $D \in [0, 2^L - 1]$, pick $r \in [0, M_L - 1]$ via `secrets.randbelow`, and compute $P = \text{BASE}[L] + r \cdot 2^L + D$.
2. **Permute:** apply an 8-round unbalanced Feistel network ($26 + 27$ bits) with `HMAC-SHA256` keyed by the normalized salt to obtain $C \in [0, 2^{53} - 1]$.
3. **Float conversion:** return `math.ldexp(C, -53)` ($C \cdot 2^{-53}$).
4. **Decrypt:** verify $x \in [0.0, 1.0)$ lies exactly on the $2^{-53}$ grid, invert the Feistel permutation to recover $P$, find the unique range $L$, discard $r$, and unpack the lower $L$ bits of $P - \text{BASE}[L]$.

## Precision Requirements

When serializing the encrypted `double` to text, JSON, CSV, or CLI arguments, always preserve all significant binary64 digits using `repr(x)` / `f"{x:.17g}"` (or native `DOUBLE PRECISION` / `FLOAT8` in databases). Rounding even the least significant digit alters the lower bits of the 53-bit ciphertext and breaks decryption.

## API Reference

- `generate_salt(num_bytes: int = 32) -> str` — generate a cryptographically random hex salt ($\ge 16$ bytes).
- `encrypt(bits, salt) -> float` / `encrypt_bool_array(bits, salt) -> float` — encrypt $1..50$ booleans (or `0`/`1` ints) into a double in $[0.0, 1.0)$.
- `decrypt(double_val, salt) -> list[bool]` / `decrypt_bool_array(double_val, salt) -> list[bool]` — recover the exact boolean list and length.
- `parse_bits(raw: str) -> list[bool]` — parse `"10110"` or `"true,false,1,0"`.
- `format_bits(bits) -> str` — format booleans as `"10110"`.
- `B53Cipher(salt)` (alias `Cipher`) — reusable cipher object with `.encrypt()`, `.decrypt()`, `.encrypt_str()`, `.decrypt_str()`, and `B53Cipher.generate()`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## License

[MIT](LICENSE)
