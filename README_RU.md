# b53

[English](https://github.com/1orgar/b53/blob/main/README.md) | **🇷🇺 Русская версия**

[![PyPI version](https://img.shields.io/pypi/v/b53.svg)](https://pypi.org/project/b53/)
[![Python versions](https://img.shields.io/pypi/pyversions/b53.svg)](https://pypi.org/project/b53/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/1orgar/b53/actions/workflows/ci.yml/badge.svg)](https://github.com/1orgar/b53/actions/workflows/ci.yml)

**`b53`** — Python-библиотека без внешних зависимостей для обратимого криптографического шифрования булева массива произвольной длины `L ∈ [1, 50]` в одно стандартное 64-битное число с плавающей точкой (`IEEE 754 binary64` / `double` / `float` в Python) на полуинтервале `[0.0, 1.0)`.

## Ключевые свойства

- **Скрытая размерность внутри числа:** длина массива `L ∈ [1, 50]` кодируется непосредственно в 53-битном пространстве мантиссы без передачи внешних метаданных.
- **Случайная компонента (Nonce) при каждой генерации:** повторное шифрование одного и того же массива с одной и той же солью даёт разные псевдослучайные `double`.
- **Биективная 53-битная перестановка:** 8-раундовая несбалансированная сеть Фейстеля (`26 + 27 = 53` бита) с раундовой функцией на базе `HMAC-SHA256` и секретной соли.
- **Цепочечная сериализация произвольной длины:** нарезает массив любого размера на фиксированное число случайных чанков и модифицирует соль от чанка к чанку — расшифровать отдельный `double` по отдельности невозможно.
- **Key stretching для паролей (`scrypt`):** растягивает пользовательский пароль в 256-битную соль с помощью стандартного `hashlib.scrypt` (`RFC 7914`).
- **Только стандартная библиотека Python 3.10+:** ноль внешних зависимостей, полная типизация (`py.typed`).

## Установка

```bash
pip install b53

# Опционально: асимметричное расширение X25519 (b53a / b53.asymmetric)
pip install "b53[asymmetric]"
```

## Быстрый старт

### Python API

```python
import b53

# 1. Генерация 256-битной соли-ключа (или key stretching из пароля через scrypt)
salt = b53.generate_salt()
# salt = b53.derive_salt("my-passphrase", context="user:42")

# 2. Шифрование массива bool (1..50 элементов) в double [0.0, 1.0)
bits = [True, False, True, True, False, False, True, False, True, True]
x1 = b53.encrypt(bits, salt)
x2 = b53.encrypt(bits, salt)  # разный результат за счёт случайного nonce
assert x1 != x2

# 3. Однозначное восстановление массива и его длины
assert b53.decrypt(x1, salt) == bits
assert b53.decrypt(x2, salt) == bits

# 4. Сериализация и десериализация массива bool произвольной длины в list[float]
many_bits = [i % 3 == 0 for i in range(250)]
doubles = b53.serialize(many_bits, salt, min_size=10)
assert b53.deserialize(doubles, salt) == many_bits
```

Также доступны функции `encrypt_bool_array` / `decrypt_bool_array`, `serialize_bool_array` / `deserialize_bool_array` и класс `B53Cipher` (`Cipher`):

```python
from b53 import B53Cipher

cipher = B53Cipher(salt)
# или: cipher = B53Cipher.from_password("my-passphrase", context="user:42")

encoded = cipher.encrypt_str("1011001011")
print(repr(encoded))
print(cipher.decrypt_str(encoded))  # "1011001011"

doubles = cipher.serialize(many_bits)  # по умолчанию min_size=10
assert cipher.deserialize(doubles) == many_bits
```

### Асимметричный режим (`b53a` / `b53.asymmetric`)

Требует `pip install "b53[asymmetric]"`. Использует `X25519` + `HKDF-SHA256`, не добавляя эфемерные ключи внутрь массива `double`:

```python
import b53a  # или: from b53 import b53a

bob = b53a.generate_keypair()

# 1. Односторонняя сессия: шифрующая сторона знает только bob.public_key,
#    капсула передаётся отдельно от выходных double.
enc, capsule = b53a.seal_session(bob.public_key, context="table:flags")
d = enc.encrypt([True, False, True, True])        # 1 точный double в [0.0, 1.0)
ds = enc.serialize([True, False] * 15)            # фиксированный list[float]

dec = b53a.open_session(capsule, bob.private_key, context="table:flags")
assert dec.decrypt(d) == [True, False, True, True]
assert dec.deserialize(ds) == [True, False] * 15

# 2. Парный обмен X25519 (без капсулы, когда у обеих сторон есть пары ключей)
alice = b53a.generate_keypair()
x = b53a.encrypt([True, False, True], alice.private_key, bob.public_key)
assert b53a.decrypt(x, bob.private_key, alice.public_key) == [True, False, True]
```

### CLI

```bash
# 1. Генерация соли
SALT=$(b53 generate-salt)

# 2. Три независимых шифрования одного массива
b53 encrypt 1011001011 --salt "$SALT" --count 3

# 3. Дешифрование
b53 decrypt 0.7419283058129402 --salt "$SALT"
```

Поддерживаются запуск через `python -m b53 ...`, `--salt-file`, переменная окружения `B53_SALT` и флаг `-q` / `--quiet`.

## Математическая модель

Число на равномерной сетке `[0.0, 1.0)` имеет вид `x = C · 2⁻⁵³`, где `C ∈ {0, 1, ..., 2⁵³ - 1}`.

Всё пространство из `2⁵³ = 9 007 199 254 740 992` состояний без остатка разбивается на 50 непересекающихся сегментов для `L ∈ [1, 50]`:

<p align="center">
  <code>&sum;<sub>L=1..50</sub> M<sub>L</sub> &middot; 2<sup>L</sup> = 2<sup>53</sup></code>
</p>

Бюджет распределяется адаптивно сверху вниз от `L = 50` к `L = 1` (около 25% остатка на шаг, не менее `M_L ≥ 3` вариантов на границе `L = 50`):

| Длина массива `L` | Комбинаций (`2^L`) | Вариантов nonce (`M_L`) | Размер сегмента (`M_L · 2^L`) |
|---:|---:|---:|---:|
| 50 | `2^50` | 3 | `3 × 2^50` |
| 49 | `2^49` | 3 | `3 × 2^49` |
| 48 | `2^48` | 3 | `3 × 2^48` |
| 47 | `2^47` | 5 | `5 × 2^47` |
| 45 | `2^45` | 13 | `13 × 2^45` |
| 40 | `2^40` | 100 | `100 × 2^40` |
| 30 | `2^30` | 5 811 | `5 811 × 2^30` |
| 20 | `2^20` | 335 103 | `335 103 × 2^20` |
| 10 | `2^10` | 19 323 738 | `~1.98 × 10^10` |
| 1 | `2^1` | 2 971 477 630 | `~5.94 × 10^9` |

## Требования к хранению и передаче `double`

При передаче через текст, CLI, CSV или JSON обязательно сохраняйте все 17 значащих цифр (`repr(x)` / `f"{x:.17g}"`, в PostgreSQL — бинарный тип `DOUBLE PRECISION` / `FLOAT8`). Округление даже последнего разряда разрушает младшие биты шифротекста.

При использовании `serialize()` / `deserialize()` порядок и полный состав массива `list[float]` должны сохраняться целиком: начальный ключ-seed привязан к количеству чанков, а каждый последующий чанк шифруется модифицированной солью от предыдущего seed, индекса и размера предыдущего чанка — расшифровать отдельный `double` по отдельности невозможно.

## Справочник API

- `generate_salt(num_bytes: int = 32) -> str` — генерация криптостойкой hex-соли (≥ 16 байт).
- `derive_salt(password, context=None, *, num_bytes=32, n=32768, r=8, p=1, maxmem=...) -> str` — растяжение пароля в hex-соль через `hashlib.scrypt` (`RFC 7914`).
- `encrypt(bits, salt) -> float` / `encrypt_bool_array(bits, salt) -> float` — шифрование `1..50` булевых значений в `double` на `[0.0, 1.0)`.
- `decrypt(double_val, salt) -> list[bool]` / `decrypt_bool_array(double_val, salt) -> list[bool]` — восстановление исходного списка `bool` и его длины.
- `serialize(bits, salt, min_size=10) -> list[float]` / `serialize_bool_array(...)` — разбиение массива произвольной длины на `(len(bits) // min_size) + 1` чанков случайной длины из `[1, min_size]` (`len(chunk[0]) < min_size`, `2 <= min_size <= 50`) с цепочечной модификацией соли.
- `deserialize(values, salt) -> list[bool]` / `deserialize_bool_array(values, salt)` — восстановление полного массива `bool` из цепочки `double`.
- `parse_bits(raw: str) -> list[bool]` — разбор строки `"10110"` или `"true,false,1,0"`.
- `format_bits(bits) -> str` — форматирование в битовую строку `"10110"`.
- `B53Cipher(salt)` (алиас `Cipher`) — объект шифра с методами `.encrypt()`, `.decrypt()`, `.serialize()`, `.deserialize()`, `.encrypt_str()`, `.decrypt_str()`, `B53Cipher.generate()` и `B53Cipher.from_password(password, context=...)`.

## Разработка и тесты

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## Лицензия

[MIT](https://github.com/1orgar/b53/blob/main/LICENSE)
