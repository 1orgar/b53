# b53

[English](README.md) | **🇷🇺 Русская версия**

[![PyPI version](https://img.shields.io/pypi/v/b53.svg)](https://pypi.org/project/b53/)
[![Python versions](https://img.shields.io/pypi/pyversions/b53.svg)](https://pypi.org/project/b53/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/1orgar/b53/actions/workflows/ci.yml/badge.svg)](https://github.com/1orgar/b53/actions/workflows/ci.yml)

**`b53`** — Python-библиотека без внешних зависимостей для обратимого криптографического шифрования булева массива произвольной длины $L \in [1, 50]$ в одно стандартное 64-битное число с плавающей точкой (`IEEE 754 binary64` / `double` / `float` в Python) на полуинтервале $[0.0, 1.0)$.

## Ключевые свойства

- **Скрытая размерность внутри числа:** длина массива $L \in [1, 50]$ кодируется непосредственно в 53-битном пространстве мантиссы без передачи внешних метаданных.
- **Случайная компонента (Nonce) при каждой генерации:** повторное шифрование одного и того же массива с одной и той же солью даёт разные псевдослучайные `double`.
- **Биективная 53-битная перестановка:** 8-раундовая несбалансированная сеть Фейстеля ($26 + 27 = 53$ бита) с раундовой функцией на базе `HMAC-SHA256` и секретной соли.
- **Только стандартная библиотека Python 3.10+:** ноль внешних зависимостей, полная типизация (`py.typed`).

## Установка

```bash
pip install b53
```

## Быстрый старт

### Python API

```python
import b53

# 1. Генерация 256-битной соли-ключа
salt = b53.generate_salt()

# 2. Шифрование массива bool (1..50 элементов) в double [0.0, 1.0)
bits = [True, False, True, True, False, False, True, False, True, True]
x1 = b53.encrypt(bits, salt)
x2 = b53.encrypt(bits, salt)  # разный результат за счёт случайного nonce
assert x1 != x2

# 3. Однозначное восстановление массива и его длины
assert b53.decrypt(x1, salt) == bits
assert b53.decrypt(x2, salt) == bits
```

Также доступны функции `encrypt_bool_array` / `decrypt_bool_array` и класс `B53Cipher` (`Cipher`):

```python
from b53 import B53Cipher

cipher = B53Cipher(salt)
encoded = cipher.encrypt_str("1011001011")
print(repr(encoded))
print(cipher.decrypt_str(encoded))  # "1011001011"
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

Число на равномерной сетке $[0.0, 1.0)$ имеет вид $x = C \cdot 2^{-53}$, где $C \in \{0, 1, \dots, 2^{53} - 1\}$.

Всё пространство из $2^{53} = 9\,007\,199\,254\,740\,992$ состояний без остатка разбивается на 50 непересекающихся сегментов для $L \in [1, 50]$:

$$\sum_{L=1}^{50} M_L \cdot 2^L = 2^{53}$$

Бюджет распределяется адаптивно сверху вниз от $L = 50$ к $L = 1$ (около 25% остатка на шаг, не менее $M_L \ge 3$ вариантов на границе $L = 50$):

| Длина массива $L$ | Комбинаций ($2^L$) | Вариантов nonce ($M_L$) | Размер сегмента ($M_L \cdot 2^L$) |
|---:|---:|---:|---:|
| 50 | $2^{50}$ | 3 | $3 \times 2^{50}$ |
| 49 | $2^{49}$ | 3 | $3 \times 2^{49}$ |
| 48 | $2^{48}$ | 3 | $3 \times 2^{48}$ |
| 47 | $2^{47}$ | 5 | $5 \times 2^{47}$ |
| 45 | $2^{45}$ | 13 | $13 \times 2^{45}$ |
| 40 | $2^{40}$ | 100 | $100 \times 2^{40}$ |
| 30 | $2^{30}$ | 5 811 | $5\,811 \times 2^{30}$ |
| 20 | $2^{20}$ | 335 103 | $335\,103 \times 2^{20}$ |
| 10 | $2^{10}$ | 19 323 738 | $\approx 1{,}98 \times 10^{10}$ |
| 1 | $2^1$ | 2 971 477 630 | $\approx 5{,}94 \times 10^9$ |

## Требования к хранению и передаче `double`

При передаче через текст, CLI, CSV или JSON обязательно сохраняйте все 17 значащих цифр (`repr(x)` / `f"{x:.17g}"`, в PostgreSQL — бинарный тип `DOUBLE PRECISION` / `FLOAT8`). Округление даже последнего разряда разрушает младшие биты шифротекста.

## Разработка и тесты

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## Лицензия

[MIT](LICENSE)
