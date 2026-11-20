"""Command-line interface for b53."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from b53 import __version__
from b53.core import (
    DEFAULT_SALT_BYTES,
    NONCE_COUNTS,
    decrypt_bool_array,
    encrypt_bool_array,
    format_bits,
    generate_salt,
    parse_bits,
)


def _resolve_salt(salt: str | None, salt_file: Path | None) -> str:
    if salt is not None and salt_file is not None:
        raise ValueError("Specify either --salt or --salt-file, not both.")
    if salt is not None:
        return salt
    if salt_file is not None:
        return salt_file.read_text(encoding="utf-8").strip()
    env_salt = os.environ.get("B53_SALT")
    if env_salt:
        return env_salt
    raise ValueError("A secret salt is required (--salt, --salt-file, or B53_SALT).")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="b53",
        description=(
            "Reversible 53-bit cryptographic packing of bool arrays (1..50) "
            "into IEEE 754 double values in [0.0, 1.0)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    salt_parser = subparsers.add_parser(
        "generate-salt",
        aliases=["keygen"],
        help="Generate a cryptographically secure hex-encoded salt.",
    )
    salt_parser.add_argument(
        "--bytes",
        type=int,
        default=DEFAULT_SALT_BYTES,
        help=f"Key length in bytes (default: {DEFAULT_SALT_BYTES} bytes = 256 bits).",
    )
    salt_parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional output file path to save the generated salt.",
    )

    enc_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a boolean array into a double in [0.0, 1.0).",
    )
    enc_parser.add_argument(
        "bits",
        help="Boolean array as bit string (1011001) or comma list (true,false,true).",
    )
    enc_parser.add_argument("--salt", default=None, help="Secret salt (hex or UTF-8 string).")
    enc_parser.add_argument("--salt-file", type=Path, default=None, help="Read salt from file.")
    enc_parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of independent random encryptions to generate.",
    )
    enc_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Print only the resulting double value(s).",
    )

    dec_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a double back into the original boolean array.",
    )
    dec_parser.add_argument(
        "value",
        help="IEEE 754 double value with full precision (e.g. repr(x)).",
    )
    dec_parser.add_argument("--salt", default=None, help="Secret salt used during encryption.")
    dec_parser.add_argument("--salt-file", type=Path, default=None, help="Read salt from file.")
    dec_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Print only the restored bit string.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``b53`` CLI."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.command in ("generate-salt", "keygen"):
            salt = generate_salt(args.bytes)
            if args.out is not None:
                args.out.write_text(salt + "\n", encoding="utf-8")
                print(f"Salt saved to {args.out}: {salt}")
            else:
                print(salt)
            return 0

        if args.command == "encrypt":
            if args.count < 1:
                raise ValueError("--count must be at least 1.")
            salt = _resolve_salt(args.salt, args.salt_file)
            bool_array = parse_bits(args.bits)
            if not args.quiet:
                print(
                    f"Length: {len(bool_array)} | "
                    f"Available random nonces: {NONCE_COUNTS[len(bool_array)]}"
                )
            for idx in range(1, args.count + 1):
                encoded = encrypt_bool_array(bool_array, salt)
                prefix = f"[{idx}] " if (args.count > 1 and not args.quiet) else ""
                print(f"{prefix}{encoded!r}")
            return 0

        if args.command == "decrypt":
            salt = _resolve_salt(args.salt, args.salt_file)
            double_val = float(args.value)
            restored = decrypt_bool_array(double_val, salt)
            bit_string = format_bits(restored)
            if args.quiet:
                print(bit_string)
            else:
                print(f"Restored length: {len(restored)}")
                print(f"Bit string:      {bit_string}")
                print(f"Python list:     {restored}")
            return 0

        parser.error(f"Unknown command: {args.command}")
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0
