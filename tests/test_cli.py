"""CLI tests for b53."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from b53 import __version__
from b53.cli import main


def test_cli_generate_salt_stdout_and_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["generate-salt"]) == 0
    stdout_salt = capsys.readouterr().out.strip()
    assert len(stdout_salt) == 64
    bytes.fromhex(stdout_salt)

    out_file = tmp_path / "salt.txt"
    assert main(["keygen", "--bytes", "16", "--out", str(out_file)]) == 0
    msg = capsys.readouterr().out
    saved = out_file.read_text(encoding="utf-8").strip()
    assert len(saved) == 32
    assert saved in msg


def test_cli_encrypt_decrypt_roundtrip_and_quiet(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    salt_file = tmp_path / "secret.salt"
    salt = "ab" * 32
    salt_file.write_text(salt + "\n", encoding="utf-8")

    # Test --salt-file + --count 3
    assert main(["encrypt", "1011001011", "--salt-file", str(salt_file), "--count", "3"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 4
    first_val = lines[1].split(" ", 1)[1]

    # Test --salt + decrypt verbose
    assert main(["decrypt", first_val, "--salt", salt]) == 0
    dec_out = capsys.readouterr().out
    assert "Restored length: 10" in dec_out
    assert "1011001011" in dec_out

    # Test B53_SALT env var + --quiet
    monkeypatch.setenv("B53_SALT", salt)
    assert main(["encrypt", "true,false,true", "-q"]) == 0
    quiet_val = capsys.readouterr().out.strip()
    assert main(["decrypt", quiet_val, "-q"]) == 0
    assert capsys.readouterr().out.strip() == "101"


def test_cli_error_handling(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("B53_SALT", raising=False)

    assert main(["encrypt", "101"]) == 1
    assert "salt is required" in capsys.readouterr().err

    assert main(["encrypt", "101", "--salt", "abc", "--count", "0"]) == 1
    assert "--count" in capsys.readouterr().err

    assert main(["decrypt", "not-a-float", "--salt", "abc"]) == 1
    assert "Error:" in capsys.readouterr().err

    assert main(["encrypt", "101", "--salt", "a", "--salt-file", "b"]) == 1
    assert "not both" in capsys.readouterr().err


def test_python_m_b53_version() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "b53", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.strip() == f"b53 {__version__}"
