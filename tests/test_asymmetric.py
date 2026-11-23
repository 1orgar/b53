"""Tests for asymmetric X25519 + HKDF-SHA256 extension (b53a / b53.asymmetric)."""

from __future__ import annotations

import builtins
import math
import pickle
import sys
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import b53
import b53.asymmetric as asym_mod
import b53.b53a as b53_sub_b53a
import b53a
from b53 import b53a as from_b53_b53a


def test_import_aliases_expose_same_api() -> None:
    assert b53a.generate_keypair is asym_mod.generate_keypair
    assert b53_sub_b53a.seal_session is asym_mod.seal_session
    assert from_b53_b53a.B53AsymmetricCipher is asym_mod.B53AsymmetricCipher
    assert b53a.AsymmetricCipher is b53a.B53AsymmetricCipher


def test_keypair_generation_and_redaction() -> None:
    kp = b53a.generate_keypair()
    assert len(kp.private_key) == 64
    assert len(kp.public_key) == 64
    assert b53a.public_key_from_private(kp.private_key) == kp.public_key
    assert b53a.public_key_from_private(bytes.fromhex(kp.private_key)) == kp.public_key

    # Repr must never leak private key.
    assert kp.private_key not in repr(kp)
    assert kp.public_key in repr(kp)
    assert "<redacted>" in repr(kp)


def test_sealed_session_roundtrip_without_key_in_output_array() -> None:
    bob = b53a.generate_keypair()
    eve = b53a.generate_keypair()

    # Multi-row session: 1 double per bool[1..50], capsule kept separately.
    enc_cipher, capsule = b53a.seal_session(bob.public_key, context="table:users")
    assert len(capsule) == 64
    bytes.fromhex(capsule)

    row1 = [True, False, True, True]
    row2 = [i % 2 == 0 for i in range(50)]
    d1 = enc_cipher.encrypt(row1)
    d2 = enc_cipher.encrypt(row2)
    assert type(d1) is float and 0.0 <= d1 < 1.0 and math.ldexp(d1, 53).is_integer()
    assert type(d2) is float and 0.0 <= d2 < 1.0 and math.ldexp(d2, 53).is_integer()

    dec_cipher = b53a.open_session(capsule, bob.private_key, context="table:users")
    assert dec_cipher.decrypt(d1) == row1
    assert dec_cipher.decrypt(d2) == row2

    # serialize_sealed preserves exact fixed chunk count (no ephemeral key stuffed in doubles).
    many = [i % 3 == 0 for i in range(42)]
    doubles, ser_capsule = b53a.serialize_sealed(many, bob.public_key, min_size=10)
    assert len(doubles) == (42 // 10) + 1
    assert ser_capsule != capsule
    assert b53a.deserialize_sealed(doubles, ser_capsule, bob.private_key) == many

    # Single-shot encrypt_sealed / decrypt_sealed.
    val, one_cap = b53a.encrypt_sealed([True, False, False, True], bob.public_key)
    assert b53a.decrypt_sealed(val, one_cap, bob.private_key) == [True, False, False, True]

    # Wrong private key or wrong context fails recovery.
    wrong_cipher = b53a.open_session(capsule, eve.private_key, context="table:users")
    assert wrong_cipher.decrypt(d2) != row2

    wrong_ctx = b53a.open_session(capsule, bob.private_key, context="table:other")
    assert wrong_ctx.decrypt(d2) != row2


def test_pairwise_asymmetric_encrypt_and_serialize() -> None:
    alice = b53a.generate_keypair()
    bob = b53a.generate_keypair()
    eve = b53a.generate_keypair()

    s_ab = b53a.derive_shared_salt(alice.private_key, bob.public_key, context="chan-1")
    s_ba = b53a.derive_shared_salt(bob.private_key, alice.public_key, context="chan-1")
    assert s_ab == s_ba
    assert s_ab != b53a.derive_shared_salt(alice.private_key, bob.public_key, context="chan-2")
    assert s_ab != b53a.derive_shared_salt(eve.private_key, bob.public_key, context="chan-1")

    bits = [True, False, True, True, False, True]
    encoded = b53a.encrypt(bits, alice.private_key, bob.public_key)
    assert b53a.decrypt(encoded, bob.private_key, alice.public_key) == bits

    many = [i % 5 < 2 for i in range(77)]
    doubles = b53a.serialize(many, alice.private_key, bob.public_key, min_size=10, context="ctx")
    assert len(doubles) == (77 // 10) + 1
    assert (
        b53a.deserialize(doubles, bob.private_key, alice.public_key, context="ctx") == many
    )


def test_asymmetric_cipher_class_native_keys_and_pickle() -> None:
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()

    alice_cipher = b53a.B53AsymmetricCipher(alice_priv, bob_priv.public_key(), context=b"row:9")
    bob_cipher = b53a.B53AsymmetricCipher(bob_priv, alice_priv.public_key(), context=b"row:9")

    assert isinstance(alice_cipher, b53.B53Cipher)
    assert "key_bytes=32" in repr(alice_cipher)

    # Verify pickle safety (e.g. for PySpark broadcast) — no unpickleable CFFI objects left.
    restored_alice = pickle.loads(pickle.dumps(alice_cipher))
    restored_bob = pickle.loads(pickle.dumps(bob_cipher))

    payload = [True, True, False, True, False, False, True]
    x = restored_alice.encrypt(payload)
    assert restored_bob.decrypt(x) == payload


def test_key_validation_and_low_order_point_rejection() -> None:
    kp = b53a.generate_keypair()

    # Low-order all-zero point must be rejected per RFC 7748 check.
    zero_hex = "00" * 32
    with pytest.raises(ValueError):
        b53a.seal_session(zero_hex)
    with pytest.raises(ValueError):
        b53a.derive_shared_salt(kp.private_key, b"\x00" * 32)

    for bad_key in ("", "   ", "zzzz", "ab" * 31, "ab" * 33):
        with pytest.raises(ValueError):
            b53a.seal_session(bad_key)
        with pytest.raises(ValueError):
            b53a.public_key_from_private(bad_key)

    with pytest.raises(ValueError):
        b53a.seal_session(kp.public_key, context="")
    with pytest.raises(ValueError):
        b53a.seal_session(kp.public_key, context=b"")

    with pytest.raises(TypeError):
        b53a.seal_session(cast(Any, 12345))
    with pytest.raises(TypeError):
        b53a.public_key_from_private(cast(Any, None))


def test_missing_cryptography_raises_clear_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("simulated missing cryptography")
        return real_import(name, *args, **kwargs)

    # Ensure base b53 works without cryptography, while b53a gives an actionable error.
    for mod in list(sys.modules):
        if mod == "cryptography" or mod.startswith("cryptography."):
            monkeypatch.delitem(sys.modules, mod, raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)

    s = b53.generate_salt()
    assert b53.decrypt(b53.encrypt([True, False], s), s) == [True, False]

    with pytest.raises(ImportError, match="b53\\[asymmetric\\]"):
        b53a.generate_keypair()
