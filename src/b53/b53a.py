"""Alias submodule re-exporting :mod:`b53.asymmetric`."""

from __future__ import annotations

from b53.asymmetric import (
    X25519_KEY_BYTES,
    AsymmetricCipher,
    B53AsymmetricCipher,
    KeyPair,
    decrypt,
    decrypt_sealed,
    derive_shared_salt,
    deserialize,
    deserialize_sealed,
    encrypt,
    encrypt_sealed,
    generate_keypair,
    open_session,
    public_key_from_private,
    seal_session,
    serialize,
    serialize_sealed,
)

__all__ = [
    "X25519_KEY_BYTES",
    "AsymmetricCipher",
    "B53AsymmetricCipher",
    "KeyPair",
    "decrypt",
    "decrypt_sealed",
    "derive_shared_salt",
    "deserialize",
    "deserialize_sealed",
    "encrypt",
    "encrypt_sealed",
    "generate_keypair",
    "open_session",
    "public_key_from_private",
    "seal_session",
    "serialize",
    "serialize_sealed",
]
