"""Asymmetric X25519 + HKDF-SHA256 extension (``b53a``) for ``b53``."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from b53.core import (
    DEFAULT_CHUNK_MIN,
    B53Cipher,
    SaltType,
    _coerce_kdf_input,
    decrypt_bool_array,
    deserialize_bool_array,
    encrypt_bool_array,
    serialize_bool_array,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

X25519_KEY_BYTES = 32


def _import_crypto() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        raise ImportError(
            "b53a requires the optional 'asymmetric' dependency: "
            "pip install 'b53[asymmetric]'"
        ) from exc
    return X25519PrivateKey, X25519PublicKey, serialization, hashes, HKDF


def _decode_key_bytes(value: SaltType, *, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{label} must not be empty.")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"{label} must be a 64-character hex string or 32 raw bytes.") from exc
    else:
        raise TypeError(
            f"{label} must be hex str, 32-byte bytes, or X25519 key object, "
            f"got {type(value).__name__}."
        )

    if len(raw) != X25519_KEY_BYTES:
        raise ValueError(f"{label} must be exactly {X25519_KEY_BYTES} bytes, got {len(raw)}.")
    return raw


def _load_private_key(private_key: SaltType | X25519PrivateKey) -> Any:
    x25519_priv_cls, _, _, _, _ = _import_crypto()
    if isinstance(private_key, (str, bytes, bytearray)):
        raw = _decode_key_bytes(private_key, label="private_key")
        return x25519_priv_cls.from_private_bytes(raw)
    if isinstance(private_key, x25519_priv_cls):
        return private_key
    raise TypeError(
        f"private_key must be hex str, 32-byte bytes, or X25519PrivateKey, "
        f"got {type(private_key).__name__}."
    )


def _load_public_key(public_key: SaltType | X25519PublicKey) -> Any:
    _, x25519_pub_cls, _, _, _ = _import_crypto()
    if isinstance(public_key, (str, bytes, bytearray)):
        raw = _decode_key_bytes(public_key, label="public_key")
        return x25519_pub_cls.from_public_bytes(raw)
    if isinstance(public_key, x25519_pub_cls):
        return public_key
    raise TypeError(
        f"public_key must be hex str, 32-byte bytes, or X25519PublicKey, "
        f"got {type(public_key).__name__}."
    )


def _raw_bytes(key_obj: Any, *, is_private: bool) -> bytes:
    _, _, serialization, _, _ = _import_crypto()
    if is_private:
        return bytes(
            key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return bytes(
        key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _exchange_x25519(priv_obj: Any, pub_obj: Any) -> bytes:
    shared = bytes(priv_obj.exchange(pub_obj))
    if shared == b"\x00" * X25519_KEY_BYTES:
        raise ValueError("Invalid X25519 key exchange (low-order public point).")
    return shared


def _hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    _, _, _, hashes, hkdf_cls = _import_crypto()
    kdf = hkdf_cls(
        algorithm=hashes.SHA256(),
        length=X25519_KEY_BYTES,
        salt=salt,
        info=info,
    )
    return bytes(kdf.derive(shared_secret))


def _build_info(prefix: bytes, context: SaltType | None) -> bytes:
    if context is None:
        return prefix
    return prefix + b":" + _coerce_kdf_input(context, label="context")


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Hex-encoded X25519 asymmetric key pair."""

    private_key: str
    public_key: str

    def __repr__(self) -> str:
        return f"KeyPair(public_key={self.public_key!r}, private_key='<redacted>')"


def generate_keypair() -> KeyPair:
    """Generate a new X25519 key pair (64-character hex-encoded keys)."""
    x25519_priv_cls, _, _, _, _ = _import_crypto()
    priv_obj = x25519_priv_cls.generate()
    pub_obj = priv_obj.public_key()
    return KeyPair(
        private_key=_raw_bytes(priv_obj, is_private=True).hex(),
        public_key=_raw_bytes(pub_obj, is_private=False).hex(),
    )


def public_key_from_private(private_key: SaltType | X25519PrivateKey) -> str:
    """Derive the 64-character hex public key corresponding to ``private_key``."""
    priv_obj = _load_private_key(private_key)
    return _raw_bytes(priv_obj.public_key(), is_private=False).hex()


def seal_session(
    recipient_public_key: SaltType | X25519PublicKey,
    *,
    context: SaltType | None = None,
) -> tuple[B53Cipher, str]:
    """Create a one-way asymmetric session from ``recipient_public_key``.

    Returns ``(cipher, capsule_hex)``. The sender needs only the recipient's
    public key and stores/transmits ``capsule_hex`` separately from the
    encrypted ``double`` payloads. Only ``recipient_private_key`` can reopen
    the session via :func:`open_session`.
    """
    x25519_priv_cls, _, _, _, _ = _import_crypto()
    recv_pub = _load_public_key(recipient_public_key)
    eph_priv = x25519_priv_cls.generate()
    eph_pub = eph_priv.public_key()

    shared = _exchange_x25519(eph_priv, recv_pub)
    eph_pub_bytes = _raw_bytes(eph_pub, is_private=False)
    recv_pub_bytes = _raw_bytes(recv_pub, is_private=False)

    info = _build_info(b"b53a:session:v1", context)
    session_key = _hkdf_derive(shared, salt=eph_pub_bytes + recv_pub_bytes, info=info)
    return B53Cipher(session_key), eph_pub_bytes.hex()


def open_session(
    capsule: SaltType | X25519PublicKey,
    recipient_private_key: SaltType | X25519PrivateKey,
    *,
    context: SaltType | None = None,
) -> B53Cipher:
    """Reopen an asymmetric session using ``capsule`` and ``recipient_private_key``."""
    eph_pub = _load_public_key(capsule)
    recv_priv = _load_private_key(recipient_private_key)
    recv_pub = recv_priv.public_key()

    shared = _exchange_x25519(recv_priv, eph_pub)
    eph_pub_bytes = _raw_bytes(eph_pub, is_private=False)
    recv_pub_bytes = _raw_bytes(recv_pub, is_private=False)

    info = _build_info(b"b53a:session:v1", context)
    session_key = _hkdf_derive(shared, salt=eph_pub_bytes + recv_pub_bytes, info=info)
    return B53Cipher(session_key)


def encrypt_sealed(
    bits: Iterable[bool],
    recipient_public_key: SaltType | X25519PublicKey,
    *,
    context: SaltType | None = None,
) -> tuple[float, str]:
    """Encrypt 1..50 booleans into ``(double_val, capsule_hex)`` using only a public key."""
    cipher, capsule = seal_session(recipient_public_key, context=context)
    return cipher.encrypt(bits), capsule


def decrypt_sealed(
    double_val: float,
    capsule: SaltType | X25519PublicKey,
    recipient_private_key: SaltType | X25519PrivateKey,
    *,
    context: SaltType | None = None,
) -> list[bool]:
    """Decrypt ``(double_val, capsule_hex)`` using ``recipient_private_key``."""
    cipher = open_session(capsule, recipient_private_key, context=context)
    return cipher.decrypt(double_val)


def serialize_sealed(
    bits: Iterable[bool],
    recipient_public_key: SaltType | X25519PublicKey,
    min_size: int = DEFAULT_CHUNK_MIN,
    *,
    context: SaltType | None = None,
) -> tuple[list[float], str]:
    """Serialize arbitrary-length booleans into ``(doubles, capsule_hex)`` via public key."""
    cipher, capsule = seal_session(recipient_public_key, context=context)
    return cipher.serialize(bits, min_size=min_size), capsule


def deserialize_sealed(
    values: Iterable[float],
    capsule: SaltType | X25519PublicKey,
    recipient_private_key: SaltType | X25519PrivateKey,
    *,
    context: SaltType | None = None,
) -> list[bool]:
    """Deserialize ``(doubles, capsule_hex)`` using ``recipient_private_key``."""
    cipher = open_session(capsule, recipient_private_key, context=context)
    return cipher.deserialize(values)


def derive_shared_salt(
    private_key: SaltType | X25519PrivateKey,
    peer_public_key: SaltType | X25519PublicKey,
    *,
    context: SaltType | None = None,
) -> str:
    """Derive a deterministic 256-bit hex salt via pairwise X25519 + HKDF-SHA256."""
    priv_obj = _load_private_key(private_key)
    peer_pub = _load_public_key(peer_public_key)

    shared = _exchange_x25519(priv_obj, peer_pub)
    own_pub_bytes = _raw_bytes(priv_obj.public_key(), is_private=False)
    peer_pub_bytes = _raw_bytes(peer_pub, is_private=False)

    first, second = sorted((own_pub_bytes, peer_pub_bytes))
    info = _build_info(b"b53a:pairwise:v1", context)
    return _hkdf_derive(shared, salt=first + second, info=info).hex()


def encrypt(
    bits: Iterable[bool],
    private_key: SaltType | X25519PrivateKey,
    peer_public_key: SaltType | X25519PublicKey,
    *,
    context: SaltType | None = None,
) -> float:
    """Encrypt 1..50 booleans into one double using pairwise X25519 key agreement."""
    salt = derive_shared_salt(private_key, peer_public_key, context=context)
    return encrypt_bool_array(bits, salt)


def decrypt(
    double_val: float,
    private_key: SaltType | X25519PrivateKey,
    peer_public_key: SaltType | X25519PublicKey,
    *,
    context: SaltType | None = None,
) -> list[bool]:
    """Decrypt one double using pairwise X25519 key agreement."""
    salt = derive_shared_salt(private_key, peer_public_key, context=context)
    return decrypt_bool_array(double_val, salt)


def serialize(
    bits: Iterable[bool],
    private_key: SaltType | X25519PrivateKey,
    peer_public_key: SaltType | X25519PublicKey,
    min_size: int = DEFAULT_CHUNK_MIN,
    *,
    context: SaltType | None = None,
) -> list[float]:
    """Serialize arbitrary-length booleans using pairwise X25519 key agreement."""
    salt = derive_shared_salt(private_key, peer_public_key, context=context)
    return serialize_bool_array(bits, salt, min_size=min_size)


def deserialize(
    values: Iterable[float],
    private_key: SaltType | X25519PrivateKey,
    peer_public_key: SaltType | X25519PublicKey,
    *,
    context: SaltType | None = None,
) -> list[bool]:
    """Deserialize chained doubles using pairwise X25519 key agreement."""
    salt = derive_shared_salt(private_key, peer_public_key, context=context)
    return deserialize_bool_array(values, salt)


class B53AsymmetricCipher(B53Cipher):
    """Pickle-safe reusable cipher bound to a pairwise X25519-derived salt."""

    def __init__(
        self,
        private_key: SaltType | X25519PrivateKey,
        peer_public_key: SaltType | X25519PublicKey,
        *,
        context: SaltType | None = None,
    ) -> None:
        salt = derive_shared_salt(private_key, peer_public_key, context=context)
        super().__init__(salt)


AsymmetricCipher = B53AsymmetricCipher

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
