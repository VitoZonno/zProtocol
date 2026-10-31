"""Primitive crittografiche usate da zProtocol.

Nessuna crittografia "fatta in casa": solo X25519 e ChaCha20-Poly1305
(libreria `cryptography`) più BLAKE2s/HMAC (libreria standard), assemblate
secondo le regole del Noise Protocol Framework (CipherState / SymmetricState).
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .errors import CryptoError

HASHLEN = 32
KEYLEN = 32
TAGLEN = 16
MAX_NONCE = 2**64 - 1


def blake2s(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def hkdf(chaining_key: bytes, ikm: bytes, n: int) -> tuple[bytes, ...]:
    """HKDF del Noise Framework (HMAC-BLAKE2s), con n uscite da 32 byte (1..4)."""
    if not 1 <= n <= 4:
        raise ValueError("n deve essere tra 1 e 4")
    temp_key = hmac_blake2s(chaining_key, ikm)
    outputs: list[bytes] = []
    previous = b""
    for i in range(1, n + 1):
        previous = hmac_blake2s(temp_key, previous + bytes([i]))
        outputs.append(previous)
    return tuple(outputs)


def nonce_bytes(n: int) -> bytes:
    """Nonce ChaCha20-Poly1305 di Noise: 32 bit a zero + contatore a 64 bit little-endian."""
    return b"\x00\x00\x00\x00" + struct.pack("<Q", n)


def rekey_key(key: bytes) -> bytes:
    """REKEY() di Noise: nuova chiave = primi 32 byte di ENCRYPT(k, 2^64-1, "", zeros)."""
    nonce = b"\x00\x00\x00\x00" + b"\xff" * 8
    return ChaCha20Poly1305(key).encrypt(nonce, b"\x00" * 32, b"")[:32]


def x25519_public(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def x25519_dh(private: bytes, public: bytes) -> bytes:
    try:
        return X25519PrivateKey.from_private_bytes(private).exchange(
            X25519PublicKey.from_public_bytes(public)
        )
    except ValueError as exc:  # punto di ordine piccolo -> segreto tutto zero
        raise CryptoError("scambio X25519 non valido") from exc


class CipherState:
    """CipherState di Noise: chiave AEAD + contatore di nonce."""

    def __init__(self, key: bytes | None = None) -> None:
        self._aead = ChaCha20Poly1305(key) if key is not None else None
        self.n = 0

    @property
    def has_key(self) -> bool:
        return self._aead is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self._aead is None:
            return plaintext
        if self.n >= MAX_NONCE:
            raise CryptoError("nonce esaurito")
        out = self._aead.encrypt(nonce_bytes(self.n), plaintext, ad)
        self.n += 1
        return out

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self._aead is None:
            return ciphertext
        if self.n >= MAX_NONCE:
            raise CryptoError("nonce esaurito")
        try:
            out = self._aead.decrypt(nonce_bytes(self.n), ciphertext, ad)
        except InvalidTag as exc:
            raise CryptoError("autenticazione fallita") from exc
        self.n += 1
        return out


class SymmetricState:
    """SymmetricState di Noise (chaining key `ck`, hash di trascrizione `h`)."""

    def __init__(self, protocol_name: bytes) -> None:
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name.ljust(HASHLEN, b"\x00")
        else:
            self.h = blake2s(protocol_name)
        self.ck = self.h
        self.cs = CipherState()

    def mix_key(self, ikm: bytes) -> None:
        self.ck, temp_k = hkdf(self.ck, ikm, 2)
        self.cs = CipherState(temp_k)

    def mix_hash(self, data: bytes) -> None:
        self.h = blake2s(self.h + data)

    def mix_key_and_hash(self, ikm: bytes) -> None:
        self.ck, temp_h, temp_k = hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.cs = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cs.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cs.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[bytes, bytes]:
        k1, k2 = hkdf(self.ck, b"", 2)
        return k1, k2
