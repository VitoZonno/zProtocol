"""Identità a lungo termine di un nodo (chiave statica X25519)."""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from .crypto import x25519_public


def peer_id(public: bytes) -> str:
    """ID leggibile del peer: base32 (32 caratteri) dell'hash BLAKE2s della chiave pubblica."""
    digest = hashlib.blake2s(public, digest_size=20).digest()
    return base64.b32encode(digest).decode("ascii").lower()


@dataclass(frozen=True)
class Identity:
    private: bytes
    public: bytes

    @classmethod
    def generate(cls) -> "Identity":
        return cls.from_private(os.urandom(32))

    @classmethod
    def from_private(cls, private: bytes) -> "Identity":
        if len(private) != 32:
            raise ValueError("la chiave privata deve essere di 32 byte")
        return cls(private, x25519_public(private))

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Identity":
        text = Path(path).read_text().strip()
        try:
            private = bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError(f"file identità non valido: {path}") from exc
        return cls.from_private(private)

    def save(self, path: str | os.PathLike[str], *, overwrite: bool = False) -> None:
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(self.private.hex() + "\n")

    @classmethod
    def load_or_create(cls, path: str | os.PathLike[str]) -> "Identity":
        if Path(path).exists():
            return cls.load(path)
        identity = cls.generate()
        identity.save(path)
        return identity

    @property
    def public_hex(self) -> str:
        return self.public.hex()

    @property
    def fingerprint(self) -> str:
        return peer_id(self.public)
