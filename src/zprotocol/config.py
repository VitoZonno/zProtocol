"""Configurazione condivisa da client e server."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable

from .identity import Identity
from .record import PaddingPolicy

_PSK_SALT = b"zprotocol/1 psk"


def derive_psk(secret: str | bytes) -> bytes:
    """Deriva la PSK a 32 byte da una passphrase (scrypt). Calcolala una volta sola."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not secret:
        raise ValueError("la PSK non può essere vuota")
    return hashlib.scrypt(secret, salt=_PSK_SALT, n=2**14, r=8, p=1, dklen=32)


@dataclass
class Config:
    psk: bytes
    identity: Identity
    # Policy sulla chiave pubblica statica del peer (pinning / allow-list).
    # None = accetta qualsiasi peer che conosca la PSK.
    verify_peer: Callable[[bytes], bool] | None = None
    padding: PaddingPolicy = field(default_factory=PaddingPolicy)
    handshake_max_pad: int = 512
    handshake_timeout: float = 10.0
    max_clock_skew: float = 120.0       # secondi di tolleranza sul timestamp di msg1
    rekey_after: int = 1 << 20          # record per direzione prima del rekey
    cover: tuple[float, float] | None = None   # (min, max) secondi tra record di copertura
    reject_delay: tuple[float, float] = (3.0, 12.0)  # tempo di "buco nero" verso chi sbaglia

    def __post_init__(self) -> None:
        if len(self.psk) != 32:
            raise ValueError("la PSK deve essere di 32 byte (usa derive_psk)")
        if self.cover is not None and not 0 < self.cover[0] <= self.cover[1]:
            raise ValueError("cover deve essere (min, max) con 0 < min <= max")
