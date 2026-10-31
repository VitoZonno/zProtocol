"""Livello record: framing cifrato, lunghezza mascherata, padding casuale, rekey.

Formato di un record sul filo (nessun byte in chiaro riconoscibile):

    [ len_enc : 2 byte ][ ciphertext : len byte ]

  len_enc    = (len(ciphertext) XOR maschera) in big-endian; la maschera è
               2 byte di BLAKE2s con chiave dedicata e contatore del record
  ciphertext = ChaCha20-Poly1305(chiave, nonce = contatore, ad = len_enc,
                                 plaintext = tipo(1) | lunghezza_dati(2) | dati | padding)
"""
from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass
from enum import IntEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .crypto import MAX_NONCE, TAGLEN, nonce_bytes, rekey_key
from .errors import RecordError

HEADER_LEN = 3
MAX_DATA = 16384
MAX_PAD_LIMIT = 4096
MAX_PLAINTEXT = HEADER_LEN + MAX_DATA + MAX_PAD_LIMIT
MIN_CIPHERTEXT = HEADER_LEN + TAGLEN
MAX_CIPHERTEXT = MAX_PLAINTEXT + TAGLEN


class RecordType(IntEnum):
    DATA = 0    # dati applicativi
    PAD = 1     # traffico di copertura, ignorato dal ricevente
    REKEY = 2   # da ora in poi il mittente usa una nuova chiave
    CLOSE = 3   # fine dei dati dal mittente (half-close autenticato)
    PING = 4
    PONG = 5


@dataclass(frozen=True)
class PaddingPolicy:
    """Aggiunge a ogni record da 0 a `max_pad` byte casuali di padding (uniforme)."""

    max_pad: int = 255

    def __post_init__(self) -> None:
        if not 0 <= self.max_pad <= MAX_PAD_LIMIT:
            raise ValueError(f"max_pad deve essere tra 0 e {MAX_PAD_LIMIT}")

    def pad_len(self) -> int:
        return secrets.randbelow(self.max_pad + 1) if self.max_pad else 0


def _mask(key: bytes, counter: int) -> int:
    digest = hashlib.blake2s(counter.to_bytes(8, "big"), key=key, digest_size=2).digest()
    return int.from_bytes(digest, "big")


class RecordCodec:
    """Cifra/decifra record per una direzione di invio e una di ricezione."""

    def __init__(
        self,
        *,
        send_key: bytes,
        recv_key: bytes,
        send_mask_key: bytes,
        recv_mask_key: bytes,
        padding: PaddingPolicy | None = None,
        rekey_after: int = 1 << 20,
    ) -> None:
        if rekey_after < 1:
            raise ValueError("rekey_after deve essere >= 1")
        self.padding = padding or PaddingPolicy()
        self.rekey_after = rekey_after
        self._send_key, self._recv_key = send_key, recv_key
        self._send_aead = ChaCha20Poly1305(send_key)
        self._recv_aead = ChaCha20Poly1305(recv_key)
        self._send_mask, self._recv_mask = send_mask_key, recv_mask_key
        self._send_n = 0
        self._recv_n = 0
        self._since_rekey = 0

    # ---- invio -----------------------------------------------------------
    def seal(self, rtype: int, data: bytes = b"") -> bytes:
        """Restituisce i byte da scrivere sul filo (può includere un REKEY anticipato)."""
        out = b""
        if self._since_rekey >= self.rekey_after:
            out += self._seal_one(RecordType.REKEY, b"")
            self._send_key = rekey_key(self._send_key)
            self._send_aead = ChaCha20Poly1305(self._send_key)
            self._since_rekey = 0
        return out + self._seal_one(rtype, data)

    def _seal_one(self, rtype: int, data: bytes) -> bytes:
        if len(data) > MAX_DATA:
            raise ValueError(f"record troppo grande (max {MAX_DATA} byte di dati)")
        if self._send_n >= MAX_NONCE:
            raise RecordError("contatore dei record esaurito")
        plaintext = struct.pack(">BH", int(rtype), len(data)) + data + bytes(self.padding.pad_len())
        ct_len = len(plaintext) + TAGLEN
        len_enc = (ct_len ^ _mask(self._send_mask, self._send_n)).to_bytes(2, "big")
        ciphertext = self._send_aead.encrypt(nonce_bytes(self._send_n), plaintext, len_enc)
        self._send_n += 1
        self._since_rekey += 1
        return len_enc + ciphertext

    # ---- ricezione -------------------------------------------------------
    def parse_length(self, len_enc: bytes) -> int:
        """Lunghezza del prossimo ciphertext, dato il suo prefisso mascherato."""
        ct_len = int.from_bytes(len_enc, "big") ^ _mask(self._recv_mask, self._recv_n)
        if not MIN_CIPHERTEXT <= ct_len <= MAX_CIPHERTEXT:
            raise RecordError("lunghezza del record non valida")
        return ct_len

    def open(self, len_enc: bytes, ciphertext: bytes) -> tuple[int, bytes]:
        """Decifra il prossimo record. Restituisce (tipo, dati)."""
        try:
            plaintext = self._recv_aead.decrypt(nonce_bytes(self._recv_n), ciphertext, len_enc)
        except InvalidTag as exc:
            raise RecordError("record non autentico (manomesso, riordinato o ripetuto)") from exc
        self._recv_n += 1
        rtype, data_len = struct.unpack_from(">BH", plaintext)
        if HEADER_LEN + data_len > len(plaintext):
            raise RecordError("lunghezza dati incoerente")
        data = plaintext[HEADER_LEN : HEADER_LEN + data_len]
        if rtype == RecordType.REKEY:
            self._recv_key = rekey_key(self._recv_key)
            self._recv_aead = ChaCha20Poly1305(self._recv_key)
        return rtype, data
