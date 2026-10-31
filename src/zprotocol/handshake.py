"""Handshake di zProtocol: Noise XXpsk0 con chiavi effimere Elligator2.

    -> psk, e                 (msg1: rappresentante di e + payload cifrato + padding)
    <- e, ee, s, es           (msg2)
    -> s, se                  (msg3)

Differenze rispetto a Noise "standard" (quindi NON interoperabile con altre
librerie Noise):
  * le chiavi effimere viaggiano come rappresentanti Elligator2 (32 byte
    indistinguibili da rumore) e sono questi byte a entrare nell'hash;
  * ogni messaggio ha un payload cifrato (versione, lunghezza del padding,
    timestamp in msg1) seguito da padding casuale autenticato nell'hash;
  * la PSK (psk0) cifra già msg1: chi non la conosce non produce un msg1
    valido e il server non risponde (resistenza al probing attivo).

Dimensioni (byte):  msg1 >= 59   msg2 >= 99   msg3 >= 67  (+ padding variabile)
"""
from __future__ import annotations

import os
import secrets
import struct
import time
from dataclasses import dataclass

from .crypto import SymmetricState, TAGLEN, hkdf, x25519_dh, x25519_public
from .elligator import EphemeralKey, decode_representative, generate_ephemeral
from .errors import CryptoError, HandshakeError

PROTOCOL_NAME = b"zProtocol/1 Noise_XXpsk0_25519+Elligator2_ChaChaPoly_BLAKE2s"
VERSION = 1
MAX_HANDSHAKE_PAD = 4096

REP_LEN = 32
STATIC_ENC_LEN = 32 + TAGLEN
MSG1_PAYLOAD_LEN = 1 + 2 + 8   # versione, lunghezza padding, timestamp
MSG23_PAYLOAD_LEN = 1 + 2      # versione, lunghezza padding

MSG1_HEAD_LEN = REP_LEN + MSG1_PAYLOAD_LEN + TAGLEN                    # 59
MSG2_HEAD_LEN = REP_LEN + STATIC_ENC_LEN + MSG23_PAYLOAD_LEN + TAGLEN  # 99
MSG3_HEAD_LEN = STATIC_ENC_LEN + MSG23_PAYLOAD_LEN + TAGLEN            # 67

_MASK_INFO = b"zprotocol/1 length-mask keys"


@dataclass(frozen=True)
class HandshakeResult:
    send_key: bytes
    recv_key: bytes
    send_mask_key: bytes
    recv_mask_key: bytes
    handshake_hash: bytes
    remote_static: bytes


class Handshake:
    """Macchina a stati del handshake. Un'istanza = un handshake = un ruolo.

    Iniziatore:  write_msg1 -> read_msg2_head -> read_msg2_pad -> write_msg3 -> finalize
    Risponditore: read_msg1_head -> read_msg1_pad -> write_msg2 -> read_msg3_head
                  -> read_msg3_pad -> finalize
    Le `read_*_head` restituiscono la lunghezza del padding che segue.
    """

    def __init__(
        self,
        *,
        initiator: bool,
        psk: bytes,
        static_private: bytes,
        max_pad: int = 512,
        prologue: bytes = b"",
    ) -> None:
        if len(psk) != 32:
            raise ValueError("la PSK deve essere di 32 byte")
        if not 0 <= max_pad <= MAX_HANDSHAKE_PAD:
            raise ValueError(f"max_pad deve essere tra 0 e {MAX_HANDSHAKE_PAD}")
        self.initiator = initiator
        self._psk = psk
        self._s_priv = static_private
        self._s_pub = x25519_public(static_private)
        self._max_pad = max_pad
        self._ss = SymmetricState(PROTOCOL_NAME)
        self._ss.mix_hash(prologue)
        self._e: EphemeralKey | None = None
        self._re_u: bytes | None = None
        self._pending_pad = 0
        self._step = 0
        self.remote_static: bytes | None = None
        self.remote_timestamp: int | None = None
        self.remote_ephemeral_rep: bytes | None = None

    # ---- helper ----------------------------------------------------------
    def _expect(self, initiator: bool, step: int) -> None:
        if self.initiator != initiator or self._step != step:
            raise HandshakeError("sequenza dell'handshake non valida")
        self._step += 1

    def _dec(self, ciphertext: bytes) -> bytes:
        try:
            return self._ss.decrypt_and_hash(ciphertext)
        except CryptoError as exc:
            raise HandshakeError("handshake non autenticato") from exc

    @staticmethod
    def _dh(private: bytes, public: bytes) -> bytes:
        try:
            return x25519_dh(private, public)
        except CryptoError as exc:
            raise HandshakeError("chiave pubblica non valida") from exc

    def _random_pad_len(self) -> int:
        return secrets.randbelow(self._max_pad + 1)

    def _parse_pad_len(self, pad_len: int) -> int:
        if pad_len > MAX_HANDSHAKE_PAD:
            raise HandshakeError("padding dell'handshake eccessivo")
        self._pending_pad = pad_len
        return pad_len

    def _read_pad(self, pad: bytes) -> None:
        if len(pad) != self._pending_pad:
            raise HandshakeError("lunghezza del padding inattesa")
        self._ss.mix_hash(pad)

    # ---- msg1: -> psk, e -------------------------------------------------
    def write_msg1(self, now: int | None = None) -> bytes:
        self._expect(True, 0)
        ss = self._ss
        ss.mix_key_and_hash(self._psk)
        self._e = generate_ephemeral()
        rep = self._e.representative
        ss.mix_hash(rep)
        ss.mix_key(rep)
        pad_len = self._random_pad_len()
        timestamp = int(time.time()) if now is None else now
        ct = ss.encrypt_and_hash(struct.pack(">BHQ", VERSION, pad_len, timestamp))
        pad = os.urandom(pad_len)
        ss.mix_hash(pad)
        return rep + ct + pad

    def read_msg1_head(self, head: bytes) -> int:
        self._expect(False, 0)
        if len(head) != MSG1_HEAD_LEN:
            raise HandshakeError("msg1 troncato")
        ss = self._ss
        rep = head[:REP_LEN]
        ss.mix_key_and_hash(self._psk)
        ss.mix_hash(rep)
        ss.mix_key(rep)
        payload = self._dec(head[REP_LEN:])
        version, pad_len, timestamp = struct.unpack(">BHQ", payload)
        if version != VERSION:
            raise HandshakeError("versione del protocollo non supportata")
        self.remote_ephemeral_rep = rep
        self.remote_timestamp = timestamp
        self._re_u = decode_representative(rep)
        return self._parse_pad_len(pad_len)

    def read_msg1_pad(self, pad: bytes) -> None:
        self._expect(False, 1)
        self._read_pad(pad)

    # ---- msg2: <- e, ee, s, es -------------------------------------------
    def write_msg2(self) -> bytes:
        self._expect(False, 2)
        ss = self._ss
        self._e = generate_ephemeral()
        rep = self._e.representative
        ss.mix_hash(rep)
        ss.mix_key(rep)
        ss.mix_key(self._dh(self._e.private, self._re_u))   # ee
        enc_s = ss.encrypt_and_hash(self._s_pub)
        ss.mix_key(self._dh(self._s_priv, self._re_u))      # es
        pad_len = self._random_pad_len()
        ct = ss.encrypt_and_hash(struct.pack(">BH", VERSION, pad_len))
        pad = os.urandom(pad_len)
        ss.mix_hash(pad)
        return rep + enc_s + ct + pad

    def read_msg2_head(self, head: bytes) -> int:
        self._expect(True, 1)
        if len(head) != MSG2_HEAD_LEN:
            raise HandshakeError("msg2 troncato")
        ss = self._ss
        rep = head[:REP_LEN]
        ss.mix_hash(rep)
        ss.mix_key(rep)
        self._re_u = decode_representative(rep)
        ss.mix_key(self._dh(self._e.private, self._re_u))   # ee
        self.remote_static = self._dec(head[REP_LEN : REP_LEN + STATIC_ENC_LEN])
        ss.mix_key(self._dh(self._e.private, self.remote_static))  # es
        payload = self._dec(head[REP_LEN + STATIC_ENC_LEN :])
        version, pad_len = struct.unpack(">BH", payload)
        if version != VERSION:
            raise HandshakeError("versione del protocollo non supportata")
        return self._parse_pad_len(pad_len)

    def read_msg2_pad(self, pad: bytes) -> None:
        self._expect(True, 2)
        self._read_pad(pad)

    # ---- msg3: -> s, se --------------------------------------------------
    def write_msg3(self) -> bytes:
        self._expect(True, 3)
        ss = self._ss
        enc_s = ss.encrypt_and_hash(self._s_pub)
        ss.mix_key(self._dh(self._s_priv, self._re_u))      # se
        pad_len = self._random_pad_len()
        ct = ss.encrypt_and_hash(struct.pack(">BH", VERSION, pad_len))
        pad = os.urandom(pad_len)
        ss.mix_hash(pad)
        return enc_s + ct + pad

    def read_msg3_head(self, head: bytes) -> int:
        self._expect(False, 3)
        if len(head) != MSG3_HEAD_LEN:
            raise HandshakeError("msg3 troncato")
        ss = self._ss
        self.remote_static = self._dec(head[:STATIC_ENC_LEN])
        ss.mix_key(self._dh(self._e.private, self.remote_static))  # se
        payload = self._dec(head[STATIC_ENC_LEN:])
        version, pad_len = struct.unpack(">BH", payload)
        if version != VERSION:
            raise HandshakeError("versione del protocollo non supportata")
        return self._parse_pad_len(pad_len)

    def read_msg3_pad(self, pad: bytes) -> None:
        self._expect(False, 4)
        self._read_pad(pad)

    # ---- fine ------------------------------------------------------------
    def finalize(self) -> HandshakeResult:
        done = 4 if self.initiator else 5
        if self._step != done or self.remote_static is None:
            raise HandshakeError("handshake non completato")
        ss = self._ss
        k1, k2 = ss.split()
        m1, m2 = hkdf(ss.ck, _MASK_INFO, 2)
        if self.initiator:
            send, recv, send_mask, recv_mask = k1, k2, m1, m2
        else:
            send, recv, send_mask, recv_mask = k2, k1, m2, m1
        return HandshakeResult(
            send_key=send,
            recv_key=recv,
            send_mask_key=send_mask,
            recv_mask_key=recv_mask,
            handshake_hash=ss.h,
            remote_static=self.remote_static,
        )
