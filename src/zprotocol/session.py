"""Sessioni asincrone sopra TCP: handshake su stream, Connection, server."""
from __future__ import annotations

import asyncio
import logging
import os
import random
import secrets
import time
from typing import Awaitable, Callable

from .config import Config
from .errors import HandshakeError, PeerRejected, TruncatedStream
from .handshake import (
    MSG1_HEAD_LEN,
    MSG2_HEAD_LEN,
    MSG3_HEAD_LEN,
    Handshake,
    HandshakeResult,
)
from .record import MAX_DATA, RecordCodec, RecordType

log = logging.getLogger("zprotocol")


class ReplayCache:
    """Ricorda i msg1 già visti per la durata della finestra di validità."""

    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self._seen: dict[bytes, float] = {}

    def add(self, key: bytes, now: float | None = None) -> bool:
        """True se nuovo, False se è un replay."""
        now = time.monotonic() if now is None else now
        if len(self._seen) > 4096:
            self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
        expiry = self._seen.get(key)
        if expiry is not None and expiry > now:
            return False
        self._seen[key] = now + self.ttl
        return True


class Connection:
    """Canale cifrato e offuscato, full-duplex, sopra un (reader, writer) asyncio.

    `send()` può essere chiamato da più task; `recv()` da un solo task.
    `recv()` restituisce b"" quando il peer ha inviato CLOSE (fine dati).
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        result: HandshakeResult,
        cfg: Config,
    ) -> None:
        self._r = reader
        self._w = writer
        self._codec = RecordCodec(
            send_key=result.send_key,
            recv_key=result.recv_key,
            send_mask_key=result.send_mask_key,
            recv_mask_key=result.recv_mask_key,
            padding=cfg.padding,
            rekey_after=cfg.rekey_after,
        )
        self.remote_static = result.remote_static
        self.handshake_hash = result.handshake_hash
        self._send_lock = asyncio.Lock()
        self._eof_sent = False
        self._eof_received = False
        self._closed = False
        self._cover_task: asyncio.Task | None = None
        if cfg.cover:
            self._cover_task = asyncio.get_running_loop().create_task(self._cover_loop(*cfg.cover))

    @property
    def peername(self):
        return self._w.get_extra_info("peername")

    # ---- invio -----------------------------------------------------------
    async def _send_record(self, rtype: RecordType, data: bytes = b"") -> None:
        async with self._send_lock:
            if self._w.is_closing():
                raise ConnectionResetError("connessione chiusa")
            self._w.write(self._codec.seal(rtype, data))
            await self._w.drain()

    async def send(self, data: bytes) -> None:
        if self._eof_sent:
            raise ConnectionResetError("canale già chiuso in scrittura")
        view = memoryview(data)
        for i in range(0, len(view), MAX_DATA):
            await self._send_record(RecordType.DATA, bytes(view[i : i + MAX_DATA]))

    async def send_eof(self) -> None:
        """Dichiara finiti i dati in uscita (half-close autenticato)."""
        if self._eof_sent:
            return
        self._eof_sent = True
        try:
            await self._send_record(RecordType.CLOSE)
        except (ConnectionError, OSError):
            pass

    async def ping(self) -> None:
        await self._send_record(RecordType.PING, os.urandom(8))

    async def _cover_loop(self, low: float, high: float) -> None:
        try:
            while not self._eof_sent:
                await asyncio.sleep(random.uniform(low, high))
                if self._eof_sent:
                    break
                await self._send_record(RecordType.PAD, bytes(secrets.randbelow(256)))
        except (ConnectionError, OSError):
            pass

    # ---- ricezione -------------------------------------------------------
    async def recv(self) -> bytes:
        while True:
            if self._eof_received:
                return b""
            try:
                len_enc = await self._r.readexactly(2)
                ct_len = self._codec.parse_length(len_enc)
                ciphertext = await self._r.readexactly(ct_len)
            except asyncio.IncompleteReadError as exc:
                raise TruncatedStream("flusso chiuso senza CLOSE autenticato") from exc
            rtype, data = self._codec.open(len_enc, ciphertext)
            if rtype == RecordType.DATA:
                if data:
                    return data
            elif rtype == RecordType.CLOSE:
                self._eof_received = True
                return b""
            elif rtype == RecordType.PING:
                await self._send_record(RecordType.PONG, data)
            # PAD, PONG, REKEY e tipi sconosciuti: ignorati

    # ---- chiusura --------------------------------------------------------
    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.send_eof()
        if self._cover_task is not None:
            self._cover_task.cancel()
        self._w.close()
        try:
            await self._w.wait_closed()
        except (ConnectionError, OSError):
            pass


# ---------------------------------------------------------------------------
# Handshake su stream
# ---------------------------------------------------------------------------
async def client_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: Config
) -> Connection:
    hs = Handshake(
        initiator=True,
        psk=cfg.psk,
        static_private=cfg.identity.private,
        max_pad=cfg.handshake_max_pad,
    )
    writer.write(hs.write_msg1())
    await writer.drain()
    pad_len = hs.read_msg2_head(await reader.readexactly(MSG2_HEAD_LEN))
    hs.read_msg2_pad(await reader.readexactly(pad_len))
    if cfg.verify_peer is not None and not cfg.verify_peer(hs.remote_static):
        raise PeerRejected("chiave pubblica del server non accettata")
    writer.write(hs.write_msg3())
    await writer.drain()
    return Connection(reader, writer, hs.finalize(), cfg)


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: Config,
    replay: ReplayCache,
) -> Connection:
    hs = Handshake(
        initiator=False,
        psk=cfg.psk,
        static_private=cfg.identity.private,
        max_pad=cfg.handshake_max_pad,
    )
    pad_len = hs.read_msg1_head(await reader.readexactly(MSG1_HEAD_LEN))
    if abs(time.time() - hs.remote_timestamp) > cfg.max_clock_skew:
        raise HandshakeError("timestamp fuori dalla finestra consentita")
    if not replay.add(hs.remote_ephemeral_rep):
        raise HandshakeError("replay di msg1")
    hs.read_msg1_pad(await reader.readexactly(pad_len))
    writer.write(hs.write_msg2())
    await writer.drain()
    pad_len = hs.read_msg3_head(await reader.readexactly(MSG3_HEAD_LEN))
    hs.read_msg3_pad(await reader.readexactly(pad_len))
    result = hs.finalize()
    if cfg.verify_peer is not None and not cfg.verify_peer(result.remote_static):
        raise PeerRejected("chiave pubblica del client non autorizzata")
    return Connection(reader, writer, result, cfg)


async def open_connection(host: str, port: int, cfg: Config) -> Connection:
    """Si connette a un server zProtocol e completa l'handshake."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        return await asyncio.wait_for(client_handshake(reader, writer, cfg), cfg.handshake_timeout)
    except asyncio.IncompleteReadError as exc:
        writer.close()
        raise HandshakeError(
            "il server ha chiuso la connessione durante l'handshake (PSK errata?)"
        ) from exc
    except asyncio.TimeoutError as exc:
        writer.close()
        raise HandshakeError("timeout durante l'handshake") from exc
    except BaseException:
        writer.close()
        raise


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
async def _blackhole(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    delay: tuple[float, float],
    max_bytes: int = 65536,
) -> None:
    """Non risponde nulla: legge e scarta per un tempo casuale, poi chiude."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + random.uniform(*delay)
    received = 0
    try:
        while received < max_bytes:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(reader.read(4096), remaining)
            if not chunk:
                break
            received += len(chunk)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def serve(
    handler: Callable[[Connection], Awaitable[None]],
    host: str,
    port: int,
    cfg: Config,
) -> asyncio.Server:
    """Avvia un server zProtocol. `handler` riceve ogni Connection autenticata.

    I client che falliscono l'handshake non ricevono alcun byte: la connessione
    viene tenuta aperta in silenzio per un tempo casuale e poi chiusa.
    """
    replay = ReplayCache(ttl=cfg.max_clock_skew * 2 + 5)

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            conn = await asyncio.wait_for(
                server_handshake(reader, writer, cfg, replay), cfg.handshake_timeout
            )
        except Exception as exc:  # qualunque fallimento -> silenzio
            log.debug("handshake rifiutato da %s: %r", peer, exc)
            await _blackhole(reader, writer, cfg.reject_delay)
            return
        try:
            await handler(conn)
        except Exception:
            log.exception("errore nel gestore della connessione da %s", peer)
        finally:
            await conn.close()

    return await asyncio.start_server(on_client, host, port)
