"""Tunnel TCP sopra zProtocol (port forwarding cifrato e offuscato).

    app  --TCP-->  [tunnel client]  ==== zProtocol ====  [tunnel server]  --TCP-->  servizio

Ogni connessione TCP locale apre una sessione zProtocol dedicata.
"""
from __future__ import annotations

import asyncio
import logging

from .config import Config
from .errors import ZProtocolError
from .session import Connection, open_connection, serve

log = logging.getLogger("zprotocol")

_READ_CHUNK = 16384


async def pipe(conn: Connection, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Collega una Connection a uno stream TCP, con half-close in entrambe le direzioni."""

    async def tcp_to_conn() -> None:
        try:
            while True:
                data = await reader.read(_READ_CHUNK)
                if not data:
                    break
                await conn.send(data)
        finally:
            await conn.send_eof()

    async def conn_to_tcp() -> None:
        try:
            while True:
                data = await conn.recv()
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except OSError:
                pass

    try:
        async with asyncio.TaskGroup() as group:
            group.create_task(tcp_to_conn())
            group.create_task(conn_to_tcp())
    except* (ZProtocolError, OSError) as errors:
        log.debug("pipe terminata: %r", errors.exceptions)
    finally:
        writer.close()
        await conn.close()


async def start_tunnel_server(
    listen_host: str, listen_port: int, forward_host: str, forward_port: int, cfg: Config
) -> asyncio.Server:
    """Accetta sessioni zProtocol e inoltra ogni flusso a forward_host:forward_port."""

    async def handler(conn: Connection) -> None:
        try:
            reader, writer = await asyncio.open_connection(forward_host, forward_port)
        except OSError as exc:
            log.warning("impossibile raggiungere %s:%s: %s", forward_host, forward_port, exc)
            return
        await pipe(conn, reader, writer)

    return await serve(handler, listen_host, listen_port, cfg)


async def start_tunnel_client(
    listen_host: str, listen_port: int, server_host: str, server_port: int, cfg: Config
) -> asyncio.Server:
    """Ascolta in locale e inoltra ogni connessione TCP al server zProtocol."""

    async def on_local(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            conn = await open_connection(server_host, server_port, cfg)
        except (OSError, ZProtocolError) as exc:
            log.warning("connessione a %s:%s fallita: %s", server_host, server_port, exc)
            writer.close()
            return
        await pipe(conn, reader, writer)

    return await asyncio.start_server(on_local, listen_host, listen_port)
