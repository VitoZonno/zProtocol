import asyncio
import os
import time

import pytest

from zprotocol import Config, Identity, derive_psk, open_connection, serve
from zprotocol.errors import HandshakeError, PeerRejected, ZProtocolError
from zprotocol.handshake import MSG1_HEAD_LEN, MSG2_HEAD_LEN, Handshake
from zprotocol.tunnel import start_tunnel_client, start_tunnel_server

PSK = bytes(range(32))


def run(coro, timeout=30):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def make_cfg(psk=PSK, **kw):
    kw.setdefault("reject_delay", (0.02, 0.05))
    kw.setdefault("handshake_timeout", 3.0)
    return Config(psk=psk, identity=Identity.generate(), **kw)


async def echo(conn):
    while True:
        data = await conn.recv()
        if not data:
            break
        await conn.send(data)


def port_of(server):
    return server.sockets[0].getsockname()[1]


def test_derive_psk():
    assert len(derive_psk("abc")) == 32
    assert derive_psk("abc") == derive_psk("abc") != derive_psk("abd")


def test_echo_roundtrip_and_identities():
    async def scenario():
        scfg, ccfg = make_cfg(), make_cfg()
        server = await serve(echo, "127.0.0.1", 0, scfg)
        async with server:
            conn = await open_connection("127.0.0.1", port_of(server), ccfg)
            assert conn.remote_static == scfg.identity.public
            await conn.send(b"ciao zProtocol")
            assert await conn.recv() == b"ciao zProtocol"
            await conn.close()

    run(scenario())


def test_large_transfer_with_rekey():
    async def scenario():
        scfg, ccfg = make_cfg(rekey_after=7), make_cfg(rekey_after=7)
        payload = os.urandom(1_000_000)
        server = await serve(echo, "127.0.0.1", 0, scfg)
        async with server:
            conn = await open_connection("127.0.0.1", port_of(server), ccfg)
            received = bytearray()

            async def sender():
                await conn.send(payload)
                await conn.send_eof()

            async def receiver():
                while data := await conn.recv():
                    received.extend(data)

            await asyncio.gather(sender(), receiver())
            await conn.close()
            assert bytes(received) == payload

    run(scenario())


def test_wrong_psk_gets_no_answer_at_all():
    async def scenario():
        scfg = make_cfg()
        server = await serve(echo, "127.0.0.1", 0, scfg)
        async with server:
            hs = Handshake(initiator=True, psk=bytes(32), static_private=os.urandom(32))
            reader, writer = await asyncio.open_connection("127.0.0.1", port_of(server))
            writer.write(hs.write_msg1())
            assert await asyncio.wait_for(reader.read(1024), 5) == b""  # nessun byte, solo chiusura
            writer.close()

            with pytest.raises(HandshakeError):
                await open_connection("127.0.0.1", port_of(server), make_cfg(psk=bytes(32)))

    run(scenario())


def test_garbage_gets_no_answer():
    async def scenario():
        server = await serve(echo, "127.0.0.1", 0, make_cfg())
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port_of(server))
            writer.write(os.urandom(300))
            assert await asyncio.wait_for(reader.read(1024), 5) == b""
            writer.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", port_of(server))
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" * 5)
            assert await asyncio.wait_for(reader.read(1024), 5) == b""
            writer.close()

    run(scenario())


def test_replayed_msg1_is_ignored():
    async def scenario():
        server = await serve(echo, "127.0.0.1", 0, make_cfg())
        async with server:
            hs = Handshake(initiator=True, psk=PSK, static_private=os.urandom(32))
            msg1 = hs.write_msg1()

            reader, writer = await asyncio.open_connection("127.0.0.1", port_of(server))
            writer.write(msg1)
            first = await asyncio.wait_for(reader.readexactly(MSG2_HEAD_LEN), 5)
            assert len(first) == MSG2_HEAD_LEN  # prima volta: il server risponde
            writer.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", port_of(server))
            writer.write(msg1)
            assert await asyncio.wait_for(reader.read(1024), 5) == b""  # replay: silenzio
            writer.close()

    run(scenario())


def test_stale_timestamp_is_ignored():
    async def scenario():
        server = await serve(echo, "127.0.0.1", 0, make_cfg(max_clock_skew=30))
        async with server:
            hs = Handshake(initiator=True, psk=PSK, static_private=os.urandom(32))
            reader, writer = await asyncio.open_connection("127.0.0.1", port_of(server))
            writer.write(hs.write_msg1(now=int(time.time()) - 3600))
            assert await asyncio.wait_for(reader.read(1024), 5) == b""
            writer.close()

    run(scenario())


def test_client_pins_server_key():
    async def scenario():
        scfg = make_cfg()
        server = await serve(echo, "127.0.0.1", 0, scfg)
        async with server:
            bad = make_cfg(verify_peer=lambda key: key == bytes(32))
            with pytest.raises(PeerRejected):
                await open_connection("127.0.0.1", port_of(server), bad)

            good = make_cfg(verify_peer=lambda key: key == scfg.identity.public)
            conn = await open_connection("127.0.0.1", port_of(server), good)
            await conn.close()

    run(scenario())


def test_server_allow_list_rejects_unknown_client():
    async def scenario():
        allowed = Identity.generate()
        scfg = make_cfg(verify_peer=lambda key: key == allowed.public)
        server = await serve(echo, "127.0.0.1", 0, scfg)
        async with server:
            stranger = await open_connection("127.0.0.1", port_of(server), make_cfg())
            with pytest.raises(ZProtocolError):
                await stranger.send(b"ciao")
                await stranger.recv()
            await stranger.close()

            friend_cfg = Config(psk=PSK, identity=allowed, handshake_timeout=3.0)
            friend = await open_connection("127.0.0.1", port_of(server), friend_cfg)
            await friend.send(b"ciao")
            assert await friend.recv() == b"ciao"
            await friend.close()

    run(scenario())


def test_cover_traffic_is_transparent():
    async def scenario():
        scfg, ccfg = make_cfg(cover=(0.01, 0.02)), make_cfg(cover=(0.01, 0.02))
        server = await serve(echo, "127.0.0.1", 0, scfg)
        async with server:
            conn = await open_connection("127.0.0.1", port_of(server), ccfg)
            await asyncio.sleep(0.4)  # nessun dato applicativo: solo copertura
            await conn.send(b"dopo il silenzio")
            assert await conn.recv() == b"dopo il silenzio"
            assert conn._codec._recv_n > 5  # sono arrivati record di copertura
            await conn.close()

    run(scenario())


def test_tunnel_end_to_end_with_half_close():
    async def scenario():
        async def target(reader, writer):  # echo che chiude a fine input
            while data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
            writer.close()

        tgt = await asyncio.start_server(target, "127.0.0.1", 0)
        tsrv = await start_tunnel_server("127.0.0.1", 0, "127.0.0.1", port_of(tgt), make_cfg())
        tcli = await start_tunnel_client("127.0.0.1", 0, "127.0.0.1", port_of(tsrv), make_cfg())
        payload = os.urandom(300_000)
        reader, writer = await asyncio.open_connection("127.0.0.1", port_of(tcli))

        async def sender():
            writer.write(payload)
            await writer.drain()
            writer.write_eof()

        async def receiver():
            return await reader.read(-1)

        _, received = await asyncio.gather(sender(), receiver())
        assert received == payload
        writer.close()
        for srv in (tcli, tsrv, tgt):
            srv.close()

    run(scenario())
