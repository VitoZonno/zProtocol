"""Interfaccia a riga di comando: `zprotocol` / `python -m zprotocol`."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import secrets
import sys
from pathlib import Path

from .chat import chat_loop
from .config import Config, derive_psk
from .errors import ZProtocolError
from .identity import Identity, peer_id
from .record import PaddingPolicy
from .session import open_connection, serve
from .tunnel import start_tunnel_client, start_tunnel_server

log = logging.getLogger("zprotocol")


# ---------------------------------------------------------------------------
# Parsing argomenti
# ---------------------------------------------------------------------------
def hostport(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"atteso HOST:PORTA, ricevuto {value!r}")
    return (host.strip("[]") or "0.0.0.0"), int(port)


def cover_range(value: str) -> tuple[float, float]:
    try:
        low, high = (float(x) for x in value.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError("atteso MIN,MAX in secondi (es. 0.5,5)") from None
    if not 0 < low <= high:
        raise argparse.ArgumentTypeError("serve 0 < MIN <= MAX")
    return low, high


def key_hex(value: str) -> bytes:
    try:
        key = bytes.fromhex(value.strip())
    except ValueError:
        raise argparse.ArgumentTypeError("chiave non valida (attesi 64 caratteri esadecimali)") from None
    if len(key) != 32:
        raise argparse.ArgumentTypeError("chiave non valida (attesi 64 caratteri esadecimali)")
    return key


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--identity", default="zprotocol.key", help="file della chiave statica (creato se manca)")
    p.add_argument("--psk", help="passphrase condivisa (visibile in `ps`: meglio --psk-file o ZPROTOCOL_PSK)")
    p.add_argument("--psk-file", help="file con la passphrase condivisa")
    p.add_argument("--max-pad", type=int, default=255, help="padding massimo per record, 0-4096 (default 255)")
    p.add_argument("--cover", type=cover_range, metavar="MIN,MAX", help="traffico di copertura ogni MIN..MAX secondi")
    p.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zprotocol", description="zProtocol: trasporto cifrato e offuscato")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="genera una identità (chiave statica)")
    p.add_argument("--out", default="zprotocol.key")
    p.add_argument("--force", action="store_true", help="sovrascrive il file se esiste")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("pubkey", help="mostra la chiave pubblica di una identità")
    p.add_argument("--identity", default="zprotocol.key")
    p.set_defaults(func=cmd_pubkey)

    p = sub.add_parser("genpsk", help="genera una passphrase casuale da usare come PSK")
    p.set_defaults(func=cmd_genpsk)

    p = sub.add_parser("serve", help="server del tunnel: inoltra le sessioni a --forward")
    _add_common(p)
    p.add_argument("--listen", type=hostport, required=True, metavar="HOST:PORTA")
    p.add_argument("--forward", type=hostport, required=True, metavar="HOST:PORTA")
    p.add_argument("--allow", type=key_hex, action="append", default=[], metavar="PUBKEY_HEX",
                   help="chiave pubblica client autorizzata (ripetibile)")
    p.add_argument("--allow-file", help="file con una chiave pubblica esadecimale per riga")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("connect", help="client del tunnel: porta locale -> server zProtocol")
    _add_common(p)
    p.add_argument("--listen", type=hostport, default=("127.0.0.1", 1080), metavar="HOST:PORTA")
    p.add_argument("--server", type=hostport, required=True, metavar="HOST:PORTA")
    p.add_argument("--server-key", type=key_hex, metavar="PUBKEY_HEX", help="chiave pubblica attesa del server (pinning)")
    p.set_defaults(func=cmd_connect)

    p = sub.add_parser("chat", help="chat peer-to-peer da terminale")
    _add_common(p)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--listen", type=hostport, metavar="HOST:PORTA")
    group.add_argument("--connect", type=hostport, metavar="HOST:PORTA")
    p.add_argument("--peer-key", type=key_hex, metavar="PUBKEY_HEX", help="chiave pubblica attesa del peer")
    p.set_defaults(func=cmd_chat)
    return parser


# ---------------------------------------------------------------------------
# Costruzione della configurazione
# ---------------------------------------------------------------------------
def _load_psk(args: argparse.Namespace) -> bytes:
    secret = args.psk
    if not secret and args.psk_file:
        secret = Path(args.psk_file).read_text().strip()
    if not secret:
        secret = os.environ.get("ZPROTOCOL_PSK")
    if not secret:
        raise SystemExit("errore: PSK mancante (usa --psk-file, ZPROTOCOL_PSK oppure --psk)")
    return derive_psk(secret)


def _load_allowed(args: argparse.Namespace) -> set[bytes]:
    allowed = set(args.allow)
    if args.allow_file:
        for line in Path(args.allow_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                allowed.add(key_hex(line))
    return allowed


def _build_config(args: argparse.Namespace, allowed: set[bytes] | None = None) -> Config:
    identity = Identity.load_or_create(args.identity)
    log.info("identità: pubkey=%s peer_id=%s", identity.public_hex, identity.fingerprint)
    verify = None
    if allowed:
        verify = lambda key: key in allowed  # noqa: E731
    return Config(
        psk=_load_psk(args),
        identity=identity,
        verify_peer=verify,
        padding=PaddingPolicy(args.max_pad),
        cover=args.cover,
    )


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


# ---------------------------------------------------------------------------
# Comandi
# ---------------------------------------------------------------------------
def cmd_keygen(args: argparse.Namespace) -> int:
    identity = Identity.generate()
    try:
        identity.save(args.out, overwrite=args.force)
    except FileExistsError:
        print(f"errore: {args.out} esiste già (usa --force per sovrascrivere)", file=sys.stderr)
        return 1
    print(f"chiave privata salvata in {args.out} (permessi 0600, non condividerla)")
    print(f"pubkey:  {identity.public_hex}")
    print(f"peer_id: {identity.fingerprint}")
    return 0


def cmd_pubkey(args: argparse.Namespace) -> int:
    identity = Identity.load(args.identity)
    print(f"pubkey:  {identity.public_hex}")
    print(f"peer_id: {identity.fingerprint}")
    return 0


def cmd_genpsk(args: argparse.Namespace) -> int:
    print(secrets.token_urlsafe(32))
    return 0


def _run(coro) -> int:
    try:
        asyncio.run(coro)
    except KeyboardInterrupt:
        return 130
    except (ZProtocolError, OSError) as exc:
        print(f"errore: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    cfg = _build_config(args, _load_allowed(args))
    if cfg.verify_peer is None:
        log.warning("nessuna allow-list: qualsiasi client che conosce la PSK può collegarsi")

    async def main() -> None:
        server = await start_tunnel_server(*args.listen, *args.forward, cfg)
        log.info("in ascolto su %s:%s -> inoltro a %s:%s", *args.listen, *args.forward)
        async with server:
            await server.serve_forever()

    return _run(main())


def cmd_connect(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    pinned = {args.server_key} if args.server_key else None
    cfg = _build_config(args, pinned)
    if pinned is None:
        log.warning("--server-key non impostata: l'identità del server NON è verificata")

    async def main() -> None:
        server = await start_tunnel_client(*args.listen, *args.server, cfg)
        log.info("in ascolto su %s:%s -> server zProtocol %s:%s", *args.listen, *args.server)
        async with server:
            await server.serve_forever()

    return _run(main())


def cmd_chat(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    pinned = {args.peer_key} if args.peer_key else None
    cfg = _build_config(args, pinned)

    async def announce(conn) -> None:
        print(f"[connesso] peer_id={peer_id(conn.remote_static)} (verificalo fuori banda)", flush=True)

    async def main() -> None:
        if args.connect:
            conn = await open_connection(*args.connect, cfg)
            try:
                await announce(conn)
                await chat_loop(conn)
            finally:
                await conn.close()
            return

        done = asyncio.Event()
        busy = False

        async def handler(conn) -> None:
            nonlocal busy
            if busy:
                return
            busy = True
            try:
                await announce(conn)
                await chat_loop(conn)
            finally:
                done.set()

        server = await serve(handler, *args.listen, cfg)
        print(f"[in attesa su {args.listen[0]}:{args.listen[1]}]", flush=True)
        async with server:
            await done.wait()

    return _run(main())


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
