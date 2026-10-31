"""Chat peer-to-peer da terminale: esempio d'uso diretto della Connection."""
from __future__ import annotations

import asyncio
import contextlib
import sys
import threading

from .session import Connection


def _clean(text: str) -> str:
    """Toglie i caratteri di controllo (niente sequenze di escape dal peer)."""
    return "".join(ch for ch in text if ch.isprintable())


async def chat_loop(conn: Connection) -> None:
    loop = asyncio.get_running_loop()
    lines: asyncio.Queue[bytes | None] = asyncio.Queue()

    def read_stdin() -> None:
        try:
            for line in sys.stdin:
                loop.call_soon_threadsafe(lines.put_nowait, line.encode("utf-8"))
            loop.call_soon_threadsafe(lines.put_nowait, None)
        except RuntimeError:  # loop già chiuso
            pass

    threading.Thread(target=read_stdin, daemon=True).start()

    async def outgoing() -> None:
        while (item := await lines.get()) is not None:
            await conn.send(item)
        await conn.send_eof()

    out_task = asyncio.create_task(outgoing())
    buf = b""
    try:
        while True:
            data = await conn.recv()
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                print(f"< {_clean(line.decode('utf-8', 'replace'))}", flush=True)
    finally:
        out_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await out_task
