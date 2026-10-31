"""Chiavi effimere X25519 con rappresentazione Elligator2.

Una chiave pubblica X25519 "normale" non è uniforme: i suoi 32 byte sono
riconoscibili come coordinata di un punto della curva. Elligator2 permette di
trasmettere al suo posto una *rappresentazione* di 32 byte indistinguibile da
rumore casuale (stessa idea di obfs4 e Monocypher).

Dettagli:
  * solo circa metà dei punti ha una rappresentazione -> si rigenera finché esiste;
  * le chiavi pubbliche X25519 appartengono al sottogruppo di ordine primo, e
    questo sarebbe un segnale statistico: si somma un punto di torsione casuale
    (ordine 8). Il DH lo ignora perché lo scalare X25519 è multiplo di 8, quindi
    il segreto condiviso non cambia;
  * i 2 bit alti della rappresentazione (che ha solo 254 bit utili) sono casuali.

L'aritmetica sui punti è Python puro, usata solo in generazione delle chiavi
(poche decine di microsecondi di inversioni modulari); il DH vero e proprio
resta delegato a OpenSSL tramite `cryptography`.
"""
from __future__ import annotations

import functools
import os
import secrets
from dataclasses import dataclass

from .crypto import x25519_public

P = 2**255 - 19
A = 486662
L = 2**252 + 27742317777372353535851937790883648493  # ordine del sottogruppo primo
_MASK254 = (1 << 254) - 1
_SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int] | None  # None = punto all'infinito


def legendre(a: int) -> int:
    ls = pow(a % P, (P - 1) // 2, P)
    return -1 if ls == P - 1 else ls


def sqrt_mod(a: int) -> int:
    """Radice quadrata modulo P (P ≡ 5 mod 8)."""
    a %= P
    x = pow(a, (P + 3) // 8, P)
    if (x * x - a) % P == 0:
        return x
    if (x * x + a) % P == 0:
        return x * _SQRT_M1 % P
    raise ValueError("non è un residuo quadratico")


BASE: tuple[int, int] = (9, sqrt_mod(9**3 + A * 81 + 9))


def _point_double(p1: Point) -> Point:
    if p1 is None:
        return None
    x1, y1 = p1
    if y1 == 0:
        return None
    lam = (3 * x1 * x1 + 2 * A * x1 + 1) * pow(2 * y1, -1, P) % P
    x3 = (lam * lam - A - 2 * x1) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        return _point_double(p1)
    lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - A - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1
    return result


@functools.lru_cache(maxsize=1)
def _torsion_points() -> tuple[Point, ...]:
    """I 8 punti del sottogruppo di torsione (il primo è l'infinito)."""
    x = 2
    while True:
        t = (x**3 + A * x * x + x) % P
        if legendre(t) == 1:
            candidate = _scalar_mult(L, (x, sqrt_mod(t)))
            if candidate is not None and _scalar_mult(4, candidate) is not None:
                break  # ordine esattamente 8
        x += 1
    points: list[Point] = [None]
    current: Point = None
    for _ in range(7):
        current = _point_add(current, candidate)
        points.append(current)
    return tuple(points)


def _u_to_representative(u: int) -> bytes | None:
    """Rappresentante Elligator2 della coordinata u, o None se non esiste."""
    if legendre(-2 * u * (u + A)) != 1:
        return None
    if secrets.randbelow(2):
        r = sqrt_mod(-u * pow(2 * (u + A), -1, P))
    else:
        r = sqrt_mod(-(u + A) * pow(2 * u, -1, P))
    r = min(r, P - r)
    r |= secrets.randbits(2) << 254
    return r.to_bytes(32, "little")


def decode_representative(representative: bytes) -> bytes:
    """Mappa Elligator2: 32 byte qualsiasi -> coordinata u (32 byte LE) di un punto valido."""
    if len(representative) != 32:
        raise ValueError("la rappresentazione deve essere di 32 byte")
    r = int.from_bytes(representative, "little") & _MASK254
    w = (-A * pow(1 + 2 * r * r, -1, P)) % P
    t = (w * w * w + A * w * w + w) % P
    u = w if legendre(t) == 1 else (-w - A) % P
    return u.to_bytes(32, "little")


@dataclass(frozen=True)
class EphemeralKey:
    private: bytes         # 32 byte, restano locali
    public: bytes          # coordinata u "sporca" (con torsione), usata per il DH
    representative: bytes  # 32 byte indistinguibili da rumore, vanno sul filo


def generate_ephemeral() -> EphemeralKey:
    torsion = _torsion_points()
    while True:
        private = os.urandom(32)
        u = int.from_bytes(x25519_public(private), "little")
        v = sqrt_mod(u**3 + A * u * u + u)
        point = _point_add((u, v), torsion[secrets.randbelow(8)])
        assert point is not None
        dirty_u = point[0]
        representative = _u_to_representative(dirty_u)
        if representative is not None:
            return EphemeralKey(private, dirty_u.to_bytes(32, "little"), representative)
