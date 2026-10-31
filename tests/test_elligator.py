import os

from zprotocol import elligator as el
from zprotocol.crypto import x25519_dh, x25519_public


def clamp(private: bytes) -> int:
    b = bytearray(private)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def test_base_point_is_on_curve():
    u, v = el.BASE
    assert (v * v - (u**3 + el.A * u * u + u)) % el.P == 0


def test_group_law_matches_openssl():
    for _ in range(5):
        private = os.urandom(32)
        point = el._scalar_mult(clamp(private), el.BASE)
        assert point[0].to_bytes(32, "little") == x25519_public(private)


def test_torsion_subgroup_has_order_8():
    points = el._torsion_points()
    assert len(points) == 8 and points[0] is None
    assert el._scalar_mult(8, points[1]) is None
    assert el._scalar_mult(4, points[1]) is not None
    assert len({p for p in points if p is not None}) == 7


def test_representative_roundtrip():
    for _ in range(100):
        key = el.generate_ephemeral()
        assert len(key.representative) == 32
        assert el.decode_representative(key.representative) == key.public


def test_dh_agrees_with_hidden_keys_and_with_clean_keys():
    for _ in range(50):
        a, b = el.generate_ephemeral(), el.generate_ephemeral()
        s1 = x25519_dh(a.private, el.decode_representative(b.representative))
        s2 = x25519_dh(b.private, el.decode_representative(a.representative))
        assert s1 == s2
        # la componente di torsione non cambia il segreto condiviso
        assert s1 == x25519_dh(a.private, x25519_public(b.private))


def test_any_32_bytes_decode_to_a_valid_curve_point():
    for _ in range(100):
        u = int.from_bytes(el.decode_representative(os.urandom(32)), "little")
        assert el.legendre(u**3 + el.A * u * u + u) == 1  # v^2 esiste: il punto è sulla curva
        x25519_dh(os.urandom(32), u.to_bytes(32, "little"))  # nessuna eccezione


def test_top_bits_of_representative_are_uniform():
    n = 400
    counts = [0, 0, 0, 0]
    for _ in range(n):
        counts[el.generate_ephemeral().representative[31] >> 6] += 1
    assert all(0.15 * n < c < 0.35 * n for c in counts), counts
