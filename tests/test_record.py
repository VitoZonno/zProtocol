import pytest

from zprotocol.crypto import TAGLEN
from zprotocol.errors import RecordError
from zprotocol.record import (
    HEADER_LEN,
    MAX_DATA,
    PaddingPolicy,
    RecordCodec,
    RecordType,
)

K1, K2 = b"\x01" * 32, b"\x02" * 32
M1, M2 = b"\x03" * 32, b"\x04" * 32


def pair(**kw):
    a = RecordCodec(send_key=K1, recv_key=K2, send_mask_key=M1, recv_mask_key=M2, **kw)
    b = RecordCodec(send_key=K2, recv_key=K1, send_mask_key=M2, recv_mask_key=M1, **kw)
    return a, b


def open_all(codec, blob):
    """Estrae tutti i record da un blob (come farebbe il lettore di stream)."""
    out = []
    while blob:
        len_enc, blob = blob[:2], blob[2:]
        n = codec.parse_length(len_enc)
        ct, blob = blob[:n], blob[n:]
        out.append(codec.open(len_enc, ct))
    return out


def test_roundtrip_all_sizes_and_types():
    a, b = pair()
    for rtype in RecordType:
        if rtype == RecordType.REKEY:
            continue  # record di controllo: lo emette solo il codec (vedi test_rekey_*)
        for size in (0, 1, 100, MAX_DATA):
            data = bytes(range(256)) * (size // 256) + bytes(size % 256)
            assert open_all(b, a.seal(rtype, data)) == [(rtype, data)]
    # e nell'altra direzione
    assert open_all(a, b.seal(RecordType.DATA, b"ciao")) == [(RecordType.DATA, b"ciao")]


def test_oversized_data_is_refused():
    a, _ = pair()
    with pytest.raises(ValueError):
        a.seal(RecordType.DATA, bytes(MAX_DATA + 1))


def test_any_tampering_is_detected():
    a, _ = pair(padding=PaddingPolicy(0))
    blob = a.seal(RecordType.DATA, b"messaggio")
    for pos in range(len(blob)):
        _, b = pair(padding=PaddingPolicy(0))
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(RecordError):
            open_all(b, bytes(bad))


def test_reordering_and_replay_are_detected():
    a, b = pair()
    r1 = a.seal(RecordType.DATA, b"uno")
    r2 = a.seal(RecordType.DATA, b"due")
    with pytest.raises(RecordError):
        open_all(b, r2)
    _, b = pair()
    open_all(b, r1)
    with pytest.raises(RecordError):
        open_all(b, r1)  # replay


def test_rekey_keeps_both_sides_in_sync():
    a, b = pair(rekey_after=3)
    first_key = a._send_key
    for i in range(20):
        payload = f"messaggio {i}".encode()
        received = open_all(b, a.seal(RecordType.DATA, payload))
        assert received[-1] == (RecordType.DATA, payload)
    assert a._send_key != first_key
    assert b._recv_key == a._send_key


def test_rekey_record_is_emitted_before_the_data():
    a, b = pair(rekey_after=2)
    blob = b""
    for i in range(5):
        blob += a.seal(RecordType.DATA, bytes([i]))
    records = open_all(b, blob)
    types = [t for t, _ in records]
    assert RecordType.REKEY in types
    assert [d for t, d in records if t == RecordType.DATA] == [bytes([i]) for i in range(5)]


def test_padding_bounds():
    a, b = pair(padding=PaddingPolicy(100))
    data = b"x" * 50
    sizes = set()
    for _ in range(300):
        blob = a.seal(RecordType.DATA, data)
        sizes.add(len(blob) - 2)
        assert open_all(b, blob) == [(RecordType.DATA, data)]
    base = HEADER_LEN + len(data) + TAGLEN
    assert min(sizes) >= base and max(sizes) <= base + 100
    assert len(sizes) > 50  # le dimensioni variano davvero


def test_length_prefix_is_masked():
    a, _ = pair(padding=PaddingPolicy(0))
    prefixes = {a.seal(RecordType.DATA, b"stessa dimensione")[:2] for _ in range(100)}
    assert len(prefixes) > 40  # stessa lunghezza reale, prefissi sempre diversi


def test_invalid_padding_policy():
    with pytest.raises(ValueError):
        PaddingPolicy(5000)
