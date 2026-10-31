import time

import pytest

from zprotocol.errors import HandshakeError
from zprotocol.handshake import (
    MSG1_HEAD_LEN,
    MSG2_HEAD_LEN,
    MSG3_HEAD_LEN,
    Handshake,
)
from zprotocol.identity import Identity

PSK = bytes(range(32))
CLIENT = Identity.generate()
SERVER = Identity.generate()


def new_pair(psk_i=PSK, psk_r=PSK, max_pad=512):
    i = Handshake(initiator=True, psk=psk_i, static_private=CLIENT.private, max_pad=max_pad)
    r = Handshake(initiator=False, psk=psk_r, static_private=SERVER.private, max_pad=max_pad)
    return i, r


def step1(i, r):
    m1 = i.write_msg1()
    pad = r.read_msg1_head(m1[:MSG1_HEAD_LEN])
    assert len(m1) - MSG1_HEAD_LEN == pad
    r.read_msg1_pad(m1[MSG1_HEAD_LEN:])
    return m1


def step2(i, r):
    m2 = r.write_msg2()
    pad = i.read_msg2_head(m2[:MSG2_HEAD_LEN])
    assert len(m2) - MSG2_HEAD_LEN == pad
    i.read_msg2_pad(m2[MSG2_HEAD_LEN:])
    return m2


def step3(i, r):
    m3 = i.write_msg3()
    pad = r.read_msg3_head(m3[:MSG3_HEAD_LEN])
    assert len(m3) - MSG3_HEAD_LEN == pad
    r.read_msg3_pad(m3[MSG3_HEAD_LEN:])
    return m3


def full(**kw):
    i, r = new_pair(**kw)
    msgs = (step1(i, r), step2(i, r), step3(i, r))
    return i, r, msgs


def test_full_handshake_agrees_on_everything():
    i, r, _ = full()
    ri, rr = i.finalize(), r.finalize()
    assert ri.send_key == rr.recv_key and ri.recv_key == rr.send_key
    assert ri.send_mask_key == rr.recv_mask_key and ri.recv_mask_key == rr.send_mask_key
    assert ri.handshake_hash == rr.handshake_hash
    assert len({ri.send_key, ri.recv_key, ri.send_mask_key, ri.recv_mask_key}) == 4
    assert ri.remote_static == SERVER.public
    assert rr.remote_static == CLIENT.public


def test_msg1_timestamp_is_current():
    i, r = new_pair()
    step1(i, r)
    assert abs(r.remote_timestamp - time.time()) < 5


def test_wrong_psk_fails_at_msg1():
    i, r = new_pair(psk_r=bytes(32))
    m1 = i.write_msg1()
    with pytest.raises(HandshakeError):
        r.read_msg1_head(m1[:MSG1_HEAD_LEN])


def test_sequence_is_enforced():
    i, r = new_pair()
    with pytest.raises(HandshakeError):
        i.write_msg3()
    with pytest.raises(HandshakeError):
        r.write_msg2()
    with pytest.raises(HandshakeError):
        i.finalize()


def flip(data: bytes, pos: int) -> bytes:
    out = bytearray(data)
    out[pos] ^= 0x01
    return bytes(out)


def test_every_bit_flip_in_msg1_head_is_detected():
    for pos in range(MSG1_HEAD_LEN):
        i, r = new_pair()
        m1 = i.write_msg1()
        with pytest.raises(HandshakeError):
            r.read_msg1_head(flip(m1[:MSG1_HEAD_LEN], pos))


def test_every_bit_flip_in_msg2_head_is_detected():
    for pos in range(MSG2_HEAD_LEN):
        i, r = new_pair()
        step1(i, r)
        m2 = r.write_msg2()
        with pytest.raises(HandshakeError):
            i.read_msg2_head(flip(m2[:MSG2_HEAD_LEN], pos))


def test_every_bit_flip_in_msg3_head_is_detected():
    for pos in range(MSG3_HEAD_LEN):
        i, r = new_pair()
        step1(i, r)
        step2(i, r)
        m3 = i.write_msg3()
        with pytest.raises(HandshakeError):
            r.read_msg3_head(flip(m3[:MSG3_HEAD_LEN], pos))


def test_padding_is_authenticated():
    # manomettere il padding di msg2 rompe l'handshake alla msg3
    for _ in range(50):
        i, r = new_pair(max_pad=64)
        step1(i, r)
        m2 = r.write_msg2()
        if len(m2) == MSG2_HEAD_LEN:
            continue
        i.read_msg2_head(m2[:MSG2_HEAD_LEN])
        i.read_msg2_pad(flip(m2[MSG2_HEAD_LEN:], 0)[: len(m2) - MSG2_HEAD_LEN])
        m3 = i.write_msg3()
        with pytest.raises(HandshakeError):
            r.read_msg3_head(m3[:MSG3_HEAD_LEN])
        return
    pytest.fail("nessun msg2 con padding generato")


def test_low_order_ephemeral_is_rejected():
    # rappresentante che decodifica in un punto qualsiasi: l'handshake non deve crashare
    i, r = new_pair()
    m1 = bytearray(i.write_msg1())
    m1[:32] = bytes(32)
    with pytest.raises(HandshakeError):
        r.read_msg1_head(bytes(m1[:MSG1_HEAD_LEN]))
