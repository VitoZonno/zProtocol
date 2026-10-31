"""Controlli statistici di base: sul filo non ci sono costanti riconoscibili."""
import os

from zprotocol.handshake import MSG1_HEAD_LEN, MSG2_HEAD_LEN, Handshake
from zprotocol.identity import Identity
from zprotocol.record import PaddingPolicy, RecordCodec, RecordType

PSK = bytes(range(32))
N = 300


def handshake_wire_messages():
    client, server = Identity.generate(), Identity.generate()
    i = Handshake(initiator=True, psk=PSK, static_private=client.private)
    r = Handshake(initiator=False, psk=PSK, static_private=server.private)
    m1 = i.write_msg1()
    r.read_msg1_head(m1[:MSG1_HEAD_LEN])
    r.read_msg1_pad(m1[MSG1_HEAD_LEN:])
    m2 = r.write_msg2()
    i.read_msg2_head(m2[:MSG2_HEAD_LEN])
    i.read_msg2_pad(m2[MSG2_HEAD_LEN:])
    m3 = i.write_msg3()
    return m1, m2, m3


def bit_balance(blobs):
    ones = sum(bin(b).count("1") for blob in blobs for b in blob)
    total = sum(len(blob) for blob in blobs) * 8
    return ones / total


def test_no_constant_byte_in_any_handshake_message_prefix():
    samples = [handshake_wire_messages() for _ in range(N)]
    for index, head in ((0, MSG1_HEAD_LEN), (1, MSG2_HEAD_LEN), (2, 67)):
        for offset in range(head):
            distinct = {s[index][offset] for s in samples}
            assert len(distinct) > 120, (index, offset, len(distinct))


def test_handshake_bits_are_balanced():
    samples = [handshake_wire_messages() for _ in range(N)]
    for index in range(3):
        assert 0.48 < bit_balance([s[index] for s in samples]) < 0.52


def test_handshake_lengths_vary():
    samples = [handshake_wire_messages() for _ in range(N)]
    for index in range(3):
        assert len({len(s[index]) for s in samples}) > 50


def test_record_bytes_look_random_even_for_constant_plaintext():
    codec = RecordCodec(
        send_key=os.urandom(32), recv_key=os.urandom(32),
        send_mask_key=os.urandom(32), recv_mask_key=os.urandom(32),
        padding=PaddingPolicy(255),
    )
    blobs = [codec.seal(RecordType.DATA, b"A" * 1000) for _ in range(N)]
    assert 0.49 < bit_balance(blobs) < 0.51
    for offset in range(2, 40):
        assert len({blob[offset] for blob in blobs}) > 120
