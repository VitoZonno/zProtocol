import os
import stat

import pytest

from zprotocol.cli import build_parser, cover_range, hostport, main


def test_hostport_parsing():
    assert hostport("127.0.0.1:4443") == ("127.0.0.1", 4443)
    assert hostport("[::1]:80") == ("::1", 80)
    assert hostport(":9000") == ("0.0.0.0", 9000)
    with pytest.raises(Exception):
        hostport("senza-porta")
    with pytest.raises(Exception):
        hostport("host:99999")


def test_cover_parsing():
    assert cover_range("0.5,5") == (0.5, 5.0)
    with pytest.raises(Exception):
        cover_range("5,1")


def test_keygen_pubkey_genpsk(tmp_path, capsys):
    key = tmp_path / "id.key"
    assert main(["keygen", "--out", str(key)]) == 0
    out = capsys.readouterr().out
    assert "pubkey:" in out
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600

    pub_line = [line for line in out.splitlines() if line.startswith("pubkey:")][0]
    assert main(["pubkey", "--identity", str(key)]) == 0
    assert pub_line in capsys.readouterr().out

    assert main(["keygen", "--out", str(key)]) == 1  # non sovrascrive
    assert main(["keygen", "--out", str(key), "--force"]) == 0

    assert main(["genpsk"]) == 0
    assert len(capsys.readouterr().out.strip()) >= 40


def test_parser_requires_a_command():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
