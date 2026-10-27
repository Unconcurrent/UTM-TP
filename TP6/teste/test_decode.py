import base64
import hashlib
from pathlib import Path

import pytest

from arsenal.forensics.decode import (
    citibil,
    decodifica,
    desfa,
    ghici_strat,
    identifica_hash,
    sparge_hash,
    sparge_xor,
)


ROOT = Path(__file__).resolve().parents[1]


def test_base64():
    strat, b = desfa("U2FsdXQ=")
    assert strat == "base64"
    assert b == b"Salut"


@pytest.mark.parametrize("text, strat", [("%2Fetc", "url"), ("48656c6c6f", "hex"),
                                          ("U2FsdXQ=", "base64"), ("FLAG{gata}", "necunoscut")])
def test_recunoastere(text, strat):
    assert ghici_strat(text) == strat


def test_hex_si_url():
    assert desfa("48656c6c6f") == ("hex", b"Hello")
    assert desfa("%2Fetc") == ("url", b"/etc")


def test_url_se_opreste_la_calea_citibila():
    fisa = decodifica(b"%2Fetc")
    assert fisa["rezultat"] == "/etc"
    assert fisa["straturi"] == ["url"]


def test_base64_invalid():
    with pytest.raises(ValueError):
        desfa("A=")


def test_straturi_din_proba():
    fisa = decodifica((ROOT / "probe/mesaj.txt").read_bytes())
    assert fisa["straturi"] == ["base64", "base64", "hex"]
    assert fisa["rezultat"] == "FLAG{straturi_de_encoding}"


def test_limita_accepta_exact_opt_straturi():
    date = b"FLAG{opt_straturi}"
    for _ in range(8):
        date = base64.b64encode(date)
    assert decodifica(date)["rezultat"] == "FLAG{opt_straturi}"


def test_limita_opreste_straturile_suplimentare():
    date = b"FLAG{noua_straturi}"
    for _ in range(9):
        date = base64.b64encode(date)
    with pytest.raises(ValueError, match="limita"):
        decodifica(date)


def test_xor_din_proba():
    cheie, clar = sparge_xor((ROOT / "probe/xor.bin").read_bytes())
    assert cheie == 128
    assert clar == b"Un singur octet tine tot secretul... gaseste-l! FLAG{xor_un_octet}"
    assert citibil(clar)
    assert not citibil(b"a\x00b")


def test_xor_gol():
    with pytest.raises(ValueError):
        sparge_xor(b"")


@pytest.mark.parametrize("algoritm", ["md5", "sha1", "sha256"])
def test_dictionar_si_identificare(algoritm, tmp_path):
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("gresit\nsecret\n")
    tinta = hashlib.new(algoritm, b"secret").hexdigest().upper()
    assert identifica_hash(tinta) == algoritm
    assert sparge_hash(tinta, wordlist) == {"algoritm": algoritm, "parola": "secret"}


def test_dictionar_fara_parola(tmp_path):
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("gresit\n")
    assert sparge_hash(hashlib.md5(b"absent").hexdigest(), wordlist) is None


def test_hash_invalid():
    with pytest.raises(ValueError):
        identifica_hash("nu este un hash")


def test_challenge():
    fisa = decodifica((ROOT / "probe/challenge.bin").read_bytes())
    assert fisa["straturi"] == ["base64", "xor"]
    assert fisa["cheie"] == 128
    assert fisa["rezultat"] == "FLAG{lant_complet_despicat}"
