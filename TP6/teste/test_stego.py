import pytest
from PIL import Image

from stego import ascunde, dezvaluie


@pytest.mark.parametrize("mesaj", ["FLAG{ascuns_in_pixeli}", "Salut, Chișinău!", ""])
def test_roundtrip_si_doar_lsb(mesaj, tmp_path):
    gazda = tmp_path / "gazda.png"
    iesire = tmp_path / "stego.png"
    Image.new("RGB", (20, 20), (70, 110, 160)).save(gazda)
    biti = ascunde(gazda, mesaj, iesire)
    assert biti == (len(mesaj.encode()) + 1) * 8
    assert dezvaluie(iesire) == mesaj
    with Image.open(gazda) as original, Image.open(iesire) as stego:
        a, b = original.tobytes(), stego.tobytes()
    assert all((x & ~1) == (y & ~1) for x, y in zip(a, b))
    assert a[biti:] == b[biti:]


def test_capacitate_include_terminatorul(tmp_path):
    gazda = tmp_path / "gazda.png"
    Image.new("RGB", (2, 2)).save(gazda)
    with pytest.raises(ValueError, match="încap"):
        ascunde(gazda, "A", tmp_path / "stego.png")


def test_jpeg_nu_este_iesire_valida(tmp_path):
    gazda = tmp_path / "gazda.png"
    Image.new("RGB", (20, 20)).save(gazda)
    with pytest.raises(ValueError, match="PNG"):
        ascunde(gazda, "test", tmp_path / "stego.jpg")


def test_mesaj_fara_terminator(tmp_path):
    cale = tmp_path / "fara.png"
    Image.new("RGB", (8, 8), (255, 255, 255)).save(cale)
    with pytest.raises(ValueError, match="terminatorul"):
        dezvaluie(cale)
