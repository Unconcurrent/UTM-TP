import zipfile
from pathlib import Path

import pytest
from PIL import Image

from forensics import citeste_exif, extrage_strings, extrage_zip, gps_zecimal, tip_real


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("nume, semnatura, tip", [
    ("document.bin", b"%PDF-1.7", "pdf"),
    ("poza.txt", b"\x89PNG\r\n\x1a\n", "png"),
    ("imagine.dat", b"\xff\xd8\xff\xe0", "jpeg"),
    ("arhiva.jpg", b"PK\x03\x04", "zip/docx"),
])
def test_semnatura_independenta_de_extensie(nume, semnatura, tip, tmp_path):
    cale = tmp_path / nume
    cale.write_bytes(semnatura)
    assert tip_real(cale) == tip


def test_strings_si_carving(tmp_path):
    proba = ROOT / "probe/ascuns.png"
    texte = extrage_strings(proba)
    assert "secret.txt" in "\n".join(texte)
    assert "FLAG{ascuns_prin_carving}" in "\n".join(texte)
    arhiva = tmp_path / "gasit.zip"
    pozitie = extrage_zip(proba, arhiva)
    assert pozitie > 0
    assert tip_real(proba) == "png"
    assert tip_real(arhiva) == "zip/docx"
    with zipfile.ZipFile(arhiva) as extras:
        assert extras.read("secret.txt") == b"FLAG{ascuns_prin_carving}\n"


def test_carving_fara_zip(tmp_path):
    cale = tmp_path / "fara.bin"
    cale.write_bytes(b"Nu exista arhiva aici.")
    with pytest.raises(ValueError, match="ZIP"):
        extrage_zip(cale, tmp_path / "gasit.zip")


def test_exif_si_gps():
    metadate, gps = citeste_exif(ROOT / "probe/foto.jpg")
    assert metadate["Make"] == "Apple"
    assert metadate["Model"] == "iPhone 13"
    assert metadate["DateTime"] == "2026:09:14 10:30:00"
    latitudine, longitudine = gps_zecimal(gps)
    assert latitudine == pytest.approx(47 + 1 / 60)
    assert longitudine == pytest.approx(28 + 51 / 60 + 27 / 3600)


def test_gps_sud_si_vest():
    latitudine, longitudine = gps_zecimal({1: "S", 2: (10, 30, 0), 3: "W", 4: (20, 15, 0)})
    assert latitudine == -10.5
    assert longitudine == -20.25


def test_imagine_fara_exif(tmp_path):
    cale = tmp_path / "simpla.png"
    Image.new("RGB", (2, 2)).save(cale)
    assert citeste_exif(cale) == ({}, {})
