import os

from arsenal.forensics.amprente import amprenta_fisier, amprente_lenes, scaneaza, tip

PROBE = os.path.join(os.path.dirname(__file__), "probe")

# Ruleaza din labs/TP13: python -m pytest -q arsenal/forensics/test_amprente.py


def test_tip_din_magic():
    assert tip(b"\x89PNG") == "PNG"
    assert tip(b"%PDF-1.4") == "PDF"
    assert tip(b"PK\x03\x04") == "ZIP"
    assert tip(b"text") == "necunoscut"


def test_amprenta_png():
    r = amprenta_fisier(os.path.join(PROBE, "imagine.png"))
    assert r == {"nume": "imagine.png", "tip": "PNG", "sha256": "ea3a9848da7e6c1d"}


def test_scaneaza_toate():
    rez = scaneaza(PROBE)
    assert len(rez) == 4
    assert [f["nume"] for f in rez] == ["arhiva.zip", "imagine.png", "note.txt", "raport.pdf"]
    assert [f["tip"] for f in rez] == ["ZIP", "PNG", "necunoscut", "PDF"]


def test_generator_ca_lista():
    assert list(amprente_lenes(PROBE)) == scaneaza(PROBE)
