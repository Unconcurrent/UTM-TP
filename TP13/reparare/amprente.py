# arsenal/forensics/amprente.py (DE REPARAT - contine 3 greseli)
# Ruleaza suita (pytest) in Lucrarea B: vei vedea testele picand. Repara pe rand,
# cate o greseala, pana la "3 passed". NU modifica testele si NU modifica probele.
import os, hashlib

MAGIC = {b"\x89PNG": "PNG", b"%PDF": "PDF", b"PK\x03\x04": "ZIP"}


def tip(head):
    for semnatura, nume in MAGIC.items():
        if head.startswith(semnatura):
            return nume
    return "necunoscut"          # greseala 1


def amprenta_fisier(cale):
    with open(cale, "rb") as f:             # greseala 2
        date = f.read()
        return {"nume": os.path.basename(cale),
                "tip": tip(date[:8]),
                "sha256": hashlib.sha256(date).hexdigest()[:16]
        }   # greseala 3


def scaneaza(folder):
    rez = []
    for nume in sorted(os.listdir(folder)):
        cale = os.path.join(folder, nume)
        if os.path.isfile(cale):
            rez.append(amprenta_fisier(cale))
    return rez
