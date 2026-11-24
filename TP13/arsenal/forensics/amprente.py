import argparse
import hashlib
import os
from collections.abc import Iterator
import mmap

MAGIC = {b"\x89PNG": "PNG", b"%PDF": "PDF", b"PK\x03\x04": "ZIP"}


def tip(head: bytes) -> str:
    """Intoarce tipul fisierului dupa semnatura de la inceputul lui sau "necunoscut"."""
    for k, v in MAGIC.items():
        if head.startswith(k):
            return v
        

    return "necunoscut"


def amprenta_fisier(cale: str) -> dict[str, str]:
    """Intoarce numele, tipul si primele 16 caractere ale amprentei SHA-256, citind fisierul prin mmap."""
    with open(cale, "rb") as f:
        f_len = os.path.getsize(cale)
        f_name = os.path.basename(cale)
        if f_len <= 0:
            return {
                'nume': f_name,
                'tip': tip(b""),
                'sha256': hashlib.sha256(b"").hexdigest()[:16]
            }

        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            head = mm[:8]
            f_type = tip(head)
            f_hash = hashlib.sha256(mm).hexdigest()[:16]
            return {
                'nume': f_name,
                'tip': f_type,
                'sha256': f_hash
            }


def scaneaza(folder: str) -> list[dict[str, str]]:
    """Intoarce fisele fisierelor din folder, in ordinea numelor, fara subdirectoare."""

    return [
        amprenta_fisier(filepath)
        for filepath in 
            [os.path.join(folder, filename) for filename in sorted(os.listdir(folder))]
        if os.path.isfile(filepath)

    ]


def amprente_lenes(folder: str) -> Iterator[dict[str, str]]:
    """Produce pe rand aceleasi fise ca scaneaza."""
    
    for filepath in [os.path.join(folder, filename) for filename in sorted(os.listdir(folder))]:
        if os.path.isfile(filepath):
            yield amprenta_fisier(filepath)


def main() -> None:
    """Tipareste fisa fiecarui fisier din folderul primit in linia de comanda."""
    parser = argparse.ArgumentParser(description="Tipul si amprenta SHA-256 pentru fisierele unui folder.")
    parser.add_argument("folder")
    args = parser.parse_args()
    folder = args.folder
    if not os.path.isdir(folder):
        parser.error(f"not a folder: {folder}")

    for x in scaneaza(folder):
        nume = x["nume"]
        f_type = x["tip"]
        sha256 = x["sha256"]
        print(f"{nume:14} {f_type:11} {sha256}")


if __name__ == "__main__":
    main()
