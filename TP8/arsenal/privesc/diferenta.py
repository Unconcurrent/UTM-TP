from __future__ import annotations

import os
import sys

if __name__ == "__main__" and not __package__:
    sys.path[0] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    __package__ = "arsenal.privesc"

import argparse

from .enum import GTFO, Result, citeste_linii, nume, wrap


def cai(fisier: str) -> set[str]:
    return wrap(citeste_linii)(fisier).then(set).unwrap()


def diferenta(acum: set[str], baza: set[str]) -> set[str]:
    return acum - baza


def main() -> int:
    parser = argparse.ArgumentParser(description="Compară capturile SUID cu sistemul curat.")
    parser.add_argument("capturi", nargs="?", default="start", help="Directorul capturilor.")
    args = parser.parse_args()

    capturi = Result.sequence(
        wrap(cai)(os.path.join(args.capturi, fisier))
        for fisier in ("baza_suid.txt", "suid.txt")
    ).match(
        lambda valoare: valoare,
        lambda eroare: print(f"Eroare: {eroare}"),
    )
    if capturi is None:
        return 1

    baza, acum = capturi
    noi = diferenta(acum, baza)
    risc = {nume(c): "mare" if nume(c) in GTFO else "normal" for c in sorted(noi)}
    periculoase = [c for c in sorted(noi) if risc[nume(c)] == "mare"]

    print("baza:", len(baza), " acum:", len(acum))
    print(len(noi), "SUID noi fata de sistemul curat")
    for c in sorted(noi):
        print(" ", c)
    print("periculoase NOI:", periculoase)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
