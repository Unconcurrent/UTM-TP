from __future__ import annotations

import os
import sys

if __name__ == "__main__" and not __package__:
    sys.path[0] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    __package__ = "arsenal.aparare"

import argparse
import json
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from functools import partial
from typing import TypedDict

from .parse_auth import Esec, cale_jurnal, citeste, citeste_esecuri, eveniment, pe_ip, primele
from .result import wrap


class Raport(TypedDict):
    esecuri: list[Esec]
    pe_ip: dict[str, int]
    suspecti: list[tuple[str, int]]


def suspecti(counts: Mapping[str, int], prag: int = 10) -> list[tuple[str, int]]:
    if prag < 1:
        raise ValueError(f"prag invalid: {prag} (cel putin 1)")
    return [
        (ip, n)
        for ip, n in sorted(counts.items(), key=lambda pereche: pereche[1], reverse=True)
        if n >= prag
    ]


def pe_ip_fereastra(evenimente: Iterable[tuple[datetime, str]], secunde: int) -> Counter[str]:
    if secunde < 1:
        raise ValueError(f"fereastra invalida: {secunde} (cel putin 1)")
    cozi: defaultdict[str, deque[datetime]] = defaultdict(deque)
    maxime: Counter[str] = Counter()
    durata = timedelta(seconds=secunde)
    for data, ip in sorted(evenimente, key=lambda pereche: pereche[0]):
        coada = cozi[ip]
        coada.append(data)
        # Ambele capete ale intervalului sunt incluse.
        while coada and coada[0] < data - durata:
            coada.popleft()
        maxime[ip] = max(maxime[ip], len(coada))
    return maxime


def analizeaza(
    cale: str,
    prag: int = 10,
    *,
    fereastra: int | None = None,
    top: int | None = None,
) -> Raport | None:
    if fereastra is None:
        esecuri = citeste_esecuri(cale)
        counts = pe_ip(esecuri)
    else:
        evenimente = citeste(cale, eveniment)
        esecuri = [Esec(user=e["user"], ip=e["ip"]) for e in evenimente]
        datate = [(e["moment"], e["ip"]) for e in evenimente if e["moment"] is not None]
        if esecuri and not datate:
            raise ValueError("Jurnalul nu conține ore valide pentru analiza temporală.")
        counts = pe_ip_fereastra(datate, fereastra)
    if not esecuri and not cale_jurnal(cale).exists():
        return None

    selecteaza = partial(suspecti, prag=prag)
    return (
        wrap(primele)(counts, top)
        .then(dict)
        .then(lambda clasament: Raport(
            esecuri=esecuri,
            pe_ip=clasament,
            suspecti=selecteaza(clasament),
        ))
        .unwrap()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Detectează tentativele SSH de tip brute force.")
    parser.add_argument("log", help="Fișierul auth.log.")
    parser.add_argument("--prag", type=int, default=10, help="Pragul de eșecuri, implicit 10.")
    parser.add_argument("--json", action="store_true", help="Afișează raportul JSON.")
    parser.add_argument("--fereastra", type=int, help="Intervalul mobil în secunde, cu maxim pe IP.")
    parser.add_argument("--top", type=int, help="Afișează primele N adrese după numărul de eșecuri.")
    args = parser.parse_args()

    raport = wrap(analizeaza)(args.log, args.prag, fereastra=args.fereastra, top=args.top).match(
        lambda valoare: valoare,
        lambda eroare: print(f"Eroare: {eroare}"),
    )
    if raport is None:
        return 1
    if args.json:
        afisare = wrap(json.dumps)(raport, indent=2, ensure_ascii=False).then(print)
        afisare.match(lambda _: None, lambda eroare: print(f"Eroare: {eroare}"))
        return 0 if afisare.is_ok else 1

    print("Esecuri de autentificare:", len(raport["esecuri"]))
    if args.fereastra is not None:
        print(f"Maxim pe interval mobil de {args.fereastra} secunde:")
    for ip, n in raport["pe_ip"].items():
        print(f"  {ip}: {n}")
    print(f"Suspecti (prag {args.prag}):")
    for ip, n in raport["suspecti"]:
        print(f"  {ip} ({n} incercari)  BRUTE FORCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
