from __future__ import annotations

import os
import sys

if __name__ == "__main__" and not __package__:
    sys.path[0] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    __package__ = "arsenal.aparare"

import argparse
import re
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

from .result import ok, wrap


class Esec(TypedDict):
    user: str
    ip: str


class Eveniment(Esec):
    moment: datetime | None


TIPAR = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")


def esec(linie: str) -> tuple[str, str] | None:
    match TIPAR.search(linie):
        case None:
            return None
        case rezultat:
            return rezultat.group(1), rezultat.group(2)


def cale_jurnal(cale: str) -> Path:
    path = Path(cale)
    if not path.exists() and path.parent == Path("start"):
        return Path(__file__).parent / path
    return path


def citeste[T](cale: str, extrage: Callable[[str], T | None]) -> list[T]:
    try:
        f = cale_jurnal(cale).open(encoding="utf-8")
    except FileNotFoundError:
        print("nu gasesc", cale)
        return []
    with f:
        return (
            ok(map(extrage, f))
            .then(lambda rezultate: [r for r in rezultate if r is not None])
            .unwrap()
        )


def citeste_esecuri(cale: str) -> list[Esec]:
    return (
        wrap(citeste)(cale, esec)
        .then_each(lambda pereche: Esec(user=pereche[0], ip=pereche[1]))
        .unwrap()
    )


def pe_ip(esecuri: Iterable[Esec]) -> Counter[str]:
    return Counter(e["ip"] for e in esecuri)


def primele(counts: Counter[str], top: int | None = None) -> list[tuple[str, int]]:
    if top is not None and top < 1:
        raise ValueError(f"top invalid: {top} (cel putin 1)")
    return [(ip, n) for ip, n in counts.most_common(top)]


def moment(linie: str) -> datetime | None:
    try:
        if linie[:4].isdigit():
            data = datetime.fromisoformat(linie.split(maxsplit=1)[0])
            return data.replace(tzinfo=UTC) if data.tzinfo is None else data.astimezone(UTC)
        # An de referință bisect pentru formatul syslog fără an.
        return datetime.strptime("2000 " + linie[:15], "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    except (ValueError, IndexError):
        return None


def eveniment(linie: str) -> Eveniment | None:
    match esec(linie):
        case None:
            return None
        case user, ip:
            return Eveniment(user=user, ip=ip, moment=moment(linie))


def main() -> int:
    parser = argparse.ArgumentParser(description="Extrage și numără eșecurile de autentificare.")
    parser.add_argument("log", help="Fișierul auth.log.")
    parser.add_argument("--top", type=int, help="Afișează primele N adrese.")
    args = parser.parse_args()

    date = wrap(citeste_esecuri)(args.log).match(
        lambda valoare: valoare,
        lambda eroare: print(f"Eroare: {eroare}"),
    )
    if date is None or (not date and not cale_jurnal(args.log).exists()):
        return 1
    clasament = wrap(primele)(pe_ip(date), args.top).match(
        lambda valoare: valoare,
        lambda eroare: print(f"Eroare: {eroare}"),
    )
    if clasament is None:
        return 1

    print("Esecuri de autentificare:", len(date))
    for ip, n in clasament:
        print(f"  {ip}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
