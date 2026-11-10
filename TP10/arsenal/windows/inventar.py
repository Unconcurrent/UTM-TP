from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Self

CAI_SUSPECTE = ("\\Temp\\", "\\Roaming\\")
SUSPECTE_ID = {4625, 1102, 7045}


@dataclass
class Proces:
    pid: int
    nume: str
    user: str
    cale: str

    def e_suspect(self) -> bool:
        return any(cale in self.cale for cale in CAI_SUSPECTE)


@dataclass
class Eveniment:
    id: int
    nivel: str
    sursa: str
    cont: str
    mesaj: str

    def e_suspect(self) -> bool:
        return self.id in SUSPECTE_ID or self.nivel == "critical"

    def explica(self) -> str:
        match self.id:
            case 4625:
                return "Autentificare eșuată; încercările repetate pot indica brute force."
            case 1102:
                return "Jurnalul de audit a fost șters."
            case 7045:
                return "A fost instalat un serviciu nou."
            case _:
                return "Eveniment critic." if self.nivel == "critical" else "Alt eveniment."


def procese_din_json(cale: str | Path) -> list[Proces]:
    with open(cale, encoding="utf-8") as f:
        date = json.load(f)
    if not isinstance(date, list):
        raise ValueError("Fișierul de procese trebuie să conțină o listă JSON.")
    return [Proces(**d) for d in date]


def evenimente_din_json(cale: str | Path) -> list[Eveniment]:
    with open(cale, encoding="utf-8") as f:
        date = json.load(f)
    if not isinstance(date, list):
        raise ValueError("Fișierul de evenimente trebuie să conțină o listă JSON.")
    return [Eveniment(**d) for d in date]


@dataclass
class Inventar:
    procese: list[Proces]
    evenimente: list[Eveniment] = field(default_factory=list)

    @classmethod
    def din_json(cls, cale: str | Path) -> Self:
        return cls(procese_din_json(cale))

    def __len__(self) -> int:
        return len(self.procese)

    def suspecte(self) -> list[Proces]:
        return [p for p in self.procese if p.e_suspect()]

    def pe_user(self) -> dict[str, list[str]]:
        grupuri: dict[str, list[str]] = {}
        for p in self.procese:
            grupuri.setdefault(p.user, []).append(p.nume)
        return grupuri

    def scor(self) -> int:
        return sum(p.e_suspect() for p in self.procese) + sum(
            e.e_suspect() for e in self.evenimente
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventar de procese Windows și alarme din jurnalul de evenimente."
    )
    parser.add_argument("capturi", type=Path, help="Directorul cu cele două capturi JSON.")
    parser.add_argument("--json", action="store_true", help="Afișează alarmele în format JSON.")
    args = parser.parse_args()
    try:
        inv = Inventar.din_json(args.capturi / "procese.json")
        inv.evenimente = evenimente_din_json(args.capturi / "evenimente.json")
        suspecte = inv.suspecte()
        alarma = [e for e in inv.evenimente if e.e_suspect()]
    except (OSError, ValueError, TypeError) as eroare:
        print(f"Eroare: {eroare}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(
            {"procese": [asdict(p) for p in suspecte],
             "evenimente": [asdict(e) for e in alarma]},
            indent=2, ensure_ascii=False,
        ))
    else:
        print(f"Procese: {len(inv)} | suspecte: {len(suspecte)}")
        for p in suspecte:
            print(f"  [{p.pid}] {p.nume} ({p.user}) {p.cale}")
        print(f"Evenimente: {len(inv.evenimente)} | alarma: {len(alarma)}")
        for e in alarma:
            print(f"  {e.id} [{e.nivel}] {e.cont}: {e.mesaj}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
