from __future__ import annotations

import os
import sys

# Evită confundarea acestui fișier cu modulul standard enum.
if __name__ == "__main__" and not __package__:
    sys.path[0] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

import argparse
import json
from collections.abc import Callable, Iterable
from typing import Final, Literal, Never, cast

# Mergem la Moscova prin Londra.
# In loc sa il fac simplu procedural
# am ales sa folosesc cele mai avansate concepte
# din programare si informatica pe care le pot reprezenta
# in Python pentru a face assigment-ul cu suflet si nu banal.
# Monade, programarea functionala, Types in Python.
type _State[T] = tuple[Literal[True], T] | tuple[Literal[False], Exception]
class Result[T]:
    """Rezultat cu valoare sau eroare."""

    def __init__(self, state: _State[T]):
        self.state: Final[_State[T]] = state

    @property
    def is_ok(self) -> bool:
        return self.state[0]

    @property
    def value(self) -> T | Exception:
        return self.state[1]

    def unwrap(self) -> T:
        state = self.state
        if state[0] is False:
            raise state[1]
        return state[1]

    def then[U](self, callback: Callable[[T], U | Result[U]]) -> Result[U]:

        state = self.state
        if state[0] is False:
            return err(state[1])
        try:
            result = callback(state[1])
            if isinstance(result, Result):
                return cast(Result[U], result)
            return ok(cast(U, result))
        except Exception as ex:
            return err(ex)

    def then_each[V, U](
        self: Result[Iterable[V]], callback: Callable[[V], U | Result[U]]
    ) -> Result[list[U]]:

        return self.then(
            lambda values: Result.sequence(ok(value).then(callback) for value in values)
        )

    @staticmethod
    def sequence[U](results: Iterable[Result[U]]) -> Result[list[U]]:
        try:
            values: list[U] = []
            for result in results:
                state = result.state
                if state[0] is False:
                    return err(state[1])
                values.append(state[1])
            return ok(values)
        except Exception as e:
            return err(e)

    def catch[U](self, callback: Callable[[Exception], U | Result[U]]) -> Result[T | U]:

        state = self.state
        return self if state[0] is True else ok(state[1]).then(callback)

    def match[U, V](self, ok_func: Callable[[T], U], err_func: Callable[[Exception], V]) -> U | V:

        state = self.state
        return ok_func(state[1]) if state[0] is True else err_func(state[1])



def ok[T](r: T) -> Result[T]: return Result((True, r))
def err(e: Exception) -> Result[Never]: return Result((False, e))

def wrap[T, **P](func: Callable[P, T]) -> Callable[P, Result[T]]:
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
        try:
            return ok(func(*args, **kwargs))
        except Exception as error:
            return err(error)

    return wrapped

def citeste_linii(path: str) -> list[str]:
    # Caută start/... lângă script dacă nu există în directorul curent.
    relative_path = os.path.normpath(path)
    if not os.path.exists(path) and os.path.dirname(relative_path) == "start":
        path = os.path.join(os.path.dirname(__file__), relative_path)
    with open(path, "r", encoding="utf-8") as f:
        return (
            ok(f.readlines())
            .then_each(str.strip)
            .then(lambda stripped_lines:
                        [l for l in stripped_lines if len(l) > 0 and not l.startswith('#')])
            .unwrap()
        )

def nume(cale: str) -> str:
    return cale.rsplit("/", 1)[-1]

def suid_nume_unice(cale: str) -> set[str]:
    return (
        wrap(citeste_linii)(cale)
        .then(lambda cai: {nume(c) for c in cai})
        .unwrap()
    )

GTFO = {"find", "vim.basic", "vim", "nmap", "cp", "bash",
        "less", "awk", "python3", "perl"}

def suid_constatari(cale: str) -> list[dict[str, str]]:
    return (
        wrap(citeste_linii)(cale)
        .then(set)
        .then(sorted)
        .then_each(lambda c: wrap(nume)(c).then(lambda n: {
            "cale": c,
            "nume": n,
            "risc": "mare" if n in GTFO else "normal",
        }))
        .unwrap()
    )

def sudo_constatari(cale: str) -> list[dict[str, str]]:
    return (
        wrap(citeste_linii)(cale)
        .then_each(lambda linie: linie.split(" : ", 1))
        .then_each(lambda pereche: (
            pereche
            if len(pereche) == 2 and all(camp.strip() for camp in pereche)
            else err(ValueError("Linie sudo invalidă: se așteaptă utilizator : drept."))
        ))
        .then(lambda perechi: [
            {
                "user": user.strip(),
                "drept": drept.strip(),
                "risc": "mare" if "NOPASSWD" in drept else "normal",
            }
            for user, drept in perechi
        ])
        .unwrap()
    )

# Cron: cinci câmpuri de timp, apoi utilizatorul și comanda.
def cron_constatari(cale: str) -> list[dict[str, str]]:
    return (
        wrap(citeste_linii)(cale)
        .then_each(str.split)
        .then_each(lambda campuri: (
            {"user": campuri[5], "comanda": " ".join(campuri[6:])}
            if len(campuri) >= 7
            else err(ValueError("Linie cron incompletă: lipsesc câmpuri obligatorii."))
        ))
        .unwrap()
    )

def enumereaza(d: str) -> dict[str, list[dict[str, str]]]:
    return Result.sequence(
        wrap(parser)(os.path.join(d, fisier))
        .then(lambda lista: (categorie, lista))
        for categorie, fisier, parser in (
            ("suid", "suid.txt", suid_constatari),
            ("sudo", "sudo.txt", sudo_constatari),
            ("cron", "crontab.txt", cron_constatari),
        )
    ).then(dict).unwrap()

def main() -> int:
    parser = argparse.ArgumentParser(description="Enumeră capturile SUID, sudo și cron.")
    parser.add_argument("capturi", help="Directorul cu fișierele capturate.")
    parser.add_argument("--json", action="store_true", help="Afișează numai raportul JSON.")
    args = parser.parse_args()

    raport = wrap(enumereaza)(args.capturi).match(
        lambda valoare: valoare,
        lambda eroare: print(f"Eroare: {eroare}"),
    )
    if raport is None:
        return 1

    try:
        if args.json:
            print(json.dumps(raport, indent=2, ensure_ascii=False))
            return 0

        for categorie, lista in raport.items():
            mari = [c for c in lista if c.get("risc") == "mare"]
            print(f"{categorie}: {len(lista)} gasite, {len(mari)} cu risc mare")

        utilizatori = {c["user"] for c in raport["sudo"]} | {c["user"] for c in raport["cron"]}
        print("utilizatori implicati:", ", ".join(sorted(utilizatori)))

        with open("enum.json", "w", encoding="utf-8") as f:
            json.dump(raport, f, indent=2, ensure_ascii=False)
        print("Raport salvat in enum.json")
        return 0
    except Exception as eroare:
        print(f"Eroare: {eroare}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
