import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]


def ghici_strat(s):
    if re.search(r"%[0-9a-fA-F]{2}", s):
        return "url"
    if s and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return "hex"
    if s and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return "base64"
    return "necunoscut"


def desfa(s):
    strat = ghici_strat(s)
    if strat == "url":
        return strat, unquote(s).encode()
    if strat == "hex":
        return strat, bytes.fromhex(s)
    if strat == "base64":
        return strat, base64.b64decode(s, validate=True)
    return strat, s.encode()


def citibil(b):
    return all(32 <= c < 127 for c in b)


def sparge_xor(date):
    if not date:
        raise ValueError("Fișierul XOR este gol.")
    for cheie in range(256):
        clar = bytes(octet ^ cheie for octet in date)
        if citibil(clar):
            return cheie, clar
    raise ValueError("Nu s-a găsit un rezultat XOR imprimabil.")


def identifica_hash(tinta):
    algoritmi = {32: "md5", 40: "sha1", 64: "sha256"}
    if not re.fullmatch(r"[0-9a-fA-F]+", tinta) or len(tinta) not in algoritmi:
        raise ValueError("Hash-ul trebuie să fie MD5, SHA-1 sau SHA-256 în hex.")
    return algoritmi[len(tinta)]


def sparge_hash(tinta, wordlist):
    algoritm = identifica_hash(tinta)
    with Path(wordlist).open(encoding="latin1") as cuvinte:
        for linie in cuvinte:
            cuvant = linie.strip()
            if hashlib.new(algoritm, cuvant.encode()).hexdigest() == tinta.lower():
                return {"algoritm": algoritm, "parola": cuvant}
    return None


def decodifica(date, wordlist=None, limita=8):
    straturi = []
    cheie = None
    for _ in range(limita + 1):
        try:
            text = date.decode("ascii").strip()
        except UnicodeDecodeError:
            break
        if wordlist is not None and len(text) in (32, 40, 64) and re.fullmatch(r"[0-9a-fA-F]+", text):
            gasit = sparge_hash(text, wordlist)
            if gasit is not None:
                if len(straturi) == limita:
                    raise ValueError("S-a atins limita de straturi; rezultatul poate fi încă codat.")
                return {"strat": gasit["algoritm"], "rezultat": gasit["parola"],
                        "straturi": straturi + [gasit["algoritm"]]}
        try:
            strat, rezultat = desfa(text)
        except (ValueError, binascii.Error):
            break
        if strat == "necunoscut" or rezultat == date:
            break
        if strat == "base64" and citibil(date) and not citibil(rezultat):
            try:
                rezultat.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    sparge_xor(rezultat)
                except ValueError:
                    break
        if len(straturi) == limita:
            raise ValueError("S-a atins limita de straturi; rezultatul poate fi încă codat.")
        date = rezultat
        straturi.append(strat)

    try:
        rezultat = date.decode("utf-8")
    except UnicodeDecodeError:
        cheie, date = sparge_xor(date)
        rezultat = date.decode("ascii")
        straturi.append("xor")

    fisa = {"strat": straturi[-1] if straturi else "necunoscut",
            "rezultat": rezultat, "straturi": straturi}
    if cheie is not None:
        fisa["cheie"] = cheie
    return fisa


def main():
    parser = argparse.ArgumentParser(description="Decoder pentru straturi, XOR și parole din dicționar.")
    parser.add_argument("intrare", help="Șirul de decodat sau calea fișierului.")
    parser.add_argument("--fisier", action="store_true")
    parser.add_argument("--hashuri", action="store_true", help="Citește câte un hash pe linie.")
    parser.add_argument("--wordlist", type=Path, default=ROOT / "probe/wordlist.txt")
    parser.add_argument("--fisa", type=Path, default=Path(__file__).with_name("fisa.json"))
    parser.add_argument("--verifica", type=Path, help="Fișierul-indiciu al provocării opționale.")
    args = parser.parse_args()
    if args.hashuri and not args.fisier:
        parser.error("--hashuri necesită --fisier.")
    if args.hashuri and args.verifica:
        parser.error("--verifica se folosește pentru un singur mesaj.")

    try:
        date = Path(args.intrare).read_bytes() if args.fisier else args.intrare.encode()
        if not date:
            raise ValueError("Intrarea este goală.")
        if args.hashuri:
            fisa = []
            for tinta in date.decode("ascii").splitlines():
                tinta = tinta.strip()
                if not tinta:
                    continue
                gasit = sparge_hash(tinta, args.wordlist)
                fisa.append({"strat": identifica_hash(tinta),
                             "rezultat": gasit["parola"] if gasit else None})
        else:
            fisa = decodifica(date, args.wordlist)
            if args.verifica:
                asteptat = args.verifica.read_text().strip().rsplit("=", 1)[-1].strip()
                verificat = hashlib.md5(fisa["rezultat"].encode()).hexdigest() == asteptat
                if not verificat:
                    raise ValueError("Mesajul nu corespunde indiciului de verificare.")
                fisa["verificare_md5"] = True
        args.fisa.parent.mkdir(parents=True, exist_ok=True)
        args.fisa.write_text(json.dumps(fisa, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(fisa, ensure_ascii=False, indent=2))
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"Eroare: {error}\n")


if __name__ == "__main__":
    main()
