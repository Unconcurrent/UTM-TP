import argparse
from pathlib import Path

from PIL import Image


def ascunde(gazda, mesaj, iesire):
    if Path(iesire).suffix.lower() != ".png":
        raise ValueError("Imaginea cu mesaj trebuie salvată în PNG.")
    if "\0" in mesaj:
        raise ValueError("Mesajul nu poate conține terminatorul zero.")
    with Image.open(gazda) as original:
        imagine = original.convert("RGB")
    date = mesaj.encode("utf-8") + b"\0"
    canale = bytearray(imagine.tobytes())
    if len(date) * 8 > len(canale):
        raise ValueError("Mesajul și terminatorul nu încap în imagine.")
    for i, octet in enumerate(date):
        for bit in range(8):
            pozitie = i * 8 + bit
            canale[pozitie] = (canale[pozitie] & ~1) | ((octet >> (7 - bit)) & 1)
    Image.frombytes("RGB", imagine.size, bytes(canale)).save(iesire)
    return len(date) * 8


def dezvaluie(cale):
    with Image.open(cale) as original:
        canale = original.convert("RGB").tobytes()
    mesaj = bytearray()
    for pozitie in range(0, len(canale) - 7, 8):
        octet = 0
        for canal in canale[pozitie:pozitie + 8]:
            octet = (octet << 1) | (canal & 1)
        if octet == 0:
            return mesaj.decode("utf-8")
        mesaj.append(octet)
    raise ValueError("Nu s-a găsit terminatorul mesajului.")


def main():
    parser = argparse.ArgumentParser(description="Ascunde și dezvăluie un mesaj în biții LSB ai canalelor RGB.")
    comenzi = parser.add_subparsers(dest="comanda", required=True)
    ascundere = comenzi.add_parser("ascunde")
    ascundere.add_argument("gazda", type=Path)
    ascundere.add_argument("mesaj")
    ascundere.add_argument("iesire", type=Path)
    dezvaluire = comenzi.add_parser("dezvaluie")
    dezvaluire.add_argument("imagine", type=Path)
    args = parser.parse_args()
    try:
        if args.comanda == "ascunde":
            biti = ascunde(args.gazda, args.mesaj, args.iesire)
            print("Mesaj ascuns:", args.mesaj)
            print("Biți înscriși, inclusiv terminatorul:", biti)
            print("Imagine salvată:", args.iesire)
        else:
            print("Mesaj dezvăluit:", dezvaluie(args.imagine))
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(2, f"Eroare: {error}\n")


if __name__ == "__main__":
    main()
