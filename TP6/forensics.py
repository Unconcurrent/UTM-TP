import argparse
import re
import zipfile
from pathlib import Path

from PIL import Image
from PIL.ExifTags import TAGS


ROOT = Path(__file__).resolve().parent


def tip_real(cale):
    with Path(cale).open("rb") as fisier:
        cap = fisier.read(8)
    for semnatura, tip in ((b"%PDF", "pdf"), (b"\x89PNG", "png"),
                           (b"\xff\xd8", "jpeg"), (b"PK\x03\x04", "zip/docx")):
        if cap.startswith(semnatura):
            return tip
    return cap.hex()


def extrage_strings(cale):
    return [text.decode("ascii") for text in re.findall(rb"[ -~]{4,}", Path(cale).read_bytes())]


def citeste_exif(cale):
    with Image.open(cale) as imagine:
        exif = imagine.getexif()
        metadate = {TAGS.get(tag, tag): valoare for tag, valoare in exif.items() if tag != 34853}
        gps = exif.get_ifd(34853) if 34853 in exif else {}
    return metadate, gps


def gps_zecimal(gps):
    def grade(valori, emisfera):
        g, m, s = (float(valoare) for valoare in valori)
        rezultat = g + m / 60 + s / 3600
        return -rezultat if emisfera in ("S", "W") else rezultat

    return grade(gps[2], gps[1]), grade(gps[4], gps[3])


def extrage_zip(cale, destinatie):
    date = Path(cale).read_bytes()
    pozitie = date.find(b"PK\x03\x04")
    if pozitie == -1:
        raise ValueError("Nu s-a găsit semnătura ZIP.")
    Path(destinatie).write_bytes(date[pozitie:])
    return pozitie


def main():
    parser = argparse.ArgumentParser(description="Semnături, strings, EXIF/GPS și file carving.")
    parser.add_argument("--probe", type=Path, default=ROOT / "probe")
    parser.add_argument("--iesire", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        foto = args.probe / "foto.jpg"
        ascuns = args.probe / "ascuns.png"
        print("B1, foto.jpg:", tip_real(foto))
        print("B1, ascuns.png:", tip_real(ascuns))
        print("B2, șiruri imprimabile din ascuns.png:")
        for text in extrage_strings(ascuns):
            print(text)
        metadate, gps = citeste_exif(foto)
        print("B3, metadate EXIF:")
        for nume, valoare in metadate.items():
            print(nume, "=", valoare)
        if gps:
            latitudine, longitudine = gps_zecimal(gps)
            print(f"Latitudine: {latitudine:.8f}")
            print(f"Longitudine: {longitudine:.8f}")
        else:
            print("Nu există coordonate GPS.")
        args.iesire.mkdir(parents=True, exist_ok=True)
        arhiva = args.iesire / "gasit.zip"
        pozitie = extrage_zip(ascuns, arhiva)
        print("B4, arhiva extrasă de la octetul", pozitie)
        with zipfile.ZipFile(arhiva) as zip_extras:
            zip_extras.extractall(args.iesire / "extras")
            for nume in zip_extras.namelist():
                print("Fișier extras:", nume)
                print(zip_extras.read(nume).decode("utf-8").rstrip())
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f"Eroare: {error}\n")


if __name__ == "__main__":
    main()
