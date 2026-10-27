# TP6 — Informații invizibile: forensics și steganografie

Lucrarea folosește exclusiv probele generate local de scriptul primit la laborator.

## Pregătire

Rulează comenzile din acest director:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python probe/pregateste.py
```

## Lucrarea A

```bash
python arsenal/forensics/decode.py U2FsdXQ= --fisa rezultate/fisa_base64.json
python arsenal/forensics/decode.py 48656c6c6f --fisa rezultate/fisa_hex.json
python arsenal/forensics/decode.py '%2Fetc' --fisa rezultate/fisa_url.json
python arsenal/forensics/decode.py probe/xor.bin --fisier --fisa rezultate/fisa_xor.json
python arsenal/forensics/decode.py probe/hashuri.txt --fisier --hashuri --fisa rezultate/fisa_hashuri.json
python arsenal/forensics/decode.py probe/challenge.bin --fisier --verifica probe/challenge_hint.txt --fisa rezultate/fisa_challenge.json
python arsenal/forensics/decode.py probe/mesaj.txt --fisier
```

Ultima comandă produce fișa cerută, `arsenal/forensics/fisa.json`. Opțiunea `--fisa` păstrează separat rezultatele celorlalte demonstrații. Recunoașterea după alfabet este euristică; decoderul este verificat pe probele acestei lucrări.

## Lucrarea B

```bash
python forensics.py
python stego.py ascunde probe/foto.jpg 'FLAG{ascuns_in_pixeli}' stego.png
python stego.py dezvaluie stego.png
```

`forensics.py` produce `gasit.zip` și `extras/secret.txt`. `stego.py` folosește câte un bit din canalele RGB, în ordine, și un octet zero pentru sfârșitul mesajului. Mesajul și terminatorul trebuie să încapă; ieșirea trebuie să fie PNG.

## Teste și rezultate

```bash
python -m pytest -v
```

`rezultate/output.txt` conține comenzile și output-ul execuției documentate. Fișele JSON și rezultatele individuale sunt în `rezultate/`. Raportul este `raport.md`, cu versiunea PDF `TP6_Radu_Sologub_SI-264.pdf`. Fișa oficială este păstrată în `sarcina.docx`.

Nu include mediul virtual sau cache-urile Python în predare. Pentru a reface rezultatele, rulează comenzile de mai sus; regenerarea probelor poate modifica marcajele temporale interne ale arhivei ZIP.
