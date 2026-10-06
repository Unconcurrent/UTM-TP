"""TP5: rulați python main.py https://cybercor.org"""

# Student: Radu Sologub, SI-264
# Un singur fișier Python, cu exercițiile marcate în ordinea din enunț.

import argparse
import csv
import hashlib
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

import requests


BASE_URL = "https://cybercor.org"
ECHO_URL = "https://httpbin.org"
TIMEOUT = 10
DEFAULT_HEADERS = {"User-Agent": "WebLab-Radu-Sologub"}
OUTPUT_DIR = Path(__file__).resolve().parent
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)


def main():
    """Rulează exercițiile în ordinea cerută și creează rapoartele finale."""
    parser = argparse.ArgumentParser(description="TP5: funcții, metode și importuri pe web")
    parser.add_argument("url", nargs="?", default=BASE_URL)
    args = parser.parse_args()
    if args.url.rstrip("/") != BASE_URL:
        parser.error(f"Folosiți site-ul indicat în laborator: {BASE_URL}")
    base = args.url

    print("PARTEA 1: IMPORTURI")

    # Exercițiul 1. requests se instalează cu pip; urllib.request este în biblioteca standard.
    import requests as requests_module
    import urllib.request as urllib_request
    print("1", requests_module.__version__, urllib_request.__name__)

    # Exercițiul 2. Modulul arată originea lui get; importul funcției scurtează apelul.
    from requests import get
    time.sleep(1)
    first = requests.get(base, timeout=TIMEOUT)
    time.sleep(1)
    second = get(base, timeout=TIMEOUT)
    print("2", first.status_code, second.status_code)

    # Exercițiul 3. Un alias util scurtează un nume lung; unul obscur îngreunează citirea.
    import requests as rq
    time.sleep(1)
    print("3", rq.get(base, timeout=TIMEOUT).status_code)

    # Exercițiul 4. Site-ul refuză User-Agent-ul implicit urllib, deci îl setăm explicit.
    request = urllib.request.Request(base, headers={"User-Agent": "Mozilla/5.0"})
    time.sleep(1)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        print("4", response.status, response.read(200).decode("utf-8"))

    # Exercițiul 5. get este funcție, Session este clasă, exceptions este modul.
    print("5", dir(requests))

    # Exercițiul 6. help arată parametrul timeout; îl folosim în cerere.
    help(requests.get)
    time.sleep(1)
    print("6", requests.get(base, timeout=TIMEOUT).status_code)

    # Exercițiul 7. perf_counter măsoară cererea; elapsed este durata raportată de Response.
    time.sleep(1)
    start = time.perf_counter()
    response = requests.get(base, timeout=TIMEOUT)
    print("7", time.perf_counter() - start, response.elapsed.total_seconds())

    # Exercițiul 8. ImportError permite un mesaj de instalare în locul opririi programului.
    try:
        import bs4
        print("8", bs4.__name__)
    except ImportError:
        print("8 Instalați modulul cu: pip install beautifulsoup4")
    # Modul = fișier importabil; pachet = colecție de module; bibliotecă = cod reutilizabil.

    print("PARTEA 2: METODE ȘI ATRIBUTE")
    time.sleep(1)
    response = requests.get(base, timeout=TIMEOUT)

    # Exercițiul 9. Toate cele patru valori de mai jos sunt atribute.
    print("9", response.status_code, response.ok, response.url, response.encoding)

    # Exercițiul 10. raise_for_status() este metodă; site-ul poate răspunde 200 și pentru o cale absentă.
    response.raise_for_status()
    time.sleep(1)
    missing = requests.get(base + "/this-page-does-not-exist", timeout=TIMEOUT)
    try:
        missing.raise_for_status()
        print("10 Calea absentă a răspuns cu", missing.status_code)
    except requests.HTTPError as error:
        print("10 Pagina nu este disponibilă:", error)

    # Exercițiul 11. items() parcurge perechile de nume și valoare ale antetelor.
    for name, value in response.headers.items():
        print("11", f"{name}: {value}")

    # Exercițiul 12. get() acceptă o valoare implicită; antetele HTTP ignoră majusculele.
    print("12", response.headers.get("Server", "lipsește"),
          response.headers.get("Content-Type", "lipsește"),
          response.headers.get("content-type", "lipsește"))

    # Exercițiul 13. lower() returnează un șir pe care putem apela count().
    print("13", response.text.lower().count("cyber"))

    # Exercițiul 14. find(), slicing și strip() extrag titlul HTML.
    html = response.text
    lower_html = html.lower()
    title_start = lower_html.find("<title>")
    title_end = lower_html.find("</title>", title_start + 7)
    title = html[title_start + 7:title_end].strip() if title_start >= 0 and title_end >= 0 else ""
    print("14", title)

    # Exercițiul 15. splitlines() și max(key=len) analizează liniile HTML.
    lines = html.splitlines()
    print("15", len(lines), len(max(lines, key=len, default="")))

    # Exercițiul 16. startswith() verifică schema URL-ului final.
    print("16", "Conexiune securizată" if response.url.startswith("https://") else
          "Conexiune nesecurizată")

    # Exercițiul 17. history conține redirecționările de la HTTP la URL-ul final.
    time.sleep(1)
    redirected = requests.get("http://cybercor.org", timeout=TIMEOUT)
    print("17", [(item.status_code, item.url) for item in redirected.history], redirected.url)

    # Exercițiul 18. HEAD primește doar antete; GET primește și corpul.
    time.sleep(1)
    head = requests.head(base, timeout=TIMEOUT)
    time.sleep(1)
    body = requests.get(base, timeout=TIMEOUT)
    print("18", len(head.content), len(body.content))

    # Exercițiul 19. Cookie-urile pot lipsi.
    cookies = [(cookie.name, cookie.secure) for cookie in response.cookies]
    print("19", cookies if cookies else "Niciun cookie setat")

    # Exercițiul 20. Session păstrează User-Agent-ul trimis serviciului de test httpbin.
    with requests.Session() as session:
        session.headers.update(DEFAULT_HEADERS)
        time.sleep(1)
        echo = session.get(ECHO_URL + "/headers", timeout=TIMEOUT)
        print("20", echo.json().get("headers", {}).get("User-Agent", "lipsește"))
    # response.text este atribut; response.json() este metodă.

    print("PARTEA 3: FUNCȚII")

    # Exercițiul 21. fetch returnează obiectul Response.
    def fetch(url, timeout=TIMEOUT, headers=None):
        """Descarcă URL-ul și returnează răspunsul."""
        time.sleep(1)
        return requests.get(url, timeout=timeout, headers=headers)

    print("21", fetch(base).status_code)

    # Exercițiul 22. get_status returnează doar codul HTTP.
    def get_status(url: str) -> int:
        """Returnează codul de stare HTTP."""
        return fetch(url).status_code

    paths = ("/", "/robots.txt", "/sitemap.xml")
    print("22", [get_status(urllib.parse.urljoin(base, path)) for path in paths])

    # Exercițiul 23. fetch folosește timeout implicit sau valoarea transmisă explicit.
    print("23", fetch(base).status_code, fetch(base, timeout=3).status_code)

    # Exercițiul 24. get_title primește HTML și nu efectuează o cerere de rețea.
    def get_title(html):
        """Returnează titlul din HTML sau șirul gol când lipsește."""
        lower = html.lower()
        start = lower.find("<title>")
        end = lower.find("</title>", start + 7)
        return html[start + 7:end].strip() if start >= 0 and end >= 0 else ""

    print("24", get_title(response.text))

    # Exercițiul 25. Docstring-ul funcției este vizibil prin help().
    help(get_title)

    # Exercițiul 26. get_status are adnotări de tip; ele nu împiedică apelul cu 123.
    try:
        print("26", get_status(123))
    except (requests.RequestException, TypeError, ValueError) as error:
        print("26", type(error).__name__, ": adnotarea nu a oprit apelul")

    # Exercițiul 27. RequestException devine False, inclusiv pentru domeniul invalid.
    def page_exists(url):
        """Returnează True pentru o pagină disponibilă, altfel False."""
        try:
            fetch(url).raise_for_status()
            return True
        except requests.RequestException:
            return False

    print("27", page_exists("https://this-domain-does-not-exist.invalid"))

    # Exercițiul 28. check_paths returnează un dicționar cale: cod HTTP.
    def check_paths(base_url, requested_paths):
        """Verifică în ordine căile date pe site."""
        result = {}
        for path in requested_paths:
            result[path] = get_status(urllib.parse.urljoin(base_url, path))
        return result

    print("28", check_paths(base, paths))

    # Exercițiul 29. name este trimis ca argument cu nume.
    def get_header(url, name, default="lipsește"):
        """Returnează valoarea unui antet sau valoarea implicită."""
        return fetch(url).headers.get(name, default)

    print("29", get_header(base, name="Server"))

    # Exercițiul 30. Verificăm cele cinci antete de securitate din enunț.
    def security_headers(url):
        """Returnează prezența fiecărui antet cerut."""
        headers = fetch(url).headers
        return {name: name in headers for name in SECURITY_HEADERS}

    checks = security_headers(base)
    print("30", checks)

    # Exercițiul 31. score_headers primește dicționarul funcției precedente.
    def score_headers(results):
        """Returnează scorul antetelor sub forma prezent/total."""
        return f"{sum(results.values())}/{len(results)}"

    print("31", score_headers(checks), score_headers(security_headers(base)))

    # Exercițiul 32. Separăm descărcarea robots.txt de analiza liniilor Disallow.
    def fetch_robots(base_url):
        """Returnează textul robots.txt sau None când lipsește."""
        try:
            result = fetch(urllib.parse.urljoin(base_url, "/robots.txt"))
            return result.text if result.ok else None
        except requests.RequestException:
            return None

    def disallowed_paths(robots_text):
        """Returnează toate valorile Disallow, inclusiv pentru un text opțional."""
        if robots_text is None:
            return []
        return [line.partition(":")[2].strip() for line in robots_text.splitlines()
                if line.strip().lower().startswith("disallow:")]

    print("32", disallowed_paths(fetch_robots(base)), disallowed_paths(None))

    # Exercițiul 33. *urls acceptă două sau mai multe URL-uri.
    def response_times(*urls):
        """Măsoară durata fiecărei cereri, fără timpul pauzei."""
        result = {}
        for url in urls:
            time.sleep(1)
            started = time.perf_counter()
            requests.get(url, timeout=TIMEOUT)
            result[url] = time.perf_counter() - started
        return result

    print("33", response_times(base, urllib.parse.urljoin(base, "/robots.txt")))

    # Exercițiul 34. **details primește detalii cu nume.
    def log(message, **details):
        """Afișează mesajul urmat de fiecare detaliu."""
        pieces = [message]
        for name, value in details.items():
            pieces.append(f"{name}={value}")
        print(" | ".join(pieces))

    log("34 verificat", url=base, status=response.status_code)
    # print afișează o valoare; return o dă apelantului pentru prelucrare.

    print("PARTEA 4: MODULE STANDARD")

    # Exercițiul 35. urlparse descompune schema, domeniul, calea, query și fragmentul.
    parsed = urllib.parse.urlparse("https://cybercor.org/path?x=1#top")
    print("35", parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)

    # Exercițiul 36. urljoin construiește URL-uri absolute din căi relative.
    print("36", [urllib.parse.urljoin(base, link) for link in
                 ("/about", "contact.html", "../index.html")])

    # Exercițiul 37. re.findall extrage href, apoi eliminăm duplicatele.
    def extract_links(html):
        """Returnează linkurile fără duplicate, în ordinea găsirii."""
        return list(dict.fromkeys(re.findall(r'href="([^"]+)"', html)))

    links = extract_links(response.text)
    print("37", links)

    # Exercițiul 38. urljoin și urlparse separă linkurile interne de cele externe.
    def split_links(links, domain):
        """Împarte linkurile în liste interne și externe."""
        internal, external = [], []
        for link in links:
            absolute = urllib.parse.urljoin(f"https://{domain}/", link)
            host = urllib.parse.urlparse(absolute).netloc
            if host == domain:
                internal.append(absolute)
            else:
                external.append(absolute)
        return internal, external

    domain = urllib.parse.urlparse(response.url).netloc
    internal, external = split_links(links, domain)
    print("38", len(internal), len(external))

    # Exercițiul 39. HTMLParser apelează handle_starttag la feed().
    class ImageFinder(HTMLParser):
        """Colectează atributele src ale tagurilor img."""

        def __init__(self):
            super().__init__()
            self.images = []

        def handle_starttag(self, tag, attrs):
            """Este apelată automat pentru fiecare tag de început."""
            src = dict(attrs).get("src") if tag == "img" else None
            if src is not None:
                self.images.append(src)

    test_html = '''<html><body><img src="/logo.png" alt="Logo"><IMG SRC="poza.jpg">
    <img alt="imagine fără src"><img src="https://cdn.example.com/banner.webp" />
    <a href="/despre">Aceasta nu este o imagine</a></body></html>'''
    finder = ImageFinder()
    finder.feed(test_html)
    assert finder.images == ["/logo.png", "poza.jpg", "https://cdn.example.com/banner.webp"]
    print("39 Testul a trecut!")
    finder = ImageFinder()
    finder.feed(response.text)
    print("39", finder.images, "taguri <img:", response.text.lower().count("<img"))
    # Ctrl+U permite compararea cu sursa; o listă goală poate fi corectă.

    # Exercițiul 40. Conținutul dinamic poate schimba amprenta paginii.
    def page_fingerprint(url):
        """Returnează amprenta SHA-256 a corpului HTTP."""
        return hashlib.sha256(fetch(url).content).hexdigest()

    print("40 Amprente egale:", page_fingerprint(base) == page_fingerprint(base))

    # Exercițiul 41. Salvăm antetele în JSON și citim fișierul înapoi.
    with (OUTPUT_DIR / "headers.json").open("w", encoding="utf-8") as output:
        json.dump(dict(response.headers), output, ensure_ascii=False, indent=2)
    with (OUTPUT_DIR / "headers.json").open(encoding="utf-8") as source:
        saved_headers = json.load(source)
    print("41", saved_headers.get("Content-Type", "lipsește"))

    # Exercițiul 42. gethostbyname întoarce adresa IPv4.
    def resolve(hostname):
        """Rezolvă un nume DNS în IPv4."""
        return socket.gethostbyname(hostname)

    print("42", resolve("cybercor.org"))

    # Exercițiul 43. Citim notAfter din certificatul TLS.
    def cert_days_left(hostname):
        """Returnează zilele întregi rămase până la expirare."""
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure:
                certificate = secure.getpeercert()
        expiry = ssl.cert_time_to_seconds(certificate["notAfter"])
        return int((expiry - time.time()) // 86400)

    try:
        print("43", cert_days_left("cybercor.org"), "zile")
    except (OSError, ssl.SSLError, KeyError, ValueError) as error:
        print("43 indisponibil:", error)
    # feed() apelează handle_starttag(); nu o apelăm direct.

    print("PARTEA 5: FUNCȚIILE REFOLOSITE ÎN ACELAȘI FIȘIER")

    # Exercițiul 44. Funcțiile fetch, get_status, get_title și security_headers sunt deja
    # definite mai sus. Cerința orală de un singur fișier înlocuiește webtools.py separat.
    print("44", get_title(fetch(base).text))

    # Exercițiul 45. Un import selectiv ar fi: from webtools import get_title, security_headers.
    # În acest fișier le apelăm direct; o funcție locală get_title ar masca numele importat.
    print("45", get_title(response.text), len(security_headers(base)))

    # Exercițiul 46. Blocul if __name__ == "__main__" se află la finalul fișierului.
    # El execută laboratorul doar când rulăm main.py, nu când importăm acest fișier.
    print("46", __name__)

    # Exercițiul 47. DEFAULT_HEADERS este o constantă de modul folosită de fetch.
    echo = fetch(ECHO_URL + "/headers", headers=DEFAULT_HEADERS)
    print("47", DEFAULT_HEADERS, echo.json()["headers"].get("User-Agent"))

    # Exercițiul 48. argparse a citit argumentul URL la începutul main().
    print("48", base)

    # Exercițiul 49. Scriem path, status și checked_at în report.csv.
    with (OUTPUT_DIR / "report.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=("path", "status", "checked_at"),
                                lineterminator="\n")
        writer.writeheader()
        for path, status in check_paths(base, paths).items():
            writer.writerow({"path": path, "status": status,
                             "checked_at": datetime.now().isoformat()})
    print("49 report.csv")

    # Exercițiul 50. Compunem datele site-ului și le salvăm în report.json.
    def site_report(url):
        """Afișează și salvează informațiile cerute despre site."""
        page = fetch(url)
        page.raise_for_status()
        site_domain = urllib.parse.urlparse(page.url).hostname
        page_links = extract_links(page.text)
        inside, outside = split_links(page_links, site_domain)
        checks = security_headers(url)
        try:
            ip = resolve(site_domain)
        except OSError as error:
            ip = f"indisponibil: {error}"
        try:
            days = cert_days_left(site_domain)
        except (OSError, ssl.SSLError, KeyError, ValueError) as error:
            days = f"indisponibil: {error}"
        time.sleep(1)
        redirect = requests.get(f"http://{site_domain}", timeout=TIMEOUT)
        history = [{"status": item.status_code, "url": item.url} for item in redirect.history]
        report = {
            "url": url,
            "status": page.status_code,
            "final_url": redirect.url,
            "title": get_title(page.text),
            "ip": ip,
            "redirects": history,
            "security_headers": checks,
            "security_score": score_headers(checks),
            "certificate_days_left": days,
            "internal_links": len(inside),
            "external_links": len(outside),
            "disallowed_paths": disallowed_paths(fetch_robots(url)),
        }
        print(f"=== Raport site: {url} ===")
        print("Cod de stare:", report["status"])
        print("URL final:", report["final_url"])
        print("Titlu:", report["title"])
        print("Adresă IP:", report["ip"])
        print("Redirecționări:", report["redirects"])
        print("Scor securitate:", report["security_score"])
        print("Certificat:", report["certificate_days_left"])
        print("Legături interne:", report["internal_links"])
        print("Legături externe:", report["external_links"])
        print("Căi interzise:", report["disallowed_paths"])
        with (OUTPUT_DIR / "report.json").open("w", encoding="utf-8") as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write("\n")
        print("Salvat în report.json")
        return report

    site_report(base)


if __name__ == "__main__":
    main()
