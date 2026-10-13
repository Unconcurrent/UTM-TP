import requests

SITES = [
    # Pagini obișnuite (Părțile 2, 3 și 4)
    "https://example.com",
    "https://httpbin.org/html",
    "https://httpbin.org/json",
    "https://httpbin.org/status/200",
    "https://httpbin.org/redirect/1",
    "https://httpbin.org/delay/2",
    # Pagini care eșuează
    "https://httpbin.org/status/404",
    "https://httpbin.org/status/500",
    "https://httpbin.org/delay/10",
    "http://this-site-does-not-exist.invalid",
    # Anteturi de securitate (Partea 5)
    "https://httpbin.org/response-headers?X-Frame-Options=DENY&X-Content-Type-Options=nosniff",
    "https://httpbin.org/response-headers?x-frame-options=DENY",
    # Răspunde aleatoriu cu 200 sau 500 (Partea 6)
    "https://httpbin.org/status/200,500",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def build_url(host, path):
    """Returnează o adresă completă, de exemplu https://example.com/login."""
    host = "https://" + host
    if path.startswith("/"):
        return host + path
    else:
        return host + "/" + path


def is_https(url):
    """Returnează True dacă adresa începe cu https://, altfel False."""
    return url.startswith("https://")


def show_response(url):
    """Trimite un GET la url și afișează statusul și Content-Type."""
    try:
        r = requests.get(url, timeout=5)
        print("Status:", r.status_code)
        print("Content-Type:", r.headers.get("Content-Type", "unknown"))
    except requests.RequestException as e:
        print("Eroare:", e)
    


def check_site(url):
    """Returnează un dicționar cu: status, content_type, length, server."""
    try:
        r = requests.get(url, timeout=5)
        return {"status": r.status_code,
                "content_type": r.headers.get("Content-Type", "unknown"),
                "length": len(r.content),
                "server": r.headers.get("Server", "unknown")}

    except requests.RequestException as e:
        return {"status": None, "error": "Site-url e prea lent sau nu exista."}
        


def scan_sites():
    """Verifică toate site-urile din SITES, afișează-le pe cele care merg și un rezumat."""
    def append_field(x, a, b):
        x[a] = b
        return x
    
    checked_sites = [append_field(check_site(site), "url", site) for site in SITES]
    ok_sites = [site for site in checked_sites if site.get("status", -1) == 200]
    sorted_sited = sorted(ok_sites, key=lambda x: x.get("length", -1), reverse=True)
    for ss in sorted_sited:
        print(ss["url"], "->", ss.get("status", 200), ", ", ss.get("length", 0), "octeți")
    print("Reușite: ", len(ok_sites), " | Eșuate: ", len(checked_sites) - len(ok_sites))


def check_headers(url):
    """Returnează un dicționar cu: present, missing, score."""
    try:
        r = requests.get(url, timeout=5)
        present = [h for h in SECURITY_HEADERS if h in r.headers]
        missing = [h for h in SECURITY_HEADERS if h not in r.headers]
        return {
            "present": present,
            "missing": missing,
            "score": len(present) * 100 // len(SECURITY_HEADERS)
        }
    except requests.RequestException:
        return {"status": None, "error": "Cererea a eșuat."}


def retry_check(url, attempts=3):
    """Încearcă de cel mult `attempts` ori; returnează un dicționar cu: status, attempts."""

    def one_try():
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 500:
                return {"stop": True, "status": r.status_code}

            return {"stop": False, "status": r.status_code}
        except Exception as e:
            return {"stop": False, "status": None, "error": str(e)}
        

    last_status = None
    r = None
    for t in range(1, attempts + 1, 1):
        r = one_try()
        if r.get("status") is not None:
            last_status = r["status"]
        if r.get("stop", True):
            break

    if "error" in r and last_status is None:
        return {
            "status": last_status,
            "attempts": t,
            "error": r.get("error", "eroare de conexiune.")
        }
    else:
        return {
                "status": last_status,
                "attempts": t
            }
    
