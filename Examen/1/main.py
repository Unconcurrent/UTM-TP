from time import sleep

from checker import (
    SITES,
    build_url,
    is_https,
    show_response,
    check_site,
    scan_sites,
    check_headers,
    retry_check,
)


host = SITES[0].removeprefix("https://")

print("Partea 1, build_url fără /:", build_url(host, "login"))
print("Partea 1, build_url cu /:", build_url(host, "/login"))
print("Partea 1, is_https HTTPS:", is_https(SITES[0]))
print("Partea 1, is_https HTTP:", is_https(SITES[9]))

print("Partea 2, show_response:", SITES[0])
show_response(SITES[0])
sleep(1)
print("Partea 2, show_response 404:", SITES[6])
show_response(SITES[6])
sleep(1)

for url in SITES:
    print("Partea 3, check_site:", url, check_site(url))
    sleep(1)

print("Partea 4, scan_sites:")
scan_sites()
sleep(1)

for url in (SITES[1], SITES[10], SITES[11], SITES[9]):
    print("Partea 5, check_headers:", url, check_headers(url))
    sleep(1)

for url in (SITES[3], SITES[6], SITES[7], SITES[9], SITES[12]):
    print("Partea 6, retry_check:", url, retry_check(url))
    sleep(1)

print("Partea 6, retry_check cu attempts=2:", SITES[7], retry_check(SITES[7], attempts=2))
