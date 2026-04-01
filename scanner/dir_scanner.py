# scanner/dir_scanner.py — Scanova AI
# Directory brute-force with 403-bypass techniques

import requests
import concurrent.futures
import os

HEADERS = {"User-Agent": "Mozilla/5.0 (Scanova-AI Scanner)"}

BYPASS_HEADERS_LIST = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Rewrite-URL": "/"},
    {"X-Real-IP": "127.0.0.1"},
]

STATUS_COLORS = {200:"green", 201:"green", 204:"green",
                 301:"blue",  302:"blue",
                 401:"yellow",403:"orange",
                 500:"red",   503:"red"}


def _load_wordlist() -> list:
    path = os.path.join(os.path.dirname(__file__), "..", "wordlists", "dirs.txt")
    if os.path.exists(path):
        with open(path, errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return words[:3000]   # cap at 3000 entries for speed
    # Fallback mini-list
    return ["admin","login","dashboard","api","backup","config","test","dev",
            ".env","robots.txt","sitemap.xml","wp-admin","wp-login.php",
            "upload","uploads","files","static","assets","database","db"]


WORDLIST = _load_wordlist()


def _check(base: str, path: str):
    url = base.rstrip("/") + "/" + path.lstrip("/")
    try:
        r    = requests.get(url, timeout=6, headers=HEADERS,
                            allow_redirects=False, verify=False)
        code = r.status_code
        if code not in (200,201,204,301,302,401,403,500,503):
            return None

        result = {"path": "/" + path, "url": url, "status": code,
                  "size": len(r.content), "bypass": None,
                  "color": STATUS_COLORS.get(code, "gray")}

        # Attempt 403 bypass
        if code == 403:
            for bh in BYPASS_HEADERS_LIST:
                try:
                    r2 = requests.get(url, timeout=5,
                                      headers={**HEADERS, **bh},
                                      allow_redirects=False, verify=False)
                    if r2.status_code == 200:
                        result["bypass"] = list(bh.keys())[0]
                        result["status"] = 200
                        result["color"]  = "green"
                        break
                except Exception:
                    pass
        return result
    except Exception:
        return None


def run_dir_scan(url: str, workers: int = 25) -> list:
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check, url, p): p for p in WORDLIST}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
    return sorted(found, key=lambda x: x["status"])
