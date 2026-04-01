# scanner/subdomain_scanner.py — Scanova AI
# DNS brute-force subdomain enumeration

import socket
import concurrent.futures

SUBDOMAINS = [
    "www","mail","ftp","admin","api","dev","staging","test","blog","shop",
    "store","app","portal","m","mobile","vpn","smtp","pop","imap","ns1",
    "ns2","cdn","static","media","img","assets","dashboard","panel","cpanel",
    "webmail","login","auth","sso","help","support","docs","beta","internal",
    "intranet","git","gitlab","jenkins","jira","confluence","wiki","forum",
    "community","status","monitor","grafana","kibana","db","database","mysql",
    "redis","s3","backup","old","legacy","demo","sandbox","qa","uat","prod",
    "secure","pay","payment","checkout","cart","account","my","client","partner",
    "analytics","report","stats","search","video","img2","mail2","smtp2",
]


def _resolve(domain, sub):
    host = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(host)
        return {"subdomain": host, "ip": ip, "status": "Found"}
    except socket.gaierror:
        return None


def run_subdomain_scan(domain: str, workers: int = 40) -> list:
    # Strip protocol if accidentally included
    domain = domain.replace("https://","").replace("http://","").strip("/")
    found  = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_resolve, domain, s): s for s in SUBDOMAINS}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
    return sorted(found, key=lambda x: x["subdomain"])
