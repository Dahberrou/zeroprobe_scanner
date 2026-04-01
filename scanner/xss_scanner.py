# scanner/xss_scanner.py — ZeroProbe
# XSS detection: reflected payload injection with risk classification

import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

PAYLOADS = [
    {"payload": "<script>alert('XSS')</script>",           "type": "Script Injection",          "risk": "High"},
    {"payload": "\"'><script>alert('XSS')</script>",       "type": "Attribute Escape + Script", "risk": "High"},
    {"payload": "<img src=x onerror=alert('XSS')>",        "type": "Event Handler (img)",       "risk": "High"},
    {"payload": "<svg/onload=alert('XSS')>",               "type": "SVG onload Event",          "risk": "High"},
    {"payload": "'><img src=x onerror=alert(1)>",          "type": "Single Quote Escape",       "risk": "High"},
    {"payload": "<body onload=alert('XSS')>",              "type": "Body onload Event",         "risk": "Medium"},
    {"payload": "\"><svg onload=alert(1)>",                "type": "Double Quote + SVG",        "risk": "High"},
    {"payload": "<iframe src=javascript:alert(1)>",        "type": "Iframe JS Protocol",        "risk": "Medium"},
    {"payload": "javascript:alert('XSS')",                 "type": "JavaScript Protocol",       "risk": "Medium"},
    {"payload": "';alert('XSS');//",                       "type": "JS Context Escape",         "risk": "High"},
    {"payload": "<input autofocus onfocus=alert('XSS')>",  "type": "Autofocus Event",           "risk": "Medium"},
    {"payload": "<details open ontoggle=alert('XSS')>",   "type": "HTML5 Toggle Event",        "risk": "Medium"},
]

RISK_META = {
    "High": {
        "description": "Reflected XSS payload was echoed back without sanitization. Attackers can inject scripts to steal session cookies, hijack accounts, or redirect users.",
        "recommendation": "Apply context-aware output encoding on all user-supplied data. Set HTTPOnly and Secure cookie flags. Implement a strict Content-Security-Policy header.",
    },
    "Medium": {
        "description": "Potentially exploitable XSS vector detected. Limited impact depending on context but still a valid attack surface.",
        "recommendation": "Use an allowlist-based input validation strategy. Consider adopting a templating engine with auto-escaping enabled.",
    },
}

SCAN_HEADERS = {"User-Agent": "Mozilla/5.0 (ZeroProbe Security Scanner)"}


def scan_xss(url: str) -> list:
    results = []
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)

    # Build test parameter list: existing params + fallback
    test_params = list(params.keys())[:3] if params else ["q", "search", "id"]

    for param in test_params:
        for item in PAYLOADS:
            payload  = item["payload"]
            base_p   = {k: (v[0] if isinstance(v, list) else v)
                        for k, v in params.items()} if params else {param: "test"}
            base_p[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(base_p)))

            try:
                r = requests.get(test_url, timeout=8, headers=SCAN_HEADERS,
                                 verify=False, allow_redirects=True)
                reflected = (payload in r.text or
                             payload.lower() in r.text.lower())
                meta = RISK_META.get(item["risk"], RISK_META["Medium"]) if reflected else {}
                results.append({
                    "payload":        payload,
                    "type":           item["type"],
                    "parameter":      param,
                    "vulnerable":     reflected,
                    "risk":           item["risk"] if reflected else "None",
                    "url":            test_url,
                    "status":         r.status_code,
                    "description":    meta.get("description", ""),
                    "recommendation": meta.get("recommendation", ""),
                })
                if reflected:
                    break   # one confirmed finding per param is enough
            except Exception as e:
                results.append({
                    "payload": payload, "type": item["type"],
                    "parameter": param, "vulnerable": False,
                    "risk": "None", "url": test_url,
                    "error": str(e),
                })

    # Deduplicate: keep unique payloads
    seen, deduped = set(), []
    for r in results:
        key = r["payload"]
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped
