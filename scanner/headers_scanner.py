# scanner/headers_scanner.py — ZeroProbe
# HTTP security headers audit with risk classification and remediation guidance

import requests

SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "description": "Prevents XSS and injection attacks by specifying allowed content sources",
        "risk": "High",
        "recommendation": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "impact": "Without CSP, attackers can inject and execute scripts from arbitrary external sources.",
    },
    {
        "name": "Strict-Transport-Security",
        "description": "Forces all connections over HTTPS (HSTS)",
        "risk": "High",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "impact": "Absence of HSTS exposes users to SSL-stripping and man-in-the-middle attacks.",
    },
    {
        "name": "X-Frame-Options",
        "description": "Prevents the page from being embedded in iframes (clickjacking protection)",
        "risk": "Medium",
        "recommendation": "X-Frame-Options: DENY",
        "impact": "Without this header, attackers can embed your pages in invisible iframes to steal clicks.",
    },
    {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing by the browser",
        "risk": "Medium",
        "recommendation": "X-Content-Type-Options: nosniff",
        "impact": "MIME sniffing allows browsers to execute files as different types, enabling script injection.",
    },
    {
        "name": "Referrer-Policy",
        "description": "Controls what referrer information is sent with outbound requests",
        "risk": "Low",
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
        "impact": "Sensitive URL parameters and paths may leak via the Referer header to third-party services.",
    },
    {
        "name": "Permissions-Policy",
        "description": "Controls access to browser APIs and device features",
        "risk": "Low",
        "recommendation": "Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()",
        "impact": "Malicious scripts may silently access device camera, microphone, or location.",
    },
    {
        "name": "X-XSS-Protection",
        "description": "Enables the browser's built-in XSS filter (legacy browsers)",
        "risk": "Low",
        "recommendation": "X-XSS-Protection: 1; mode=block",
        "impact": "Legacy browsers without CSP support may be vulnerable to reflected XSS without this.",
    },
    {
        "name": "Cache-Control",
        "description": "Controls browser and proxy caching behavior for sensitive responses",
        "risk": "Medium",
        "recommendation": "Cache-Control: no-store, no-cache, must-revalidate, private",
        "impact": "Sensitive pages cached by browsers or proxies may expose user data to other users.",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "description": "Isolates browsing context from cross-origin windows",
        "risk": "Medium",
        "recommendation": "Cross-Origin-Opener-Policy: same-origin",
        "impact": "Without COOP, malicious cross-origin pages can access your window object.",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "description": "Prevents other origins from loading your resources",
        "risk": "Low",
        "recommendation": "Cross-Origin-Resource-Policy: same-origin",
        "impact": "Cross-origin resource leakage can expose internal data via Spectre-type side channels.",
    },
]

SCAN_HEADERS = {"User-Agent": "Mozilla/5.0 (ZeroProbe Security Scanner)"}


def scan_headers(url: str) -> list:
    results = []
    try:
        r = requests.get(url, timeout=8, headers=SCAN_HEADERS, verify=False)
        for h in SECURITY_HEADERS:
            value  = r.headers.get(h["name"])
            status = "Present" if value else "Missing"
            results.append({
                "header":         h["name"],
                "description":    h["description"],
                "risk":           h["risk"] if not value else "None",
                "status":         status,
                "value":          value or "N/A",
                "recommendation": h["recommendation"],
                "impact":         h["impact"] if not value else "",
            })
    except Exception as e:
        results.append({"error": str(e)})
    return results
