# scanner/main_scanner.py — ZeroProbe
# Orchestrates all scan modules (kept for backwards compatibility)

from scanner.xss_scanner     import scan_xss
from scanner.sqli_scanner    import scan_sqli
from scanner.headers_scanner import scan_headers


def run_full_scan(url: str) -> dict:
    """Run all scanners sequentially and return a combined report dict."""
    return {
        "url":     url,
        "xss":     scan_xss(url),
        "sqli":    scan_sqli(url),
        "headers": scan_headers(url),
    }
