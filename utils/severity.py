# utils/severity.py — ZeroProbe
# Risk severity scoring with granular weights per finding type

RISK_WEIGHTS = {
    # XSS
    "Critical": 5,
    "High":     3,
    "Medium":   2,
    "Low":      1,
    "None":     0,
}

HEADER_RISK_WEIGHTS = {"High": 2, "Medium": 1, "Low": 0}


def calculate_severity(report: dict) -> dict:
    score = 0

    # XSS findings
    for x in report.get("xss", []):
        if x.get("vulnerable"):
            score += RISK_WEIGHTS.get(x.get("risk", "High"), 3)

    # SQLi findings
    for s in report.get("sqli", []):
        if s.get("vulnerable"):
            score += RISK_WEIGHTS.get(s.get("risk", "Critical"), 5)

    # Missing headers (weighted by header risk level)
    for h in report.get("headers", []):
        if h.get("status") == "Missing":
            score += HEADER_RISK_WEIGHTS.get(h.get("risk", "Medium"), 1)

    # Determine severity tier
    if   score >= 15: level, color, badge = "Critical", "critical", "CRITICAL"
    elif score >= 8:  level, color, badge = "High",     "high",     "HIGH"
    elif score >= 4:  level, color, badge = "Medium",   "medium",   "MEDIUM"
    else:             level, color, badge = "Low",      "low",      "LOW"

    xss_count  = sum(1 for x in report.get("xss",  []) if x.get("vulnerable"))
    sqli_count = sum(1 for s in report.get("sqli", []) if s.get("vulnerable"))
    miss_count = sum(1 for h in report.get("headers", []) if h.get("status") == "Missing")

    return {
        "issues":       score,
        "level":        level,
        "color":        color,
        "badge":        badge,
        "pct":          min(score * 5, 100),
        "xss_count":    xss_count,
        "sqli_count":   sqli_count,
        "miss_headers": miss_count,
    }
