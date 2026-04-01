# utils/ai_report.py — ZeroProbe
# AI Security Analyst — OpenAI GPT-4o-mini with comprehensive local fallback

import os
from openai import OpenAI

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = OpenAI(api_key=os.getenv("OPENAI_API_KEY") or "sk-placeholder")
    return _client

SYSTEM_PROMPT = """You are a senior penetration tester writing a professional security report for ZeroProbe.
Analyze the vulnerability scan data and produce a structured, technical report.

Use EXACTLY this format for each vulnerability:

[VULN: <Name> | SEVERITY: Critical/High/Medium/Low]
Description: <2 concise technical sentences>
Risk: <specific attack scenario an adversary could execute>
Fix:
1. <concrete remediation step>
2. <concrete remediation step>
3. <concrete remediation step>
Secure Example:
<minimal code or config snippet demonstrating the fix>
---

End with a single line: Overall Assessment: <one-line executive summary>

Rules: be direct and technical, no preamble, no marketing language, no filler."""


def generate_ai_report(report: dict) -> str:
    try:
        xss_found  = [x for x in report.get("xss",  []) if x.get("vulnerable")]
        sqli_found = [s for s in report.get("sqli", []) if s.get("vulnerable")]
        miss_hdrs  = [h for h in report.get("headers", []) if h.get("status") == "Missing"]

        prompt = (
            f"Target: {report.get('url')}\n\n"
            f"XSS findings ({len(xss_found)}): {[x['payload'] for x in xss_found[:3]]}\n"
            f"SQLi findings ({len(sqli_found)}): {[s['payload'] for s in sqli_found[:3]]}\n"
            f"Missing headers ({len(miss_hdrs)}): {[h['header'] for h in miss_hdrs]}\n\n"
            "Produce the structured security report."
        )

        resp = _get_client().chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user",   "content": prompt}],
            max_tokens=1800, temperature=0.2,
        )
        return resp.choices[0].message.content

    except Exception as e:
        print(f"[AI] Falling back to local analysis: {e}")
        return _local_analysis(report)


def _local_analysis(report: dict) -> str:
    xss_found  = [x for x in report.get("xss",  []) if x.get("vulnerable")]
    sqli_found = [s for s in report.get("sqli", []) if s.get("vulnerable")]
    miss_hdrs  = [h for h in report.get("headers", []) if h.get("status") == "Missing"]
    total      = len(xss_found) + len(sqli_found) + len(miss_hdrs)

    sev = ("Critical" if total >= 8 else
           "High"     if total >= 5 else
           "Medium"   if total >= 2 else "Low")
    parts = []

    if xss_found:
        types = ", ".join(sorted({x.get("type", "Reflected") for x in xss_found}))
        parts.append(f"""[VULN: Cross-Site Scripting (XSS) | SEVERITY: High]
Description: {len(xss_found)} XSS payload(s) were reflected in server responses without encoding. Types: {types}.
Risk: An attacker can inject scripts to steal session tokens, hijack user accounts, redirect victims to phishing pages, or perform actions on their behalf.
Fix:
1. Apply context-aware output encoding on all user-supplied data before rendering (HTML, JS, URL, CSS contexts).
2. Implement a strict Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'.
3. Set the HTTPOnly and Secure flags on all session cookies to prevent script access.
Secure Example:
  # Flask / Jinja2 (auto-escaping)
  from markupsafe import escape
  safe_output = escape(user_input)   # escapes <, >, ", ', &
---""")

    if sqli_found:
        techniques = ", ".join(sorted({s.get("technique", "Error-Based") for s in sqli_found}))
        db_types   = ", ".join(sorted({s.get("db_type", "Unknown") for s in sqli_found if s.get("db_type") != "N/A"}))
        parts.append(f"""[VULN: SQL Injection | SEVERITY: Critical]
Description: {len(sqli_found)} SQL injection vector(s) confirmed via {techniques}. Backend DBMS: {db_types or 'Unknown'}.
Risk: Full database read/write access, authentication bypass, data exfiltration, and potential OS-level command execution via stacked queries or UDF abuse.
Fix:
1. Use parameterized queries or prepared statements for every database interaction — never concatenate user input.
2. Apply the principle of least privilege: the application DB user must not have DDL, DROP, or FILE privileges.
3. Suppress all database error messages in production; log them server-side only.
Secure Example:
  # Python (psycopg2 / SQLite)
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

  # SQLAlchemy ORM (inherently parameterized)
  User.query.filter_by(id=user_id).first()
---""")

    if miss_hdrs:
        high_risk = [h for h in miss_hdrs if h.get("risk") == "High"]
        med_risk  = [h for h in miss_hdrs if h.get("risk") == "Medium"]
        header_list = ", ".join(h["header"] for h in miss_hdrs[:5])
        sev_label = "High" if high_risk else "Medium"
        parts.append(f"""[VULN: Missing Security Headers | SEVERITY: {sev_label}]
Description: {len(miss_hdrs)} critical HTTP security header(s) absent from server responses: {header_list}.
Risk: Exposes the application to XSS injection ({len(high_risk)} high-risk headers missing), clickjacking, MIME-type sniffing, and cleartext MITM interception.
Fix:
1. Add Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'.
2. Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.
3. Add X-Frame-Options: DENY and X-Content-Type-Options: nosniff to every response.
Secure Example:
  # Nginx — add to server block
  add_header Content-Security-Policy "default-src 'self'" always;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
---""")

    if not parts:
        parts.append("[VULN: None Detected | SEVERITY: Low]\nDescription: No active vulnerabilities detected in this scan pass.\nRisk: Baseline posture appears acceptable; recommend regular rescanning.\nFix:\n1. Continue periodic scanning.\n2. Monitor CVE feeds for used libraries.\n3. Perform manual code review for business-logic flaws.\nSecure Example: N/A\n---")

    parts.append(f"Overall Assessment: {sev} risk — {total} weighted finding(s) detected across XSS, SQLi, and header audit. (Local analysis — AI API unavailable)")
    return "\n\n".join(parts)
