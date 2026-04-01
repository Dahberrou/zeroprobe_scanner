# Scanova AI — Scan. Detect. Secure.
### Developed by Dah Berrou © 2026

An advanced AI-powered web vulnerability scanner built as a graduation project.

## Project Structure
```
scanova/
├── app.py                    # Flask main application
├── requirements.txt
├── wordlists/
│   └── dirs.txt              # 29K directory brute-force wordlist
├── scanner/
│   ├── main_scanner.py       # Orchestrates all scanners (threaded)
│   ├── xss_scanner.py        # XSS detection (10 payloads)
│   ├── sqli_scanner.py       # SQL Injection detection (18 payloads)
│   ├── headers_scanner.py    # HTTP security header audit
│   ├── subdomain_scanner.py  # DNS brute-force enumeration
│   └── dir_scanner.py        # Directory brute-force + 403 bypass
├── utils/
│   ├── ai_report.py          # OpenAI GPT-4o-mini AI analysis
│   ├── severity.py           # Weighted severity scoring
│   └── pdf_report.py         # ReportLab PDF generation
└── templates/
    ├── base.html             # Shared sidebar layout
    ├── index.html            # Main vulnerability scanner
    ├── subdomains.html       # Subdomain enumeration
    ├── dirscan.html          # Directory brute-force
    └── about.html            # Project info
```

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set your OpenAI API key (optional — falls back to local analysis)
export OPENAI_API_KEY="sk-..."

# 3. Run
python app.py
# Open http://127.0.0.1:5000
```

## Features
- **XSS Scanner** — 10 reflected-XSS payloads
- **SQLi Scanner** — 18 payloads + error fingerprinting across 13 DB engines
- **Header Audit** — 8 critical security headers checked
- **Subdomain Enumeration** — DNS brute-force (concurrent)
- **Directory Brute-Force** — 29K wordlist + automatic 403 bypass with 5 techniques
- **Smart AI Box** — OpenAI GPT-4o-mini structured vulnerability analysis with fix steps
- **PDF Export** — Professional ReportLab report
- **Threaded Engine** — All scanners run concurrently for speed
