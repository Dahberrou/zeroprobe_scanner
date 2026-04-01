# utils/pdf_report.py — ZeroProbe
# Professional penetration testing report — ReportLab

from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable, PageBreak)
from reportlab.lib.styles    import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units     import cm
from reportlab.lib           import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums     import TA_CENTER, TA_RIGHT
from datetime import datetime

# ── Color palette ─────────────────────────────────────────────────────────────
C_NAVY   = colors.HexColor("#0D1117")
C_BLUE   = colors.HexColor("#3B82F6")
C_CYAN   = colors.HexColor("#06B6D4")
C_RED    = colors.HexColor("#EF4444")
C_ORANGE = colors.HexColor("#F97316")
C_AMBER  = colors.HexColor("#F59E0B")
C_GREEN  = colors.HexColor("#10B981")
C_DARK   = colors.HexColor("#1E293B")
C_MID    = colors.HexColor("#334155")
C_LIGHT  = colors.HexColor("#64748B")
C_PALE   = colors.HexColor("#F1F5F9")
C_WHITE  = colors.white
C_ROW2   = colors.HexColor("#F8FAFC")
C_VULN   = colors.HexColor("#FEF2F2")
C_SAFE   = colors.HexColor("#F0FDF4")

SEV_COLORS = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_AMBER,
    "Low":      C_GREEN,
    "None":     C_LIGHT,
}


def _sev_color(level: str):
    return SEV_COLORS.get(level, C_LIGHT)


def generate_pdf(report: dict, severity: dict, ai_report: str,
                 filename: str = "zeroprobe_report.pdf") -> str:
    doc = SimpleDocTemplate(
        filename, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2.2*cm,
        title="ZeroProbe Security Report",
        author="ZeroProbe",
    )

    # ── Styles ────────────────────────────────────────────────────────────────
    def sty(name, **kw):
        return ParagraphStyle(name, **kw)

    Cover  = sty("Cover",  fontSize=28, fontName="Helvetica-Bold",
                 textColor=C_WHITE, leading=34, spaceAfter=8, alignment=TA_CENTER)
    Sub    = sty("Sub",    fontSize=12, textColor=colors.HexColor("#94A3B8"),
                 spaceAfter=4, alignment=TA_CENTER)
    H1     = sty("H1",     fontSize=15, fontName="Helvetica-Bold",
                 textColor=C_DARK, spaceBefore=14, spaceAfter=6)
    H2     = sty("H2",     fontSize=11, fontName="Helvetica-Bold",
                 textColor=C_BLUE, spaceBefore=8, spaceAfter=4)
    Body   = sty("Body",   fontSize=9.5, leading=15, textColor=C_MID, spaceAfter=3)
    Code   = sty("Code",   fontSize=8.5, fontName="Courier",
                 backColor=colors.HexColor("#F1F5F9"),
                 textColor=C_DARK, leftIndent=10, leading=13, spaceAfter=4)
    Foot   = sty("Foot",   fontSize=7.5, textColor=C_LIGHT,
                 alignment=TA_CENTER, spaceBefore=6)
    SevTxt = sty("SevTxt", fontSize=13, fontName="Helvetica-Bold",
                 textColor=_sev_color(severity.get("level", "Low")),
                 alignment=TA_CENTER)

    out = []

    # ── Cover page ────────────────────────────────────────────────────────────
    out.append(Spacer(1, 1.5*cm))
    # Header bar (simulate with colored table)
    bar_data = [[Paragraph("ZeroProbe", sty("BH", fontSize=24, fontName="Helvetica-Bold",
                                             textColor=C_WHITE, alignment=TA_CENTER))]]
    bar = Table(bar_data, colWidths=[17*cm])
    bar.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 16),
        ("BOTTOMPADDING", (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [8]),
    ]))
    out.append(bar)
    out.append(Spacer(1, 0.6*cm))

    out.append(Paragraph("Web Vulnerability Assessment Report", Sub))
    out.append(Paragraph("Penetration Testing Report — Confidential", sty(
        "Sub2", fontSize=10, textColor=C_LIGHT, alignment=TA_CENTER, spaceAfter=20)))
    out.append(Spacer(1, 0.4*cm))

    # Meta table
    meta = [
        ["Target URL",  report.get("url", "N/A")],
        ["Scan Date",   datetime.now().strftime("%Y-%m-%d %H:%M UTC")],
        ["Risk Level",  severity.get("level", "N/A")],
        ["Risk Score",  str(severity.get("issues", 0))],
        ["XSS Found",   str(severity.get("xss_count", 0))],
        ["SQLi Found",  str(severity.get("sqli_count", 0))],
        ["Hdrs Missing",str(severity.get("miss_headers", 0))],
    ]
    mt = Table(meta, colWidths=[3.8*cm, 13.2*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EFF6FF")),
        ("BACKGROUND", (1, 0), (1, -1), C_WHITE),
        ("TEXTCOLOR",  (0, 0), (0, -1), C_BLUE),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [C_WHITE, C_ROW2]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    out.append(mt)
    out.append(Spacer(1, 0.5*cm))

    # Severity badge
    sev_data = [[Paragraph(severity.get("level", "Unknown").upper(),
                            sty("SB", fontSize=18, fontName="Helvetica-Bold",
                                textColor=C_WHITE, alignment=TA_CENTER))]]
    sev_color = _sev_color(severity.get("level", "Low"))
    sev_tbl = Table(sev_data, colWidths=[4*cm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", [6]),
    ]))
    out.append(sev_tbl)
    out.append(Spacer(1, 0.4*cm))
    out.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#E2E8F0")))
    out.append(Spacer(1, 0.3*cm))
    out.append(Paragraph(
        "This report was generated by ZeroProbe Security Intelligence Platform. "
        "It is intended solely for the authorized target and should be treated as confidential.",
        sty("Disc", fontSize=8.5, textColor=C_LIGHT, leading=13)
    ))

    out.append(PageBreak())

    # ── Executive Summary ────────────────────────────────────────────────────
    out.append(Paragraph("Executive Summary", H1))
    out.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#BFDBFE")))
    out.append(Spacer(1, 6))

    xss_found  = [x for x in report.get("xss",  []) if x.get("vulnerable")]
    sqli_found = [s for s in report.get("sqli", []) if s.get("vulnerable")]
    miss_hdrs  = [h for h in report.get("headers", []) if h.get("status") == "Missing"]

    summary_text = (
        f"ZeroProbe performed a comprehensive automated vulnerability assessment against "
        f"<b>{report.get('url', 'the target')}</b>. "
        f"The scan covered XSS injection, SQL injection, and HTTP security header analysis. "
        f"The overall risk posture is rated <b>{severity.get('level', 'Unknown')}</b> "
        f"with a weighted score of <b>{severity.get('issues', 0)}</b>."
    )
    out.append(Paragraph(summary_text, Body))
    out.append(Spacer(1, 8))

    # Findings summary table
    sum_data = [["Category", "Payloads Tested", "Vulnerabilities", "Severity"],
                ["XSS Injection",         str(len(report.get("xss", []))),     str(len(xss_found)),  "High" if xss_found else "—"],
                ["SQL Injection",         str(len(report.get("sqli", []))),    str(len(sqli_found)), "Critical" if sqli_found else "—"],
                ["Security Headers",      str(len(report.get("headers", []))), str(len(miss_hdrs)),  "High" if [h for h in miss_hdrs if h.get('risk')=='High'] else "Medium" if miss_hdrs else "—"],
    ]
    st = Table(sum_data, colWidths=[6*cm, 3.5*cm, 3.5*cm, 4*cm])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW2]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ]))
    out.append(st)
    out.append(Spacer(1, 14))

    # ── AI / Analyst Section ─────────────────────────────────────────────────
    out.append(Paragraph("Security Analysis & Recommendations", H1))
    out.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#BFDBFE")))
    out.append(Spacer(1, 6))

    if ai_report:
        for line in ai_report.split("\n"):
            line = line.strip()
            if not line:
                out.append(Spacer(1, 3))
                continue
            if line.startswith("[VULN:") or line.startswith("Overall Assessment"):
                out.append(Paragraph(f"<b>{line}</b>", H2))
            elif line.startswith("---"):
                out.append(HRFlowable(width="100%", thickness=0.3,
                                      color=colors.HexColor("#E2E8F0")))
                out.append(Spacer(1, 6))
            elif any(line.startswith(k) for k in ("Description:", "Risk:", "Fix:", "Secure Example:")):
                out.append(Paragraph(f"<b>{line}</b>", Body))
            elif line and line[0].isdigit() and "." in line[:3]:
                out.append(Paragraph(f"  {line}", Body))
            elif line.startswith(" ") or "cursor." in line or "add_header" in line or "#" in line:
                out.append(Paragraph(line, Code))
            else:
                out.append(Paragraph(line, Body))

    out.append(Spacer(1, 14))

    # ── Detailed Results ──────────────────────────────────────────────────────
    def findings_table(title, rows, col_headers):
        out.append(Paragraph(title, H1))
        out.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#BFDBFE")))
        out.append(Spacer(1, 4))
        cw = [17 * cm / len(col_headers)] * len(col_headers)
        data = [col_headers] + rows
        tb = Table(data, colWidths=cw, repeatRows=1)
        row_bg = []
        for i, row in enumerate(rows, start=1):
            status_val = str(row[1]).lower() if len(row) > 1 else ""
            bg = C_VULN if "vuln" in status_val else (C_SAFE if "safe" in status_val else C_WHITE if i % 2 == 0 else C_ROW2)
            row_bg.append(("BACKGROUND", (0, i), (-1, i), bg))
        style = [
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 7),
            ("WORDWRAP",      (0, 0), (-1, -1), 1),
        ] + row_bg
        tb.setStyle(TableStyle(style))
        out.append(tb)
        out.append(Spacer(1, 12))

    findings_table(
        "XSS Injection Findings",
        [[x.get("payload", "")[:50],
          "Vulnerable" if x.get("vulnerable") else "Safe",
          x.get("risk", "—"),
          x.get("type", "—")]
         for x in report.get("xss", [])],
        ["Payload", "Status", "Risk", "Type"]
    )

    findings_table(
        "SQL Injection Findings",
        [[s.get("payload", "")[:45],
          "Vulnerable" if s.get("vulnerable") else "Safe",
          s.get("risk", "—"),
          s.get("technique", "—"),
          s.get("db_type", "—")]
         for s in report.get("sqli", [])],
        ["Payload", "Status", "Risk", "Technique", "DBMS"]
    )

    findings_table(
        "Security Headers Audit",
        [[h.get("header", ""), h.get("status", ""), h.get("risk", "—"),
          (h.get("value") or "N/A")[:30]]
         for h in report.get("headers", []) if "error" not in h],
        ["Header", "Status", "Risk", "Value"]
    )

    # ── Footer ────────────────────────────────────────────────────────────────
    out.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))
    out.append(Paragraph(
        "ZeroProbe Security Intelligence Platform — Developed by Dah Berrou © 2026 | "
        "This report is confidential and intended for authorized recipients only.",
        Foot
    ))

    doc.build(out)
    return filename
