from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from datetime import datetime
import io


TIER_COLORS = {
    "CRITICAL":   RGBColor(0xEF, 0x44, 0x44),
    "HIGH":       RGBColor(0xF9, 0x73, 0x16),
    "MEDIUM":     RGBColor(0xF5, 0x9E, 0x0B),
    "LOW":        RGBColor(0x84, 0xCC, 0x16),
    "ACCEPTABLE": RGBColor(0x22, 0xC5, 0x5E),
}

ORANGE = RGBColor(0xFF, 0x80, 0x00)
BLACK  = RGBColor(0x1A, 0x1A, 0x1A)


def _set_cell_bg(cell, hex_color: str):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _heading(doc, text: str, level: int = 1):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(text)
    run.bold = True
    run.font.color.rgb = ORANGE if level == 1 else BLACK
    run.font.size = Pt(14 if level == 1 else 11)
    return p


def build_docx(assessment: dict) -> bytes:
    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin    = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin   = Inches(1.25)
        section.right_margin  = Inches(1.25)

    # Title block
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("VENDOR RISK ASSESSMENT REPORT")
    run.bold = True
    run.font.size = Pt(20)
    run.font.color.rgb = BLACK

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run2 = sub.add_run(f"{assessment['company_name']}  ·  {assessment['domain']}")
    run2.font.size = Pt(11)
    run2.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    date_p = doc.add_paragraph()
    date_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    date_p.add_run(f"Assessed: {datetime.utcnow().strftime('%B %d, %Y')}  ·  Assessment ID: {assessment['assessment_id']}")

    doc.add_paragraph()

    # Overall risk score
    _heading(doc, "OVERALL RISK RATING")
    score_table = doc.add_table(rows=1, cols=3)
    score_table.style = "Table Grid"
    cells = score_table.rows[0].cells

    cells[0].text = "Overall Score"
    cells[1].text = f"{assessment['overall_score']} / 100"
    cells[2].text = assessment['risk_tier']

    tier = assessment['risk_tier']
    _set_cell_bg(cells[0], "1A1A1A")
    _set_cell_bg(cells[1], "F0F0F0")
    hex_map = {"CRITICAL": "EF4444", "HIGH": "F97316", "MEDIUM": "F59E0B", "LOW": "84CC16", "ACCEPTABLE": "22C55E"}
    _set_cell_bg(cells[2], hex_map.get(tier, "6B7280"))

    for cell in cells:
        for para in cell.paragraphs:
            for run in para.runs:
                run.bold = True
                run.font.size = Pt(11)
        cells[0].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cells[2].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    doc.add_paragraph()

    # Executive summary
    _heading(doc, "EXECUTIVE SUMMARY")
    summary_para = doc.add_paragraph(assessment.get("claude_summary", "No summary available."))
    summary_para.paragraph_format.space_after = Pt(8)

    # OSINT findings
    _heading(doc, "OSINT INTELLIGENCE FINDINGS")
    osint = assessment.get("osint_findings", {})

    osint_items = [
        ("SSL/TLS Grade",          osint.get("ssl_grade") or "Not Retrieved"),
        ("Known Data Breaches",    str(osint.get("breach_count", 0))),
        ("VirusTotal Malicious",   str(osint.get("vt_malicious", 0))),
        ("Exposed Risky Ports",    ", ".join(str(p) for p in osint.get("exposed_ports", [])) or "None Detected"),
        ("Negative News Results",  str(osint.get("negative_news_count", 0))),
        ("Lawsuits Found",         str(osint.get("lawsuit_count", 0))),
        ("CISA KEV Matches",       str(osint.get("kev_matches", 0))),
        ("Safe Browsing Threat",   "YES" if osint.get("safe_browsing_threat") else "No"),
        ("BBB Rating",             osint.get("bbb_rating", "Not Found")),
        ("BBB Complaints",         str(osint.get("bbb_complaints", 0))),
        ("Domain Registered",      osint.get("registered", "Unknown")),
    ]

    osint_table = doc.add_table(rows=len(osint_items), cols=2)
    osint_table.style = "Table Grid"
    for i, (label, value) in enumerate(osint_items):
        row = osint_table.rows[i]
        row.cells[0].text = label
        row.cells[1].text = value
        _set_cell_bg(row.cells[0], "F0F0F0")
        for cell in row.cells:
            for para in cell.paragraphs:
                para.runs[0].font.size = Pt(10)

    # Security incidents from Claude
    incidents = osint.get("security_incidents", [])
    if incidents:
        doc.add_paragraph()
        _heading(doc, "REPORTED SECURITY INCIDENTS", level=2)
        for incident in incidents:
            p = doc.add_paragraph(f"• {incident}", style="Normal")
            p.paragraph_format.left_indent = Inches(0.25)

    key_findings = osint.get("key_findings", "")
    if key_findings:
        doc.add_paragraph()
        kf = doc.add_paragraph()
        kf.add_run("Intelligence Summary: ").bold = True
        kf.add_run(key_findings)

    doc.add_paragraph()

    # Domain scores table
    _heading(doc, "RISK DOMAIN SCORES")
    domain_scores = assessment.get("domain_scores", [])
    if domain_scores:
        header_row_count = 1
        d_table = doc.add_table(rows=header_row_count + len(domain_scores), cols=4)
        d_table.style = "Table Grid"

        headers = ["Domain", "OSINT Score", "Questionnaire Score", "Combined Score"]
        header_cells = d_table.rows[0].cells
        for i, h in enumerate(headers):
            header_cells[i].text = h
            _set_cell_bg(header_cells[i], "1A1A1A")
            header_cells[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            header_cells[i].paragraphs[0].runs[0].bold = True
            header_cells[i].paragraphs[0].runs[0].font.size = Pt(10)

        for i, ds in enumerate(domain_scores):
            row = d_table.rows[i + 1]
            row.cells[0].text = ds["label"]
            row.cells[1].text = f"{ds['osint_score']:.0f}"
            row.cells[2].text = f"{ds['questionnaire_score']:.0f}"
            row.cells[3].text = f"{ds['combined_score']:.0f}"
            if i % 2 == 0:
                for cell in row.cells:
                    _set_cell_bg(cell, "FAFAFA")
            for cell in row.cells:
                for para in cell.paragraphs:
                    if para.runs:
                        para.runs[0].font.size = Pt(10)

    doc.add_paragraph()

    # Recommendations
    _heading(doc, "PRIORITIZED RECOMMENDATIONS")
    for ds in domain_scores:
        recs = ds.get("recommendations", [])
        if recs:
            _heading(doc, ds["label"], level=2)
            for rec in recs:
                p = doc.add_paragraph(f"→  {rec}", style="Normal")
                p.paragraph_format.left_indent = Inches(0.25)
                p.paragraph_format.space_after = Pt(4)

    doc.add_paragraph()

    # Footer
    footer_p = doc.add_paragraph()
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer_run = footer_p.add_run(
        f"Generated by Vendor Risk Scorer · michael@coburn.org · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )
    footer_run.font.size = Pt(8)
    footer_run.font.color.rgb = RGBColor(0x99, 0x99, 0x99)

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()
