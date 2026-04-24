import httpx
import os
import base64
import logging
from datetime import datetime
from report import build_docx

logger = logging.getLogger(__name__)

RESEND_API_KEY  = os.environ.get("RESEND_API_KEY")
FROM_ADDRESS    = "Vendor Risk Scorer <michael@coburn.org>"

TIER_HEX = {
    "CRITICAL":   "#EF4444",
    "HIGH":       "#F97316",
    "MEDIUM":     "#F59E0B",
    "LOW":        "#84CC16",
    "ACCEPTABLE": "#22C55E",
}


def _build_html(assessment: dict) -> str:
    tier       = assessment["risk_tier"]
    tier_color = TIER_HEX.get(tier, "#6B7280")
    score      = assessment["overall_score"]
    company    = assessment["company_name"]
    domain     = assessment["domain"]
    summary    = assessment.get("claude_summary", "")
    osint      = assessment.get("osint_findings", {})

    domain_rows = "".join(
        f"""<tr>
              <td style="padding:8px 12px;border-bottom:1px solid #eee;font-size:13px;">{ds['label']}</td>
              <td style="padding:8px 12px;border-bottom:1px solid #eee;font-size:13px;text-align:center;">{ds['osint_score']:.0f}</td>
              <td style="padding:8px 12px;border-bottom:1px solid #eee;font-size:13px;text-align:center;">{ds['questionnaire_score']:.0f}</td>
              <td style="padding:8px 12px;border-bottom:1px solid #eee;font-size:13px;text-align:center;font-weight:700;">{ds['combined_score']:.0f}</td>
            </tr>"""
        for ds in assessment.get("domain_scores", [])
    )

    top_recs = []
    for ds in assessment.get("domain_scores", []):
        for rec in ds.get("recommendations", [])[:1]:
            top_recs.append(f"<li style='margin-bottom:6px;font-size:13px;'><strong>{ds['label']}:</strong> {rec}</li>")
    rec_html = "<ul style='padding-left:20px;margin:0;'>" + "".join(top_recs[:6]) + "</ul>"

    return f"""
<html><body style="font-family:Arial,sans-serif;max-width:860px;margin:0 auto;background:#f4f6f8;">

<div style="background:#1A1A1A;color:#fff;padding:24px 32px;border-radius:8px 8px 0 0;">
  <h1 style="margin:0;letter-spacing:3px;font-size:22px;color:#FF8000;">VENDOR RISK SCORER</h1>
  <p style="color:#999;margin:4px 0 0;font-size:12px;">
    Assessment Report · {datetime.utcnow().strftime("%B %d, %Y")} · michael@coburn.org
  </p>
</div>

<div style="background:#fff;border:1px solid #dde3ea;padding:28px 32px;">
  <h2 style="color:#1A1A1A;margin-top:0;">{company} <span style="font-size:14px;color:#888;font-weight:400;">({domain})</span></h2>

  <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
    <tr>
      <td style="padding:16px;background:#f8f9fb;border:1px solid #eee;width:50%;text-align:center;">
        <div style="font-size:42px;font-weight:900;color:#1A1A1A;">{score}</div>
        <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.1em;">Overall Score</div>
      </td>
      <td style="padding:16px;background:{tier_color};border:1px solid #eee;width:50%;text-align:center;">
        <div style="font-size:28px;font-weight:900;color:#fff;">{tier}</div>
        <div style="font-size:11px;color:rgba(255,255,255,.8);text-transform:uppercase;letter-spacing:.1em;">Risk Tier</div>
      </td>
    </tr>
  </table>

  <h3 style="color:#FF8000;font-size:13px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;">Executive Summary</h3>
  <p style="font-size:14px;line-height:1.7;color:#333;margin-bottom:24px;">{summary}</p>

  <h3 style="color:#FF8000;font-size:13px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;">Domain Scores</h3>
  <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
    <tr style="background:#1A1A1A;color:#fff;">
      <th style="padding:8px 12px;text-align:left;font-size:12px;">Domain</th>
      <th style="padding:8px 12px;font-size:12px;">OSINT</th>
      <th style="padding:8px 12px;font-size:12px;">Questionnaire</th>
      <th style="padding:8px 12px;font-size:12px;">Combined</th>
    </tr>
    {domain_rows}
  </table>

  <h3 style="color:#FF8000;font-size:13px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;">Top Recommendations</h3>
  {rec_html}
</div>

<div style="background:#1A1A1A;color:#666;padding:16px 32px;text-align:center;font-size:11px;border-radius:0 0 8px 8px;">
  Vendor Risk Scorer · michael@coburn.org · coburn.org/tools · Assessment ID: {assessment['assessment_id']}
</div>

</body></html>"""


async def send_report(assessment: dict, recipient: str, note: str = "") -> bool:
    if not RESEND_API_KEY:
        logger.error("RESEND_API_KEY not set")
        return False

    company = assessment["company_name"]
    tier    = assessment["risk_tier"]

    docx_bytes  = build_docx(assessment)
    docx_b64    = base64.b64encode(docx_bytes).decode()
    filename    = f"VendorRisk_{company.replace(' ', '_')}_{tier}.docx"

    html_body   = _build_html(assessment)
    if note:
        html_body = html_body.replace(
            "<h2 style",
            f'<div style="background:#fff8e1;border-left:3px solid #FF8000;padding:10px 16px;margin-bottom:16px;font-size:13px;">{note}</div><h2 style',
        )

    payload = {
        "from": FROM_ADDRESS,
        "to": [recipient],
        "subject": f"Vendor Risk Report — {company} — {tier} Risk",
        "html": html_body,
        "attachments": [{
            "filename": filename,
            "content": docx_b64,
        }],
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=30.0,
        )
        logger.info(f"Resend response: {r.status_code} {r.text}")
        r.raise_for_status()
        return True
