from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import httpx
import json
import os
import logging
from datetime import datetime, timezone, timedelta

from models import (
    LookupRequest, LookupResponse,
    AssessRequest, AssessResponse, DomainScore,
    ExportRequest, EmailRequest,
)
from osint import gather_all
from scoring import (
    QUESTIONNAIRE, compute_questionnaire_scores,
    compute_osint_scores, combine_and_score,
)
from report import build_docx
from email_service import send_report

from supabase import create_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SUPABASE_URL  = os.environ.get("SUPABASE_URL")
SUPABASE_KEY  = os.environ.get("SUPABASE_KEY")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

app = FastAPI(title="Vendor Risk Scorer API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://www.coburn.org", "https://coburn.org", "http://localhost"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "Vendor Risk Scorer online", "version": "1.0.0"}


# ── Company Lookup ────────────────────────────────────────────────────────────

@app.post("/api/lookup", response_model=LookupResponse)
async def lookup(req: LookupRequest):
    domain = req.domain or _infer_domain(req.company_name)
    whois_info = {}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}")
            if r.status_code == 200:
                data = r.json()
                events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                whois_info["registered"] = events.get("registration", "")
    except Exception:
        pass

    return LookupResponse(
        company_name=req.company_name,
        domain=domain,
        registered=whois_info.get("registered"),
    )


def _infer_domain(company_name: str) -> str:
    clean = company_name.lower().strip()
    remove = ["inc", "llc", "ltd", "corp", "corporation", "the", "co", "company"]
    parts = [w for w in clean.split() if w not in remove]
    slug = "".join(parts[:2])
    return f"{slug}.com"


# ── Full Assessment ───────────────────────────────────────────────────────────

@app.post("/api/assess", response_model=AssessResponse)
async def assess(req: AssessRequest):
    domain   = req.domain.lower().strip()
    company  = req.company_name.strip()

    # Check Supabase cache (30-day TTL)
    osint_data = None
    vendor_id  = None

    if supabase and req.use_cached_osint:
        cached = supabase.table("vendors").select("*").eq("domain", domain).execute()
        if cached.data:
            vendor = cached.data[0]
            vendor_id = vendor["id"]
            fetched_at = vendor.get("osint_fetched_at")
            if fetched_at:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
                if age < timedelta(days=30):
                    osint_data = vendor.get("osint_raw")
                    logger.info(f"Using cached OSINT for {domain} (age: {age})")

    if osint_data is None:
        logger.info(f"Fetching fresh OSINT for {domain}")
        osint_data = await gather_all(company, domain)

        if supabase:
            upsert_result = supabase.table("vendors").upsert({
                "domain":           domain,
                "company_name":     company,
                "osint_raw":        osint_data,
                "osint_fetched_at": datetime.utcnow().isoformat(),
            }, on_conflict="domain").execute()
            if upsert_result.data:
                vendor_id = upsert_result.data[0]["id"]

    # Score
    questionnaire_answers = [{"question_id": a.question_id, "answer": a.answer} for a in req.questionnaire]
    osint_scores          = compute_osint_scores(osint_data)
    questionnaire_scores  = compute_questionnaire_scores(questionnaire_answers)
    overall_score, tier, tier_color, domain_results = combine_and_score(osint_scores, questionnaire_scores)

    # Claude executive summary
    claude_summary = await _generate_summary(company, domain, overall_score, tier, osint_data, domain_results)

    # Store assessment
    assessment_id = None
    if supabase:
        a_result = supabase.table("assessments").insert({
            "vendor_id":            vendor_id,
            "questionnaire":        questionnaire_answers,
            "osint_scores":         osint_scores,
            "questionnaire_scores": questionnaire_scores,
            "domain_scores":        domain_results,
            "overall_score":        overall_score,
            "risk_tier":            tier,
            "claude_summary":       claude_summary,
        }).execute()
        if a_result.data:
            assessment_id = a_result.data[0]["id"]

    assessment_id = assessment_id or "preview"

    response = AssessResponse(
        assessment_id=assessment_id,
        company_name=company,
        domain=domain,
        overall_score=overall_score,
        risk_tier=tier,
        tier_color=tier_color,
        domain_scores=[DomainScore(**ds) for ds in domain_results],
        osint_findings=osint_data,
        claude_summary=claude_summary,
        assessed_at=datetime.utcnow().isoformat(),
    )

    return response


async def _generate_summary(company, domain, score, tier, osint, domain_results) -> str:
    if not ANTHROPIC_KEY:
        return f"{company} received an overall vendor risk score of {score}/100, placing them in the {tier} risk tier."

    top_concerns = [
        f"{ds['label']} ({ds['combined_score']:.0f}/100)"
        for ds in sorted(domain_results, key=lambda x: x["combined_score"])[:3]
    ]

    prompt = f"""Write a concise 3-sentence executive summary for a vendor security risk assessment.

Vendor: {company} ({domain})
Overall Score: {score}/100
Risk Tier: {tier}
Top Risk Areas: {', '.join(top_concerns)}
Key OSINT Signals:
- SSL Grade: {osint.get('ssl_grade', 'N/A')}
- Known Breaches: {osint.get('breach_count', 0)}
- Negative News: {osint.get('negative_news_count', 0)} results
- Lawsuits: {osint.get('lawsuit_count', 0)}
- BBB Rating: {osint.get('bbb_rating', 'N/A')}
- Key Findings: {osint.get('key_findings', 'None')}

Write the summary in a professional, direct tone suitable for a CISO briefing.
Do not use markdown. Plain text only."""

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": "claude-sonnet-4-5", "max_tokens": 300, "messages": [{"role": "user", "content": prompt}]},
            )
            data = r.json()
            return " ".join(b["text"] for b in data.get("content", []) if b.get("type") == "text")
    except Exception as e:
        logger.warning(f"Claude summary error: {e}")
        return f"{company} received an overall vendor risk score of {score}/100, placing them in the {tier} risk tier. Review domain scores and recommendations below."


# ── Export .docx ──────────────────────────────────────────────────────────────

@app.post("/api/export")
async def export(req: ExportRequest):
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    result = supabase.table("assessments").select("*, vendors(*)").eq("id", req.assessment_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Assessment not found")

    row    = result.data[0]
    vendor = row.get("vendors", {}) or {}

    assessment = {
        "assessment_id": row["id"],
        "company_name":  vendor.get("company_name", "Unknown"),
        "domain":        vendor.get("domain", ""),
        "overall_score": float(row["overall_score"]),
        "risk_tier":     row["risk_tier"],
        "domain_scores": row["domain_scores"],
        "osint_findings": vendor.get("osint_raw", {}),
        "claude_summary": row.get("claude_summary", ""),
    }

    docx_bytes = build_docx(assessment)
    filename   = f"VendorRisk_{assessment['company_name'].replace(' ', '_')}_{assessment['risk_tier']}.docx"

    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Email Report ──────────────────────────────────────────────────────────────

@app.post("/api/email")
async def email_report(req: EmailRequest):
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")

    result = supabase.table("assessments").select("*, vendors(*)").eq("id", req.assessment_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Assessment not found")

    row    = result.data[0]
    vendor = row.get("vendors", {}) or {}

    assessment = {
        "assessment_id": row["id"],
        "company_name":  vendor.get("company_name", "Unknown"),
        "domain":        vendor.get("domain", ""),
        "overall_score": float(row["overall_score"]),
        "risk_tier":     row["risk_tier"],
        "domain_scores": row["domain_scores"],
        "osint_findings": vendor.get("osint_raw", {}),
        "claude_summary": row.get("claude_summary", ""),
    }

    success = await send_report(assessment, req.recipient_email, req.note or "")
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send email")

    # Record send
    supabase.table("assessments").update({
        "email_sent_to": [req.recipient_email],
        "email_sent_at": datetime.utcnow().isoformat(),
    }).eq("id", req.assessment_id).execute()

    return {"status": "sent", "recipient": req.recipient_email}


# ── Questionnaire Definition ──────────────────────────────────────────────────

@app.get("/api/questionnaire")
def get_questionnaire():
    return QUESTIONNAIRE
