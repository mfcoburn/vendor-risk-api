import asyncio
import httpx
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

VIRUSTOTAL_KEY    = os.environ.get("VIRUSTOTAL_API_KEY")
SHODAN_KEY        = os.environ.get("SHODAN_API_KEY")
NEWS_API_KEY      = os.environ.get("NEWS_API_KEY")
SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
ANTHROPIC_KEY     = os.environ.get("ANTHROPIC_API_KEY")


async def fetch_ssl_grade(domain: str, client: httpx.AsyncClient) -> str:
    try:
        r = await client.get(
            "https://api.ssllabs.com/api/v3/analyze",
            params={"host": domain, "fromCache": "on", "maxAge": "168", "all": "done"},
            timeout=20.0,
        )
        if r.status_code == 200:
            data = r.json()
            endpoints = data.get("endpoints", [])
            if endpoints:
                return endpoints[0].get("grade", "")
    except Exception as e:
        logger.warning(f"SSL Labs error for {domain}: {e}")
    return ""


async def fetch_hibp_breaches(domain: str, client: httpx.AsyncClient) -> int:
    """Check public HIBP breach list for domain matches (no API key needed)."""
    try:
        r = await client.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"user-agent": "VendorRiskScorer/1.0"},
            timeout=15.0,
        )
        if r.status_code == 200:
            breaches = r.json()
            domain_root = domain.lower().split(".")[0]
            matches = [
                b for b in breaches
                if domain_root in b.get("Domain", "").lower()
                or domain_root in b.get("Name", "").lower()
            ]
            return len(matches)
    except Exception as e:
        logger.warning(f"HIBP error for {domain}: {e}")
    return 0


async def fetch_virustotal(domain: str, client: httpx.AsyncClient) -> dict:
    if not VIRUSTOTAL_KEY:
        return {}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=15.0,
        )
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
            }
    except Exception as e:
        logger.warning(f"VirusTotal error for {domain}: {e}")
    return {}


async def fetch_shodan(domain: str, client: httpx.AsyncClient) -> list:
    if not SHODAN_KEY:
        return []
    try:
        r = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={"query": f"hostname:{domain}", "key": SHODAN_KEY},
            timeout=15.0,
        )
        if r.status_code == 200:
            data = r.json()
            ports = list({m.get("port") for m in data.get("matches", []) if m.get("port")})
            return ports
    except Exception as e:
        logger.warning(f"Shodan error for {domain}: {e}")
    return []


async def fetch_negative_news(company: str, client: httpx.AsyncClient) -> int:
    if not NEWS_API_KEY:
        return 0
    try:
        r = await client.get(
            "https://newsapi.org/v2/everything",
            params={
                "q": f'"{company}" breach OR hack OR lawsuit OR fine OR penalty OR vulnerability',
                "sortBy": "publishedAt",
                "pageSize": 10,
                "apiKey": NEWS_API_KEY,
            },
            timeout=15.0,
        )
        if r.status_code == 200:
            return r.json().get("totalResults", 0)
    except Exception as e:
        logger.warning(f"NewsAPI error for {company}: {e}")
    return 0


async def fetch_courtlistener(company: str, client: httpx.AsyncClient) -> int:
    try:
        r = await client.get(
            "https://www.courtlistener.com/api/rest/v4/dockets/",
            params={"q": company, "order_by": "score desc", "page_size": 5},
            timeout=15.0,
        )
        if r.status_code == 200:
            return r.json().get("count", 0)
    except Exception as e:
        logger.warning(f"CourtListener error for {company}: {e}")
    return 0


async def fetch_cisa_kev(company: str, client: httpx.AsyncClient) -> int:
    """Check if vendor name appears in CISA Known Exploited Vulnerabilities."""
    try:
        r = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20.0,
        )
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            company_lower = company.lower()
            matches = [
                v for v in vulns
                if company_lower in v.get("vendorProject", "").lower()
            ]
            return len(matches)
    except Exception as e:
        logger.warning(f"CISA KEV error for {company}: {e}")
    return 0


async def fetch_safe_browsing(domain: str, client: httpx.AsyncClient) -> bool:
    if not SAFE_BROWSING_KEY:
        return False
    try:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}",
            json={
                "client": {"clientId": "vendor-risk-scorer", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"https://{domain}"}],
                },
            },
            timeout=10.0,
        )
        if r.status_code == 200:
            return bool(r.json().get("matches"))
    except Exception as e:
        logger.warning(f"Safe Browsing error for {domain}: {e}")
    return False


async def fetch_whois(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}", timeout=10.0)
        if r.status_code == 200:
            data = r.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            entities = data.get("entities", [])
            registrar = ""
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                registrar = field[3]
                                break
            return {
                "registered": events.get("registration", ""),
                "registrar": registrar,
            }
    except Exception as e:
        logger.warning(f"WHOIS error for {domain}: {e}")
    return {}


async def fetch_claude_intelligence(company: str, domain: str) -> dict:
    """Use Claude web search to gather supplemental OSINT: BBB, D&B, news, regulatory actions."""
    if not ANTHROPIC_KEY:
        return {"claude_findings": ""}
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            body = {
                "model": "claude-sonnet-4-5",
                "max_tokens": 1000,
                "tools": [{"type": "web_search_20250305", "name": "web_search"}],
                "messages": [{
                    "role": "user",
                    "content": f"""Search for security and business risk information about the company "{company}" (domain: {domain}).

Find and report on:
1. BBB rating and any complaint patterns
2. Any data breaches or security incidents in the past 3 years
3. Regulatory fines or enforcement actions
4. Major lawsuits related to data privacy or security
5. Any negative press about their security posture

Respond ONLY with a JSON object (no markdown):
{{
  "bbb_rating": "A+/A/B/C/D/F/NR or Not Found",
  "bbb_complaints": 0,
  "security_incidents": ["brief description of each"],
  "regulatory_actions": ["brief description of each"],
  "key_findings": "2-3 sentence summary of overall risk signals found"
}}"""
                }],
            }
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                    "anthropic-beta": "web-search-2025-03-05",
                },
                json=body,
            )
            data = r.json()
            text = " ".join(
                block["text"] for block in data.get("content", [])
                if block.get("type") == "text"
            )
            clean = text.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
    except Exception as e:
        logger.warning(f"Claude intelligence error: {e}")
    return {"claude_findings": "Unable to retrieve supplemental intelligence."}


async def gather_all(company: str, domain: str) -> dict:
    """Run all OSINT sources in parallel and return combined findings."""
    logger.info(f"Starting OSINT for {company} ({domain})")

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            fetch_ssl_grade(domain, client),
            fetch_hibp_breaches(domain, client),
            fetch_virustotal(domain, client),
            fetch_shodan(domain, client),
            fetch_negative_news(company, client),
            fetch_courtlistener(company, client),
            fetch_cisa_kev(company, client),
            fetch_safe_browsing(domain, client),
            fetch_whois(domain, client),
            return_exceptions=True,
        )

    ssl_grade, breach_count, vt_data, exposed_ports, \
    negative_news, lawsuit_count, kev_matches, safe_browsing_threat, whois_data = [
        r if not isinstance(r, Exception) else None for r in results
    ]

    claude_data = await fetch_claude_intelligence(company, domain)

    osint = {
        "ssl_grade":            ssl_grade or "",
        "breach_count":         breach_count or 0,
        "vt_malicious":         (vt_data or {}).get("vt_malicious", 0),
        "vt_suspicious":        (vt_data or {}).get("vt_suspicious", 0),
        "exposed_ports":        exposed_ports or [],
        "negative_news_count":  negative_news or 0,
        "lawsuit_count":        lawsuit_count or 0,
        "kev_matches":          kev_matches or 0,
        "safe_browsing_threat": safe_browsing_threat or False,
        "registered":           (whois_data or {}).get("registered", ""),
        "registrar":            (whois_data or {}).get("registrar", ""),
        "bbb_rating":           claude_data.get("bbb_rating", "Not Found"),
        "bbb_complaints":       claude_data.get("bbb_complaints", 0),
        "security_incidents":   claude_data.get("security_incidents", []),
        "regulatory_actions":   claude_data.get("regulatory_actions", []),
        "key_findings":         claude_data.get("key_findings", ""),
        "fetched_at":           datetime.utcnow().isoformat(),
    }

    logger.info(f"OSINT complete for {domain}: {osint}")
    return osint
