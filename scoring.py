DOMAINS = {
    "data_encryption": {
        "label": "Data Classification & Encryption",
        "weight": 0.15,
        "questions": ["q1", "q2", "q3"],
    },
    "access_control": {
        "label": "Access Control & IAM",
        "weight": 0.15,
        "questions": ["q4", "q5", "q6"],
    },
    "incident_response": {
        "label": "Incident Response & Breach Notification",
        "weight": 0.12,
        "questions": ["q7", "q8"],
    },
    "third_party": {
        "label": "Third-Party / Supply Chain Risk",
        "weight": 0.12,
        "questions": ["q9", "q10"],
    },
    "vulnerability_mgmt": {
        "label": "Vulnerability & Patch Management",
        "weight": 0.10,
        "questions": ["q11", "q12", "q13"],
    },
    "compliance": {
        "label": "Compliance & Certifications",
        "weight": 0.10,
        "questions": ["q14", "q15", "q16"],
    },
    "business_continuity": {
        "label": "Business Continuity & DR",
        "weight": 0.10,
        "questions": ["q17", "q18"],
    },
    "security_awareness": {
        "label": "Security Awareness & Training",
        "weight": 0.08,
        "questions": ["q19", "q20"],
    },
    "network_security": {
        "label": "Network & Endpoint Security",
        "weight": 0.08,
        "questions": ["q21", "q22"],
    },
}

QUESTIONNAIRE = [
    {"id": "q1",  "domain": "data_encryption",    "text": "Does the vendor encrypt data at rest using AES-256 or equivalent?"},
    {"id": "q2",  "domain": "data_encryption",    "text": "Does the vendor enforce TLS 1.2+ for all data in transit?"},
    {"id": "q3",  "domain": "data_encryption",    "text": "Does the vendor maintain a formal data classification policy?"},
    {"id": "q4",  "domain": "access_control",     "text": "Does the vendor enforce MFA for all privileged and remote access?"},
    {"id": "q5",  "domain": "access_control",     "text": "Does the vendor apply least-privilege principles to all accounts?"},
    {"id": "q6",  "domain": "access_control",     "text": "Does the vendor conduct quarterly access reviews?"},
    {"id": "q7",  "domain": "incident_response",  "text": "Does the vendor have a documented and tested incident response plan?"},
    {"id": "q8",  "domain": "incident_response",  "text": "Does the vendor commit to breach notification within 72 hours?"},
    {"id": "q9",  "domain": "third_party",        "text": "Does the vendor conduct security assessments of their own sub-processors?"},
    {"id": "q10", "domain": "third_party",        "text": "Does the vendor maintain a formal vendor management program?"},
    {"id": "q11", "domain": "vulnerability_mgmt", "text": "Does the vendor conduct annual third-party penetration testing?"},
    {"id": "q12", "domain": "vulnerability_mgmt", "text": "Does the vendor patch critical vulnerabilities within 30 days?"},
    {"id": "q13", "domain": "vulnerability_mgmt", "text": "Does the vendor operate a vulnerability disclosure or bug bounty program?"},
    {"id": "q14", "domain": "compliance",         "text": "Does the vendor hold a current SOC 2 Type II report?"},
    {"id": "q15", "domain": "compliance",         "text": "Does the vendor hold ISO 27001 certification?"},
    {"id": "q16", "domain": "compliance",         "text": "Is the vendor compliant with applicable regulations (GDPR, HIPAA, PCI DSS)?"},
    {"id": "q17", "domain": "business_continuity","text": "Does the vendor have a documented Business Continuity Plan?"},
    {"id": "q18", "domain": "business_continuity","text": "Does the vendor conduct annual DR testing with documented results?"},
    {"id": "q19", "domain": "security_awareness", "text": "Does the vendor conduct annual security awareness training for all staff?"},
    {"id": "q20", "domain": "security_awareness", "text": "Does the vendor run regular phishing simulation exercises?"},
    {"id": "q21", "domain": "network_security",   "text": "Does the vendor deploy EDR/XDR on all endpoints?"},
    {"id": "q22", "domain": "network_security",   "text": "Does the vendor maintain network segmentation between environments?"},
]

ANSWER_SCORES = {"yes": 100.0, "partial": 50.0, "no": 0.0, "unknown": 10.0}

TIER_MAP = [
    (80, "ACCEPTABLE", "#22c55e"),
    (65, "LOW",        "#84cc16"),
    (45, "MEDIUM",     "#f59e0b"),
    (25, "HIGH",       "#f97316"),
    (0,  "CRITICAL",   "#ef4444"),
]

RECOMMENDATIONS = {
    "data_encryption": {
        "CRITICAL": ["Immediately implement AES-256 encryption for all data at rest", "Enforce TLS 1.3 for all data in transit", "Establish a data classification policy before sharing any sensitive data"],
        "HIGH":     ["Audit current encryption standards and upgrade legacy ciphers", "Implement a formal data classification policy", "Review key management procedures"],
        "MEDIUM":   ["Ensure encryption applies to all backups and archives", "Validate encryption coverage across cloud storage"],
    },
    "access_control": {
        "CRITICAL": ["Mandate MFA for all accounts immediately", "Conduct emergency access review — remove all orphaned accounts", "Implement PAM for privileged accounts"],
        "HIGH":     ["Deploy just-in-time access for administrative functions", "Enforce least-privilege across all service accounts", "Schedule immediate access certification"],
        "MEDIUM":   ["Implement quarterly access reviews", "Review service account permissions and rotate credentials"],
    },
    "incident_response": {
        "CRITICAL": ["Require vendor to produce a documented IR plan within 30 days", "Establish contractual 72-hour breach notification SLA", "Conduct tabletop exercise before expanding data sharing"],
        "HIGH":     ["Validate IR plan covers your data types and threat scenarios", "Confirm breach notification covers all applicable regulations"],
        "MEDIUM":   ["Request evidence of last IR tabletop exercise", "Confirm escalation paths and communication templates are current"],
    },
    "third_party": {
        "CRITICAL": ["Conduct immediate security assessment of all vendor sub-processors", "Require vendor to list all sub-processors with access to your data", "Mandate security requirements in all sub-processor contracts"],
        "HIGH":     ["Build vendor risk management program with annual reviews", "Require SOC 2 or equivalent from all sub-processors handling your data"],
        "MEDIUM":   ["Schedule annual vendor security reviews", "Audit sub-processor list for changes"],
    },
    "vulnerability_mgmt": {
        "CRITICAL": ["Require third-party penetration test results before proceeding", "Establish emergency patch SLA for CISA KEV items", "Deploy automated vulnerability scanning immediately"],
        "HIGH":     ["Implement 30-day SLA for critical vulnerability remediation", "Require evidence of patch management metrics"],
        "MEDIUM":   ["Establish or join a vulnerability disclosure program", "Review patch management cadence and metrics"],
    },
    "compliance": {
        "CRITICAL": ["Do not expand data sharing until SOC 2 Type II is obtained", "Conduct compliance gap assessment immediately", "Map vendor controls to your regulatory requirements"],
        "HIGH":     ["Establish vendor timeline for SOC 2 or ISO 27001 certification", "Request and review most recent audit findings"],
        "MEDIUM":   ["Verify regulatory compliance for your specific data types", "Confirm compliance scope covers systems handling your data"],
    },
    "business_continuity": {
        "CRITICAL": ["Require BCP documentation before proceeding", "Define contractual RTOs and RPOs", "Verify geographic redundancy for critical systems"],
        "HIGH":     ["Request evidence of annual DR test results", "Validate backup and recovery procedures cover your data"],
        "MEDIUM":   ["Confirm DR testing cadence and last test date", "Review SLA commitments and uptime guarantees"],
    },
    "security_awareness": {
        "CRITICAL": ["Require evidence of annual security training program", "Include mandatory security training in contract terms", "Request training completion rates for staff with access to your data"],
        "HIGH":     ["Request phishing simulation metrics and trend data", "Require training coverage for relevant threat vectors"],
        "MEDIUM":   ["Verify training is updated for current threat landscape", "Request security culture metrics or awareness program overview"],
    },
    "network_security": {
        "CRITICAL": ["Require immediate remediation of exposed high-risk services", "Demand evidence of EDR deployment across all endpoints", "Review network architecture before data integration"],
        "HIGH":     ["Require network segmentation between production and dev environments", "Confirm continuous network monitoring is in place"],
        "MEDIUM":   ["Verify firewall rule review cadence", "Confirm endpoint protection coverage and patch levels"],
    },
}


def score_to_tier(score: float):
    for threshold, tier, color in TIER_MAP:
        if score >= threshold:
            return tier, color
    return "CRITICAL", "#ef4444"


def compute_questionnaire_scores(answers: list) -> dict:
    answer_map = {a["question_id"]: a["answer"] for a in answers}
    scores = {}
    for domain_id, cfg in DOMAINS.items():
        domain_scores = [ANSWER_SCORES.get(answer_map.get(qid, "unknown"), 10.0) for qid in cfg["questions"]]
        scores[domain_id] = sum(domain_scores) / len(domain_scores)
    return scores


def compute_osint_scores(osint: dict) -> dict:
    scores = {d: 70.0 for d in DOMAINS}

    ssl_grade = osint.get("ssl_grade", "")
    ssl_map = {"A+": 100, "A": 92, "A-": 85, "B": 65, "C": 40, "D": 20, "F": 0, "T": 10, "M": 10}
    if ssl_grade in ssl_map:
        scores["data_encryption"] = float(ssl_map[ssl_grade])

    breach_count = int(osint.get("breach_count", 0))
    if breach_count > 0:
        scores["incident_response"] = max(5.0, 70.0 - (breach_count * 15))
        scores["data_encryption"] = max(5.0, scores["data_encryption"] - (breach_count * 10))

    vt_malicious = int(osint.get("vt_malicious", 0))
    vt_suspicious = int(osint.get("vt_suspicious", 0))
    if vt_malicious > 0:
        scores["network_security"] = max(0.0, 70.0 - (vt_malicious * 20))
    elif vt_suspicious > 0:
        scores["network_security"] = max(30.0, 70.0 - (vt_suspicious * 10))

    risky_ports = {21, 23, 3389, 5900, 445, 1433, 3306, 6379, 27017}
    exposed = [p for p in osint.get("exposed_ports", []) if p in risky_ports]
    if exposed:
        scores["network_security"] = max(5.0, scores["network_security"] - (len(exposed) * 15))

    negative_news = int(osint.get("negative_news_count", 0))
    if negative_news > 0:
        scores["incident_response"] = max(5.0, scores["incident_response"] - (negative_news * 8))
        scores["compliance"] = max(20.0, scores["compliance"] - (negative_news * 5))

    lawsuit_count = int(osint.get("lawsuit_count", 0))
    if lawsuit_count > 0:
        scores["compliance"] = max(5.0, scores["compliance"] - min(lawsuit_count * 12, 50))

    kev_matches = int(osint.get("kev_matches", 0))
    if kev_matches > 0:
        scores["vulnerability_mgmt"] = max(5.0, 70.0 - (kev_matches * 20))

    if osint.get("safe_browsing_threat"):
        scores["network_security"] = max(0.0, scores["network_security"] - 35)

    return scores


def combine_and_score(osint_scores: dict, questionnaire_scores: dict) -> tuple:
    osint_weight, q_weight = 0.60, 0.40
    domain_results = []
    weighted_total = 0.0

    for domain_id, cfg in DOMAINS.items():
        o_score = osint_scores.get(domain_id, 50.0)
        q_score = questionnaire_scores.get(domain_id, 10.0)
        combined = round((o_score * osint_weight) + (q_score * q_weight), 1)
        tier, _ = score_to_tier(combined)
        recs = RECOMMENDATIONS.get(domain_id, {}).get(tier, [])
        weighted_total += combined * cfg["weight"]
        domain_results.append({
            "domain_id": domain_id,
            "label": cfg["label"],
            "weight": cfg["weight"],
            "osint_score": round(o_score, 1),
            "questionnaire_score": round(q_score, 1),
            "combined_score": combined,
            "findings": [],
            "recommendations": recs,
        })

    overall = round(weighted_total, 1)
    tier, color = score_to_tier(overall)
    return overall, tier, color, domain_results
