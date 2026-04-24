from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class LookupRequest(BaseModel):
    company_name: str
    domain: Optional[str] = None


class LookupResponse(BaseModel):
    company_name: str
    domain: str
    registered: Optional[str] = None
    country: Optional[str] = None
    registrar: Optional[str] = None


class QuestionnaireAnswer(BaseModel):
    question_id: str
    answer: str  # "yes" | "partial" | "no" | "unknown"


class AssessRequest(BaseModel):
    company_name: str
    domain: str
    questionnaire: List[QuestionnaireAnswer]
    use_cached_osint: bool = True


class DomainScore(BaseModel):
    domain_id: str
    label: str
    weight: float
    osint_score: float
    questionnaire_score: float
    combined_score: float
    findings: List[str]
    recommendations: List[str]


class AssessResponse(BaseModel):
    assessment_id: str
    company_name: str
    domain: str
    overall_score: float
    risk_tier: str
    tier_color: str
    domain_scores: List[DomainScore]
    osint_findings: Dict[str, Any]
    claude_summary: str
    assessed_at: str


class ExportRequest(BaseModel):
    assessment_id: str


class EmailRequest(BaseModel):
    assessment_id: str
    recipient_email: str
    note: Optional[str] = None
