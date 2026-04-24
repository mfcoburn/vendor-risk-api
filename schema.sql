-- Run this in Supabase SQL Editor (project: vendor-risk)

CREATE TABLE vendors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT UNIQUE NOT NULL,
    company_name    TEXT NOT NULL,
    osint_raw       JSONB,
    osint_fetched_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE assessments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID REFERENCES vendors(id),
    questionnaire       JSONB NOT NULL,
    osint_scores        JSONB NOT NULL,
    questionnaire_scores JSONB NOT NULL,
    domain_scores       JSONB NOT NULL,
    overall_score       NUMERIC NOT NULL,
    risk_tier           TEXT NOT NULL,
    recommendations     JSONB,
    claude_summary      TEXT,
    email_sent_to       TEXT[],
    email_sent_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vendors_domain ON vendors(domain);
CREATE INDEX idx_assessments_vendor ON assessments(vendor_id);
CREATE INDEX idx_assessments_created ON assessments(created_at DESC);
