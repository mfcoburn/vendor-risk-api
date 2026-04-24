# Vendor Risk Scorer — Architecture

## System Flow

```
coburn.org/tools-vendor-risk.html (Vercel)
        ↓ POST /api/assess
GCP Cloud Run (FastAPI, Python 3.12, 512Mi)
        ↓ parallel async
OSINT Sources (10 sources)          Supabase (cache + storage)
        ↓
Claude API — claude-sonnet-4-5 (executive summary)
        ↓
Results → screen + .docx download + Resend email
```

## GCP Resources

| Resource        | Name                 | Region      |
|-----------------|----------------------|-------------|
| Project         | vendor-risk-coburn   | —           |
| Cloud Run       | vendor-risk-api      | us-central1 |
| Service Account | vendor-risk-runner   | —           |
| Secret          | ANTHROPIC_API_KEY    | global      |
| Secret          | RESEND_API_KEY       | global      |
| Secret          | SUPABASE_URL         | global      |
| Secret          | SUPABASE_KEY         | global      |
| Secret          | VIRUSTOTAL_API_KEY   | global      |
| Secret          | SHODAN_API_KEY       | global      |
| Secret          | NEWS_API_KEY         | global      |
| Secret          | GOOGLE_SAFE_BROWSING_KEY | global  |

## Scoring Model

| Stream          | Weight |
|-----------------|--------|
| OSINT signals   | 60%    |
| Questionnaire   | 40%    |

### Risk Tiers
| Score   | Tier       |
|---------|------------|
| 80–100  | ACCEPTABLE |
| 65–79   | LOW        |
| 45–64   | MEDIUM     |
| 25–44   | HIGH       |
| 0–24    | CRITICAL   |

## OSINT Sources

| Source           | Key Required | Notes                        |
|------------------|-------------|------------------------------|
| SSL Labs         | No          | fromCache=on, 7-day max age  |
| HIBP (public)    | No          | Public breach list only      |
| VirusTotal       | Yes (free)  | VIRUSTOTAL_API_KEY           |
| Shodan           | Yes (free)  | SHODAN_API_KEY               |
| NewsAPI          | Yes (free)  | NEWS_API_KEY                 |
| CourtListener    | No          | Federal dockets              |
| CISA KEV         | No          | Known exploited vulns        |
| Google Safe Browse | Yes (free) | GOOGLE_SAFE_BROWSING_KEY    |
| RDAP/WHOIS       | No          | Domain registration          |
| Claude Web Search| Yes         | ANTHROPIC_API_KEY — BBB, D&B, news |

## Database (Supabase)

- `vendors` — cached OSINT per domain (30-day TTL)
- `assessments` — full assessment records with scores and recommendations

## Why These Choices

**Cloud Run:** Same infrastructure as sentinel-coburn. FedRAMP-authorized,
scales to zero, no idle cost.

**Supabase:** Free tier sufficient for demo/internal use. Postgres with
REST API avoids writing a custom ORM layer.

**Resend:** Already proven in Sentinel — coburn.org domain verified,
consistent deliverability.

**OSINT-first design:** 60% of the score comes from automated intelligence
the user never has to gather manually. The questionnaire (40%) captures
what only the user knows from vendor conversations.
