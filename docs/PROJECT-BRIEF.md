# Project Brief: Anisakys Anti-Phishing Detection Engine

**Version**: 1.2.0
**Status**: Production - Stabilized
**Classification**: Blue Team Security Tool
**Created**: 2025-11-21
**Last Updated**: 2026-01-25

---

## Executive Summary

**Anisakys** is an enterprise-grade automated phishing detection and reporting engine designed for blue teams, SOC analysts, and cybersecurity professionals. The system provides comprehensive threat hunting capabilities with full ICANN compliance for abuse reporting.

The project has undergone **significant stabilization and enhancement** (Nov 2025 - Jan 2026), successfully addressing the critical issues identified in the initial assessment. The core architecture has been modularized, redirect detection implemented, and comprehensive testing added.

### Related Projects

- **cloud-adm-anisakys**: Microservicio frontend que se comunica con la API REST de Anisakys

---

## Project Context

### Current State

- **Production Status**: System operational and stabilized
- **Version**: 1.2.0 (Python 3.12+)
- **Repository**: https://github.com/JuanVilla424/anisakys
- **License**: GPL-3.0
- **Tech Stack**: Python, PostgreSQL, Flask, SQLAlchemy
- **Current Branch**: `dev`
- **Production Path**: `/opt/anisakys/`
- **Service**: `systemd anisakys-api`

### Stabilization Completed (Jan 2026)

| Achievement                | Details                                              |
| -------------------------- | ---------------------------------------------------- |
| **main.py Modularization** | Reduced from 7,389 → 1,258 LOC (-83%)                |
| **Modules Extracted**      | 14 specialized modules created                       |
| **Test Suite**             | 5,578 LOC across 29 test files                       |
| **Redirect Detection**     | Fully implemented (330 LOC)                          |
| **Structured Logging**     | JSON logs with correlation IDs (313 LOC)             |
| **Circuit Breakers**       | Production-ready implementation (309 LOC)            |
| **URL Lexical Analysis**   | Typosquatting, homoglyphs, keywords (767 LOC)        |
| **Google Safe Browsing**   | API v4 integration (219 LOC)                         |
| **GSB Re-scan Job**        | Periodic re-verification of existing sites (280 LOC) |

### Business Criticality

This tool is being positioned as a **professional security arm** for the organization's blue team operations. The system's reliability and effectiveness are paramount as it directly impacts:

- Real-time phishing threat detection
- ICANN compliance reporting
- SOC operational efficiency
- Organizational security posture

---

## Problem Statement (Original) & Resolution Status

### 1. **Threat Actor Evolution** (Critical) - ✅ RESOLVED

**Original Issue**: Attackers evolved tactics using sophisticated redirection techniques.

**Resolution**: Implemented `src/detection/redirect_analyzer.py`:

- Follows up to 5 redirect hops
- Detects Cloudflare intermediaries
- Calculates risk score (0-100)
- Detects URL shorteners and cross-domain redirects
- Full test coverage in `tests/detection/test_redirect_analyzer.py`

### 2. **Database Integrity Issues** (High) - ✅ RESOLVED

**Original Issue**: Duplicate records and constraint violations.

**Resolution**:

- Upsert logic implemented in `src/reporting/report_tracker.py`
- Database constraints added
- Enhanced `src/database/manager.py` module

### 3. **Abuse Contact Discovery** (High) - ✅ IMPROVED

**Original Issue**: Cannot reliably identify abuse contacts.

**Resolution**:

- `src/intelligence/abuse_contact_resolver.py` (334 LOC)
- `src/reporting/email_detector.py` (840 LOC)
- Enhanced WHOIS parsing
- Full test coverage in `tests/intelligence/test_abuse_contact_resolver.py`

### 4. **Multi-API Detection Accuracy** (Medium) - ✅ ENHANCED

**Original Issue**: Inconsistent API integrations.

**Resolution**:

- Circuit breakers implemented (`src/circuit_breaker.py`)
- Modular API clients in `src/intelligence/`:
  - `virustotal.py`, `urlvoid.py`, `phishtank.py`
  - **NEW**: `google_safe_browsing.py` (API v4)
- `multi_api_validator.py` orchestrates all APIs
- URL lexical analysis in `src/detection/url_analyzer.py`

### 5. **Operational Logging & Monitoring** (Medium) - ✅ RESOLVED

**Original Issue**: Insufficient logging.

**Resolution**: `src/observability/structured_logger.py`:

- JSON-formatted logs
- Correlation IDs for request tracing
- Log rotation (50MB max, 30 backups)
- Contextual logging functions

---

## Remaining Issues / Backlog

### 1. **Google Safe Browsing Reporting** (Medium) - ✅ RESOLVED (Jan 2026)

**Issue**: GSB integration only queries threats, does not report new phishing URLs.

**Resolution**: Implemented `src/intelligence/gsb_reporter.py` (280 LOC):

- Dual-strategy: crx-report API (free) with Web Risk API fallback
- Automatic submission when abuse reports are sent
- API endpoint: `POST /api/v1/gsb/report`
- Supports optional screenshot attachment

### 2. **GSB Re-scan Job** (Medium) - ✅ RESOLVED (Jan 2026)

**Issue**: Sites not in GSB initially might be added later, status changes missed.

**Resolution**: Implemented `src/monitoring/gsb_rescan.py` (280 LOC):

- Background job runs every 12 hours
- Re-verifies existing sites against GSB API
- Alerts on status changes (safe → threat)
- Database tracking: gsb_result, gsb_threat_type, gsb_last_check, gsb_safe columns
- API endpoints: `/api/v1/gsb/rescan`, `/api/v1/gsb/status`, `/api/v1/gsb/check`

---

## Technical Architecture

### Core Components

```mermaid
graph TB
    A[Domain Generation Engine] --> B[Multi-API Threat Scanner]
    B --> C[Confidence Scoring]
    C --> D{Auto-Report Threshold}
    D -->|>85%| E[Automated ICANN Reporting]
    D -->|70-85%| F[Manual Review Queue]
    E --> G[Report Tracker]
    F --> G
    G --> H[Follow-up System]

    I[REST API Server] --> B
    J[Screenshot Service] --> E
    K[PostgreSQL DB] --> G

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#fff8e1
    style E fill:#e8f5e8
    style G fill:#ffebee
```

### Technology Stack

| Layer             | Technology            | Purpose                  |
| ----------------- | --------------------- | ------------------------ |
| **Runtime**       | Python 3.12+          | Core application logic   |
| **Database**      | PostgreSQL 12+        | Primary data persistence |
| **Web Framework** | Flask                 | REST API server          |
| **ORM**           | SQLAlchemy            | Database abstraction     |
| **Email**         | SMTP (configurable)   | Abuse report delivery    |
| **Templating**    | Jinja2                | Email template rendering |
| **WHOIS**         | python-whois, ipwhois | Domain/IP intelligence   |
| **DNS**           | dnspython             | DNS resolution           |
| **HTTP**          | requests, psutil      | Web scanning             |
| **Rate Limiting** | flask-limiter         | API protection           |
| **Validation**    | validators, pydantic  | Data validation          |

### Database Schema (Key Tables)

**phishing_sites**

- Core detection records
- Status tracking (active/down/timeout)
- Confidence scores
- Multi-API results

**abuse_reports**

- ICANN-compliant report tracking
- SLA deadline monitoring (2 business days)
- Response tracking
- Escalation management

**Relationships**

- Foreign key: `abuse_reports.site_id` → `phishing_sites.id`

### Key Modules (Updated Jan 2026)

```
src/
├── main.py                    # Slim orchestrator (1,258 LOC, -83% from original)
├── config.py                  # Pydantic settings management
├── circuit_breaker.py         # 🆕 API resilience (309 LOC)
│
├── detection/                 # 🆕 Modularized detection engine
│   ├── url_analyzer.py        # Typosquatting, homoglyphs, keywords (767 LOC)
│   ├── redirect_analyzer.py   # 5-hop redirect chain analysis (330 LOC)
│   ├── scanner.py             # Core scanning logic (536 LOC)
│   ├── analyzer.py            # Content analysis (469 LOC)
│   ├── google_ads_detector.py # Phishing detection in Google Ads (1,177 LOC)
│   └── utils.py               # Detection utilities (185 LOC)
│
├── intelligence/              # 🆕 Modularized API integrations
│   ├── multi_api_validator.py # API orchestrator (566 LOC)
│   ├── virustotal.py          # VirusTotal client (255 LOC)
│   ├── urlvoid.py             # URLVoid client (178 LOC)
│   ├── phishtank.py           # PhishTank client (183 LOC)
│   ├── google_safe_browsing.py# 🆕 GSB API v4 (219 LOC)
│   ├── grinder.py             # Grinder integration (438 LOC)
│   └── abuse_contact_resolver.py # Contact resolution (334 LOC)
│
├── observability/             # 🆕 Production monitoring
│   └── structured_logger.py   # JSON logs + correlation IDs (313 LOC)
│
├── reporting/                 # 🆕 Modularized reporting + ICANN compliance
│   ├── abuse_manager.py           # Abuse report management (1,870 LOC)
│   ├── email_detector.py          # Email discovery (840 LOC)
│   ├── report_tracker.py          # ICANN compliance tracking (936 LOC)
│   └── abuse_contact_validator.py # Email validation for abuse contacts (430 LOC)
│
├── api/                       # REST API
│   └── phishing_api.py        # Flask API server (747 LOC)
│
├── database/                  # 🆕 Database layer
│   └── manager.py             # DB operations (518 LOC)
│
├── data/                      # 🆕 Static data
│   ├── asn_abuse_db.py        # ASN → abuse email mapping
│   ├── provider_abuse_db.py   # Provider → abuse email mapping
│   └── whois_servers.py       # WHOIS server list
│
├── monitoring/                # Site monitoring
│   ├── takedown.py            # Takedown tracking (126 LOC)
│   └── gsb_rescan.py          # 🆕 GSB re-verification job (280 LOC)
│
├── generators/                # Query generation
│   └── query_generator.py     # Domain permutations
│
├── models/                    # Data models
│   └── config.py              # Configuration models (131 LOC)
│
├── screenshot_service.py      # Visual evidence capture (417 LOC)
└── shutdown.py                # Graceful shutdown handler
```

**Total Source LOC**: ~14,434 lines (modularized)

---

## Current Capabilities

### Detection Engine

- **Domain Generation**: Permutation-based keyword expansion (180 concurrent threads)
- **DNS Validation**: Smart retry logic with failure pattern detection
- **Content Analysis**: ML-enhanced pattern recognition
- **Multi-API Scanning**: Parallel queries to 3+ threat intelligence sources
- **Confidence Scoring**: 0-100% aggregated threat assessment

### Abuse Reporting

- **Enhanced Email Discovery**: Multi-source abuse contact resolution
  - ASN-based lookup (309 providers mapped)
  - Provider name matching
  - WHOIS parsing with fallback strategies
  - Cloudflare-specific handling

- **ICANN Compliance**:
  - 2-day SLA tracking
  - Multi-level CC escalation
  - Professional email templates (Jinja2)
  - Complete audit trail

- **Screenshot Capture**: Visual evidence attachment

### REST API

- **External Integration**: Bearer token authentication
- **Endpoints**:
  - `POST /api/v1/report` - Submit phishing reports
  - `POST /api/v1/multi-scan` - Multi-API validation
  - `GET /api/v1/status/<url>` - Report status check
  - `GET /api/v1/stats` - System statistics
  - `GET /api/v1/health` - Health monitoring
  - `POST /api/v1/gsb/rescan` - 🆕 Trigger manual GSB re-scan
  - `GET /api/v1/gsb/status` - 🆕 GSB job stats and recent threats
  - `POST /api/v1/gsb/check` - 🆕 Check single URL against GSB
  - `POST /api/v1/gsb/report` - 🆕 Report phishing URL to GSB

### Automation

- **Auto-Analysis Queue**: Background processing of detected threats
- **Configurable Thresholds**:
  - Auto-report: ≥85% confidence
  - Manual review: 70-84% confidence
- **Priority-Based Processing**: High/Medium/Low prioritization

---

## Known Issues (Prioritized)

### P0 - Critical

1. **[REDIRECT-DETECTION]** Redirection chain analysis not implemented
   - **Impact**: Missing advanced phishing campaigns
   - **Affected**: Core detection engine
   - **Workaround**: None currently

### P1 - High

2. **[DB-DUPLICATES]** Report duplication in abuse_reports table
   - **Impact**: Data integrity, inaccurate metrics
   - **Affected**: `src/reporting/report_tracker.py`
   - **Status**: Partially fixed with upsert logic (pending testing)
   - **File**: src/reporting/report_tracker.py:339-463

3. **[ABUSE-CONTACT-MULTI]** Multiple abuse contacts not handled properly
   - **Impact**: Incomplete reporting
   - **Affected**: `src/reporting/abuse_contact_validator.py`
   - **Workaround**: Manual intervention

4. **[LOGGING-PROD]** Production logging insufficient for troubleshooting
   - **Impact**: Difficult post-mortem analysis
   - **Affected**: Entire system
   - **Workaround**: None

### P2 - Medium

5. **[API-RELIABILITY]** Multi-API timeout and rate limit handling
   - **Impact**: Inconsistent threat assessments
   - **Affected**: `src/main.py` (API integration layer)

6. **[WHOIS-PARSING]** Non-standard WHOIS responses fail to parse
   - **Impact**: Missing abuse contacts
   - **Affected**: `src/reporting/abuse_contact_validator.py`

---

## Technical Debt (Updated Jan 2026)

### Resolved ✅

1. ~~**Monolithic main.py**~~: Reduced from 7,389 → 1,258 LOC (-83%)
2. ~~**Limited test coverage**~~: Now 5,578 LOC across 29 test files
3. ~~**No structured logging**~~: JSON logs with correlation IDs implemented
4. ~~**No circuit breakers**~~: Full implementation with retry/backoff
5. ~~**No redirect detection**~~: 5-hop analysis with risk scoring

### Remaining

1. **Documentation drift**: Docs lagged behind implementation (being addressed)
2. **Coverage metrics**: Need to run `pytest --cov` to get exact percentage
3. **GSB reporting**: Only queries, doesn't report new phishing URLs to Google
4. **API documentation**: OpenAPI/Swagger docs for REST API not generated

---

## Dependencies

### Production Dependencies

```toml
python = "^3.12"
setuptools = "^75.2.0"
idna = "^3.0"
certifi = "^2025.1.31"
bump2version = "^1.0.0"
requests = "~2.32.3"
pydantic = ">=2.9.1"
pydantic-settings = ">=2.0.0"
python-whois = ">=0.9.4"
jinja2 = ">=3.1.6"
ipwhois = ">=1.2.0"
psutil = ">=6.1.1"
sqlalchemy = "*"
psycopg2-binary = "*"
```

### Development Dependencies

```toml
pre-commit = "^4.0.0"
pylint = "^3.3.0"
yamllint = "^1.35.0"
isort = "^6.0.0"
toml = "^0.10.0"
black = "^25.1.0"
pytest = "^8.3.1"
pytest-cov = "^6.0.0"
coverage = "^7.2.5"
```

---

## Configuration Requirements

### Environment Variables (Critical)

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/anisakys

# Core Settings
KEYWORDS=bank,login,verify,secure,account
DOMAINS=.com,.net,.org,.info
TIMEOUT=30

# SMTP
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
ABUSE_EMAIL_SENDER=reports@yourorg.com

# API Keys (Optional but Recommended)
VIRUSTOTAL_API_KEY=your_key
URLVOID_API_KEY=your_key
PHISHTANK_API_KEY=your_key

# Auto-Analysis
AUTO_MULTI_API_SCAN=true
AUTO_REPORT_THRESHOLD_CONFIDENCE=85
MANUAL_REVIEW_THRESHOLD_CONFIDENCE=70
```

---

## Success Criteria (Status as of Jan 2026)

### Immediate Stabilization (Sprint 1-2) - ✅ COMPLETE

- [x] **Redirect Detection**: Implemented in `src/detection/redirect_analyzer.py` (5 hops)
- [x] **Database Integrity**: Upsert logic + constraints implemented
- [x] **Logging Infrastructure**: JSON structured logging with rotation
- [x] **Abuse Contact Accuracy**: Enhanced resolver + email detector

### Professional Hardening (Sprint 3-4) - ✅ MOSTLY COMPLETE

- [x] **Test Coverage**: 5,578 LOC tests (need to verify % coverage)
- [x] **API Reliability**: Circuit breakers with exponential backoff
- [ ] **Monitoring**: Prometheus metrics + Grafana dashboards (pending)
- [x] **Documentation**: Architecture docs exist (this update syncs them)

### Advanced Capabilities (Sprint 5+) - 🔄 IN PROGRESS

- [x] **URL Lexical Analysis**: Typosquatting, homoglyphs, keywords detection
- [x] **Google Safe Browsing**: API v4 query integration
- [ ] **GSB Reporting**: Submit detected URLs to Google (pending)
- [x] **Grinder Integration**: Implemented in `src/intelligence/grinder.py`
- [ ] **Multi-Tenant**: Not started
- [ ] **Executive Dashboards**: Not started

---

## Stakeholders

| Role                    | Responsibility                   | Contact         |
| ----------------------- | -------------------------------- | --------------- |
| **Security Operations** | Primary user, threat hunting     | SOC Team        |
| **Development**         | System maintenance, enhancements | Dev Team        |
| **Compliance**          | ICANN reporting requirements     | Compliance Team |
| **Infrastructure**      | Database, hosting, monitoring    | Ops Team        |

---

## Next Steps (Updated Jan 2026)

### Completed Phases ✅

~~**Phase 1: Discovery & Stabilization**~~ - DONE
~~**Phase 2: Core Fixes**~~ - DONE
~~**Phase 3: Quality Assurance**~~ - MOSTLY DONE

### Current Phase: Enhancement & Monitoring

1. **Google Safe Browsing Reporting** (Priority: Medium)
   - Implement URL submission to GSB API
   - Add reporting for verified phishing URLs
   - Track submission status

2. **GSB Query Validation** (Priority: Low)
   - Add logging to verify GSB API responses
   - Monitor for false negatives
   - Compare GSB vs other API results

3. **Test Coverage Metrics** (Priority: Medium)
   - Run `pytest --cov=src --cov-report=html`
   - Identify gaps in coverage
   - Add tests for uncovered paths

4. **Prometheus Metrics** (Priority: Low)
   - Add metrics endpoint
   - Track: scans/min, detections, API latencies
   - Configure Grafana dashboards

5. **Documentation Sync** (Priority: High) - IN PROGRESS
   - ✅ Update PROJECT-BRIEF.md
   - Update BACKLOG.md
   - Update CONTEXT.md

---

## Risk Assessment

| Risk                     | Probability | Impact   | Mitigation                                                |
| ------------------------ | ----------- | -------- | --------------------------------------------------------- |
| **Threat Actor Evasion** | High        | Critical | Implement redirect detection, enhance ML patterns         |
| **Database Corruption**  | Medium      | High     | Add comprehensive backup strategy, transaction safeguards |
| **API Rate Limiting**    | Medium      | Medium   | Implement request queuing, multi-account rotation         |
| **False Positives**      | Medium      | High     | Enhance confidence scoring, add manual review queue       |
| **Scalability Issues**   | Low         | Medium   | Performance profiling, horizontal scaling design          |

---

## Budget Considerations

### Development Effort Estimate

- **Phase 1** (Discovery): 2 weeks, 1 senior developer
- **Phase 2** (Core Fixes): 2 weeks, 1 senior + 1 mid-level developer
- **Phase 3** (QA & Docs): 2 weeks, 1 QA engineer + 1 technical writer

### Infrastructure Costs (Monthly)

- PostgreSQL hosting: ~$50-100
- API subscriptions (VT, URLVoid): ~$150-300
- Monitoring (Grafana Cloud): ~$50
- **Total**: ~$250-450/month

---

## Appendix

### A. Repository Structure

```
anisakys/
├── .ai/                    # BMAD agent configurations
├── .claude/                # Claude Code configurations
├── attachments/            # Email attachments storage
├── database/               # Database migrations & schemas
├── docs/                   # Documentation
├── logs/                   # Application logs
├── protocols/              # BMAD protocols
├── screenshots/            # Screenshot evidence
├── scripts/                # Automation scripts
├── src/                    # Source code
├── temp/                   # Temporary files
├── templates/              # Email templates
├── tests/                  # Test suite
├── .env                    # Environment configuration
├── .gitignore              # Git ignore rules
├── anisakys.py             # Main entry point
├── pyproject.toml          # Poetry configuration
├── README.md               # Project README
└── requirements.txt        # Pip dependencies
```

### B. Git Workflow

- **Main Branch**: `main` (production-ready code)
- **Development Branch**: `dev` (active development)
- **Feature Branches**: `feature/<name>` (new features)
- **Bugfix Branches**: `fix/<issue>` (bug fixes)
- **Versioning**: Semantic versioning (bump2version)

### C. Key Contacts & Resources

- **Repository**: https://github.com/JuanVilla424/anisakys
- **Issue Tracker**: GitHub Issues
- **Commit Convention**: Conventional Commits with gitmoji
- **Code Style**: Black formatter, Pylint, isort

---

**Document Control**
Last Review: 2026-01-25
Next Review: 2026-02-15
Owner: Security Operations Team
Classification: Internal Use Only

---

## Changelog

| Date       | Version | Changes                                                                                                                                |
| ---------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-01-25 | 1.2.0   | Major update: Documented all stabilization work completed Nov 2025 - Jan 2026. Added new modules, resolved issues, updated next steps. |
| 2025-11-21 | 1.1.0   | Initial assessment of stabilization needs                                                                                              |
