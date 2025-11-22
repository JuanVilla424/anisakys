# Project Brief: Anisakys Anti-Phishing Detection Engine

**Version**: 1.1.0
**Status**: Production - Requiring Stabilization
**Classification**: Blue Team Security Tool
**Created**: 2025-11-21
**Last Updated**: 2025-11-21

---

## Executive Summary

**Anisakys** is an enterprise-grade automated phishing detection and reporting engine designed for blue teams, SOC analysts, and cybersecurity professionals. The system provides comprehensive threat hunting capabilities with full ICANN compliance for abuse reporting.

The project has reached a critical juncture where it requires **professional stabilization and enhancement** to address evolving threat actor tactics and operational challenges.

---

## Project Context

### Current State

- **Production Status**: System is operational but experiencing reliability issues
- **Version**: 1.1.0 (Python 3.12+)
- **Repository**: https://github.com/JuanVilla424/anisakys
- **License**: GPL-3.0
- **Tech Stack**: Python, PostgreSQL, Flask, SQLAlchemy
- **Current Branch**: `dev`

### Business Criticality

This tool is being positioned as a **professional security arm** for the organization's blue team operations. The system's reliability and effectiveness are paramount as it directly impacts:

- Real-time phishing threat detection
- ICANN compliance reporting
- SOC operational efficiency
- Organizational security posture

---

## Problem Statement

### 1. **Threat Actor Evolution** (Critical)

**Issue**: Attackers have evolved their tactics using sophisticated redirection techniques.

- **Current Behavior**: Phishing sites now employ multi-layer redirects
- **Impact**: Cloudflare's security systems cannot detect phishing in redirected URLs
- **Consequence**: Traditional detection methods are being bypassed
- **Business Impact**: False negatives leading to undetected phishing campaigns

**Root Cause**: Detection engine relies on direct URL analysis without following redirect chains.

### 2. **Database Integrity Issues** (High)

**Issue**: Report tracking system experiencing data consistency problems.

- **Symptoms**:

  - Duplicate report records in `abuse_reports` table
  - Insertion failures on constraint violations
  - Inconsistent state between `phishing_sites` and `abuse_reports`

- **Impact**: Inaccurate reporting metrics, potential data loss

- **Status**: Partially addressed in recent commit (src/report_tracker.py) with upsert logic

### 3. **Abuse Contact Discovery Failures** (High)

**Issue**: System cannot reliably identify abuse contacts for all hosting scenarios.

- **Symptoms**:

  - Missing abuse emails for certain ASNs/providers
  - Incorrect handling of multiple abuse contacts
  - Failures with non-standard WHOIS responses

- **Impact**: Reports cannot be sent, manual intervention required

- **Current Coverage**: Extensive ASN database (309 entries) but gaps remain

### 4. **Multi-API Detection Accuracy** (Medium)

**Issue**: Integration with threat intelligence APIs not functioning optimally.

- **Affected APIs**:

  - VirusTotal (70+ engines)
  - URLVoid (30+ sources)
  - PhishTank (community database)

- **Symptoms**:
  - Inconsistent confidence scoring
  - API timeout handling issues
  - Rate limiting not properly managed

### 5. **Operational Logging & Monitoring** (Medium)

**Issue**: Insufficient logging for production troubleshooting.

- **Symptoms**:

  - Error logs from previous executions not preserved
  - Difficulty diagnosing failures post-execution
  - No centralized monitoring

- **Impact**: Reactive problem-solving, delayed incident response

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

### Key Modules

```
src/
├── main.py              # Core detection engine (7,389 lines)
├── config.py            # Pydantic settings management
├── logger.py            # Logging infrastructure
├── report_tracker.py    # ICANN compliance tracking
├── abuse_contact_validator.py  # Email validation
├── screenshot_service.py       # Visual evidence capture
├── google_ads_detector.py      # Ad-based phishing detection
└── repopulate.py        # Database utilities
```

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
   - **Affected**: `src/report_tracker.py`
   - **Status**: Partially fixed with upsert logic (pending testing)
   - **File**: src/report_tracker.py:339-463

3. **[ABUSE-CONTACT-MULTI]** Multiple abuse contacts not handled properly

   - **Impact**: Incomplete reporting
   - **Affected**: `src/abuse_contact_validator.py`
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
   - **Affected**: `src/abuse_contact_validator.py`

---

## Technical Debt

1. **Monolithic main.py**: 7,389 lines - requires modularization
2. **Limited test coverage**: No comprehensive test suite visible
3. **Configuration management**: Mixed environment variables and hardcoded values
4. **Error handling**: Inconsistent exception handling patterns
5. **Documentation**: Code comments sparse, no API documentation

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

## Success Criteria

### Immediate Stabilization (Sprint 1-2)

- [ ] **Redirect Detection**: Implement redirect chain following (max 5 hops)
- [ ] **Database Integrity**: Eliminate duplicate report issues
- [ ] **Logging Infrastructure**: Production-grade logging with rotation
- [ ] **Abuse Contact Accuracy**: >95% success rate in email discovery

### Professional Hardening (Sprint 3-4)

- [ ] **Test Coverage**: ≥80% code coverage with unit + integration tests
- [ ] **API Reliability**: Implement circuit breakers and retry strategies
- [ ] **Monitoring**: Prometheus metrics + Grafana dashboards
- [ ] **Documentation**: Complete API docs, runbooks, architecture diagrams

### Advanced Capabilities (Sprint 5+)

- [ ] **Machine Learning**: Enhanced phishing pattern detection
- [ ] **Threat Intelligence**: Grinder integration (already partially implemented)
- [ ] **Multi-Tenant**: Support for multiple organizations
- [ ] **Advanced Reporting**: Executive dashboards, trend analysis

---

## Stakeholders

| Role                    | Responsibility                   | Contact         |
| ----------------------- | -------------------------------- | --------------- |
| **Security Operations** | Primary user, threat hunting     | SOC Team        |
| **Development**         | System maintenance, enhancements | Dev Team        |
| **Compliance**          | ICANN reporting requirements     | Compliance Team |
| **Infrastructure**      | Database, hosting, monitoring    | Ops Team        |

---

## Next Steps (Recommended)

### Phase 1: Discovery & Stabilization (Week 1-2)

1. **Deep Code Analysis**

   - Architect to review entire codebase
   - Identify critical refactoring needs
   - Map technical debt

2. **Issue Reproduction**

   - Create test environments
   - Reproduce all reported issues
   - Document error patterns

3. **Logging Enhancement**
   - Implement structured logging (JSON)
   - Add correlation IDs
   - Set up log aggregation

### Phase 2: Core Fixes (Week 3-4)

4. **Redirect Detection Implementation**

   - Design redirect chain following logic
   - Implement with configurable depth limits
   - Add Cloudflare bypass detection

5. **Database Integrity**

   - Test upsert logic comprehensively
   - Add database constraints
   - Implement transaction isolation

6. **Abuse Contact Improvements**
   - Enhance WHOIS parsing
   - Add provider discovery fallbacks
   - Implement contact validation

### Phase 3: Quality Assurance (Week 5-6)

7. **Test Suite Development**

   - Unit tests for all core modules
   - Integration tests for API workflows
   - End-to-end testing scenarios

8. **Performance Optimization**

   - Profile multi-threading efficiency
   - Optimize database queries
   - Implement caching strategies

9. **Documentation Sprint**
   - Architecture documentation
   - API reference documentation
   - Operational runbooks

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
Last Review: 2025-11-21
Next Review: 2025-12-05
Owner: Security Operations Team
Classification: Internal Use Only
