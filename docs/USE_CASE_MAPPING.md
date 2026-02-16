# Use Case to System Component Mapping
**Version:** 2.0.0-alpha
**Date:** 2026-01-03
**Purpose:** Map use cases to technical implementation components

---

## Component Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                         FRONTEND                              │
│  React + TypeScript + TanStack Query + Tailwind CSS          │
│                                                                │
│  Pages:                                                        │
│  ├─ Scanner (UC-001, UC-002)                                  │
│  ├─ Sites (UC-030, UC-032)                                    │
│  ├─ Reports (UC-022, UC-023, UC-031)                          │
│  ├─ Research (UC-004, UC-007)                                 │
│  ├─ Analytics (UC-040, UC-041, UC-045)                        │
│  └─ Settings (UC-050, UC-052, UC-053)                         │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ REST API / GraphQL
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                      API LAYER (FastAPI)                      │
│                                                                │
│  Routes:                                                       │
│  ├─ /api/v1/phishing/* (UC-001, UC-002, UC-003)              │
│  ├─ /api/v1/reports/* (UC-020, UC-021, UC-022)               │
│  ├─ /api/v1/analytics/* (UC-040, UC-041, UC-045)             │
│  ├─ /api/v1/research/* (UC-004, UC-007)                      │
│  ├─ /api/v1/admin/* (UC-050, UC-051, UC-052)                 │
│  └─ /api/v1/webhooks/* (UC-072)                              │
│                                                                │
│  Middleware:                                                   │
│  ├─ AuthMiddleware (UC-070)                                   │
│  ├─ RateLimitMiddleware (UC-070)                              │
│  └─ LoggingMiddleware (UC-055)                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                      SERVICE LAYER                            │
│                                                                │
│  ├─ PhishingDetectionService                                  │
│  │   ├─ scan_url() (UC-001)                                   │
│  │   ├─ bulk_scan() (UC-002)                                  │
│  │   └─ auto_generate_domains() (UC-003)                      │
│  │                                                             │
│  ├─ ThreatValidationService                                   │
│  │   ├─ multi_api_validation() (UC-010)                       │
│  │   ├─ ml_classification() (UC-011)                          │
│  │   └─ visual_similarity() (UC-012)                          │
│  │                                                             │
│  ├─ AbuseReportingService                                     │
│  │   ├─ generate_report() (UC-020)                            │
│  │   ├─ send_report() (UC-021)                                │
│  │   ├─ track_status() (UC-022)                               │
│  │   └─ escalate() (UC-023)                                   │
│  │                                                             │
│  ├─ MonitoringService                                         │
│  │   ├─ check_takedown() (UC-030)                             │
│  │   ├─ track_sla() (UC-031)                                  │
│  │   └─ follow_up() (UC-033)                                  │
│  │                                                             │
│  ├─ AnalyticsService                                          │
│  │   ├─ get_dashboard_stats() (UC-040)                        │
│  │   ├─ generate_report() (UC-041)                            │
│  │   └─ export_intelligence() (UC-042)                        │
│  │                                                             │
│  └─ ResearchService                                           │
│      ├─ typosquatting_analysis() (UC-004)                     │
│      ├─ generate_dorks() (UC-007)                             │
│      └─ ct_monitoring() (UC-005)                              │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    INTEGRATION LAYER                          │
│                                                                │
│  ├─ VirusTotalClient (UC-010)                                 │
│  ├─ URLVoidClient (UC-010)                                    │
│  ├─ PhishTankClient (UC-010)                                  │
│  ├─ GrinderClient (UC-025)                                    │
│  ├─ SMTPClient (UC-021)                                       │
│  ├─ CTLogClient (UC-005)                                      │
│  └─ SocialMediaClient (UC-006)                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     REPOSITORY LAYER                          │
│                                                                │
│  ├─ PhishingSiteRepository (CRUD operations)                  │
│  ├─ AbuseReportRepository (CRUD operations)                   │
│  ├─ RegistrarRepository (CRUD operations)                     │
│  └─ UserRepository (UC-051)                                   │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    DATABASE (PostgreSQL)                      │
│                                                                │
│  Tables:                                                       │
│  ├─ phishing_sites                                            │
│  ├─ abuse_reports                                             │
│  ├─ registrar_abuse                                           │
│  ├─ hosting_abuse                                             │
│  ├─ users (multi-tenancy)                                     │
│  └─ audit_logs (UC-055)                                       │
└──────────────────────────────────────────────────────────────┘
```

---

## Use Case to Component Map

### 1. Phishing Detection (UC-001 to UC-007)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-001: Manual URL Submission | PhishingDetectionService | scan_url() | P0 |
| UC-002: Bulk URL Scanning | PhishingDetectionService | bulk_scan() | P1 |
| UC-003: Automated Domain Generation | PhishingDetectionService | auto_generate_domains() | P2 |
| UC-004: Typosquatting Detection | ResearchService | typosquatting_analysis() | P1 |
| UC-005: CT Monitoring | ResearchService | monitor_ct_logs() | P2 |
| UC-006: Social Media Monitoring | ResearchService | monitor_social_media() | P3 |
| UC-007: Google Dorks Research | ResearchService | generate_dorks() | P2 |

**Implementation Notes:**
- Scanner page (frontend) calls PhishingDetectionService
- Bulk operations queued via Celery tasks
- CT monitoring runs as background daemon
- Research tools in Research page

---

### 2. Threat Validation (UC-010 to UC-015)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-010: Multi-API Validation | ThreatValidationService | multi_api_validation() | P0 |
| UC-011: ML-Based Classification | ThreatValidationService | ml_classification() | P2 |
| UC-012: Visual Similarity | ThreatValidationService | visual_similarity() | P2 |
| UC-013: Content Analysis (NLP) | ThreatValidationService | nlp_analysis() | P2 |
| UC-014: WHOIS Investigation | ThreatValidationService | whois_lookup() | P1 |
| UC-015: Manual Assessment | Frontend + Service | manual_review() | P1 |

**Implementation Notes:**
- Multi-API runs in parallel with async/await
- ML models loaded at service startup
- Visual similarity uses OpenCV/scikit-image
- WHOIS cached for 24 hours

---

### 3. Abuse Reporting (UC-020 to UC-025)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-020: Generate ICANN Report | AbuseReportingService | generate_report() | P0 |
| UC-021: Send Abuse Email | AbuseReportingService | send_report() | P0 |
| UC-022: Track Report Status | AbuseReportingService | track_status() | P1 |
| UC-023: Escalation Management | AbuseReportingService | escalate() | P1 |
| UC-024: Registrar Communication | AbuseReportingService | send_communication() | P1 |
| UC-025: Grinder IP Reporting | GrinderClient | report_ip() | P1 |

**Implementation Notes:**
- Report generation uses Jinja2 templates
- SMTP client with retry logic
- Status tracking via background worker
- Escalation triggered by SLA deadline

---

### 4. Monitoring & Tracking (UC-030 to UC-034)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-030: Takedown Monitoring | MonitoringService | check_takedown() | P0 |
| UC-031: SLA Compliance Tracking | MonitoringService | track_sla() | P1 |
| UC-032: Site Status Updates | MonitoringService | update_status() | P0 |
| UC-033: Follow-up Automation | MonitoringService | automated_followup() | P1 |
| UC-034: Campaign Correlation | AnalyticsService | correlate_campaigns() | P2 |

**Implementation Notes:**
- Celery periodic tasks (every 2 hours)
- HTTP HEAD requests for efficiency
- SLA calculations with timezone handling
- Campaign correlation uses ML clustering

---

### 5. Analytics & Reporting (UC-040 to UC-045)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-040: View Security Dashboard | AnalyticsService | get_dashboard_stats() | P0 |
| UC-041: Generate Analytics Report | AnalyticsService | generate_report() | P1 |
| UC-042: Threat Intelligence Export | AnalyticsService | export_intelligence() | P2 |
| UC-043: Executive Summary | AnalyticsService | executive_summary() | P1 |
| UC-044: Compliance Reporting | AnalyticsService | compliance_report() | P1 |
| UC-045: Performance Metrics | MonitoringService | performance_metrics() | P1 |

**Implementation Notes:**
- Dashboard uses cached queries (30s TTL)
- Report generation uses Celery (async)
- Export formats: CSV, JSON, STIX, MISP
- Prometheus integration for metrics

---

### 6. Administration (UC-050 to UC-055)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-050: System Configuration | ConfigService | update_config() | P0 |
| UC-051: User Management | UserService | manage_users() | P1 |
| UC-052: API Integration Setup | IntegrationService | setup_api() | P0 |
| UC-053: Alert Configuration | AlertService | configure_alerts() | P1 |
| UC-054: Backup & Restore | BackupService | backup() / restore() | P0 |
| UC-055: Audit Log Review | AuditService | query_logs() | P1 |

**Implementation Notes:**
- Settings stored in database + cache
- User management with RBAC
- API credentials encrypted (AES-256)
- Automated daily backups

---

### 7. Collaboration (UC-060 to UC-064)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-060: Case Assignment | CollaborationService | assign_case() | P2 |
| UC-061: Notes & Comments | CollaborationService | add_note() | P2 |
| UC-062: Team Notifications | NotificationService | send_notification() | P1 |
| UC-063: Knowledge Sharing | KnowledgeBaseService | create_article() | P3 |
| UC-064: Workflow Approval | ApprovalService | request_approval() | P2 |

**Implementation Notes:**
- WebSocket for real-time notifications
- Markdown support for notes
- Email + Slack integrations
- Knowledge base with full-text search

---

### 8. API Integration (UC-070 to UC-074)

| Use Case | Component | Method | Priority |
|----------|-----------|--------|----------|
| UC-070: API Authentication | AuthMiddleware | authenticate() | P0 |
| UC-071: Programmatic URL Submission | PhishingAPI | submit_url() | P0 |
| UC-072: Webhook Configuration | WebhookService | configure_webhook() | P2 |
| UC-073: SIEM Integration | SIEMIntegrationService | send_event() | P1 |
| UC-074: Third-Party Export | ExportService | export_data() | P2 |

**Implementation Notes:**
- FastAPI dependency injection for auth
- Async endpoints for better throughput
- Webhook signing with HMAC-SHA256
- CEF/LEEF format for SIEM

---

## Technology Stack per Use Case Category

### Frontend Components

```typescript
// Scanner Page (UC-001, UC-002)
src/pages/Scanner.tsx
  ├─ URLInput component
  ├─ BulkUpload component
  └─ ScanResults component

// Sites Page (UC-030, UC-032)
src/pages/Sites.tsx
  ├─ SitesTable component
  ├─ StatusFilter component
  └─ SiteDetails modal

// Reports Page (UC-020, UC-022, UC-023)
src/pages/Reports.tsx
  ├─ ReportsTable component
  ├─ SLAIndicator component
  └─ EscalationActions component

// Research Page (UC-004, UC-007)
src/pages/Research.tsx
  ├─ TyposquattingTab component
  ├─ DorksGeneratorTab component
  └─ ResultsDisplay component

// Analytics Page (UC-040, UC-041)
src/pages/Analytics.tsx
  ├─ DashboardCharts (Recharts)
  ├─ MetricsCards component
  └─ ExportButton component

// Settings Page (UC-050, UC-052)
src/pages/Settings.tsx
  ├─ SMTPConfig component
  ├─ APIIntegrations component
  └─ UserManagement component
```

### Backend Services

```python
# Service Layer
src/services/
  ├─ phishing_detection.py (UC-001, UC-002, UC-003)
  │   └─ PhishingDetectionService
  ├─ threat_validation.py (UC-010, UC-011, UC-012)
  │   └─ ThreatValidationService
  ├─ abuse_reporting.py (UC-020, UC-021, UC-022, UC-023)
  │   └─ AbuseReportingService
  ├─ monitoring.py (UC-030, UC-031, UC-033)
  │   └─ MonitoringService
  ├─ analytics.py (UC-040, UC-041, UC-042)
  │   └─ AnalyticsService
  └─ research.py (UC-004, UC-005, UC-007)
      └─ ResearchService

# Integration Layer
src/integrations/
  ├─ virustotal.py (UC-010)
  ├─ urlvoid.py (UC-010)
  ├─ phishtank.py (UC-010)
  ├─ grinder.py (UC-025)
  ├─ smtp_client.py (UC-021)
  └─ ct_monitor.py (UC-005)

# Background Tasks
src/tasks/
  ├─ analysis_tasks.py (UC-003, UC-005)
  ├─ monitoring_tasks.py (UC-030, UC-031)
  └─ reporting_tasks.py (UC-023, UC-033)
```

### Database Schema

```sql
-- Core Tables
phishing_sites (UC-001, UC-002, UC-003, UC-030)
  ├─ Stores detected phishing URLs
  └─ Tracks status, confidence, threat level

abuse_reports (UC-020, UC-021, UC-022)
  ├─ ICANN compliance reports
  └─ SLA tracking fields

registrar_abuse (UC-020, UC-024)
  ├─ Registrar contact information
  └─ Performance metrics

users (UC-051)
  ├─ User accounts
  └─ RBAC permissions

audit_logs (UC-055)
  ├─ All state-changing actions
  └─ Tamper-proof logging

-- Future Tables
campaigns (UC-034)
  └─ Correlated phishing campaigns

knowledge_base (UC-063)
  └─ Team knowledge articles

webhooks (UC-072)
  └─ Webhook configurations
```

---

## Implementation Roadmap by Use Case

### Sprint 1-2 (P0 - Must-Have)

**Week 1-2 Focus:**
- UC-001: Manual URL Submission ✅ (EXISTS)
- UC-010: Multi-API Validation ✅ (EXISTS)
- UC-020: Generate ICANN Report ✅ (EXISTS)
- UC-021: Send Abuse Email ✅ (EXISTS)
- UC-030: Takedown Monitoring ✅ (EXISTS)
- UC-032: Site Status Updates ✅ (EXISTS)
- UC-040: View Security Dashboard ✅ (EXISTS)
- UC-050: System Configuration ✅ (EXISTS)
- UC-052: API Integration Setup ✅ (EXISTS)
- UC-070: API Authentication ✅ (IMPROVED - httpOnly cookies)

**Status:** Core functionality exists, needs refactoring to layered architecture

---

### Sprint 3-4 (P1 - Should-Have)

**Week 3-4 Focus:**
- UC-002: Bulk URL Scanning (enhance existing)
- UC-004: Typosquatting Detection ✅ (EXISTS)
- UC-014: WHOIS Investigation ✅ (EXISTS)
- UC-022: Track Report Status ✅ (EXISTS)
- UC-023: Escalation Management ✅ (EXISTS)
- UC-031: SLA Compliance Tracking ✅ (EXISTS)
- UC-041: Generate Analytics Report (enhance existing)
- UC-051: User Management (NEW)
- UC-071: Programmatic URL Submission ✅ (EXISTS)

---

### Sprint 5-6 (P2 - Could-Have)

**Week 5-6 Focus:**
- UC-003: Automated Domain Generation ✅ (EXISTS)
- UC-005: CT Monitoring ✅ (EXISTS)
- UC-007: Google Dorks Research ✅ (EXISTS)
- UC-011: ML-Based Classification ✅ (EXISTS)
- UC-012: Visual Similarity ✅ (EXISTS)
- UC-034: Campaign Correlation (NEW)
- UC-042: Threat Intelligence Export (NEW)
- UC-072: Webhook Configuration (NEW)

---

## Cross-Cutting Concerns

### Authentication & Authorization
- **Use Cases:** UC-070, UC-051
- **Components:** AuthMiddleware, UserService
- **Implementation:** JWT + httpOnly cookies, RBAC

### Logging & Audit
- **Use Cases:** UC-055
- **Components:** AuditService, LoggingMiddleware
- **Implementation:** Database audit logs, Prometheus metrics

### Caching
- **Use Cases:** UC-010 (API responses), UC-040 (dashboard)
- **Components:** Redis cache layer
- **Implementation:** TTL-based caching, cache invalidation

### Background Processing
- **Use Cases:** UC-003, UC-005, UC-030, UC-033
- **Components:** Celery + Redis
- **Implementation:** Periodic tasks, async queues

### Notifications
- **Use Cases:** UC-062, UC-023
- **Components:** NotificationService
- **Implementation:** Email, WebSocket, Webhooks

---

## Dependencies Between Use Cases

```
UC-001 (Manual Scan)
  └─> UC-010 (Multi-API Validation)
      └─> UC-020 (Generate Report)
          └─> UC-021 (Send Report)
              └─> UC-022 (Track Status)
                  └─> UC-030 (Monitor Takedown)
                      └─> UC-023 (Escalation if needed)

UC-004 (Typosquatting)
  └─> UC-012 (Visual Similarity)
      └─> UC-010 (Multi-API Validation)

UC-040 (Dashboard)
  └─> Depends on data from UC-001, UC-020, UC-030

UC-051 (User Management)
  └─> Required for UC-060, UC-061, UC-064 (Collaboration)
```

---

## Component Interaction Diagram

```
Frontend (React)
    │
    │ HTTP/REST
    ▼
API Layer (FastAPI)
    │
    ├─> AuthMiddleware ─────> UserRepository
    │
    ├─> PhishingDetectionService
    │   ├─> VirusTotalClient ──> VirusTotal API
    │   ├─> URLVoidClient ─────> URLVoid API
    │   └─> PhishTankClient ───> PhishTank API
    │
    ├─> AbuseReportingService
    │   ├─> SMTPClient ────────> SMTP Server
    │   └─> GrinderClient ─────> Grinder API
    │
    ├─> MonitoringService
    │   └─> Celery Tasks ──────> Background Workers
    │
    └─> AnalyticsService
        └─> PhishingSiteRepository
            └─> PostgreSQL Database
```

---

**Mapping Status:** ✅ Complete
**Total Components:** 25+
**Total Use Cases Mapped:** 74
**Next Step:** Create test scenarios from use cases
