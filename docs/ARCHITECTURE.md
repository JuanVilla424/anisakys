# Anisakys - Technical Architecture Document

**Version**: 2.0.0
**Status**: Production - Stabilized
**Architecture Type**: Modular Enterprise Anti-Phishing Engine
**Last Updated**: 2026-03-22
**Architect**: Winston (BMAD Solution Architect)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current Architecture](#current-architecture)
3. [Component Inventory](#component-inventory)
4. [Observability Infrastructure](#observability-infrastructure)
5. [API Reference](#api-reference)
6. [Configuration Reference](#configuration-reference)
7. [Risk Analysis](#risk-analysis)
8. [Appendices](#appendices)

---

## Executive Summary

### Context

Anisakys is a **production-grade anti-phishing detection engine** that has completed a full architectural transformation from a 7,389-line monolith to a modular, resilient, enterprise system. All critical issues identified in v1.1.1 have been resolved.

### Completed Transformation

| Decision                              | Status      | Outcome                                            |
| ------------------------------------- | ----------- | -------------------------------------------------- |
| **Modularize main.py**                | ✅ Complete | 7,389 → 1,277 LOC (-83%), 14 modules extracted     |
| **Implement Redirect Chain Analysis** | ✅ Complete | `src/detection/redirect_analyzer.py` (330 LOC)     |
| **Structured Logging Infrastructure** | ✅ Complete | JSON + correlation IDs, 11 modules instrumented    |
| **API Circuit Breakers**              | ✅ Complete | 4 API clients (VT, URLVoid, PhishTank, Grinder)    |
| **ICANN Compliance Tracking**         | ✅ Complete | 2-day SLA, escalation, abuse contact validation    |
| **Google Ads Detection**              | ✅ Restored | `src/detection/google_ads_detector.py` (1,177 LOC) |
| **Observability Modules**             | ✅ Complete | metrics.py, health.py, tracing.py                  |

### Current System Metrics

- **Total codebase**: ~12,500 LOC across 48 files
- **Test suite**: 5,578 LOC, 29 files, 64+ passing tests
- **API integrations**: VirusTotal, URLVoid, PhishTank, Google Safe Browsing, Grinder
- **Threat detection**: 5 levels (critical → high → medium → low → clean)
- **Brands monitored**: Bancolombia, Davivienda, BBVA, PayPal, Google, Microsoft, Apple, Amazon, Netflix, Mercado Libre, DIAN, and more

---

## Current Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         ANISAKYS ENGINE                          │
│                                                                   │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐ │
│  │  Detection  │    │ Intelligence │    │     Reporting       │ │
│  │             │    │              │    │                     │ │
│  │ url_analyzer│───▶│multi_api_val │───▶│  abuse_manager     │ │
│  │ redirect_an │    │ virustotal   │    │  report_tracker    │ │
│  │ scanner     │    │ urlvoid      │    │  email_detector    │ │
│  │ analyzer    │    │ phishtank    │    │  abuse_contact_val │ │
│  │ google_ads  │    │ gsb          │    │                     │ │
│  └─────────────┘    │ grinder      │    └─────────────────────┘ │
│                     └──────────────┘                             │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐ │
│  │Observability│    │  Database    │    │      API            │ │
│  │             │    │              │    │                     │ │
│  │ struct_log  │    │  manager.py  │    │  phishing_api.py   │ │
│  │ metrics.py  │    │  (SQLAlchemy)│    │  (Flask REST)      │ │
│  │ health.py   │    │  PostgreSQL  │    │                     │ │
│  │ tracing.py  │    └──────────────┘    └─────────────────────┘ │
│  └─────────────┘                                                 │
│                                                                   │
│  ┌─────────────┐    ┌──────────────┐                            │
│  │  Monitoring │    │  Resilience  │                            │
│  │             │    │              │                            │
│  │ gsb_rescan  │    │circuit_break │                            │
│  │ takedown    │    │(CLOSED/OPEN/ │                            │
│  │             │    │ HALF_OPEN)   │                            │
│  └─────────────┘    └──────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
src/
├── main.py                        # Orchestrator (1,277 LOC)
├── config.py                      # Pydantic settings
├── circuit_breaker.py             # API resilience (309 LOC)
├── logger.py                      # Root logger
├── screenshot_service.py          # Playwright/Selenium captures (417 LOC)
├── shutdown.py                    # Graceful shutdown handler
│
├── detection/                     # Threat detection layer
│   ├── url_analyzer.py            # Lexical URL analysis (767 LOC)
│   ├── redirect_analyzer.py       # Redirect chain following (330 LOC)
│   ├── scanner.py                 # Main scanner (536 LOC)
│   ├── analyzer.py                # Content analysis (469 LOC)
│   ├── google_ads_detector.py     # Google Ads phishing (1,177 LOC)
│   └── utils.py                   # Utilities
│
├── intelligence/                  # Threat intelligence APIs
│   ├── multi_api_validator.py     # Orchestrator (586 LOC)
│   ├── virustotal.py              # VirusTotal API (255 LOC)
│   ├── urlvoid.py                 # URLVoid API (178 LOC)
│   ├── phishtank.py               # PhishTank API (183 LOC)
│   ├── google_safe_browsing.py    # GSB API v4 (219 LOC)
│   ├── gsb_reporter.py            # GSB URL reporting (371 LOC)
│   ├── grinder.py                 # Grinder integration (439 LOC)
│   └── abuse_contact_resolver.py  # Contact resolution (334 LOC)
│
├── observability/                 # Logging, metrics, health, tracing
│   ├── structured_logger.py       # JSON logs + correlation IDs (313 LOC)
│   ├── metrics.py                 # Centralized metrics registry (301 LOC)
│   ├── health.py                  # Component health checks (275 LOC)
│   └── tracing.py                 # Span management (223 LOC)
│
├── reporting/                     # ICANN compliance & abuse reporting
│   ├── abuse_manager.py           # Report orchestration (1,908 LOC)
│   ├── email_detector.py          # Abuse email detection (862 LOC)
│   ├── report_tracker.py          # ICANN SLA tracking (936 LOC)
│   └── abuse_contact_validator.py # Email deliverability (430 LOC)
│
├── api/                           # REST API
│   └── phishing_api.py            # Flask endpoints (1,070 LOC)
│
├── database/                      # Data layer
│   └── manager.py                 # SQLAlchemy operations (819 LOC)
│
├── monitoring/                    # Background monitoring
│   ├── gsb_rescan.py              # GSB re-scan job (325 LOC)
│   └── takedown.py                # Takedown tracking (126 LOC)
│
├── data/                          # Static lookup data
│   ├── asn_abuse_db.py            # ASN → abuse email mapping
│   ├── provider_abuse_db.py       # Provider → abuse email mapping
│   ├── registrar_abuse_db.py      # Registrar abuse contacts
│   ├── registrar_form_db.py       # Registrar web forms
│   └── whois_servers.py           # WHOIS server list
│
├── dns/                           # DNS utilities
│   └── network_utils.py           # DNS resolution helpers
│
├── generators/                    # Domain generators
│   └── query_generator.py         # Query generation
│
└── models/                        # Runtime config models
    └── config.py                  # Dynamic config model
```

---

## Component Inventory

| Component                   | File                                         | LOC   | Status                                    |
| --------------------------- | -------------------------------------------- | ----- | ----------------------------------------- |
| **Core Engine**             | `src/main.py`                                | 1,277 | ✅ Refactored from 7,389                  |
| **Configuration**           | `src/config.py`                              | ~80   | ✅ Pydantic-based                         |
| **Circuit Breaker**         | `src/circuit_breaker.py`                     | 309   | ✅ CLOSED/OPEN/HALF_OPEN                  |
| **Root Logger**             | `src/logger.py`                              | ~30   | ✅ Bootstrap logger                       |
| **Screenshot Service**      | `src/screenshot_service.py`                  | 417   | ✅ Playwright + Selenium                  |
| **Structured Logger**       | `src/observability/structured_logger.py`     | 313   | ✅ JSON + correlation IDs                 |
| **Metrics Registry**        | `src/observability/metrics.py`               | 301   | ✅ Thread-safe counters/gauges/histograms |
| **Health Checks**           | `src/observability/health.py`                | 275   | ✅ DB + circuit breakers + disk           |
| **Span Tracing**            | `src/observability/tracing.py`               | 223   | ✅ Context-var spans                      |
| **URL Analyzer**            | `src/detection/url_analyzer.py`              | 767   | ✅ Typosquatting, homoglyphs, 55 TLDs     |
| **Redirect Analyzer**       | `src/detection/redirect_analyzer.py`         | 330   | ✅ 5-hop chain following                  |
| **Scanner**                 | `src/detection/scanner.py`                   | 536   | ✅ Main scan orchestration                |
| **Content Analyzer**        | `src/detection/analyzer.py`                  | 469   | ✅ HTML/content analysis                  |
| **Google Ads Detector**     | `src/detection/google_ads_detector.py`       | 1,177 | ✅ Ad scraping + homoglyph detection      |
| **Multi-API Validator**     | `src/intelligence/multi_api_validator.py`    | 586   | ✅ 6-API orchestration                    |
| **VirusTotal**              | `src/intelligence/virustotal.py`             | 255   | ✅ 70+ engines, circuit-broken            |
| **URLVoid**                 | `src/intelligence/urlvoid.py`                | 178   | ✅ 30+ sources, circuit-broken            |
| **PhishTank**               | `src/intelligence/phishtank.py`              | 183   | ✅ Community DB, circuit-broken           |
| **Google Safe Browsing**    | `src/intelligence/google_safe_browsing.py`   | 219   | ✅ API v4                                 |
| **GSB Reporter**            | `src/intelligence/gsb_reporter.py`           | 371   | ✅ URL submission to GSB                  |
| **Grinder**                 | `src/intelligence/grinder.py`                | 439   | ✅ Circuit-broken                         |
| **Abuse Contact Resolver**  | `src/intelligence/abuse_contact_resolver.py` | 334   | ✅ WHOIS + ASN lookup                     |
| **Abuse Manager**           | `src/reporting/abuse_manager.py`             | 1,908 | ✅ Full report lifecycle                  |
| **Email Detector**          | `src/reporting/email_detector.py`            | 862   | ✅ Abuse email extraction                 |
| **Report Tracker**          | `src/reporting/report_tracker.py`            | 936   | ✅ ICANN 2-day SLA                        |
| **Abuse Contact Validator** | `src/reporting/abuse_contact_validator.py`   | 430   | ✅ Format + MX + SMTP                     |
| **REST API**                | `src/api/phishing_api.py`                    | 1,070 | ✅ Flask + rate limiting                  |
| **DB Manager**              | `src/database/manager.py`                    | 819   | ✅ SQLAlchemy + PostgreSQL                |
| **GSB Rescan**              | `src/monitoring/gsb_rescan.py`               | 325   | ✅ Background rescan job                  |
| **Takedown Monitor**        | `src/monitoring/takedown.py`                 | 126   | ✅ Site status tracking                   |

---

## Observability Infrastructure

### Structured Logging (`src/observability/structured_logger.py`)

JSON-formatted logs with correlation IDs via `ContextVar`. Every log record includes:

```json
{
  "timestamp": "2026-03-22T10:30:45.123Z",
  "level": "INFO",
  "logger": "anisakys.detection",
  "message": "Phishing site detected",
  "correlation_id": "abc-123-def",
  "context": {
    "url": "https://phishing.com",
    "confidence": 95,
    "event_type": "detection"
  }
}
```

**Instrumented modules**: main, database, circuit_breaker, virustotal, urlvoid, phishtank, grinder, gsb_reporter, multi_api_validator, gsb_rescan, abuse_manager (11 modules).

### Metrics Registry (`src/observability/metrics.py`)

Thread-safe singleton with counters, gauges, and histograms. No external dependencies.

```python
from src.observability.metrics import increment_counter, set_gauge, observe_histogram, get_metrics

increment_counter("anisakys_scans_total")
increment_counter("anisakys_api_calls_total", api_name="VirusTotal")
set_gauge("anisakys_circuit_breaker_state", 1.0, api_name="URLVoid")
observe_histogram("anisakys_api_latency_seconds", 0.342, api_name="URLVoid")
```

**Predefined metrics**:

| Metric                                    | Type      | Labels     |
| ----------------------------------------- | --------- | ---------- |
| `anisakys_scans_total`                    | Counter   | —          |
| `anisakys_detections_total`               | Counter   | —          |
| `anisakys_redirect_chains_detected_total` | Counter   | —          |
| `anisakys_api_calls_total`                | Counter   | `api_name` |
| `anisakys_reports_sent_total`             | Counter   | —          |
| `anisakys_circuit_breaker_state`          | Gauge     | `api_name` |
| `anisakys_api_latency_seconds`            | Histogram | `api_name` |
| `anisakys_scan_duration_seconds`          | Histogram | —          |

### Health Checks (`src/observability/health.py`)

Extensible registry with built-in checks for database, circuit breakers, and disk space.

```python
from src.observability.health import create_health_checker

checker = create_health_checker(db_engine=engine, circuit_breakers=breakers)
result = checker.check_all()
# {"status": "healthy"|"degraded"|"unhealthy", "components": {...}}
```

**Status semantics**:

- `healthy` — all checks pass
- `degraded` — warning conditions (circuit breaker HALF_OPEN, disk >85%)
- `unhealthy` — critical failure (DB unreachable, circuit breaker OPEN, disk >95%)

### Span Tracing (`src/observability/tracing.py`)

Context-manager based spans that extend correlation IDs with timing and hierarchy.

```python
from src.observability.tracing import trace_operation

with trace_operation("virustotal_lookup", url="https://example.com") as span:
    result = virustotal.check(url)
    span.attributes["detections"] = result.detections
# Logs: {"event_type": "span_complete", "span": "virustotal_lookup", "duration_ms": 342}
```

### Circuit Breaker (`src/circuit_breaker.py`)

Wraps all 4 external API clients:

| API        | State tracking      | Failure threshold | Recovery |
| ---------- | ------------------- | ----------------- | -------- |
| VirusTotal | CircuitBreakerStats | 5 failures        | 60s      |
| URLVoid    | CircuitBreakerStats | 5 failures        | 60s      |
| PhishTank  | CircuitBreakerStats | 5 failures        | 60s      |
| Grinder    | CircuitBreakerStats | 5 failures        | 60s      |

---

## API Reference

### Endpoints

| Endpoint               | Method | Auth   | Description             |
| ---------------------- | ------ | ------ | ----------------------- |
| `/api/v1/health`       | GET    | None   | Health check            |
| `/api/v1/multi-scan`   | POST   | Bearer | Full scan with all APIs |
| `/api/v1/sites`        | GET    | Bearer | List phishing sites     |
| `/api/v1/reports`      | GET    | Bearer | List abuse reports      |
| `/api/v1/status/<url>` | GET    | Bearer | Report status for URL   |
| `/api/v1/stats`        | GET    | Bearer | System statistics       |
| `/api/v1/gsb/rescan`   | POST   | Bearer | Trigger GSB rescan      |

**Authentication**: `Authorization: Bearer <ANISAKYS_API_KEY>`

### Threat Levels

| Level      | Triggers                                                              |
| ---------- | --------------------------------------------------------------------- |
| `critical` | Homoglyphs detected, PhishTank confirmed, GSB malware                 |
| `high`     | Typosquatting, combo-squatting, GSB social engineering                |
| `medium`   | Suspicious keywords, suspicious TLD (forced minimum), domain <30 days |
| `low`      | Marginal indicators                                                   |
| `clean`    | No threats detected                                                   |

**Note**: Suspicious TLD forces minimum threat level `medium` (cannot be `low`).

---

## Configuration Reference

```bash
# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=xxx
URLVOID_API_KEY=xxx
PHISHTANK_API_KEY=xxx
GOOGLE_SAFE_BROWSING_API_KEY=xxx

# Anisakys API
ANISAKYS_API_KEY=xxx

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/anisakys_db

# SMTP (abuse reports)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user
SMTP_PASS=pass

# Scanning behavior
AUTO_MULTI_API_SCAN=true
AUTO_REPORT_THRESHOLD_CONFIDENCE=85
MANUAL_REVIEW_THRESHOLD_CONFIDENCE=70

# Redirect analysis
ENABLE_REDIRECT_ANALYSIS=true
MAX_REDIRECT_HOPS=5

# Logging
LOG_LEVEL=INFO
STRUCTURED_LOGGING=true
```

---

## Risk Analysis

### Remaining Items

| Item                           | Priority | Notes                                                                                    |
| ------------------------------ | -------- | ---------------------------------------------------------------------------------------- |
| **Prometheus endpoint**        | Medium   | metrics.py registry ready; needs `/metrics` Flask endpoint + `prometheus_client` wrapper |
| **Metrics instrumentation**    | Medium   | Call `increment_counter()` from API clients, scanner, report manager                     |
| **health endpoint deep check** | Medium   | health.py ready; update `/api/v1/health` to use `create_health_checker()`                |
| **Alembic migrations**         | Low      | DB schema managed via raw SQL; migration tooling not set up                              |
| **Tests for reporting/**       | Low      | 2,710 LOC in reporting/ with minimal test coverage                                       |
| **Tests for monitoring/**      | Low      | gsb_rescan, takedown untested                                                            |
| **GSB validation in prod**     | Low      | Verify GSB queries work against live API                                                 |

### Architectural Risks (Resolved)

| Risk                                               | Resolution                                        |
| -------------------------------------------------- | ------------------------------------------------- |
| ~~main.py monolith 7,389 LOC~~                     | ✅ 1,277 LOC, 14 modules extracted                |
| ~~No redirect detection (40-60% false negatives)~~ | ✅ redirect_analyzer.py, 5-hop chain following    |
| ~~No structured logging, impossible to debug~~     | ✅ JSON + correlation IDs, 11 modules             |
| ~~API failures cascade (no circuit breakers)~~     | ✅ 4 circuit breakers with OPEN/HALF_OPEN/CLOSED  |
| ~~Duplicate entries in abuse_reports~~             | ✅ Upsert logic in report_tracker.py              |
| ~~Legacy modules in src/ root~~                    | ✅ Relocated to reporting/, deleted repopulate.py |
| ~~google_ads_detector.py accidentally deleted~~    | ✅ Restored from git history                      |

---

## Appendices

### Appendix A: Feature Flags

```bash
ENABLE_REDIRECT_ANALYSIS=true    # Redirect chain following (5 hops)
STRUCTURED_LOGGING=true          # JSON log format
LOG_LEVEL=INFO                   # DEBUG | INFO | WARNING | ERROR
AUTO_MULTI_API_SCAN=true         # Auto-scan new sites with all APIs
```

### Appendix B: Operations

```bash
# Systemd service
sudo systemctl status anisakys-api
sudo systemctl restart anisakys-api
sudo journalctl -u anisakys-api -f

# Development → Production deploy
sudo cp src/detection/url_analyzer.py /opt/anisakys/src/detection/
sudo chown anisakys:anisakys /opt/anisakys/src/detection/url_analyzer.py
sudo systemctl restart anisakys-api

# Tests
pytest tests/ -x --timeout=30
pytest tests/ --cov=src --cov-report=html
```

---

**Document Control**
Author: Winston (BMAD Solution Architect) + BMAD Dev Team
Last Updated: 2026-03-22
Version: 2.0.0
