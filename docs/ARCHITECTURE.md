# Anisakys Enterprise Architecture
**Version:** 2.0.0-alpha
**Status:** Design Phase
**Last Updated:** 2026-01-03

---

## Table of Contents
- [Current State](#current-state)
- [Target Architecture](#target-architecture)
- [Migration Strategy](#migration-strategy)
- [Technology Stack](#technology-stack)
- [Security Architecture](#security-architecture)
- [Scalability Plan](#scalability-plan)

---

## Current State (v1.1.0)

### Problems with Monolithic Architecture

```
src/
└── main.py (8,086 lines) ← MONOLITH
    ├── 18+ classes mixed together
    ├── API routes + business logic + data access
    ├── No separation of concerns
    ├── Difficult to test
    └── Cannot scale horizontally
```

**Critical Issues:**
- ❌ God Object anti-pattern
- ❌ Tight coupling
- ❌ No dependency injection
- ❌ Flask (synchronous, no async)
- ❌ NullPool (no connection pooling) → **FIXED**
- ❌ Threading with GIL (doesn't scale)

---

## Target Architecture (v2.0.0)

### Layered Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐  │
│  │   REST API     │  │   GraphQL API  │  │  WebSockets  │  │
│  │   (FastAPI)    │  │   (Strawberry) │  │   (Socket.IO)│  │
│  └────────────────┘  └────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                      SERVICE LAYER                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Phishing    │  │   Abuse      │  │  Threat Intel    │  │
│  │  Detection   │  │   Reporting  │  │  Aggregation     │  │
│  │  Service     │  │   Service    │  │  Service         │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Screenshot  │  │   ML/AI      │  │  OSINT           │  │
│  │  Service     │  │   Service    │  │  Service         │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                    REPOSITORY LAYER                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Phishing    │  │   Abuse      │  │  Registrar       │  │
│  │  Site Repo   │  │   Report     │  │  Repo            │  │
│  │              │  │   Repo       │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                       DATA LAYER                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  PostgreSQL (with QueuePool, Read Replicas, JSONB)    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Cross-Cutting Concerns

```
┌─────────────────────────────────────────────────────────────┐
│                   INFRASTRUCTURE LAYER                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Redis       │  │   Celery     │  │  RabbitMQ        │  │
│  │  (Cache)     │  │   (Tasks)    │  │  (Message Broker)│  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  S3/Minio    │  │  Prometheus  │  │  Sentry          │  │
│  │  (Storage)   │  │  (Metrics)   │  │  (Error Tracking)│  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## New Directory Structure

```
src/
├── __init__.py
├── main.py                    # ← Slim entry point (<100 lines)
├── config/
│   ├── __init__.py
│   ├── settings.py           # Pydantic settings
│   ├── logging.py            # Logging configuration
│   └── database.py           # DB configuration
│
├── api/                      # PRESENTATION LAYER
│   ├── __init__.py
│   ├── app.py               # FastAPI app instance
│   ├── dependencies.py      # Dependency injection
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── auth.py          # Authentication middleware
│   │   ├── cors.py          # CORS middleware
│   │   ├── rate_limit.py    # Rate limiting
│   │   └── logging.py       # Request/response logging
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── phishing.py   # Phishing endpoints
│   │   │   ├── analytics.py  # Analytics endpoints
│   │   │   ├── reports.py    # Reporting endpoints
│   │   │   ├── scanner.py    # Scanner endpoints
│   │   │   └── admin.py      # Admin endpoints
│   │   └── graphql/
│   │       ├── __init__.py
│   │       ├── schema.py     # GraphQL schema
│   │       └── resolvers.py  # GraphQL resolvers
│   └── schemas/              # Pydantic models
│       ├── __init__.py
│       ├── request.py        # Request models
│       ├── response.py       # Response models
│       └── common.py         # Shared models
│
├── services/                 # SERVICE LAYER (Business Logic)
│   ├── __init__.py
│   ├── phishing_detection.py
│   ├── abuse_reporting.py
│   ├── threat_intelligence.py
│   ├── screenshot_service.py
│   ├── ml_classifier.py
│   ├── osint_service.py
│   └── email_service.py
│
├── repositories/             # REPOSITORY LAYER (Data Access)
│   ├── __init__.py
│   ├── base.py              # Base repository with CRUD
│   ├── phishing_site.py     # PhishingSiteRepository
│   ├── abuse_report.py      # AbuseReportRepository
│   ├── registrar.py         # RegistrarRepository
│   └── scan_result.py       # ScanResultRepository
│
├── models/                   # DATA MODELS (SQLAlchemy)
│   ├── __init__.py
│   ├── base.py              # Declarative Base
│   ├── phishing_site.py     # PhishingSite model
│   ├── abuse_report.py      # AbuseReport model
│   ├── registrar.py         # Registrar model
│   └── user.py              # User model (multi-tenancy)
│
├── integrations/             # EXTERNAL API INTEGRATIONS
│   ├── __init__.py
│   ├── base.py              # Base integration with retry/circuit breaker
│   ├── virustotal.py        # VirusTotal client
│   ├── urlvoid.py           # URLVoid client
│   ├── phishtank.py         # PhishTank client
│   └── grinder.py           # Grinder client
│
├── tasks/                    # BACKGROUND TASKS (Celery)
│   ├── __init__.py
│   ├── celery_app.py        # Celery configuration
│   ├── analysis.py          # Analysis tasks
│   ├── reporting.py         # Reporting tasks
│   └── monitoring.py        # Monitoring tasks
│
├── utils/                    # UTILITIES
│   ├── __init__.py
│   ├── validators.py        # Input validators
│   ├── security.py          # Security helpers
│   ├── cache.py             # Cache decorators
│   └── helpers.py           # Common helpers
│
└── auth/                     # AUTHENTICATION (NEW)
    ├── __init__.py
    ├── jwt_handler.py       # JWT token management
    ├── password.py          # Password hashing
    └── permissions.py       # RBAC permissions
```

---

## Migration Strategy

### Phase 1: Extract Integrations (Week 1-2)
**Goal:** Move external API clients to `integrations/`

```python
# Before (main.py:863)
class VirusTotalIntegration:
    # 200+ lines

# After (src/integrations/virustotal.py)
from src.integrations.base import BaseIntegration

class VirusTotalClient(BaseIntegration):
    # Same logic, but isolated & testable
```

**Benefits:**
- ✅ Testable with mocks
- ✅ Reusable across services
- ✅ Circuit breaker pattern
- ✅ Retry logic centralized

**Effort:** 1 week

---

### Phase 2: Create Data Models (Week 2-3)
**Goal:** Extract SQLAlchemy models to `models/`

```python
# Before (main.py:3661)
# Raw SQL: text("CREATE TABLE phishing_sites...")

# After (src/models/phishing_site.py)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, TIMESTAMP, JSON

class Base(DeclarativeBase):
    pass

class PhishingSite(Base):
    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(2048), unique=True)
    confidence_score: Mapped[int] = mapped_column(Integer)
    virustotal_result: Mapped[dict] = mapped_column(JSON)  # ← JSONB
    # ... proper ORM models
```

**Benefits:**
- ✅ Type safety
- ✅ Relationships defined
- ✅ Migrations with Alembic
- ✅ Query optimization

**Effort:** 1 week

---

### Phase 3: Repository Pattern (Week 3-4)
**Goal:** Create repository layer for data access

```python
# src/repositories/base.py
from typing import Generic, TypeVar, Type, List, Optional
from sqlalchemy.orm import Session

T = TypeVar('T')

class BaseRepository(Generic[T]):
    def __init__(self, model: Type[T], session: Session):
        self.model = model
        self.session = session

    def get(self, id: int) -> Optional[T]:
        return self.session.query(self.model).filter_by(id=id).first()

    def get_all(self, skip: int = 0, limit: int = 100) -> List[T]:
        return self.session.query(self.model).offset(skip).limit(limit).all()

    def create(self, obj: T) -> T:
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)
        return obj

    # ... update, delete, etc.

# src/repositories/phishing_site.py
class PhishingSiteRepository(BaseRepository[PhishingSite]):
    def get_by_url(self, url: str) -> Optional[PhishingSite]:
        return self.session.query(self.model).filter_by(url=url).first()

    def get_pending_analysis(self, limit: int = 50) -> List[PhishingSite]:
        return (
            self.session.query(self.model)
            .filter_by(auto_analysis_status="pending")
            .limit(limit)
            .all()
        )
```

**Benefits:**
- ✅ Testable (mock repository)
- ✅ Consistent data access
- ✅ No raw SQL in services
- ✅ Transaction management

**Effort:** 1 week

---

### Phase 4: Service Layer (Week 4-6)
**Goal:** Extract business logic to services

```python
# src/services/phishing_detection.py
from src.repositories.phishing_site import PhishingSiteRepository
from src.integrations.virustotal import VirusTotalClient
from src.integrations.urlvoid import URLVoidClient
from src.integrations.phishtank import PhishTankClient

class PhishingDetectionService:
    def __init__(
        self,
        repo: PhishingSiteRepository,
        virustotal: VirusTotalClient,
        urlvoid: URLVoidClient,
        phishtank: PhishTankClient
    ):
        self.repo = repo
        self.virustotal = virustotal
        self.urlvoid = urlvoid
        self.phishtank = phishtank

    async def analyze_url(self, url: str) -> PhishingAnalysisResult:
        """
        Perform multi-API analysis with confidence scoring.
        """
        # Run APIs in parallel (async)
        vt_task = self.virustotal.scan_url(url)
        uv_task = self.urlvoid.check_url(url)
        pt_task = self.phishtank.check_url(url)

        vt_result, uv_result, pt_result = await asyncio.gather(
            vt_task, uv_task, pt_task
        )

        # Aggregate results
        confidence = self._calculate_confidence(vt_result, uv_result, pt_result)
        threat_level = self._determine_threat_level(confidence)

        # Save to database
        site = PhishingSite(
            url=url,
            confidence_score=confidence,
            threat_level=threat_level,
            virustotal_result=vt_result,
            urlvoid_result=uv_result,
            phishtank_result=pt_result
        )

        return self.repo.create(site)
```

**Benefits:**
- ✅ Business logic isolated
- ✅ Dependency injection
- ✅ Easy to test
- ✅ Async/await support

**Effort:** 2 weeks

---

### Phase 5: FastAPI Migration (Week 6-8)
**Goal:** Migrate from Flask to FastAPI

```python
# src/api/app.py
from fastapi import FastAPI
from src.api.routes.v1 import phishing, analytics, reports
from src.api.middleware.auth import AuthMiddleware
from src.api.middleware.cors import setup_cors

app = FastAPI(
    title="Anisakys Enterprise API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Middleware
app.add_middleware(AuthMiddleware)
setup_cors(app)

# Routes
app.include_router(phishing.router, prefix="/api/v1", tags=["phishing"])
app.include_router(analytics.router, prefix="/api/v1", tags=["analytics"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])

# src/api/routes/v1/phishing.py
from fastapi import APIRouter, Depends
from src.api.dependencies import get_phishing_service
from src.services.phishing_detection import PhishingDetectionService

router = APIRouter()

@router.post("/scan")
async def scan_url(
    url: str,
    service: PhishingDetectionService = Depends(get_phishing_service)
):
    result = await service.analyze_url(url)
    return result
```

**Benefits:**
- ✅ Async/await native
- ✅ Auto-generated OpenAPI docs
- ✅ Better performance
- ✅ Type validation (Pydantic)

**Effort:** 2 weeks

---

### Phase 6: Celery Tasks (Week 8-10)
**Goal:** Replace threading with Celery

```python
# src/tasks/celery_app.py
from celery import Celery

celery_app = Celery(
    'anisakys',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

# src/tasks/analysis.py
from src.tasks.celery_app import celery_app

@celery_app.task(bind=True, max_retries=3)
def analyze_pending_sites(self):
    """
    Background task to analyze pending phishing sites.
    """
    service = get_phishing_service()
    pending = service.get_pending_sites(limit=100)

    for site in pending:
        try:
            service.analyze_site(site.id)
        except Exception as exc:
            self.retry(exc=exc, countdown=60)
```

**Benefits:**
- ✅ No GIL bottleneck
- ✅ Distributed workers
- ✅ Retry mechanism
- ✅ Task prioritization

**Effort:** 2 weeks

---

## Technology Stack

### Current (v1.1.0)
```yaml
Backend:
  - Python 3.12
  - Flask (sync)
  - SQLAlchemy (raw SQL)
  - Threading
  - PostgreSQL

Frontend:
  - React 18
  - TypeScript
  - Vite
  - Tailwind CSS
```

### Target (v2.0.0)
```yaml
Backend:
  - Python 3.12
  - FastAPI (async) ← NEW
  - SQLAlchemy 2.0 (ORM) ← IMPROVED
  - Celery + Redis ← NEW
  - PostgreSQL 16

Background Processing:
  - Celery ← NEW
  - Redis (broker + cache) ← NEW
  - RabbitMQ (optional) ← NEW

Storage:
  - S3/MinIO (screenshots) ← NEW
  - PostgreSQL (metadata)

Monitoring:
  - Prometheus ← NEW
  - Grafana ← NEW
  - Sentry ← NEW
  - ELK Stack ← NEW

Frontend:
  - React 18
  - TypeScript
  - Vite
  - Tailwind CSS
  - React Query (✓ already using)
```

---

## Security Architecture

### Authentication Flow

```
┌─────────┐         ┌──────────┐        ┌──────────┐
│ Client  │         │ FastAPI  │        │  Redis   │
│(Browser)│         │   API    │        │  Cache   │
└─────────┘         └──────────┘        └──────────┘
     │                    │                   │
     │ POST /auth/login   │                   │
     ├───────────────────>│                   │
     │  {api_key}         │                   │
     │                    │ Validate API key  │
     │                    │ Generate JWT      │
     │                    │                   │
     │  Set httpOnly      │                   │
     │  cookies           │                   │
     │<───────────────────┤                   │
     │                    │                   │
     │ GET /api/v1/stats  │                   │
     ├───────────────────>│                   │
     │  Cookie: token     │ Verify JWT        │
     │                    ├──────────────────>│
     │                    │ Check cache       │
     │                    │<──────────────────┤
     │  Response + data   │                   │
     │<───────────────────┤                   │
```

### Multi-Tenancy

```python
# Database schema with tenant isolation
class PhishingSite(Base):
    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))  # ← NEW
    url: Mapped[str]
    # ...

    # Row-level security
    __table_args__ = (
        Index('idx_tenant_url', 'tenant_id', 'url'),
    )
```

---

## Scalability Plan

### Horizontal Scaling

```
                    ┌──────────────┐
                    │ Load Balancer│
                    │  (Nginx/ALB) │
                    └──────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    ┌───────┐          ┌───────┐          ┌───────┐
    │FastAPI│          │FastAPI│          │FastAPI│
    │ Pod 1 │          │ Pod 2 │          │ Pod 3 │
    └───────┘          └───────┘          └───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                    ┌──────────────┐
                    │  PostgreSQL  │
                    │   Cluster    │
                    │ (Primary +   │
                    │  Replicas)   │
                    └──────────────┘
```

### Performance Targets

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| Concurrent Users | 50 | 10,000 | 200x |
| Requests/sec | 100 | 1,000+ | 10x |
| Response Time (p95) | 2s | <500ms | 4x |
| Background Tasks | 20/min | 1,000/min | 50x |
| Database QPS | 500 | 10,000+ | 20x |

---

## Next Steps

### Sprint 1-2 (Weeks 1-4)
- [x] Fix critical vulnerabilities ✅
- [x] Add database pooling ✅
- [x] Setup CI/CD ✅
- [ ] Extract integrations
- [ ] Create ORM models

### Sprint 3-4 (Weeks 5-8)
- [ ] Implement repository pattern
- [ ] Create service layer
- [ ] Migrate to FastAPI

### Sprint 5-6 (Weeks 9-12)
- [ ] Implement Celery tasks
- [ ] Add Redis caching
- [ ] Performance testing

---

**Architecture Status:** ✅ Design Complete
**Next Review:** Week 2 (after Phase 1 completion)
**Owner:** Winston (Architect) + Amelia (Dev Lead)
