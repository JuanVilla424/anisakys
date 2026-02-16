# UC-APPENDIX-A: Database Schema Specification

**Version:** 2.0.0-alpha  
**Date:** 2026-01-03  
**Status:** Specification  
**Owner:** Database Architecture Team

---

## Overview

This document defines the complete PostgreSQL 16 database schema for Anisakys Enterprise, including all tables, columns, indexes, constraints, and relationships.

**Database:** PostgreSQL 16  
**ORM:** SQLAlchemy 2.0  
**Migrations:** Alembic

---

## Core Tables

### 1. users

**Purpose:** User authentication and profile management

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    tier VARCHAR(20) NOT NULL DEFAULT 'community',  -- community, professional, business, enterprise
    status VARCHAR(20) NOT NULL DEFAULT 'active',   -- active, suspended, cancelled
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP,
    
    -- Constraints
    CONSTRAINT check_tier CHECK (tier IN ('community', 'professional', 'business', 'enterprise')),
    CONSTRAINT check_status CHECK (status IN ('active', 'suspended', 'cancelled')),
    CONSTRAINT check_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tier ON users(tier);
CREATE INDEX idx_users_status ON users(status);
```

**SQLAlchemy Model:**

```python
class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    tier: Mapped[str] = mapped_column(String(20), default='community')
    status: Mapped[str] = mapped_column(String(20), default='active')
    email_verified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at: Mapped[Optional[datetime]]
    
    # Relationships
    api_keys: Mapped[List["APIKey"]] = relationship(back_populates="user")
    scans: Mapped[List["Scan"]] = relationship(back_populates="user")
```

---

### 2. api_keys

**Purpose:** API key management for programmatic access

```sql
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,  -- SHA256 hash of actual key
    key_prefix VARCHAR(20) NOT NULL,         -- First 8 chars for display (ak_12345678...)
    name VARCHAR(100),                       -- User-defined name ("Production API", "Dev Key")
    scopes TEXT[],                           -- Array of permissions: ['scan:read', 'scan:write', 'reports:read']
    rate_limit_tier VARCHAR(20),             -- Override tier rate limit if needed
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,                    -- NULL = never expires
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT fk_api_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;
```

---

### 3. scans

**Purpose:** URL scan results and metadata

```sql
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    url_hash VARCHAR(64) NOT NULL,           -- SHA256 hash for deduplication
    scan_type VARCHAR(20) NOT NULL,          -- 'manual', 'batch', 'scheduled', 'api'
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, processing, completed, failed
    
    -- Threat Assessment
    threat_level VARCHAR(20),                -- safe, low, medium, high, critical
    confidence_score DECIMAL(5,2),           -- 0.00 to 100.00
    is_phishing BOOLEAN,
    
    -- API Results (JSONB for flexibility)
    virustotal_result JSONB,                 -- {positives: 45, total: 70, permalink: "..."}
    urlvoid_result JSONB,                    -- {blacklists: 15, total_checks: 30}
    phishtank_result JSONB,                  -- {in_database: true, verified: true}
    grinder_result JSONB,                    -- {reputation_score: 25}
    
    -- Evidence
    screenshot_url TEXT,                     -- S3/MinIO path
    screenshot_hash VARCHAR(64),             -- For deduplication
    html_snapshot_url TEXT,                  -- Archived HTML
    
    -- Metadata
    domain VARCHAR(255),                     -- Extracted domain
    ip_address INET,                         -- Resolved IP
    country_code VARCHAR(2),                 -- GeoIP lookup
    hosting_provider VARCHAR(255),
    
    -- Timestamps
    scan_started_at TIMESTAMP,
    scan_completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Performance Metrics
    scan_duration_ms INT,                    -- Milliseconds
    
    -- Constraints
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT check_status CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    CONSTRAINT check_threat_level CHECK (threat_level IN ('safe', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT check_confidence_score CHECK (confidence_score BETWEEN 0 AND 100)
);

-- Indexes
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_url_hash ON scans(url_hash);
CREATE INDEX idx_scans_domain ON scans(domain);
CREATE INDEX idx_scans_threat_level ON scans(threat_level);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_status ON scans(status);

-- Composite index for common query: user's recent scans
CREATE INDEX idx_scans_user_created ON scans(user_id, created_at DESC);

-- GIN index for JSONB queries
CREATE INDEX idx_scans_virustotal_result ON scans USING GIN (virustotal_result);
```

**SQLAlchemy Model:**

```python
class Scan(Base):
    __tablename__ = 'scans'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default='pending')
    
    threat_level: Mapped[Optional[str]] = mapped_column(String(20))
    confidence_score: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 2))
    is_phishing: Mapped[Optional[bool]]
    
    virustotal_result: Mapped[Optional[dict]] = mapped_column(JSON)
    urlvoid_result: Mapped[Optional[dict]] = mapped_column(JSON)
    phishtank_result: Mapped[Optional[dict]] = mapped_column(JSON)
    grinder_result: Mapped[Optional[dict]] = mapped_column(JSON)
    
    screenshot_url: Mapped[Optional[str]] = mapped_column(Text)
    screenshot_hash: Mapped[Optional[str]] = mapped_column(String(64))
    html_snapshot_url: Mapped[Optional[str]] = mapped_column(Text)
    
    domain: Mapped[Optional[str]] = mapped_column(String(255))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 support
    country_code: Mapped[Optional[str]] = mapped_column(String(2))
    hosting_provider: Mapped[Optional[str]] = mapped_column(String(255))
    
    scan_started_at: Mapped[Optional[datetime]]
    scan_completed_at: Mapped[Optional[datetime]]
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    scan_duration_ms: Mapped[Optional[int]]
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="scans")
    abuse_reports: Mapped[List["AbuseReport"]] = relationship(back_populates="scan")
```

---

### 4. batch_scans

**Purpose:** Batch URL scanning management

```sql
CREATE TABLE batch_scans (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    batch_name VARCHAR(255),
    total_urls INT NOT NULL,
    completed_urls INT DEFAULT 0,
    failed_urls INT DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, processing, completed, failed
    progress_percentage DECIMAL(5,2) DEFAULT 0.00,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    
    -- Constraints
    CONSTRAINT fk_batch_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT check_batch_status CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

CREATE INDEX idx_batch_scans_user_id ON batch_scans(user_id);
CREATE INDEX idx_batch_scans_status ON batch_scans(status);
CREATE INDEX idx_batch_scans_created_at ON batch_scans(created_at DESC);
```

---

### 5. abuse_reports

**Purpose:** ICANN abuse report tracking

```sql
CREATE TABLE abuse_reports (
    id SERIAL PRIMARY KEY,
    scan_id INT REFERENCES scans(id) ON DELETE SET NULL,  -- Can exist without scan
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    
    -- Report Details
    report_type VARCHAR(50) NOT NULL,        -- 'phishing', 'malware', 'spam', 'copyright'
    recipient_email TEXT[] NOT NULL,         -- Array of recipients (registrar, hosting, phishtank)
    subject VARCHAR(500),
    body TEXT,
    attachments TEXT[],                      -- S3/MinIO paths
    
    -- ICANN SLA Tracking
    icann_sla_deadline TIMESTAMP,            -- submission_time + 48 hours
    icann_sla_status VARCHAR(20),            -- compliant, approaching, overdue, waived
    sla_alert_sent BOOLEAN DEFAULT FALSE,
    
    -- Status Tracking
    status VARCHAR(20) NOT NULL DEFAULT 'draft',  -- draft, submitted, acknowledged, resolved, rejected
    submitted_at TIMESTAMP,
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP,
    
    -- Response Tracking
    response_received BOOLEAN DEFAULT FALSE,
    response_text TEXT,
    response_received_at TIMESTAMP,
    
    -- Metadata
    manual_submission BOOLEAN DEFAULT FALSE,
    created_by INT REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT fk_abuse_reports_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_abuse_reports_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT check_report_type CHECK (report_type IN ('phishing', 'malware', 'spam', 'copyright', 'other')),
    CONSTRAINT check_report_status CHECK (status IN ('draft', 'submitted', 'acknowledged', 'resolved', 'rejected')),
    CONSTRAINT check_icann_sla_status CHECK (icann_sla_status IN ('compliant', 'approaching', 'overdue', 'waived'))
);

CREATE INDEX idx_abuse_reports_scan_id ON abuse_reports(scan_id);
CREATE INDEX idx_abuse_reports_user_id ON abuse_reports(user_id);
CREATE INDEX idx_abuse_reports_status ON abuse_reports(status);
CREATE INDEX idx_abuse_reports_icann_sla_deadline ON abuse_reports(icann_sla_deadline);
CREATE INDEX idx_abuse_reports_submitted_at ON abuse_reports(submitted_at DESC);
```

---

### 6. domain_watchlist

**Purpose:** Monitored domains for brand protection

```sql
CREATE TABLE domain_watchlist (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    brand_name VARCHAR(255),
    monitoring_enabled BOOLEAN DEFAULT TRUE,
    alert_threshold VARCHAR(20) DEFAULT 'medium',  -- low, medium, high, critical
    
    -- Monitoring Configuration
    check_typosquatting BOOLEAN DEFAULT TRUE,
    check_certificate_transparency BOOLEAN DEFAULT TRUE,
    check_social_media BOOLEAN DEFAULT FALSE,
    
    -- Notifications
    notify_email BOOLEAN DEFAULT TRUE,
    notify_webhook BOOLEAN DEFAULT FALSE,
    webhook_url TEXT,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_checked_at TIMESTAMP,
    
    -- Constraints
    CONSTRAINT fk_watchlist_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT unique_user_domain UNIQUE (user_id, domain)
);

CREATE INDEX idx_watchlist_user_id ON domain_watchlist(user_id);
CREATE INDEX idx_watchlist_domain ON domain_watchlist(domain);
CREATE INDEX idx_watchlist_monitoring_enabled ON domain_watchlist(monitoring_enabled);
```

---

### 7. audit_logs

**Purpose:** Security audit trail for compliance

```sql
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,               -- BIGSERIAL for high volume
    user_id INT REFERENCES users(id) ON DELETE SET NULL,  -- NULL if user deleted
    action VARCHAR(100) NOT NULL,            -- 'user.login', 'scan.create', 'report.submit'
    resource_type VARCHAR(50),               -- 'scan', 'user', 'api_key', 'report'
    resource_id INT,
    
    -- Request Context
    ip_address INET,
    user_agent TEXT,
    request_method VARCHAR(10),              -- GET, POST, PUT, DELETE
    request_path TEXT,
    
    -- Changes (for UPDATE operations)
    old_values JSONB,
    new_values JSONB,
    
    -- Result
    status VARCHAR(20),                      -- success, failure, error
    error_message TEXT,
    
    -- Timestamps
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT check_status CHECK (status IN ('success', 'failure', 'error'))
);

-- Indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Partitioning by month for performance (optional, for high volume)
-- CREATE TABLE audit_logs_2026_01 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
```

---

### 8. usage_tracking

**Purpose:** Track resource usage for billing

```sql
CREATE TABLE usage_tracking (
    id BIGSERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier VARCHAR(20) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,      -- 'url_scan', 'api_request', 'storage_gb'
    quantity INT NOT NULL DEFAULT 1,
    
    -- Metadata
    scan_id INT REFERENCES scans(id) ON DELETE SET NULL,
    api_endpoint TEXT,
    
    -- Timestamps
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    billing_period DATE NOT NULL,            -- YYYY-MM-01 format
    
    -- Constraints
    CONSTRAINT fk_usage_tracking_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_usage_user_period ON usage_tracking(user_id, billing_period);
CREATE INDEX idx_usage_resource_type ON usage_tracking(resource_type);
CREATE INDEX idx_usage_timestamp ON usage_tracking(timestamp DESC);
```

---

## Relationships Diagram

```
users
 ├── api_keys (1:N)
 ├── scans (1:N)
 ├── batch_scans (1:N)
 ├── abuse_reports (1:N)
 ├── domain_watchlist (1:N)
 ├── audit_logs (1:N)
 └── usage_tracking (1:N)

scans
 └── abuse_reports (1:N)
```

---

## Data Retention & Lifecycle

### Retention Policies by Tier

**Community:**
- Scans: 30 days
- Audit logs: 90 days
- Screenshots: 30 days

**Professional:**
- Scans: 365 days (1 year)
- Audit logs: 2 years
- Screenshots: 365 days

**Business:**
- Scans: Unlimited (with optional archival)
- Audit logs: 7 years (compliance)
- Screenshots: Unlimited

**Enterprise:**
- Custom retention per contract

### Lifecycle SQL

```sql
-- Delete old scans (Community tier)
DELETE FROM scans
WHERE user_id IN (SELECT id FROM users WHERE tier = 'community')
  AND created_at < NOW() - INTERVAL '30 days';

-- Archive old audit logs (move to cold storage)
INSERT INTO audit_logs_archive
SELECT * FROM audit_logs
WHERE timestamp < NOW() - INTERVAL '2 years';

DELETE FROM audit_logs
WHERE timestamp < NOW() - INTERVAL '2 years';
```

---

## Performance Optimization

### Connection Pooling

```python
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,           # Persistent connections
    max_overflow=40,        # Burst capacity
    pool_pre_ping=True,     # Verify connection health
    pool_recycle=3600,      # Recycle every hour
    echo=False
)
```

### Query Optimization Examples

```python
# GOOD: Use pagination
scans = db.query(Scan).filter_by(user_id=user_id) \
    .order_by(Scan.created_at.desc()) \
    .limit(50).offset(page * 50).all()

# BAD: Load all scans
scans = db.query(Scan).filter_by(user_id=user_id).all()  # Could be millions!

# GOOD: Select specific columns
results = db.query(Scan.id, Scan.url, Scan.threat_level) \
    .filter_by(user_id=user_id).all()

# GOOD: Use joins efficiently
scans_with_reports = db.query(Scan).join(AbuseReport) \
    .filter(Scan.user_id == user_id).all()
```

---

## Migration Strategy

### Initial Migration (Alembic)

```python
# alembic/versions/001_initial_schema.py
def upgrade():
    # Create tables in dependency order
    op.create_table('users', ...)
    op.create_table('api_keys', ...)
    op.create_table('scans', ...)
    op.create_table('abuse_reports', ...)
    # ... etc
    
def downgrade():
    # Drop in reverse order
    op.drop_table('abuse_reports')
    op.drop_table('scans')
    op.drop_table('api_keys')
    op.drop_table('users')
```

### Future Migrations

- Sprint 3: Add `campaigns` table for campaign correlation
- Sprint 4: Add `certificates` table for CT monitoring
- Sprint 5: Add `tenants` table for multi-tenancy

---

**Status:** ✅ COMPLETE - Ready for Implementation  
**Next:** Generate Alembic migration scripts  
**Owner:** Database Architecture Team
