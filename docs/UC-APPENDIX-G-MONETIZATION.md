# UC-APPENDIX-G: Monetization Strategy

**Version:** 2.0.0-alpha  
**Date:** 2026-01-03  
**Status:** Specification  
**Owner:** Product Management

---

## Overview

This document defines the monetization strategy for Anisakys Enterprise, including pricing tiers, feature restrictions, rate limits, and billing integration.

**Business Model:** SaaS subscription + API usage-based billing

---

## Pricing Tiers

### Tier 1: Community (Free Forever)

**Target Audience:** Individual security researchers, students, small nonprofits

**Price:** $0/month

**Limits:**
- **URL Scans:** 100 scans/month
- **Batch Scans:** Max 10 URLs per batch
- **API Rate Limit:** 60 requests/hour (1 req/min)
- **Concurrent Scans:** 2 simultaneous
- **Data Retention:** 30 days
- **Domain Watchlist:** 5 domains
- **Users:** 1 user only
- **Support:** Community forum only

**Features Included:**
- ✅ Manual URL scanning (UC-001)
- ✅ Basic threat detection (UC-010)
- ✅ Screenshot capture (UC-012)
- ✅ Export to CSV (UC-044)
- ❌ Batch scanning (UC-002) - limited to 10
- ❌ Abuse reporting (UC-020)
- ❌ ICANN compliance tracking (UC-022)
- ❌ Dashboard analytics (UC-033)
- ❌ Custom reports (UC-040)
- ❌ API access (UC-070)

---

### Tier 2: Professional ($99/month)

**Target Audience:** Small security teams, MSSPs, individual SOC analysts

**Price:** $99/month or $990/year (2 months free)

**Limits:**
- **URL Scans:** 10,000 scans/month
- **Batch Scans:** Max 1,000 URLs per batch
- **API Rate Limit:** 1,000 requests/hour
- **Concurrent Scans:** 25 simultaneous
- **Data Retention:** 365 days (1 year)
- **Domain Watchlist:** 100 domains
- **Users:** 5 users
- **Support:** Email support (24h SLA)

**Features Included:**
- ✅ All Community features
- ✅ Batch URL scanning (UC-002) - full
- ✅ Automated abuse reporting (UC-020)
- ✅ ICANN SLA tracking (UC-022)
- ✅ Domain monitoring (UC-003)
- ✅ Dashboard analytics (UC-033)
- ✅ Custom report builder (UC-040)
- ✅ Scheduled reports (UC-041)
- ✅ RESTful API access (UC-070)
- ✅ Webhook notifications (UC-071)
- ✅ CSV/JSON export (UC-044)
- ❌ Certificate Transparency monitoring (UC-004)
- ❌ SSO/SAML (UC-051)
- ❌ White-label branding
- ❌ SLA guarantees

---

### Tier 3: Business ($499/month)

**Target Audience:** Medium enterprises, dedicated SOC teams, brand protection agencies

**Price:** $499/month or $4,990/year (2 months free)

**Limits:**
- **URL Scans:** 100,000 scans/month
- **Batch Scans:** Max 10,000 URLs per batch
- **API Rate Limit:** 10,000 requests/hour
- **Concurrent Scans:** 100 simultaneous
- **Data Retention:** Unlimited (with lifecycle policies)
- **Domain Watchlist:** 1,000 domains
- **Users:** 25 users
- **Support:** Priority email + chat (4h SLA)

**Features Included:**
- ✅ All Professional features
- ✅ Certificate Transparency monitoring (UC-004)
- ✅ Threat intelligence correlation (UC-014)
- ✅ Campaign correlation (UC-034)
- ✅ Team collaboration (UC-060, UC-061)
- ✅ Advanced analytics (UC-042, UC-043)
- ✅ STIX/MISP export (UC-044)
- ✅ SSO/SAML (UC-051)
- ✅ Audit logging (UC-054)
- ✅ SLA: 99.5% uptime
- ❌ White-label branding
- ❌ Dedicated infrastructure
- ❌ Custom integrations

---

### Tier 4: Enterprise (Custom Pricing)

**Target Audience:** Large enterprises, Fortune 500, government agencies, global MSSPs

**Price:** Starting at $2,500/month (custom quotes)

**Limits:**
- **URL Scans:** Unlimited (fair use: 1M+/month)
- **Batch Scans:** Unlimited
- **API Rate Limit:** Custom (100K+/hour)
- **Concurrent Scans:** 500+ simultaneous
- **Data Retention:** Custom (multi-year, compliance-driven)
- **Domain Watchlist:** Unlimited
- **Users:** Unlimited
- **Support:** Dedicated TAM, phone support (1h SLA), 24/7 on-call

**Features Included:**
- ✅ All Business features
- ✅ White-label branding
- ✅ Dedicated infrastructure (isolated DB, workers)
- ✅ Custom integrations (SIEM, SOAR, ticketing)
- ✅ Multi-tenancy support (namespaces + isolated DBs)
- ✅ On-premise deployment option
- ✅ SLA: 99.9% uptime with penalties
- ✅ Professional services (custom rules, training)
- ✅ Quarterly business reviews (QBRs)
- ✅ SOC 2 Type II compliance
- ✅ Custom ML model training
- ✅ Dedicated account manager

---

## Feature Matrix

| Feature | Community | Professional | Business | Enterprise |
|---------|-----------|--------------|----------|------------|
| **URL Scans/month** | 100 | 10K | 100K | Unlimited |
| Manual Scanning | ✅ | ✅ | ✅ | ✅ |
| Batch Scanning | 10 max | 1K max | 10K max | Unlimited |
| Multi-API Validation | ✅ | ✅ | ✅ | ✅ |
| Screenshot Capture | ✅ | ✅ | ✅ | ✅ |
| Abuse Reporting | ❌ | ✅ | ✅ | ✅ |
| ICANN SLA Tracking | ❌ | ✅ | ✅ | ✅ |
| Domain Monitoring | ❌ | ✅ | ✅ | ✅ |
| CT Monitoring | ❌ | ❌ | ✅ | ✅ |
| Dashboard Analytics | ❌ | ✅ | ✅ | ✅ |
| Custom Reports | ❌ | ✅ | ✅ | ✅ |
| Scheduled Reports | ❌ | ✅ | ✅ | ✅ |
| API Access | ❌ | ✅ | ✅ | ✅ |
| Webhooks | ❌ | ✅ | ✅ | ✅ |
| Team Collaboration | ❌ | ❌ | ✅ | ✅ |
| SSO/SAML | ❌ | ❌ | ✅ | ✅ |
| STIX/MISP Export | ❌ | ❌ | ✅ | ✅ |
| Audit Logging | ❌ | ❌ | ✅ | ✅ |
| White-label | ❌ | ❌ | ❌ | ✅ |
| Dedicated Infrastructure | ❌ | ❌ | ❌ | ✅ |
| On-premise Option | ❌ | ❌ | ❌ | ✅ |
| **Users** | 1 | 5 | 25 | Unlimited |
| **Data Retention** | 30 days | 1 year | Unlimited | Custom |
| **Support SLA** | None | 24h | 4h | 1h + 24/7 |
| **Uptime SLA** | None | None | 99.5% | 99.9% |

---

## Rate Limiting Specification

### Implementation: Token Bucket Algorithm

Each tier has a token bucket with the following parameters:

**Community:**
```python
RATE_LIMIT_CONFIG = {
    'tier': 'community',
    'tokens_per_hour': 60,
    'burst_capacity': 10,  # Can burst to 10 requests at once
    'refill_rate': 1  # 1 token per minute
}
```

**Professional:**
```python
RATE_LIMIT_CONFIG = {
    'tier': 'professional',
    'tokens_per_hour': 1000,
    'burst_capacity': 100,
    'refill_rate': 16.67  # ~17 tokens per minute
}
```

**Business:**
```python
RATE_LIMIT_CONFIG = {
    'tier': 'business',
    'tokens_per_hour': 10000,
    'burst_capacity': 500,
    'refill_rate': 166.67  # ~167 tokens per minute
}
```

**Enterprise:**
```python
RATE_LIMIT_CONFIG = {
    'tier': 'enterprise',
    'tokens_per_hour': 100000,  # Or custom
    'burst_capacity': 2000,
    'refill_rate': 1666.67  # ~1667 tokens per minute
}
```

### Rate Limit Headers

All API responses include rate limit information:

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 742
X-RateLimit-Reset: 1704297600
X-RateLimit-Tier: professional
```

### Rate Limit Exceeded Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 3600
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704297600

{
  "error": "Rate limit exceeded",
  "message": "You have exceeded your hourly rate limit of 1000 requests. Limit resets at 2026-01-03T15:00:00Z.",
  "tier": "professional",
  "upgrade_url": "https://anisakys.com/pricing"
}
```

---

## Usage Tracking & Billing

### Metered Resources

The following resources are metered for billing:

1. **URL Scans** (primary metric)
   - Charged per successful scan
   - Failed scans (4xx/5xx errors) not counted
   - Cached results not counted (if same URL scanned <24h ago)

2. **API Requests** (secondary metric)
   - All authenticated API calls
   - Excludes auth endpoints (/auth/login, /auth/refresh)

3. **Storage** (for Enterprise only)
   - Screenshots: $0.03/GB/month
   - Historical data beyond retention: $0.02/GB/month

4. **Overages** (when monthly limits exceeded)
   - Professional: $0.02 per scan over 10K limit
   - Business: $0.01 per scan over 100K limit
   - Enterprise: Negotiated rates

### Usage Tracking Implementation

**Database Schema:**

```sql
CREATE TABLE usage_tracking (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    tier VARCHAR(20) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,  -- 'url_scan', 'api_request', 'storage_gb'
    quantity INT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    metadata JSONB,  -- Additional context
    INDEX idx_user_period (user_id, timestamp)
);

CREATE TABLE billing_periods (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    tier VARCHAR(20) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    url_scans_used INT DEFAULT 0,
    url_scans_limit INT NOT NULL,
    api_requests_used INT DEFAULT 0,
    overage_charges DECIMAL(10,2) DEFAULT 0,
    total_amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',  -- active, overdue, cancelled
    INDEX idx_user_period (user_id, period_start)
);
```

**Usage Counter Service:**

```python
class UsageTracker:
    def record_scan(self, user_id: int, tier: str):
        """Record a URL scan and check limits."""
        # Increment counter
        current_period = self.get_current_billing_period(user_id)
        current_period.url_scans_used += 1
        
        # Check limit
        if current_period.url_scans_used > current_period.url_scans_limit:
            # Calculate overage
            overage = current_period.url_scans_used - current_period.url_scans_limit
            overage_rate = self.get_overage_rate(tier)
            current_period.overage_charges += overage_rate
            
            # Alert user
            self.send_overage_alert(user_id, overage, overage_rate)
        
        db.session.commit()
        
        return {
            'scans_used': current_period.url_scans_used,
            'scans_limit': current_period.url_scans_limit,
            'scans_remaining': max(0, current_period.url_scans_limit - current_period.url_scans_used),
            'overage_charges': current_period.overage_charges
        }
```

---

## Billing Integration

### Payment Provider: Stripe

**Subscription Products:**

```python
STRIPE_PRODUCTS = {
    'professional': {
        'price_id': 'price_xxxxxxxxxxxxxxxx',
        'amount': 9900,  # $99.00
        'interval': 'month'
    },
    'business': {
        'price_id': 'price_yyyyyyyyyyyyyyyy',
        'amount': 49900,  # $499.00
        'interval': 'month'
    },
    'enterprise': {
        # Custom quotes, manual invoicing
        'price_id': None,
        'amount': None,
        'interval': 'custom'
    }
}
```

**Metered Billing (for overages):**

```python
# Report usage to Stripe at end of billing period
stripe.SubscriptionItem.create_usage_record(
    subscription_item_id='si_xxxxxxxxxxxxxxxx',
    quantity=overage_scans,
    timestamp=int(time.time()),
    action='increment'
)
```

### Use Cases Impacted

- **UC-070:** API Access - Check tier before allowing access
- **UC-074:** Rate Limiting - Enforce limits per tier
- **UC-001, UC-002:** Scanning - Check monthly scan limits
- **UC-050:** User Management - Enforce user limits per tier
- **UC-052:** API Key Management - Tier-specific API keys

---

## Migration & Grandfathering

### Beta Users (if applicable)

Existing beta users grandfathered at:
- **Professional tier pricing** for first 12 months
- After 12 months, standard pricing applies with 30-day notice

### Free Trial

All paid tiers offer:
- **14-day free trial** (no credit card required for Professional)
- **Full feature access** during trial
- **Auto-upgrade prompt** on day 10
- **Auto-downgrade to Community** if not upgraded by day 14

---

## Compliance & Legal

### Terms of Service

- **Fair Use Policy:** No scraping, reselling, or abusive behavior
- **Data Ownership:** Customer owns all scan data
- **SLA Credits:** Business/Enterprise tiers receive 10% monthly credit per 0.1% downtime below SLA
- **Cancellation:** Cancel anytime, prorated refund within 30 days

### DMCA / Abuse

- Platform may suspend accounts violating TOS
- Refund policy: Full refund if suspended erroneously

---

## Implementation Roadmap

### Sprint 1-2 (MVP):
- ✅ Community tier only
- ✅ Basic rate limiting (60/hour)
- ✅ Hardcoded tier in user model
- ❌ No billing integration
- ❌ No usage tracking (just scan count)

### Sprint 3-4:
- ✅ Professional tier
- ✅ Stripe subscription integration
- ✅ Usage tracking (scans, API requests)
- ✅ Tier-based feature flags
- ✅ Upgrade/downgrade workflows

### Sprint 5:
- ✅ Business tier
- ✅ Overage billing
- ✅ Advanced analytics for usage
- ✅ Self-service tier changes

### Post-Launch:
- ✅ Enterprise tier (custom quotes)
- ✅ Multi-tenancy for Enterprise
- ✅ Dedicated infrastructure

---

## Success Metrics

**Target Conversion Rates:**
- Community → Professional: 5% (month 3)
- Professional → Business: 15% (month 12)

**Target MRR (Monthly Recurring Revenue):**
- Month 3: $5K MRR (50 Professional)
- Month 6: $15K MRR (100 Professional, 10 Business)
- Month 12: $50K MRR (200 Professional, 50 Business, 5 Enterprise)

---

**Status:** ✅ COMPLETE - Ready for Implementation  
**Next:** Create database schema with tier field  
**Owner:** Product Management + Engineering
