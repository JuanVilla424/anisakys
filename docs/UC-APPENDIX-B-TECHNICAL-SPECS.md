# UC-APPENDIX-B: Technical Specifications

**Version:** 2.0.0-alpha  
**Date:** 2026-01-03  
**Status:** Specification  
**Owner:** Engineering Team

---

## 1. ICANN Compliance Specification

### Legal Framework

**ICANN RAA (Registrar Accreditation Agreement) Section 3.18:**
- Registrars MUST investigate and respond to abuse reports within **48 business hours**
- "Abuse" includes: phishing, malware distribution, botnets, spamming

**Business Hours:**
- Monday-Friday, 9am-5pm in registrar's timezone
- Excludes weekends and public holidays
- **Example:** Report submitted Friday 4pm → Deadline Tuesday 4pm (skips weekend)

### SLA Calculation

```python
def calculate_icann_deadline(submitted_at: datetime, registrar_timezone: str) -> datetime:
    """Calculate 48 business hour deadline."""
    import holidays
    import pytz
    
    tz = pytz.timezone(registrar_timezone)
    current = submitted_at.astimezone(tz)
    hours_remaining = 48
    
    while hours_remaining > 0:
        current += timedelta(hours=1)
        
        # Skip weekends
        if current.weekday() in (5, 6):  # Saturday, Sunday
            continue
        
        # Skip public holidays
        if current.date() in holidays.US():  # Use registrar's country
            continue
        
        # Only count 9am-5pm
        if 9 <= current.hour < 17:
            hours_remaining -= 1
    
    return current
```

### Abuse Report Format (RFC 3849 compliant)

```
To: abuse@registrar.com
Subject: [URGENT] Phishing Site Report - example-phishing.com
X-ICANN-Compliance: RAA-3.18

Dear Abuse Team,

We are reporting a phishing website hosted under your registrar's domain:

URL: http://example-phishing.com/paypal-login
Domain: example-phishing.com
Registrar: Example Registrar LLC
Submitted: 2026-01-03 14:30:00 UTC
Deadline: 2026-01-07 14:30:00 UTC (48 business hours)

THREAT EVIDENCE:
- VirusTotal: 45/70 antivirus engines flagged (64%)
- PhishTank: Verified phishing site (ID: 123456)
- Targets: PayPal customers
- Screenshot: [attached]

WHOIS Information:
- Registrar: Example Registrar LLC
- Creation Date: 2026-01-01
- Registrant: REDACTED FOR PRIVACY

We request immediate takedown or suspension under ICANN RAA Section 3.18.

Please confirm receipt and provide case number.

Thank you,
Anisakys Security Team
compliance@anisakys.com
```

### Registrar Abuse Contacts

```python
# Known registrars and their abuse contacts
REGISTRAR_ABUSE_CONTACTS = {
    'godaddy': 'abuse@godaddy.com',
    'namecheap': 'abuse@namecheap.com',
    'cloudflare': 'abuse@cloudflare.com',
    'google-domains': 'registrar-abuse@google.com',
    'network-solutions': 'abuse@networksolutions.com',
    # Fallback: use WHOIS abuse email
    'default': lambda domain: get_whois_abuse_email(domain)
}
```

### SLA Monitoring

```python
# Alert thresholds
ICANN_ALERT_HOURS = {
    '6h_warning': 42,    # 48h - 6h = Alert
    '1h_critical': 47,   # 48h - 1h = Critical alert
    'overdue': 48        # SLA breached
}
```

---

## 2. Performance Targets (REALISTIC)

### Revised Performance Targets

**Original (UNREALISTIC):**
- URL Scan p95: <3s ❌
- Concurrent users: 50+ ✅

**Revised (REALISTIC):**

| Metric | p50 | p95 | p99 | Max |
|--------|-----|-----|-----|-----|
| **URL Scan (All APIs)** | 5s | 10s | 15s | 30s |
| **URL Scan (Degraded - 1 API)** | 2s | 5s | 8s | 15s |
| **URL Scan (Cached)** | 100ms | 300ms | 500ms | 1s |
| **Batch Scan (1000 URLs)** | - | - | - | 20min |
| **API Request** | 50ms | 200ms | 500ms | 2s |
| **Database Query** | 5ms | 50ms | 100ms | 500ms |

### Performance Budget Breakdown

**Single URL Scan (Full Pipeline):**
```
1. URL validation:           10ms
2. Check cache:             20ms
3. DNS resolution:          100ms
4. Parallel API calls:      5-10s (slowest wins)
   ├─ VirusTotal:          2-7s
   ├─ URLVoid:             1-4s
   └─ PhishTank:           0.5-2s
5. Screenshot capture:      3-10s (headless Chrome)
6. WHOIS lookup:           500ms-2s
7. Calculate confidence:    10ms
8. Database write:         50ms
9. Generate response:      20ms
───────────────────────────────────
TOTAL p95:                 ~10s ✅
```

### Caching Strategy

```python
# Cache scan results for 24 hours
CACHE_CONFIG = {
    'scan_results': {
        'ttl': 86400,  # 24 hours
        'key': 'scan:{url_hash}',
        'backend': 'redis'
    },
    'api_responses': {
        'virustotal': 86400,   # 24h (VT data stable)
        'urlvoid': 3600,       # 1h (blacklists change frequently)
        'phishtank': 7200,     # 2h (community updates)
    }
}

def get_cached_scan(url_hash: str) -> Optional[dict]:
    """Check if URL was scanned in last 24h."""
    return redis.get(f'scan:{url_hash}')
```

### Load Testing Targets

```yaml
# Locust / k6 test scenarios
scenarios:
  baseline:
    users: 10
    spawn_rate: 1/s
    duration: 5min
    expected_p95: 10s
  
  target_load:
    users: 50
    spawn_rate: 5/s
    duration: 10min
    expected_p95: 12s
  
  stress_test:
    users: 100
    spawn_rate: 10/s
    duration: 5min
    acceptable_error_rate: 5%
```

---

## 3. Error Handling Strategy

### Error Taxonomy

**Transient Errors** (Retry with exponential backoff):
- Network timeout
- HTTP 429 (Rate Limit)
- HTTP 503 (Service Unavailable)
- DNS resolution timeout
- Database connection timeout

**Permanent Errors** (Fail immediately):
- HTTP 401 (Unauthorized - invalid API key)
- HTTP 403 (Forbidden - account suspended)
- HTTP 404 (Not Found - bad endpoint)
- Malformed URL
- SQL constraint violation

### Retry Policy

```python
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((Timeout, ConnectionError, HTTPError))
)
def call_external_api(url: str, api: str) -> dict:
    """Call external API with automatic retry."""
    try:
        response = httpx.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        if e.response.status_code in (401, 403, 404):
            raise  # Don't retry permanent errors
        raise  # Retry transient errors
```

### Circuit Breaker

```python
from circuitbreaker import circuit

@circuit(failure_threshold=5, recovery_timeout=60)
def virustotal_scan(url: str) -> dict:
    """Call VirusTotal with circuit breaker."""
    # If 5 consecutive failures, open circuit for 60 seconds
    return call_virustotal_api(url)
```

### Graceful Degradation

```python
async def multi_api_scan(url: str) -> dict:
    """Scan with graceful degradation."""
    tasks = [
        virustotal_scan(url),
        urlvoid_scan(url),
        phishtank_scan(url)
    ]
    
    # Gather results, don't fail if some APIs down
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    successful_apis = []
    failed_apis = []
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            failed_apis.append(API_NAMES[i])
            logger.warning(f"{API_NAMES[i]} failed: {result}")
        else:
            successful_apis.append((API_NAMES[i], result))
    
    # Require minimum 1 API success
    if not successful_apis:
        raise AllAPIsFailedError("All threat intelligence APIs failed")
    
    # Calculate confidence with available data
    confidence = calculate_confidence(successful_apis)
    
    return {
        'confidence_score': confidence,
        'apis_responding': len(successful_apis),
        'apis_failed': failed_apis,
        'warning': f'{len(failed_apis)} APIs unavailable' if failed_apis else None
    }
```

### User-Facing Error Messages

```python
ERROR_MESSAGES = {
    # Don't expose internal details
    'all_apis_failed': "Unable to scan URL. Please try again in a few minutes.",
    'invalid_url': "Invalid URL format. Please check and try again.",
    'rate_limit': f"Rate limit exceeded. Your limit resets in {minutes} minutes.",
    'server_error': "An unexpected error occurred. Our team has been notified.",
    
    # Never expose:
    # ❌ "Database connection failed: PostgreSQL timeout"
    # ❌ "VirusTotal API key invalid"
    # ❌ "Internal Server Error: NoneType has no attribute 'get'"
}
```

---

## 4. Concurrency Model

### Architecture Decision

**Use BOTH async/await AND Celery** (different use cases):

#### FastAPI Endpoints (async/await)
```python
@app.post("/api/scan")
async def scan_url(url: str):
    """Synchronous scan - user waits for result."""
    # Use async/await for I/O-bound operations
    results = await multi_api_scan(url)  # Parallel API calls
    await save_to_db(results)           # Async DB write
    return results
```

**When to use async/await:**
- API requests to external services
- Database queries
- I/O-bound operations
- User expects immediate response (<30s)

#### Celery Background Tasks
```python
@celery_app.task
def batch_scan_task(batch_id: int, urls: List[str]):
    """Asynchronous batch scan - runs in background."""
    for url in urls:
        result = sync_scan_url(url)  # Can be sync in worker
        update_batch_progress(batch_id, result)
```

**When to use Celery:**
- Long-running tasks (>30s)
- Batch processing (1000+ URLs)
- Scheduled jobs (daily CT monitoring)
- Tasks that can fail and retry later
- User doesn't wait for result (202 Accepted)

### Concurrency Comparison

| Feature | Async/Await | Celery |
|---------|-------------|--------|
| **Response Time** | Immediate | Async (poll status) |
| **Use Case** | Single scan | Batch, scheduled jobs |
| **Scalability** | Limited by workers | Horizontal (add workers) |
| **Error Handling** | Return to user | Retry queue |
| **Progress Tracking** | N/A (completes fast) | Required (long-running) |

### Worker Configuration

```python
# Celery worker config
CELERY_CONFIG = {
    'broker_url': 'redis://localhost:6379/0',
    'result_backend': 'redis://localhost:6379/0',
    'task_serializer': 'json',
    'accept_content': ['json'],
    'timezone': 'UTC',
    'worker_concurrency': 10,  # 10 concurrent tasks per worker
    'worker_prefetch_multiplier': 4,
    'task_acks_late': True,  # Acknowledge after completion
    'task_reject_on_worker_lost': True,
}

# Task priority
CELERY_TASK_PRIORITY = {
    'icann_deadline_alert': 0,    # Highest
    'user_scan': 5,
    'batch_scan': 7,
    'scheduled_monitoring': 9     # Lowest
}
```

---

## 5. Screenshot Capture with Fallbacks

### Fallback Strategy (4-tier)

```python
async def capture_screenshot(url: str) -> Optional[str]:
    """Capture screenshot with 4-tier fallback."""
    
    # Tier 1: Headless Chrome (Puppeteer/Playwright)
    try:
        return await screenshot_with_playwright(url)
    except (BrowserError, TimeoutError) as e:
        logger.warning(f"Playwright failed: {e}")
    
    # Tier 2: Screenshot API Service (screenshotapi.net)
    try:
        return await screenshot_with_api(url)
    except (APIError, RateLimitError) as e:
        logger.warning(f"Screenshot API failed: {e}")
    
    # Tier 3: Selenium with real browser profile
    try:
        return await screenshot_with_selenium(url)
    except Exception as e:
        logger.warning(f"Selenium failed: {e}")
    
    # Tier 4: Return None (screenshot unavailable)
    logger.error(f"All screenshot methods failed for {url}")
    return None  # Continue scan without screenshot
```

### Playwright Configuration (Stealth)

```python
from playwright.async_api import async_playwright

async def screenshot_with_playwright(url: str) -> str:
    """Capture screenshot with anti-bot evasion."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox'
            ]
        )
        
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            locale='en-US',
            timezone_id='America/New_York',
            # Stealth: Remove webdriver property
            extra_http_headers={
                'Accept-Language': 'en-US,en;q=0.9'
            }
        )
        
        # Inject stealth scripts
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        """)
        
        page = await context.new_page()
        
        try:
            await page.goto(url, timeout=10000, wait_until='networkidle')
            screenshot_bytes = await page.screenshot(full_page=True)
            
            # Upload to S3/MinIO
            screenshot_url = await upload_screenshot(screenshot_bytes, url)
            return screenshot_url
        finally:
            await browser.close()
```

### Success Rate Targets

- **Tier 1 (Playwright):** 60-70% success
- **Tier 2 (API Service):** 80-90% success (fallback)
- **Tier 3 (Selenium):** 50-60% success (heavy, slow)
- **Overall:** 80%+ success rate acceptable

**Acceptance Criteria:** System MUST continue scan even if screenshot fails

---

## 6. API Versioning Strategy

### URL-Based Versioning

```
https://api.anisakys.com/v1/scan
https://api.anisakys.com/v2/scan
```

**Rationale:** 
- Clear and explicit
- Easy to route (different controllers)
- Widely adopted (Stripe, GitHub, Twitter APIs)

### Versioning Policy

**v1 Support:**
- Supported for 12 months after v2 release
- Security fixes only (no new features)
- Deprecation warnings in response headers:
  ```http
  X-API-Version: v1
  X-API-Deprecation: true
  X-API-Sunset: 2027-01-01
  Link: <https://docs.anisakys.com/api/v2/migration>; rel="deprecation"
  ```

**v2 Changes (planned):**
- New response format (nested objects instead of flat)
- ISO 8601 timestamps (instead of Unix epoch)
- HATEOAS links
- Pagination with cursor (instead of offset)

### Version Negotiation

```python
@app.post("/v1/scan")
async def scan_url_v1(url: str):
    """V1 API - Flat response."""
    result = await scan_url(url)
    return {
        'url': result.url,
        'threat_level': result.threat_level,
        'confidence_score': float(result.confidence_score),
        'timestamp': int(result.created_at.timestamp()),  # Unix epoch
    }

@app.post("/v2/scan")
async def scan_url_v2(url: str):
    """V2 API - Nested response."""
    result = await scan_url(url)
    return {
        'data': {
            'url': result.url,
            'threat': {
                'level': result.threat_level,
                'confidence_score': float(result.confidence_score)
            },
            'timestamps': {
                'scanned_at': result.created_at.isoformat(),  # ISO 8601
                'completed_at': result.scan_completed_at.isoformat()
            }
        },
        'links': {
            'self': f'/v2/scans/{result.id}',
            'report': f'/v2/scans/{result.id}/report'
        }
    }
```

---

**Status:** ✅ COMPLETE - All Critical Technical Specs Defined  
**Next:** Update USE_CASES.md with revised performance targets  
**Owner:** Engineering Team
