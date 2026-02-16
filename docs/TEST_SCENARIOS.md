# Anisakys Enterprise - Test Scenarios Specification

**Version:** 2.0.0-alpha  
**Last Updated:** 2026-01-03  
**Status:** Draft  
**Owner:** Test Engineering Team

---

## Document Overview

This document defines comprehensive test scenarios derived from the 74 use cases documented in `USE_CASES.md`. Each test scenario includes:

- **Test ID**: Unique identifier (TS-XXX)
- **Use Case Mapping**: Links to originating use case (UC-XXX)
- **Test Type**: Unit, Integration, E2E, Security, Performance
- **Priority**: P0 (Critical), P1 (High), P2 (Medium), P3 (Low)
- **Test Data**: Required test fixtures and data
- **Expected Outcome**: Acceptance criteria
- **Automation Status**: Manual, Automated, Partial

---

## Test Coverage Matrix

| Category | Use Cases | Test Scenarios | Unit Tests | Integration Tests | E2E Tests | Coverage Target |
|----------|-----------|----------------|------------|-------------------|-----------|-----------------|
| Phishing Detection | 7 | 28 | 42 | 14 | 7 | 80% |
| Threat Validation | 6 | 24 | 36 | 12 | 6 | 75% |
| Abuse Reporting | 6 | 18 | 24 | 9 | 6 | 70% |
| Monitoring & Tracking | 5 | 15 | 20 | 8 | 5 | 70% |
| Analytics & Reporting | 6 | 18 | 24 | 9 | 6 | 65% |
| Administration | 6 | 24 | 30 | 12 | 6 | 75% |
| Collaboration | 5 | 15 | 18 | 8 | 5 | 60% |
| API Integration | 5 | 20 | 30 | 10 | 5 | 80% |
| **TOTAL** | **46** | **162** | **224** | **82** | **46** | **73%** |

---

## Test Environment Configuration

### 1. Test Database Setup

```python
# tests/conftest.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

@pytest.fixture(scope="session")
def test_db_engine():
    """Create test database engine with isolated schema."""
    engine = create_engine(
        "postgresql://anisakys_test:test_password@localhost:5432/anisakys_test",
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=10
    )
    yield engine
    engine.dispose()

@pytest.fixture(scope="function")
def db_session(test_db_engine):
    """Create isolated database session per test."""
    connection = test_db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()
```

### 2. Mock External APIs

```python
# tests/mocks/api_mocks.py
import pytest
from unittest.mock import Mock, patch

@pytest.fixture
def mock_virustotal():
    """Mock VirusTotal API responses."""
    with patch('src.integrations.virustotal.VirusTotalClient') as mock:
        mock.return_value.scan_url.return_value = {
            'positives': 45,
            'total': 70,
            'permalink': 'https://virustotal.com/gui/url/...',
            'scan_date': '2026-01-03 10:00:00'
        }
        yield mock

@pytest.fixture
def mock_urlvoid():
    """Mock URLVoid API responses."""
    with patch('src.integrations.urlvoid.URLVoidClient') as mock:
        mock.return_value.check_url.return_value = {
            'blacklists': 15,
            'total_checks': 30,
            'risk_score': 85
        }
        yield mock

@pytest.fixture
def mock_phishtank():
    """Mock PhishTank API responses."""
    with patch('src.integrations.phishtank.PhishTankClient') as mock:
        mock.return_value.check_url.return_value = {
            'in_database': True,
            'valid': True,
            'verified': True,
            'verification_time': '2026-01-03 09:30:00'
        }
        yield mock
```

### 3. Test Data Fixtures

```python
# tests/fixtures/test_data.py
import pytest
from datetime import datetime, timedelta

@pytest.fixture
def sample_phishing_urls():
    """Sample phishing URLs for testing."""
    return [
        "http://paypal-verify-account.suspicious.com",
        "https://amazon-security-alert.phishing.net",
        "http://facebook-login-secure.fake-site.org",
        "https://bank-of-america-alert.scam.ru"
    ]

@pytest.fixture
def sample_legitimate_urls():
    """Sample legitimate URLs for testing."""
    return [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.mozilla.org"
    ]

@pytest.fixture
def sample_scan_results():
    """Sample scan result data."""
    return {
        'url': 'http://example-phishing.com',
        'confidence_score': 85.5,
        'threat_level': 'critical',
        'virustotal_positives': 45,
        'urlvoid_blacklists': 15,
        'phishtank_verified': True,
        'scan_timestamp': datetime.utcnow(),
        'screenshot_url': '/screenshots/abc123.png'
    }
```

---

## Category 1: Phishing Detection Test Scenarios

### TS-001: Manual URL Submission - Valid Phishing URL

**Use Case:** UC-001  
**Priority:** P0  
**Type:** E2E, Integration, Unit  
**Status:** Automated

**Test Description:**  
Verify that submitting a known phishing URL returns correct threat assessment with high confidence score.

**Preconditions:**
- User authenticated with valid API key
- External APIs (VirusTotal, URLVoid, PhishTank) accessible
- Database connection available

**Test Data:**
```python
test_url = "http://paypal-security-verify.malicious.com"
expected_threat_level = "critical"
expected_min_confidence = 80.0
```

**Test Steps:**
1. Navigate to Scanner page (/scanner)
2. Enter `test_url` in URL input field
3. Click "Scan URL" button
4. Wait for scan completion (max 5 seconds)
5. Verify results displayed

**Expected Results:**
- Status code: 200
- Response contains `scan_id`
- `threat_level` = "critical" or "high"
- `confidence_score` >= 80.0
- `virustotal_positives` > 0
- `phishtank_verified` = True
- Screenshot captured and stored
- Database record created

**Acceptance Criteria:**
```python
def test_manual_url_submission_phishing(client, db_session, mock_virustotal, mock_phishtank):
    """TS-001: Submit known phishing URL and verify threat detection."""
    # Arrange
    url = "http://paypal-security-verify.malicious.com"
    
    # Act
    response = client.post('/api/scan', json={'url': url})
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data['threat_level'] in ['critical', 'high']
    assert data['confidence_score'] >= 80.0
    assert 'scan_id' in data
    assert data['virustotal_positives'] > 0
    
    # Verify database record
    scan = db_session.query(ScanResult).filter_by(url=url).first()
    assert scan is not None
    assert scan.threat_level == data['threat_level']
```

**Test File:** `tests/e2e/test_phishing_detection.py::test_manual_url_submission_phishing`

---

### TS-002: Manual URL Submission - Legitimate URL

**Use Case:** UC-001  
**Priority:** P0  
**Type:** E2E, Integration  
**Status:** Automated

**Test Description:**  
Verify that submitting a legitimate URL returns low threat assessment with appropriate confidence score.

**Test Data:**
```python
test_url = "https://www.wikipedia.org"
expected_threat_level = "safe"
expected_max_confidence = 20.0
```

**Test Steps:**
1. Submit legitimate URL via Scanner page
2. Verify low threat level returned
3. Confirm confidence score < 20%

**Expected Results:**
- `threat_level` = "safe" or "low"
- `confidence_score` < 20.0
- `virustotal_positives` = 0
- `phishtank_verified` = False

**Acceptance Criteria:**
```python
def test_manual_url_submission_legitimate(client, db_session, mock_virustotal, mock_phishtank):
    """TS-002: Submit legitimate URL and verify safe classification."""
    # Arrange
    url = "https://www.wikipedia.org"
    
    # Act
    response = client.post('/api/scan', json={'url': url})
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data['threat_level'] in ['safe', 'low']
    assert data['confidence_score'] < 20.0
    assert data['virustotal_positives'] == 0
    assert data['phishtank_verified'] is False
```

**Test File:** `tests/e2e/test_phishing_detection.py::test_manual_url_submission_legitimate`

---

### TS-003: URL Validation - Invalid URL Format

**Use Case:** UC-001  
**Priority:** P0  
**Type:** Unit, Integration  
**Status:** Automated

**Test Description:**  
Verify that invalid URL formats are rejected with appropriate error messages.

**Test Data:**
```python
invalid_urls = [
    "not-a-url",
    "htp://missing-t.com",
    "javascript:alert('xss')",
    "file:///etc/passwd",
    "",
    None,
    "http://",
    "ftp://not-supported.com"
]
```

**Expected Results:**
- Status code: 400 (Bad Request)
- Error message: "Invalid URL format"
- No database record created
- No API calls made

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("invalid_url", [
    "not-a-url",
    "htp://missing-t.com",
    "javascript:alert('xss')",
    "file:///etc/passwd",
    "",
    "http://",
])
def test_url_validation_invalid_format(client, invalid_url):
    """TS-003: Reject invalid URL formats."""
    # Act
    response = client.post('/api/scan', json={'url': invalid_url})
    
    # Assert
    assert response.status_code == 400
    assert 'Invalid URL format' in response.json()['error']
```

**Test File:** `tests/unit/test_url_validation.py::test_url_validation_invalid_format`

---

### TS-004: Batch URL Scanning - Multiple URLs

**Use Case:** UC-002  
**Priority:** P0  
**Type:** Integration, E2E  
**Status:** Automated

**Test Description:**  
Verify that batch scanning of multiple URLs (up to 100) completes successfully with individual results.

**Test Data:**
```python
batch_urls = [
    "http://phishing-site-1.com",
    "http://phishing-site-2.com",
    "https://www.google.com",
    "http://suspicious-paypal.net",
    # ... up to 100 URLs
]
```

**Expected Results:**
- Status code: 202 (Accepted)
- Batch job ID returned
- All URLs scanned within 2 minutes
- Individual results accessible via batch ID
- Progress tracking available (0-100%)

**Acceptance Criteria:**
```python
def test_batch_url_scanning(client, db_session, celery_worker):
    """TS-004: Batch scan multiple URLs and track progress."""
    # Arrange
    urls = ["http://phishing-{}.com".format(i) for i in range(50)]
    
    # Act
    response = client.post('/api/scan/batch', json={'urls': urls})
    
    # Assert - Job accepted
    assert response.status_code == 202
    batch_id = response.json()['batch_id']
    assert batch_id is not None
    
    # Wait for completion (max 120 seconds)
    timeout = 120
    start_time = time.time()
    while time.time() - start_time < timeout:
        status_response = client.get(f'/api/scan/batch/{batch_id}/status')
        progress = status_response.json()['progress']
        if progress == 100:
            break
        time.sleep(2)
    
    # Verify completion
    assert progress == 100
    
    # Verify results
    results_response = client.get(f'/api/scan/batch/{batch_id}/results')
    results = results_response.json()['results']
    assert len(results) == 50
    assert all('scan_id' in r for r in results)
```

**Test File:** `tests/integration/test_batch_scanning.py::test_batch_url_scanning`

---

### TS-005: Domain Monitoring - Typosquatting Detection

**Use Case:** UC-003  
**Priority:** P1  
**Type:** Integration, Unit  
**Status:** Automated

**Test Description:**  
Verify that domain monitoring detects typosquatting variants of monitored brands.

**Test Data:**
```python
original_domain = "paypal.com"
expected_variants = [
    "paypa1.com",      # Character substitution
    "paypall.com",     # Character duplication
    "paypai.com",      # Character omission
    "paypal-login.com", # Hyphenation
    "www-paypal.com"   # Prefix addition
]
```

**Expected Results:**
- All variants detected
- Levenshtein distance calculated
- Similarity score >= 80%
- Alerts generated for high-risk variants

**Acceptance Criteria:**
```python
def test_domain_monitoring_typosquatting(db_session):
    """TS-005: Detect typosquatting variants of monitored domains."""
    # Arrange
    from src.services.domain_monitoring import DomainMonitoringService
    service = DomainMonitoringService(db_session)
    
    original = "paypal.com"
    variants = [
        "paypa1.com",
        "paypall.com",
        "paypai.com",
        "paypal-login.com"
    ]
    
    # Act
    results = service.detect_typosquatting(original, variants)
    
    # Assert
    assert len(results) == len(variants)
    for result in results:
        assert result['similarity_score'] >= 80.0
        assert 'levenshtein_distance' in result
        assert result['typosquatting_type'] in [
            'character_substitution',
            'character_duplication',
            'character_omission',
            'hyphenation'
        ]
```

**Test File:** `tests/unit/test_domain_monitoring.py::test_typosquatting_detection`

---

### TS-006: Certificate Transparency Monitoring

**Use Case:** UC-004  
**Priority:** P1  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that Certificate Transparency log monitoring detects newly registered certificates for monitored domains.

**Test Data:**
```python
monitored_domain = "paypal.com"
new_cert_domains = [
    "secure-paypal-login.com",
    "paypal-verify.net",
    "www.paypal-support.org"
]
```

**Expected Results:**
- New certificates detected within 24 hours
- Certificate details stored (issuer, validity, SANs)
- Alerts sent to administrators
- Historical tracking of certificate issuance

**Acceptance Criteria:**
```python
def test_certificate_transparency_monitoring(db_session, mock_ct_logs):
    """TS-006: Monitor CT logs for suspicious certificate registrations."""
    # Arrange
    from src.services.certificate_monitoring import CertificateMonitoringService
    service = CertificateMonitoringService(db_session)
    
    monitored_domain = "paypal.com"
    
    # Act
    new_certs = service.check_ct_logs(monitored_domain, hours=24)
    
    # Assert
    assert len(new_certs) > 0
    for cert in new_certs:
        assert 'issuer' in cert
        assert 'not_before' in cert
        assert 'not_after' in cert
        assert 'subject_alternative_names' in cert
        assert monitored_domain in cert['subject_alternative_names'][0]
```

**Test File:** `tests/integration/test_certificate_monitoring.py::test_ct_log_monitoring`

---

### TS-007: Historical Data Analysis - Trend Detection

**Use Case:** UC-005  
**Priority:** P2  
**Type:** Integration, Unit  
**Status:** Automated

**Test Description:**  
Verify that historical analysis identifies increasing phishing trends for specific brands.

**Test Data:**
```python
# 30 days of scan data with increasing phishing attempts
scan_data = {
    'brand': 'PayPal',
    'days': 30,
    'daily_scans': [10, 12, 15, 18, 22, 25, 30, 35, 42, ...],  # Increasing trend
    'daily_threats': [2, 3, 4, 5, 7, 8, 10, 12, 15, ...]      # 30-50% threat rate
}
```

**Expected Results:**
- Trend detected as "increasing"
- Percentage increase calculated (e.g., +150% over 30 days)
- Alert triggered if increase > 50%
- Recommendation: "Increase monitoring frequency"

**Acceptance Criteria:**
```python
def test_historical_trend_detection(db_session):
    """TS-007: Detect increasing phishing trends from historical data."""
    # Arrange
    from src.services.analytics import AnalyticsService
    service = AnalyticsService(db_session)
    
    # Create 30 days of historical data with increasing trend
    for day in range(30):
        scans = 10 + day * 2  # Increasing from 10 to 68 scans/day
        threats = int(scans * 0.4)  # 40% threat rate
        create_test_data(db_session, day, scans, threats)
    
    # Act
    trend = service.analyze_trend('PayPal', days=30)
    
    # Assert
    assert trend['direction'] == 'increasing'
    assert trend['percentage_change'] > 50
    assert trend['alert_triggered'] is True
    assert 'Increase monitoring' in trend['recommendation']
```

**Test File:** `tests/unit/test_analytics.py::test_trend_detection`

---

## Category 2: Threat Validation Test Scenarios

### TS-010: Multi-API Validation - All APIs Responding

**Use Case:** UC-010  
**Priority:** P0  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that multi-API validation aggregates results from all 3 APIs (VirusTotal, URLVoid, PhishTank) when all are available.

**Test Data:**
```python
url = "http://suspicious-banking.com"
virustotal_response = {'positives': 45, 'total': 70}
urlvoid_response = {'blacklists': 15, 'total_checks': 30}
phishtank_response = {'verified': True, 'valid': True}
```

**Expected Results:**
- Confidence score calculated from weighted average (60% VT, 30% UV, 10% PT)
- All API responses stored in database
- Response time < 3 seconds (p95)
- Threat level determined by highest severity API

**Acceptance Criteria:**
```python
def test_multi_api_validation_all_responding(client, mock_virustotal, mock_urlvoid, mock_phishtank):
    """TS-010: Aggregate results from all 3 threat intelligence APIs."""
    # Arrange
    url = "http://suspicious-banking.com"
    
    # Act
    start_time = time.time()
    response = client.post('/api/validate', json={'url': url})
    duration = time.time() - start_time
    
    # Assert - Response time
    assert duration < 3.0  # p95 requirement
    
    # Assert - Aggregated results
    data = response.json()
    assert 'virustotal' in data['api_results']
    assert 'urlvoid' in data['api_results']
    assert 'phishtank' in data['api_results']
    
    # Assert - Confidence calculation
    # 60% VT + 30% UV + 10% PT
    vt_score = (45/70) * 100 * 0.6  # 38.57
    uv_score = (15/30) * 100 * 0.3  # 15.00
    pt_score = 100 * 0.1             # 10.00
    expected_confidence = vt_score + uv_score + pt_score  # 63.57
    
    assert abs(data['confidence_score'] - expected_confidence) < 1.0
```

**Test File:** `tests/integration/test_threat_validation.py::test_multi_api_all_responding`

---

### TS-011: Multi-API Validation - Partial API Failure

**Use Case:** UC-010  
**Priority:** P0  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that validation continues with degraded confidence when 1-2 APIs fail, but succeeds if at least 1 API responds.

**Test Data:**
```python
scenarios = [
    {'virustotal': 'success', 'urlvoid': 'timeout', 'phishtank': 'timeout'},
    {'virustotal': 'timeout', 'urlvoid': 'success', 'phishtank': 'timeout'},
    {'virustotal': 'success', 'urlvoid': 'success', 'phishtank': 'timeout'},
]
```

**Expected Results:**
- Scan succeeds with warning
- Confidence score adjusted for missing APIs
- Warning message: "Partial validation - X APIs unavailable"
- Retry scheduled for failed APIs

**Acceptance Criteria:**
```python
def test_multi_api_partial_failure(client, mock_virustotal):
    """TS-011: Handle partial API failures gracefully."""
    # Arrange - Only VirusTotal responding
    url = "http://test-phishing.com"
    
    with patch('src.integrations.urlvoid.URLVoidClient.check_url') as mock_uv:
        mock_uv.side_effect = Timeout("URLVoid timeout")
        
        with patch('src.integrations.phishtank.PhishTankClient.check_url') as mock_pt:
            mock_pt.side_effect = Timeout("PhishTank timeout")
            
            # Act
            response = client.post('/api/validate', json={'url': url})
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data['warning'] == 'Partial validation - 2 APIs unavailable'
    assert 'virustotal' in data['api_results']
    assert 'urlvoid' not in data['api_results']
    assert 'phishtank' not in data['api_results']
    assert data['apis_responding'] == 1
    assert data['retry_scheduled'] is True
```

**Test File:** `tests/integration/test_threat_validation.py::test_partial_api_failure`

---

### TS-012: Confidence Score Calculation - Edge Cases

**Use Case:** UC-011  
**Priority:** P1  
**Type:** Unit  
**Status:** Automated

**Test Description:**  
Verify confidence score calculation for edge cases (0%, 100%, boundary values).

**Test Data:**
```python
edge_cases = [
    {'vt_positives': 0, 'vt_total': 70, 'expected': 0.0},      # No threats
    {'vt_positives': 70, 'vt_total': 70, 'expected': 100.0},   # All threats
    {'vt_positives': 35, 'vt_total': 70, 'expected': 50.0},    # Exactly 50%
    {'vt_positives': 1, 'vt_total': 70, 'expected': 1.43},     # Minimal threat
]
```

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("vt_positives,vt_total,expected_score", [
    (0, 70, 0.0),
    (70, 70, 100.0),
    (35, 70, 50.0),
    (1, 70, 1.43),
])
def test_confidence_score_edge_cases(vt_positives, vt_total, expected_score):
    """TS-012: Calculate confidence scores for edge cases."""
    # Arrange
    from src.services.threat_validation import calculate_confidence_score
    
    # Act
    score = calculate_confidence_score(
        virustotal_positives=vt_positives,
        virustotal_total=vt_total,
        urlvoid_blacklists=0,
        phishtank_verified=False
    )
    
    # Assert
    assert abs(score - expected_score) < 0.1
```

**Test File:** `tests/unit/test_confidence_calculation.py::test_edge_cases`

---

### TS-013: Screenshot Capture - Success and Failure

**Use Case:** UC-012  
**Priority:** P1  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that screenshots are captured for accessible URLs and gracefully handled for inaccessible URLs.

**Test Data:**
```python
accessible_url = "https://example.com"
inaccessible_urls = [
    "http://localhost:99999",        # Invalid port
    "http://192.168.1.254:8080",    # Network unreachable
    "http://timeout-test.invalid",   # DNS resolution failure
]
```

**Expected Results:**
- Accessible URL: Screenshot saved to `/screenshots/{hash}.png`
- Inaccessible URL: Error logged, scan continues without screenshot
- Screenshot metadata stored (timestamp, file size, dimensions)

**Acceptance Criteria:**
```python
def test_screenshot_capture_success(client, tmp_path):
    """TS-013a: Capture screenshot for accessible URL."""
    # Arrange
    url = "https://example.com"
    
    # Act
    response = client.post('/api/scan', json={'url': url})
    
    # Assert
    data = response.json()
    assert 'screenshot_url' in data
    assert data['screenshot_url'].startswith('/screenshots/')
    
    # Verify file exists
    screenshot_path = tmp_path / data['screenshot_url'].lstrip('/')
    assert screenshot_path.exists()
    assert screenshot_path.stat().st_size > 1000  # At least 1KB

def test_screenshot_capture_failure(client, caplog):
    """TS-013b: Handle screenshot failure gracefully."""
    # Arrange
    url = "http://localhost:99999"
    
    # Act
    response = client.post('/api/scan', json={'url': url})
    
    # Assert
    data = response.json()
    assert response.status_code == 200  # Scan still succeeds
    assert data['screenshot_url'] is None
    assert 'Screenshot capture failed' in caplog.text
```

**Test File:** `tests/integration/test_screenshot_capture.py`

---

### TS-014: WHOIS Data Enrichment

**Use Case:** UC-013  
**Priority:** P2  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that WHOIS data is retrieved and parsed correctly for domain enrichment.

**Test Data:**
```python
test_domains = [
    "google.com",        # Established domain
    "newly-registered-phishing-2026-01-01.com",  # Recent registration
    "privacy-protected.com",  # WHOIS privacy enabled
]
```

**Expected Results:**
- Registrar information extracted
- Registration date parsed
- Expiration date calculated
- Domain age determined
- Risk factors identified (age < 30 days = high risk)

**Acceptance Criteria:**
```python
def test_whois_data_enrichment(db_session):
    """TS-014: Retrieve and parse WHOIS data for domain analysis."""
    # Arrange
    from src.services.whois_service import WHOISService
    service = WHOISService(db_session)
    
    domain = "example-phishing.com"
    
    # Act
    whois_data = service.get_whois_data(domain)
    
    # Assert
    assert 'registrar' in whois_data
    assert 'registration_date' in whois_data
    assert 'expiration_date' in whois_data
    assert 'domain_age_days' in whois_data
    
    # Risk assessment
    if whois_data['domain_age_days'] < 30:
        assert whois_data['age_risk_level'] == 'high'
    elif whois_data['domain_age_days'] < 365:
        assert whois_data['age_risk_level'] == 'medium'
    else:
        assert whois_data['age_risk_level'] == 'low'
```

**Test File:** `tests/integration/test_whois_enrichment.py`

---

## Category 3: Abuse Reporting Test Scenarios

### TS-020: Automated Abuse Report Generation

**Use Case:** UC-020  
**Priority:** P0  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that abuse reports are automatically generated when critical threats are detected.

**Test Data:**
```python
critical_threat = {
    'url': 'http://paypal-verify-account.scam.ru',
    'threat_level': 'critical',
    'confidence_score': 95.0,
    'phishtank_verified': True,
    'virustotal_positives': 65
}
```

**Expected Results:**
- Abuse report created within 5 seconds
- Report includes: URL, threat summary, evidence (VT/PT), screenshot
- Report sent to: hosting provider, domain registrar, PhishTank
- ICANN 2-day SLA compliance tracked

**Acceptance Criteria:**
```python
def test_automated_abuse_report_generation(client, db_session, mock_smtp):
    """TS-020: Auto-generate abuse reports for critical threats."""
    # Arrange
    url = "http://paypal-verify-account.scam.ru"
    
    # Trigger critical threat detection
    response = client.post('/api/scan', json={'url': url})
    scan_id = response.json()['scan_id']
    
    # Wait for async abuse report generation
    time.sleep(6)
    
    # Act - Check abuse reports
    reports = db_session.query(AbuseReport).filter_by(scan_id=scan_id).all()
    
    # Assert
    assert len(reports) >= 1
    report = reports[0]
    assert report.url == url
    assert report.threat_level == 'critical'
    assert report.status == 'submitted'
    assert report.recipients == ['abuse@hosting.com', 'abuse@registrar.com']
    assert report.icann_sla_deadline is not None
    
    # Verify email sent
    assert mock_smtp.send_email.called
```

**Test File:** `tests/integration/test_abuse_reporting.py::test_auto_generation`

---

### TS-021: Manual Abuse Report Submission

**Use Case:** UC-021  
**Priority:** P1  
**Type:** E2E  
**Status:** Automated

**Test Description:**  
Verify that security analysts can manually create and submit abuse reports with custom details.

**Test Steps:**
1. Navigate to Report Details page for a scan
2. Click "Create Abuse Report" button
3. Fill in custom details (recipient, message, evidence)
4. Submit report
5. Verify submission confirmation

**Acceptance Criteria:**
```python
def test_manual_abuse_report_submission(client, db_session, authenticated_user):
    """TS-021: Manually create and submit abuse report."""
    # Arrange
    scan_id = create_test_scan(db_session, threat_level='high')
    
    # Act - Create manual abuse report
    response = client.post(f'/api/reports/abuse', json={
        'scan_id': scan_id,
        'recipients': ['abuse@example.com', 'security@example.com'],
        'message': 'Custom abuse report message',
        'include_screenshot': True,
        'include_whois': True
    })
    
    # Assert
    assert response.status_code == 201
    data = response.json()
    assert data['report_id'] is not None
    assert data['status'] == 'submitted'
    assert data['submitted_at'] is not None
    
    # Verify database record
    report = db_session.query(AbuseReport).get(data['report_id'])
    assert report.manual_submission is True
    assert report.created_by == authenticated_user.id
```

**Test File:** `tests/e2e/test_manual_abuse_reporting.py`

---

### TS-022: ICANN Compliance Tracking

**Use Case:** UC-022  
**Priority:** P0  
**Type:** Integration  
**Status:** Automated

**Test Description:**  
Verify that ICANN 2-day SLA compliance is tracked and alerts are triggered for approaching deadlines.

**Test Data:**
```python
# Create abuse report submitted 1.5 days ago (approaching deadline)
report_timestamp = datetime.utcnow() - timedelta(hours=36)
deadline = report_timestamp + timedelta(days=2)
```

**Expected Results:**
- SLA deadline calculated as submission_time + 48 hours
- Alert triggered at deadline - 6 hours
- Alert message: "ICANN deadline approaching for report #{id}"
- Report marked "overdue" if no response after 48 hours

**Acceptance Criteria:**
```python
def test_icann_compliance_tracking(db_session, celery_worker):
    """TS-022: Track ICANN 2-day SLA compliance for abuse reports."""
    # Arrange - Create report submitted 42 hours ago (6 hours before deadline)
    report = create_abuse_report(
        db_session,
        submitted_at=datetime.utcnow() - timedelta(hours=42)
    )
    
    # Act - Run compliance check task
    from src.tasks.compliance import check_icann_sla_compliance
    alerts = check_icann_sla_compliance.apply().get()
    
    # Assert
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert['report_id'] == report.id
    assert alert['message'] == f'ICANN deadline approaching for report #{report.id}'
    assert alert['hours_remaining'] <= 6
    
    # Test overdue scenario
    report.submitted_at = datetime.utcnow() - timedelta(hours=49)
    db_session.commit()
    
    alerts = check_icann_sla_compliance.apply().get()
    assert len([a for a in alerts if a['status'] == 'overdue']) == 1
```

**Test File:** `tests/integration/test_icann_compliance.py`

---

## Category 4: Performance & Load Test Scenarios

### TS-100: Concurrent URL Scanning - Load Test

**Use Case:** UC-001, UC-002  
**Priority:** P0  
**Type:** Performance  
**Status:** Automated

**Test Description:**  
Verify system handles 50+ concurrent URL scans without degradation.

**Test Configuration:**
```python
concurrent_users = 50
urls_per_user = 10
total_scans = 500
max_response_time_p95 = 3.0  # seconds
max_response_time_p99 = 5.0  # seconds
```

**Expected Results:**
- All 500 scans complete successfully
- p95 response time < 3 seconds
- p99 response time < 5 seconds
- 0% error rate
- Database connection pool not exhausted

**Acceptance Criteria:**
```python
def test_concurrent_scanning_load(client, db_session):
    """TS-100: Load test with 50 concurrent users scanning URLs."""
    import concurrent.futures
    import statistics
    
    # Arrange
    urls = [f"http://test-phishing-{i}.com" for i in range(500)]
    response_times = []
    errors = []
    
    def scan_url(url):
        try:
            start = time.time()
            response = client.post('/api/scan', json={'url': url})
            duration = time.time() - start
            response_times.append(duration)
            if response.status_code != 200:
                errors.append(response.status_code)
        except Exception as e:
            errors.append(str(e))
    
    # Act - Execute 500 scans with 50 concurrent workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_url, urls)
    
    # Assert
    p95 = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
    p99 = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
    
    assert len(errors) == 0, f"Errors occurred: {errors}"
    assert p95 < 3.0, f"p95 response time {p95} exceeds 3 seconds"
    assert p99 < 5.0, f"p99 response time {p99} exceeds 5 seconds"
    assert len(response_times) == 500
```

**Test File:** `tests/performance/test_load.py::test_concurrent_scanning`

---

### TS-101: Database Query Performance

**Use Case:** All  
**Priority:** P0  
**Type:** Performance  
**Status:** Automated

**Test Description:**  
Verify critical database queries execute within performance budgets.

**Query Performance Targets:**
```python
query_budgets = {
    'get_scan_by_id': 0.010,           # 10ms
    'list_recent_scans': 0.050,        # 50ms
    'search_scans_by_url': 0.100,      # 100ms
    'aggregate_statistics': 0.500,     # 500ms
    'generate_report': 1.000,          # 1 second
}
```

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("query_name,max_duration", [
    ('get_scan_by_id', 0.010),
    ('list_recent_scans', 0.050),
    ('search_scans_by_url', 0.100),
    ('aggregate_statistics', 0.500),
])
def test_database_query_performance(db_session, query_name, max_duration):
    """TS-101: Verify database queries meet performance budgets."""
    # Arrange - Populate with 10,000 test records
    populate_test_data(db_session, num_records=10000)
    
    # Act
    start = time.time()
    
    if query_name == 'get_scan_by_id':
        result = db_session.query(ScanResult).get(5000)
    elif query_name == 'list_recent_scans':
        result = db_session.query(ScanResult).order_by(
            ScanResult.created_at.desc()
        ).limit(50).all()
    elif query_name == 'search_scans_by_url':
        result = db_session.query(ScanResult).filter(
            ScanResult.url.like('%phishing%')
        ).all()
    elif query_name == 'aggregate_statistics':
        result = db_session.query(
            func.count(ScanResult.id),
            func.avg(ScanResult.confidence_score),
            func.max(ScanResult.created_at)
        ).first()
    
    duration = time.time() - start
    
    # Assert
    assert duration < max_duration, (
        f"{query_name} took {duration:.3f}s, exceeds budget of {max_duration}s"
    )
```

**Test File:** `tests/performance/test_database_performance.py`

---

## Category 5: Security Test Scenarios

### TS-110: Authentication - API Key Validation

**Use Case:** UC-050, UC-070  
**Priority:** P0  
**Type:** Security, Unit  
**Status:** Automated

**Test Description:**  
Verify that invalid, expired, or missing API keys are rejected.

**Test Cases:**
```python
security_test_cases = [
    {'api_key': None, 'expected': 401, 'description': 'Missing API key'},
    {'api_key': '', 'expected': 401, 'description': 'Empty API key'},
    {'api_key': 'invalid_key', 'expected': 401, 'description': 'Invalid API key'},
    {'api_key': 'expired_key', 'expected': 401, 'description': 'Expired API key'},
    {'api_key': 'revoked_key', 'expected': 401, 'description': 'Revoked API key'},
]
```

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("api_key,expected_status,description", [
    (None, 401, 'Missing API key'),
    ('', 401, 'Empty API key'),
    ('invalid_key', 401, 'Invalid API key'),
    ('expired_key', 401, 'Expired key'),
])
def test_api_key_authentication(client, api_key, expected_status, description):
    """TS-110: Reject invalid API keys."""
    # Arrange
    headers = {}
    if api_key is not None:
        headers['Authorization'] = f'Bearer {api_key}'
    
    # Act
    response = client.get('/api/scans', headers=headers)
    
    # Assert
    assert response.status_code == expected_status, description
    if expected_status == 401:
        assert 'Unauthorized' in response.json()['error']
```

**Test File:** `tests/security/test_authentication.py`

---

### TS-111: Authorization - Role-Based Access Control

**Use Case:** UC-050, UC-051  
**Priority:** P0  
**Type:** Security  
**Status:** Automated

**Test Description:**  
Verify that users can only access resources permitted by their role.

**Test Scenarios:**
```python
rbac_scenarios = [
    {
        'role': 'viewer',
        'allowed': ['GET /api/scans', 'GET /api/reports'],
        'forbidden': ['POST /api/scan', 'DELETE /api/scans/*', 'POST /api/admin/*']
    },
    {
        'role': 'analyst',
        'allowed': ['GET /api/scans', 'POST /api/scan', 'POST /api/reports/abuse'],
        'forbidden': ['DELETE /api/scans/*', 'POST /api/admin/*']
    },
    {
        'role': 'admin',
        'allowed': ['*'],  # All endpoints
        'forbidden': []
    }
]
```

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("role", ['viewer', 'analyst', 'admin'])
def test_role_based_access_control(client, role):
    """TS-111: Enforce RBAC policies."""
    # Arrange
    user = create_test_user(role=role)
    client.login(user)
    
    # Test allowed endpoints
    if role == 'viewer':
        assert client.get('/api/scans').status_code == 200
        assert client.post('/api/scan', json={'url': 'http://test.com'}).status_code == 403
        assert client.delete('/api/scans/1').status_code == 403
    
    elif role == 'analyst':
        assert client.get('/api/scans').status_code == 200
        assert client.post('/api/scan', json={'url': 'http://test.com'}).status_code == 200
        assert client.delete('/api/scans/1').status_code == 403
    
    elif role == 'admin':
        assert client.get('/api/scans').status_code == 200
        assert client.post('/api/scan', json={'url': 'http://test.com'}).status_code == 200
        assert client.delete('/api/scans/1').status_code == 200
```

**Test File:** `tests/security/test_authorization.py`

---

### TS-112: Input Validation - SQL Injection Prevention

**Use Case:** All  
**Priority:** P0  
**Type:** Security  
**Status:** Automated

**Test Description:**  
Verify that SQL injection attempts are blocked and do not compromise the database.

**Attack Payloads:**
```python
sql_injection_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE scans;--",
    "' UNION SELECT * FROM users--",
    "admin'--",
    "1' AND '1'='1",
]
```

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "'; DROP TABLE scans;--",
    "' UNION SELECT * FROM users--",
])
def test_sql_injection_prevention(client, db_session, payload):
    """TS-112: Prevent SQL injection attacks."""
    # Arrange
    url_with_payload = f"http://test.com/{payload}"
    
    # Act
    response = client.post('/api/scan', json={'url': url_with_payload})
    
    # Assert - Query should be sanitized, not executed
    # Either returns 400 (invalid URL) or safely handles payload
    assert response.status_code in [200, 400]
    
    # Verify database integrity - tables still exist
    tables = db_session.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall()
    assert len(tables) > 0  # Tables not dropped
    
    # Verify no SQL error messages exposed
    if response.status_code == 400:
        assert 'SQL' not in response.json().get('error', '')
```

**Test File:** `tests/security/test_sql_injection.py`

---

### TS-113: XSS Prevention - Output Encoding

**Use Case:** UC-040, UC-041  
**Priority:** P0  
**Type:** Security  
**Status:** Automated

**Test Description:**  
Verify that user-provided content is properly escaped to prevent XSS attacks.

**Attack Payloads:**
```python
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
]
```

**Acceptance Criteria:**
```python
@pytest.mark.parametrize("payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
])
def test_xss_prevention(client, payload):
    """TS-113: Prevent XSS attacks through output encoding."""
    # Arrange - Submit URL with XSS payload in query param
    url_with_payload = f"http://test.com/?search={payload}"
    
    # Act
    response = client.post('/api/scan', json={'url': url_with_payload})
    
    # Assert - Payload should be HTML-escaped in response
    response_text = response.json()['url']
    assert '<script>' not in response_text
    assert '&lt;script&gt;' in response_text or payload not in response_text
    assert 'onerror=' not in response_text
```

**Test File:** `tests/security/test_xss_prevention.py`

---

## Test Execution Strategy

### Phase 1: Unit Tests (Sprint 1)
- **Target:** 50% code coverage minimum
- **Focus:** Core business logic, validation, calculations
- **Execution:** Local development, pre-commit hooks
- **Duration:** ~2 minutes

### Phase 2: Integration Tests (Sprint 1-2)
- **Target:** API integration, database operations, external services
- **Focus:** Component interactions, error handling
- **Execution:** CI pipeline (GitHub Actions)
- **Duration:** ~10 minutes

### Phase 3: E2E Tests (Sprint 2)
- **Target:** Critical user workflows
- **Focus:** Full stack integration, UI interactions
- **Execution:** Nightly builds
- **Duration:** ~30 minutes

### Phase 4: Performance Tests (Sprint 3)
- **Target:** Load, stress, scalability
- **Focus:** Database performance, concurrent requests
- **Execution:** Weekly performance pipeline
- **Duration:** ~60 minutes

### Phase 5: Security Tests (Continuous)
- **Target:** OWASP Top 10, compliance
- **Focus:** Authentication, authorization, input validation
- **Execution:** Every PR, nightly scans
- **Duration:** ~15 minutes

---

## Test Automation Infrastructure

### CI/CD Integration

```yaml
# .github/workflows/test-suite.yml (Updated)
name: Test Suite

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run unit tests
        run: |
          poetry install
          poetry run pytest tests/unit -v --cov=src --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: test_password
    steps:
      - name: Run integration tests
        run: poetry run pytest tests/integration -v

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Run E2E tests
        run: poetry run pytest tests/e2e -v --headed

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Run security tests
        run: |
          poetry run pytest tests/security -v
          poetry run bandit -r src/
          poetry run safety check
```

### Test Data Management

```python
# tests/fixtures/database.py
import pytest
from faker import Faker

fake = Faker()

@pytest.fixture
def test_scan_data():
    """Generate realistic test scan data."""
    return {
        'url': fake.url(),
        'threat_level': random.choice(['safe', 'low', 'medium', 'high', 'critical']),
        'confidence_score': random.uniform(0, 100),
        'virustotal_positives': random.randint(0, 70),
        'screenshot_url': f'/screenshots/{fake.uuid4()}.png',
    }

@pytest.fixture
def populate_database(db_session, num_records=1000):
    """Populate database with test data for performance testing."""
    scans = [
        ScanResult(
            url=fake.url(),
            threat_level=random.choice(['safe', 'low', 'medium', 'high', 'critical']),
            confidence_score=random.uniform(0, 100),
            created_at=fake.date_time_between(start_date='-30d', end_date='now')
        )
        for _ in range(num_records)
    ]
    db_session.bulk_save_objects(scans)
    db_session.commit()
```

---

## Next Steps

1. **Review and Approval** (CURRENT)
   - Review test scenarios with stakeholders
   - Validate acceptance criteria
   - Approve test coverage targets

2. **Test Implementation** (Sprint 1)
   - Implement P0 unit tests
   - Setup CI/CD integration
   - Achieve 50% code coverage

3. **Integration Testing** (Sprint 1-2)
   - Implement API integration tests
   - Mock external services
   - Database transaction testing

4. **E2E Testing** (Sprint 2)
   - Setup Playwright/Cypress
   - Implement critical user workflows
   - Screenshot comparison testing

5. **Performance Testing** (Sprint 3)
   - Load testing with 50+ concurrent users
   - Database query optimization
   - Caching strategy validation

6. **Security Testing** (Continuous)
   - OWASP Top 10 validation
   - Penetration testing
   - Compliance verification

---

**Document Status:** Draft  
**Next Review:** 2026-01-04  
**Owner:** Murat (Test Engineering Architect)
