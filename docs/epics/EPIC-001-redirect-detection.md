# Epic 001: Redirect Chain Detection & Analysis

**Epic ID**: EPIC-001
**Priority**: P0 - Critical
**Status**: Ready for Development
**Sprint**: Sprint 2 (Days 8-14)
**Created**: 2025-11-21
**Owner**: Development Team

---

## Business Value

**Problem**: Attackers are bypassing detection by using multi-hop redirect chains. Cloudflare's security scanning only sees the initial "clean" domain, while the actual phishing content is served after multiple redirects.

**Impact**:

- **Current False Negative Rate**: 40-60% for modern phishing campaigns
- **Estimated Lost Detections**: ~200-400 phishing sites per week
- **Business Risk**: HIGH - Core product effectiveness severely compromised

**Value Proposition**: Implementing redirect chain analysis will increase detection accuracy by 60%, bringing false negative rate from 40-60% down to <10%.

---

## Scope

### In Scope

- Follow HTTP redirect chains (301, 302, 303, 307, 308) up to 5 hops
- Capture all intermediate URLs in the redirect chain
- Detect Cloudflare proxying in redirect chains
- Calculate risk score based on redirect characteristics
- Store complete redirect chain audit trail in database
- Integrate redirect analysis into main scan flow
- Apply threat intelligence to ALL URLs in chain (not just initial)

### Out of Scope

- JavaScript-based redirects (meta refresh, window.location)
- Client-side redirects (handled in future epic)
- Real-time redirect monitoring (batch analysis only)
- Redirect chain visualization UI

---

## Technical Approach

**Architecture Reference**: `docs/ARCHITECTURE.md` - Solution 1

**Key Components**:

1. **RedirectAnalyzer Class** (`src/detection/redirect_analyzer.py`)

   - Follows redirects with `allow_redirects=False` (manual control)
   - Timeout per hop: 10 seconds
   - Max hops: 5 (configurable via `MAX_REDIRECT_HOPS` env var)
   - Detects redirect loops
   - Identifies cross-domain redirects

2. **RedirectChain Data Model**

   - Captures: initial_url, final_url, all hops, timestamps, flags
   - Risk scoring algorithm (0-100)
   - Suspicious pattern detection (TLDs, URL shorteners, domain length)

3. **Database Schema**

   - New table: `redirect_chains`
   - Foreign key to `phishing_sites`
   - Stores hops as JSONB for flexibility

4. **Integration Point**
   - In `PhishingDetectionEngine.scan_site()` (main.py:6139+)
   - Before content analysis, after DNS validation
   - Redirect risk score feeds into confidence calculation

---

## Acceptance Criteria

### AC-001: Redirect Chain Following

- [ ] System follows HTTP 3xx redirects up to MAX_REDIRECT_HOPS (default: 5)
- [ ] Each hop is captured with: URL, status code, headers, response time
- [ ] Redirect loops are detected and chain terminates gracefully
- [ ] Timeout per hop is enforced (10s default)
- [ ] Final destination URL is correctly identified

### AC-002: Cloudflare Detection

- [ ] Cloudflare proxying is detected via Server header or CF-RAY header
- [ ] Cloudflare intermediary is flagged in redirect chain analysis
- [ ] Risk score increases when Cloudflare is detected in chain (not final destination)

### AC-003: Risk Scoring

- [ ] Risk score calculated 0-100 based on:
  - Number of redirects (more = higher risk)
  - Suspicious TLDs (.ru, .cn, .tk, etc.)
  - Cross-domain redirects
  - Cloudflare intermediary usage
  - URL shorteners in chain
- [ ] Risk score >= 50 marks chain as "suspicious"
- [ ] Risk score correctly influences overall confidence score

### AC-004: Database Persistence

- [ ] `redirect_chains` table created via migration
- [ ] All redirect chains stored with complete hop details (JSONB)
- [ ] Foreign key relationship to `phishing_sites` table
- [ ] ON DELETE CASCADE works correctly

### AC-005: Integration

- [ ] Redirect analysis integrated into main scan flow
- [ ] Both initial URL AND final destination URL analyzed for phishing content
- [ ] All intermediate URLs checked against threat intelligence APIs
- [ ] Feature flag `ENABLE_REDIRECT_ANALYSIS` controls functionality

### AC-006: Observability

- [ ] Redirect chain details logged (structured JSON)
- [ ] Metrics tracked: chains detected, average hops, risk score distribution
- [ ] Errors logged with context (which hop failed, why)

---

## User Stories

1. **Story 001.1**: Implement RedirectAnalyzer class (8 points)
2. **Story 001.2**: Create redirect_chains database table (3 points)
3. **Story 001.3**: Integrate redirect analysis into scan flow (5 points)
4. **Story 001.4**: Add feature flag and configuration (2 points)
5. **Story 001.5**: Testing and validation (5 points)

**Total Story Points**: 23 points

---

## Dependencies

**Blockers**:

- None (can start immediately)

**Required Before**:

- EPIC-002 (Structured Logging) - Nice to have but not required

**Depends On**:

- Database access (PostgreSQL)
- Existing scan flow in main.py

---

## Risks & Mitigations

| Risk                                                  | Probability | Impact   | Mitigation                                                                                                 |
| ----------------------------------------------------- | ----------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| **Redirect analysis breaks existing scans**           | Medium      | Critical | Feature flag ENABLE_REDIRECT_ANALYSIS=false for rollback, comprehensive testing with real phishing samples |
| **Performance degradation**                           | Medium      | Medium   | 10s timeout per hop (max 50s for 5 hops), parallel processing where possible                               |
| **External sites block automated redirect following** | Low         | Low      | Use realistic browser headers, respect robots.txt for non-phishing domains                                 |
| **Infinite redirect loops crash system**              | Low         | High     | Loop detection via seen_urls set, max hops limit enforced                                                  |

---

## Testing Strategy

### Unit Tests

- `test_redirect_analyzer.py`:
  - Test redirect following (1, 3, 5 hops)
  - Test loop detection
  - Test timeout enforcement
  - Test risk scoring algorithm
  - Test Cloudflare detection

### Integration Tests

- `test_redirect_integration.py`:
  - Test integration with scan flow
  - Test database persistence
  - Test feature flag behavior
  - Test with real phishing samples (safe test environment)

### Performance Tests

- Measure impact on scan time
- Verify timeout behavior under load
- Test concurrent redirect analysis (threading)

---

## Success Metrics

**Before Implementation**:

- False Negative Rate: 40-60%
- Redirect-based attacks: Undetected

**After Implementation**:

- False Negative Rate: <10%
- Redirect chains captured: >95% of scans
- Risk score accuracy: >90% (validated against known phishing samples)
- Performance impact: <15% increase in scan time

---

## Documentation Requirements

- [ ] Update README.md with redirect analysis feature
- [ ] Document ENABLE_REDIRECT_ANALYSIS environment variable
- [ ] Add architecture diagram showing redirect flow
- [ ] Create runbook for troubleshooting redirect issues
- [ ] Update API documentation (if REST API exposes redirect data)

---

## References

- **Architecture Design**: `docs/ARCHITECTURE.md` - Solution 1
- **Project Brief**: `docs/PROJECT-BRIEF.md` - P0 Issue
- **Related Code**: `src/main.py:6146` (current request.get call)
- **Database Schema**: `docs/ARCHITECTURE.md` - Appendix (redirect_chains table)

---

**Status Updates**:

- 2025-11-21: Epic created, ready for story breakdown
