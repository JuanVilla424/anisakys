# Anisakys - Product Backlog

**Version**: 1.1.1
**Last Updated**: 2025-11-21
**Product Owner**: Sarah (BMAD PO)
**Sprint Planning**: 4 Sprints x 7 days = 28 days total

---

## Backlog Overview

This backlog contains all work items derived from:

- **Project Brief**: `docs/PROJECT-BRIEF.md`
- **Architecture Document**: `docs/ARCHITECTURE.md`

**Total Epics**: 6
**Total Story Points**: ~120 points
**Estimated Duration**: 4 sprints (28 days)

---

## Epic Summary

| Epic ID      | Title                             | Priority      | Story Points | Sprint   | Status |
| ------------ | --------------------------------- | ------------- | ------------ | -------- | ------ |
| **EPIC-001** | Redirect Chain Detection          | P0 - Critical | 23           | Sprint 2 | Ready  |
| **EPIC-002** | Structured Logging Infrastructure | P1 - High     | 21           | Sprint 1 | Ready  |
| **EPIC-003** | Database Schema Enhancements      | P1 - High     | 15           | Sprint 1 | Ready  |
| **EPIC-004** | API Circuit Breakers              | P1 - High     | 18           | Sprint 1 | Ready  |
| **EPIC-005** | Multi-Abuse Contact Handling      | P1 - High     | 12           | Sprint 2 | Ready  |
| **EPIC-006** | Main.py Modularization            | P2 - Medium   | 31           | Sprint 3 | Ready  |

**Total**: 120 story points

---

## Sprint Plan

### Sprint 1: Foundation (Days 1-7) - 54 points

**Goal**: Establish observability and fix critical data integrity issues

**Epics**:

- EPIC-002: Structured Logging (21 points)
- EPIC-003: Database Schema Enhancements (15 points)
- EPIC-004: API Circuit Breakers (18 points)

**Key Deliverables**:

- ✅ JSON structured logging with correlation IDs
- ✅ Database constraints to prevent duplicates
- ✅ Circuit breaker pattern for external APIs
- ✅ Feature flags for all new functionality

**Success Criteria**:

- All logs are JSON-formatted
- Zero duplicate report errors
- API failures don't cascade (circuit breakers engage)
- MTTR reduced from 4hrs to <1hr

---

### Sprint 2: Core Enhancements (Days 8-14) - 35 points

**Goal**: Implement redirect detection and multi-abuse contact handling

**Epics**:

- EPIC-001: Redirect Chain Detection (23 points)
- EPIC-005: Multi-Abuse Contact Handling (12 points)

**Key Deliverables**:

- ✅ RedirectAnalyzer class with 5-hop following
- ✅ Redirect chain database table
- ✅ Risk scoring algorithm (0-100)
- ✅ Normalized abuse contact resolution
- ✅ Multi-recipient email sending

**Success Criteria**:

- Redirect chains captured for >95% of scans
- False negative rate drops from 40-60% to <10%
- All abuse contacts resolved (no missing emails)
- Multi-contact scenarios handled correctly

---

### Sprint 3: Modularization (Days 15-21) - 31 points

**Goal**: Refactor main.py monolith into modules

**Epics**:

- EPIC-006: Main.py Modularization (31 points)

**Key Deliverables**:

- ✅ Extract modules: detection/, intelligence/, reporting/, observability/
- ✅ Create base classes and interfaces
- ✅ Update all imports and integration points
- ✅ Maintain 100% backward compatibility

**Success Criteria**:

- main.py reduced from 7389 to <500 lines
- All tests pass after refactoring
- No regressions in functionality
- Code maintainability score improves by >50%

---

### Sprint 4: Quality & Monitoring (Days 22-28) - Ongoing

**Goal**: Comprehensive testing and production monitoring

**Activities**:

- Unit tests for all new modules (target: 80% coverage)
- Integration tests for workflows
- Performance testing and optimization
- Prometheus metrics implementation
- Grafana dashboard creation
- Documentation updates

**Key Deliverables**:

- ✅ Test suite with >80% coverage
- ✅ Prometheus metrics endpoint
- ✅ 3 Grafana dashboards (Detection, APIs, Reports)
- ✅ Updated README and runbooks
- ✅ Deployment checklist

**Success Criteria**:

- Test coverage >80%
- All critical paths have integration tests
- Metrics visible in real-time
- Alerting configured for critical failures

---

## Epic Details

### EPIC-001: Redirect Chain Detection (P0)

**Business Value**: Increase detection accuracy by 60%, addressing the #1 evasion technique used by modern phishing campaigns.

**User Stories**:

1. **STORY-001.1**: Implement RedirectAnalyzer class (8 points)
2. **STORY-001.2**: Create redirect_chains database table (3 points)
3. **STORY-001.3**: Integrate redirect analysis into scan flow (5 points)
4. **STORY-001.4**: Add feature flag and configuration (2 points)
5. **STORY-001.5**: Testing and validation (5 points)

**Acceptance Criteria Summary**:

- Follows HTTP 3xx redirects up to 5 hops
- Detects Cloudflare intermediary usage
- Calculates risk score (0-100)
- Stores complete chain in database
- Feature flag: `ENABLE_REDIRECT_ANALYSIS`

**Documentation**: `docs/epics/EPIC-001-redirect-detection.md`

---

### EPIC-002: Structured Logging Infrastructure (P1)

**Business Value**: Reduce MTTR by 70% through comprehensive, searchable logs with request tracing.

**User Stories**:

1. **STORY-002.1**: Implement StructuredFormatter class (5 points) ⭐ **READY**
2. **STORY-002.2**: Add correlation ID management (3 points)
3. **STORY-002.3**: Configure log rotation and handlers (2 points)
4. **STORY-002.4**: Create convenience logging functions (3 points)
5. **STORY-002.5**: Migrate existing log calls (5 points)
6. **STORY-002.6**: Testing and validation (3 points)

**Acceptance Criteria Summary**:

- All logs output as valid JSON
- Correlation IDs for request tracing
- Log rotation (50MB max, 30 backups)
- Configurable log levels via `LOG_LEVEL`
- Contextual logging (URL, confidence, API metrics)

**Documentation**: `docs/epics/EPIC-002-structured-logging.md`

---

### EPIC-003: Database Schema Enhancements (P1)

**Business Value**: Eliminate duplicate records and improve data integrity.

**User Stories**:

1. **STORY-003.1**: Add unique constraints to abuse_reports (3 points)
2. **STORY-003.2**: Add CASCADE foreign keys (2 points)
3. **STORY-003.3**: Create redirect_chains table (3 points)
4. **STORY-003.4**: Create abuse_report_recipients table (4 points)
5. **STORY-003.5**: Test migrations and rollback (3 points)

**Acceptance Criteria Summary**:

- UNIQUE constraint on (site_url, DATE(report_date))
- ON DELETE CASCADE for all foreign keys
- New tables created via Alembic migrations
- Zero duplicate insertion errors

---

### EPIC-004: API Circuit Breakers (P1)

**Business Value**: Improve system resilience by preventing cascade failures from external APIs.

**User Stories**:

1. **STORY-004.1**: Implement CircuitBreaker class (5 points)
2. **STORY-004.2**: Implement RetryStrategy class (3 points)
3. **STORY-004.3**: Create ResilientAPIClient base class (4 points)
4. **STORY-004.4**: Wrap VirusTotal client (2 points)
5. **STORY-004.5**: Wrap URLVoid and PhishTank clients (2 points)
6. **STORY-004.6**: Testing and monitoring (2 points)

**Acceptance Criteria Summary**:

- Circuit breaker states: CLOSED, OPEN, HALF_OPEN
- Exponential backoff retry (max 3 retries)
- Configurable thresholds via environment variables
- Metrics tracked: circuit state, failure rate

---

### EPIC-005: Multi-Abuse Contact Handling (P1)

**Business Value**: Successfully resolve and send to all abuse contacts, eliminating manual intervention.

**User Stories**:

1. **STORY-005.1**: Normalize ASN/Provider databases to lists (3 points)
2. **STORY-005.2**: Implement AbuseContactResolver class (4 points)
3. **STORY-005.3**: Update email sending for multiple recipients (2 points)
4. **STORY-005.4**: Track per-contact in database (2 points)
5. **STORY-005.5**: Testing with real multi-contact scenarios (1 point)

**Acceptance Criteria Summary**:

- All ASN_ABUSE_EMAIL_DB entries normalized to lists
- Resolver returns deduplicated list of contacts
- Emails sent to all contacts (or separate emails per contact)
- Database tracks which contacts were used

---

### EPIC-006: Main.py Modularization (P2)

**Business Value**: Improve code maintainability, reduce technical debt by 60%.

**User Stories**:

1. **STORY-006.1**: Create module structure (2 points)
2. **STORY-006.2**: Extract domain_generator module (4 points)
3. **STORY-006.3**: Extract dns_resolver module (3 points)
4. **STORY-006.4**: Extract API clients to intelligence/ (6 points)
5. **STORY-006.5**: Extract reporting modules (4 points)
6. **STORY-006.6**: Refactor main.py to orchestrator (8 points)
7. **STORY-006.7**: Update imports and test integration (4 points)

**Acceptance Criteria Summary**:

- New module structure: detection/, intelligence/, reporting/, observability/
- main.py reduced to <500 lines (currently 7389)
- All tests pass after refactoring
- Zero functional regressions

---

## Story Status Legend

- 🟢 **Ready**: Fully defined, acceptance criteria clear, dependencies resolved
- 🟡 **In Progress**: Currently being worked on
- ✅ **Done**: Completed and merged
- 🔴 **Blocked**: Dependency or blocker preventing progress
- ⭐ **Highest Priority**: Critical path item

---

## Velocity Tracking

**Planned Velocity**:

- Sprint 1: 54 points (Foundation)
- Sprint 2: 35 points (Core Enhancements)
- Sprint 3: 31 points (Modularization)
- Sprint 4: Testing & Monitoring (no points, quality focus)

**Total Planned**: 120 points over 4 sprints (~30 points/sprint average)

---

## Dependencies Map

```
EPIC-002 (Logging) ──┐
                     ├──> EPIC-001 (Redirects)
EPIC-003 (Database) ─┘

EPIC-004 (Circuit Breakers) ──> EPIC-001 (Redirects)

EPIC-005 (Multi-Contact) ──> EPIC-003 (Database)

EPIC-006 (Modularization) ──> ALL PREVIOUS EPICS
```

**Critical Path**: EPIC-002 → EPIC-003 → EPIC-001 → EPIC-006

---

## Risk Register

| Risk                               | Mitigation                                   | Owner    |
| ---------------------------------- | -------------------------------------------- | -------- |
| **Redirect analysis breaks scans** | Feature flag ENABLE_REDIRECT_ANALYSIS        | Dev Team |
| **Database migration downtime**    | Run during maintenance window, full backup   | DevOps   |
| **Modularization regressions**     | Incremental refactor, 100% test coverage     | Dev Team |
| **Velocity overestimation**        | Re-estimate after Sprint 1, adjust Sprint 2+ | PO       |

---

## Definition of Ready (Stories)

Before a story enters a sprint:

- [ ] User story follows "As a... I want... So that..." format
- [ ] Acceptance criteria are clear and testable
- [ ] Tasks are broken down and estimated
- [ ] Dependencies identified and resolved
- [ ] Architecture design exists (if needed)
- [ ] Test strategy defined
- [ ] Team understands the story (no questions)

---

## Definition of Done (Stories)

Before a story is marked complete:

- [ ] All acceptance criteria met
- [ ] All tasks completed
- [ ] Unit tests written and passing
- [ ] Integration tests written (if applicable)
- [ ] Code reviewed and approved
- [ ] Documentation updated
- [ ] No linting errors
- [ ] Manually tested
- [ ] Merged to dev branch

---

## References

- **Project Brief**: `docs/PROJECT-BRIEF.md`
- **Architecture**: `docs/ARCHITECTURE.md`
- **Epics**: `docs/epics/EPIC-*.md`
- **Stories**: `docs/stories/STORY-*.md`

---

**Backlog Maintenance**:

- Review backlog weekly
- Update story points based on actual velocity
- Re-prioritize as needed
- Add new stories as requirements emerge
