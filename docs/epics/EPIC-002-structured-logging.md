# Epic 002: Structured Logging Infrastructure

**Epic ID**: EPIC-002
**Priority**: P1 - High
**Status**: Ready for Development
**Sprint**: Sprint 1 (Days 1-7)
**Created**: 2025-11-21
**Owner**: Development Team

---

## Business Value

**Problem**: Production debugging is impossible due to inadequate logging. When failures occur, there is no way to trace what happened, leading to extended downtime and inability to reproduce issues.

**Impact**:

- **Mean Time To Repair (MTTR)**: Currently 4+ hours
- **Post-Mortem Analysis**: Impossible (logs don't exist or are incomplete)
- **Business Risk**: MEDIUM - Cannot meet SLAs for security operations

**Value Proposition**: Implementing structured logging will reduce MTTR by 70% (from 4hrs to ~30min) through correlation IDs, searchable JSON logs, and comprehensive context.

---

## Scope

### In Scope

- JSON-formatted structured logs (machine-parseable)
- Correlation IDs for request tracing across components
- Log rotation (daily, 30-day retention)
- Per-module configurable log levels
- Contextual logging (URL, keywords, confidence scores, API names)
- Log aggregation ready (ELK/Grafana Loki compatible)
- Performance metrics in logs (timing data)
- Exception stack traces with context

### Out of Scope

- Log aggregation platform setup (ELK/Grafana Loki) - separate epic
- Real-time log alerting - handled by monitoring epic
- Log-based metrics (use Prometheus instead)
- Log anonymization/PII scrubbing (add if needed later)

---

## Technical Approach

**Architecture Reference**: `docs/ARCHITECTURE.md` - Solution 2

**Key Components**:

1. **StructuredFormatter Class** (`src/observability/structured_logger.py`)
   - Custom logging.Formatter for JSON output
   - Fields: timestamp (ISO8601), level, logger, message, correlation_id, context, exception
   - Source location for ERROR+ levels (file, line, function)

2. **Correlation ID Management**
   - ContextVar for thread-safe correlation ID storage
   - Auto-generated UUID per scan cycle
   - Propagated through all log calls within same context

3. **Log Configuration**
   - Console handler (JSON) for production
   - File handler with RotatingFileHandler (50MB max, 30 backups)
   - Configurable via environment variables (LOG_LEVEL, LOG_FILE)

4. **Convenience Functions**
   - `log_with_context()` - Add custom context to any log
   - `log_detection()` - Standard detection event logging
   - `log_api_call()` - Standard API call logging
   - `log_error()` - Error logging with context

---

## Acceptance Criteria

### AC-001: JSON Log Format

- [ ] All logs output as valid JSON (parseable by `json.loads()`)
- [ ] Required fields present: timestamp, level, logger, message, correlation_id
- [ ] Timestamp is ISO8601 UTC format
- [ ] Context field contains custom metadata (URL, confidence, etc.)

### AC-002: Correlation IDs

- [ ] Correlation ID generated at start of each scan cycle
- [ ] All logs within same scan contain same correlation_id
- [ ] Correlation ID is thread-safe (uses ContextVar)
- [ ] Correlation ID visible in all log outputs

### AC-003: Log Rotation

- [ ] Logs rotate when file exceeds 50MB
- [ ] Keep 30 backup files (30 days retention)
- [ ] Old logs automatically deleted after 30 days
- [ ] No disk space exhaustion issues

### AC-004: Configurable Log Levels

- [ ] LOG_LEVEL environment variable controls minimum log level
- [ ] Valid levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- [ ] Per-module log levels configurable (optional)
- [ ] Default level is INFO

### AC-005: Contextual Logging

- [ ] Detection events logged with: url, confidence, keywords
- [ ] API calls logged with: api_name, url, status_code, response_time_ms
- [ ] Errors logged with: error_type, context, stack_trace
- [ ] Database operations logged with: table, operation, duration

### AC-006: Integration

- [ ] All existing `logger.info()`, `logger.error()` calls migrated to structured format
- [ ] No unstructured log statements remain in codebase
- [ ] Console output is JSON (not human-readable) in production
- [ ] Backward compatible (logs still work if new logger not configured)

---

## User Stories

1. **Story 002.1**: Implement StructuredFormatter class (5 points)
2. **Story 002.2**: Add correlation ID management (3 points)
3. **Story 002.3**: Configure log rotation and handlers (2 points)
4. **Story 002.4**: Create convenience logging functions (3 points)
5. **Story 002.5**: Migrate existing log calls (5 points)
6. **Story 002.6**: Testing and validation (3 points)

**Total Story Points**: 21 points

---

## Dependencies

**Blockers**:

- None (can start immediately)

**Required Before**:

- None

**Depends On**:

- Existing logger.py (will be replaced/enhanced)

---

## Risks & Mitigations

| Risk                                           | Probability | Impact | Mitigation                                                                   |
| ---------------------------------------------- | ----------- | ------ | ---------------------------------------------------------------------------- |
| **Log rotation fills disk**                    | Medium      | Medium | Monitor disk space, alert at 80% full, 30-day retention limit                |
| **JSON logs are hard to read during dev**      | High        | Low    | Provide dev mode with human-readable format, or use `jq` for pretty-printing |
| **Performance impact from JSON serialization** | Low         | Low    | JSON serialization is fast, test with benchmarks                             |
| **Migration breaks existing logs**             | Medium      | Medium | Incremental migration, test each module, feature flag for rollback           |

---

## Testing Strategy

### Unit Tests

- `test_structured_logger.py`:
  - Test JSON formatting
  - Test correlation ID generation/propagation
  - Test log rotation behavior
  - Test context field inclusion
  - Test exception formatting

### Integration Tests

- `test_logging_integration.py`:
  - Test logging across modules with same correlation ID
  - Test log file creation and rotation
  - Test environment variable configuration
  - Test performance (measure overhead)

---

## Success Metrics

**Before Implementation**:

- MTTR: 4+ hours
- Log searchability: Manual grep (unstructured)
- Request tracing: Impossible

**After Implementation**:

- MTTR: <30 minutes
- Log searchability: JSON queries (jq, ELK)
- Request tracing: Via correlation_id
- Log completeness: 100% of events captured with context

---

## Documentation Requirements

- [ ] Update README.md with logging configuration
- [ ] Document all LOG\_\* environment variables
- [ ] Create developer guide for using structured logging
- [ ] Add examples of querying logs with jq
- [ ] Document log schema (JSON fields)

---

## References

- **Architecture Design**: `docs/ARCHITECTURE.md` - Solution 2
- **Project Brief**: `docs/PROJECT-BRIEF.md` - P1 Issue
- **Python Logging Docs**: https://docs.python.org/3/library/logging.html

---

**Status Updates**:

- 2025-11-21: Epic created, ready for story breakdown
