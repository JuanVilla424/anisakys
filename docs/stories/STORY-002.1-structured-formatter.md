# User Story 002.1: Implement StructuredFormatter Class

**Story ID**: STORY-002.1
**Epic**: EPIC-002 (Structured Logging Infrastructure)
**Priority**: P1 - High
**Story Points**: 5
**Sprint**: Sprint 1 (Days 1-2)
**Status**: Ready for Development
**Assigned**: Developer
**Created**: 2025-11-21

---

## User Story

**As a** DevOps engineer / SOC analyst
**I want** all application logs in structured JSON format
**So that** I can easily parse, query, and analyze logs for debugging and monitoring

---

## Acceptance Criteria

### AC-1: StructuredFormatter Class Exists

**Given** the codebase
**When** I look in `src/observability/structured_logger.py`
**Then** I should find a `StructuredFormatter` class that inherits from `logging.Formatter`

### AC-2: JSON Output Format

**Given** a log message is emitted
**When** the StructuredFormatter formats it
**Then** the output should be valid JSON with these required fields:

- `timestamp` (ISO8601 UTC, e.g., "2025-11-21T10:30:45.123Z")
- `level` (string: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
- `logger` (string: logger name, e.g., "anisakys.detection")
- `message` (string: the log message)
- `correlation_id` (string: UUID or null)

### AC-3: Context Field Inclusion

**Given** a log message with context data
**When** logged using `extra={'context': {...}}`
**Then** the JSON output should include a `context` field with the provided data

Example:

```json
{
  "timestamp": "2025-11-21T10:30:45.123Z",
  "level": "INFO",
  "logger": "anisakys.detection",
  "message": "Phishing site detected",
  "correlation_id": "abc-123-def-456",
  "context": {
    "url": "https://phishing.com",
    "confidence": 95,
    "keywords": ["login", "bank"]
  }
}
```

### AC-4: Exception Formatting

**Given** an exception is logged
**When** using `logger.exception()` or `logger.error(..., exc_info=True)`
**Then** the JSON output should include an `exception` field with the stack trace

### AC-5: Source Location for Errors

**Given** a log at ERROR level or higher
**When** formatted by StructuredFormatter
**Then** the JSON output should include a `source` field with:

- `file` (pathname)
- `line` (line number)
- `function` (function name)

### AC-6: No Unhandled Serialization Errors

**Given** any log message with any data type in context
**When** StructuredFormatter attempts to format it
**Then** it should not raise a JSON serialization error
**And** non-serializable objects should be converted to strings

---

## Technical Implementation

### Files to Create

1. **`src/observability/__init__.py`** (new directory)

   ```python
   """Observability module for logging, metrics, and tracing."""
   ```

2. **`src/observability/structured_logger.py`**

### Implementation Details

**Key Classes/Functions**:

```python
import logging
import json
import sys
from datetime import datetime
from contextvars import ContextVar

# Global context variable for correlation ID
correlation_id_var: ContextVar[str] = ContextVar('correlation_id', default=None)

class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Build base log data
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id_var.get(),
        }

        # Add exception if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add custom context
        if hasattr(record, 'context'):
            log_data["context"] = record.context

        # Add source location for ERROR+
        if record.levelno >= logging.ERROR:
            log_data["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Serialize to JSON
        try:
            return json.dumps(log_data, default=str)  # default=str handles non-serializable
        except Exception as e:
            # Fallback if JSON serialization fails
            return json.dumps({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": "ERROR",
                "message": f"Log formatting error: {str(e)}",
                "original_message": str(record.getMessage()),
            })
```

**Helper Functions**:

```python
def set_correlation_id(correlation_id: str = None) -> str:
    """Set correlation ID for current context."""
    if correlation_id is None:
        import uuid
        correlation_id = str(uuid.uuid4())
    correlation_id_var.set(correlation_id)
    return correlation_id

def get_correlation_id() -> str:
    """Get current correlation ID."""
    return correlation_id_var.get()
```

---

## Tasks (Ordered)

### Task 1: Create Module Structure (15 min)

- [ ] Create directory `src/observability/`
- [ ] Create `src/observability/__init__.py`
- [ ] Create `src/observability/structured_logger.py`

### Task 2: Implement StructuredFormatter (45 min)

- [ ] Define `StructuredFormatter` class
- [ ] Implement `format()` method
- [ ] Add timestamp formatting (ISO8601 UTC)
- [ ] Add base fields (level, logger, message, correlation_id)
- [ ] Add context field handling
- [ ] Add exception formatting
- [ ] Add source location for ERROR+
- [ ] Add JSON serialization with error handling

### Task 3: Implement Correlation ID Management (30 min)

- [ ] Import ContextVar
- [ ] Create `correlation_id_var` ContextVar
- [ ] Implement `set_correlation_id()` function
- [ ] Implement `get_correlation_id()` function
- [ ] Test thread-safety

### Task 4: Write Unit Tests (60 min)

- [ ] Create `tests/observability/test_structured_logger.py`
- [ ] Test basic JSON formatting
- [ ] Test context field inclusion
- [ ] Test exception formatting
- [ ] Test source location for errors
- [ ] Test correlation ID propagation
- [ ] Test non-serializable object handling
- [ ] Test edge cases (None values, empty context, etc.)

### Task 5: Documentation (20 min)

- [ ] Add docstrings to all classes/functions
- [ ] Add usage examples in module docstring
- [ ] Document JSON schema in comments

---

## Definition of Done

- [ ] All acceptance criteria met
- [ ] All tasks completed
- [ ] Unit tests written and passing (coverage >90%)
- [ ] Code reviewed
- [ ] Documentation complete (docstrings + examples)
- [ ] No linting errors (`pylint`, `black`, `isort`)
- [ ] Manually tested with sample logs
- [ ] Committed to feature branch

---

## Testing Strategy

### Unit Tests

```python
# tests/observability/test_structured_logger.py

import json
import logging
from src.observability.structured_logger import (
    StructuredFormatter,
    set_correlation_id,
    get_correlation_id
)

def test_basic_json_formatting():
    """Test that basic log produces valid JSON."""
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None
    )

    output = formatter.format(record)
    log_data = json.loads(output)  # Should not raise

    assert log_data["level"] == "INFO"
    assert log_data["logger"] == "test.logger"
    assert log_data["message"] == "Test message"
    assert "timestamp" in log_data
    assert "correlation_id" in log_data

def test_context_field():
    """Test context field inclusion."""
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Detection event",
        args=(),
        exc_info=None
    )
    record.context = {"url": "https://test.com", "confidence": 90}

    output = formatter.format(record)
    log_data = json.loads(output)

    assert "context" in log_data
    assert log_data["context"]["url"] == "https://test.com"
    assert log_data["context"]["confidence"] == 90

def test_correlation_id():
    """Test correlation ID management."""
    # Set correlation ID
    corr_id = set_correlation_id("test-123")
    assert get_correlation_id() == "test-123"

    # Verify it appears in logs
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test",
        args=(),
        exc_info=None
    )

    output = formatter.format(record)
    log_data = json.loads(output)
    assert log_data["correlation_id"] == "test-123"

# ... more tests for exception, source location, etc.
```

### Manual Testing

```python
# manual_test.py

import logging
from src.observability.structured_logger import StructuredFormatter, set_correlation_id

# Setup logger
logger = logging.getLogger("anisakys.test")
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()
handler.setFormatter(StructuredFormatter())
logger.addHandler(handler)

# Test
set_correlation_id("manual-test-123")

logger.info("Basic info message")
logger.info("Message with context", extra={"context": {"url": "https://test.com", "score": 95}})

try:
    1 / 0
except Exception:
    logger.exception("Error occurred")

logger.error("Error without exception")
```

**Expected Output** (each line is valid JSON):

```json
{"timestamp":"2025-11-21T10:30:45.123Z","level":"INFO","logger":"anisakys.test","message":"Basic info message","correlation_id":"manual-test-123"}
{"timestamp":"2025-11-21T10:30:45.124Z","level":"INFO","logger":"anisakys.test","message":"Message with context","correlation_id":"manual-test-123","context":{"url":"https://test.com","score":95}}
{"timestamp":"2025-11-21T10:30:45.125Z","level":"ERROR","logger":"anisakys.test","message":"Error occurred","correlation_id":"manual-test-123","exception":"Traceback...","source":{"file":"manual_test.py","line":18,"function":"<module>"}}
```

---

## Dependencies

**Required**:

- Python 3.12+
- Standard library: `logging`, `json`, `datetime`, `contextvars`

**No External Packages Needed** (uses Python stdlib only)

---

## Notes

- StructuredFormatter is stateless (thread-safe)
- ContextVar ensures correlation_id is thread-safe
- JSON serialization uses `default=str` for non-serializable objects
- Error handling prevents formatter from crashing on bad data

---

## References

- **Epic**: EPIC-002 (Structured Logging Infrastructure)
- **Architecture**: `docs/ARCHITECTURE.md` - Solution 2
- **Python Logging**: https://docs.python.org/3/library/logging.html
- **ContextVars**: https://docs.python.org/3/library/contextvars.html

---

**Status Updates**:

- 2025-11-21: Story created, ready for development
