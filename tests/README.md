# 🧪 Anisakys Test Suite

Comprehensive test suite for the Anisakys phishing detection engine.

## 📋 Test Coverage

### Unit Tests

1. **Database Tests** (`test_database_upgrade.py`)

   - Database schema upgrades
   - Column addition and type fixes
   - PostgreSQL/SQLite compatibility

2. **Multi-API Validation Tests** (`test_multi_api_validation.py`)

   - VirusTotal API integration
   - URLVoid API integration
   - PhishTank API integration
   - Threat level calculations
   - API error handling

3. **Abuse Reporting Tests** (`test_abuse_reporting.py`)
   - Email sending functionality
   - Template rendering
   - Attachment handling
   - CC recipient management
   - Uses your email: `r6ty5r296it6tl4eg5m.constant214@passinbox.com`

### Functional Tests

4. **End-to-End Tests** (`test_functional_e2e.py`)
   - Complete workflow testing
   - Concurrent scanning
   - Database persistence
   - REST API functionality
   - Error recovery
   - Auto-analysis workflow

## 🚀 Running Tests

### Quick Start

```bash
# Run all tests
python tests/run_tests.py

# Run with integration tests
python tests/run_tests.py --integration

# Run specific test file
pytest tests/test_database_upgrade.py -v

# Run with coverage
pytest --cov=src tests/
```

### Test Environment

The test suite uses:

- Test database: `postgresql://postgres:j*3_7f-jh.s5.as@localhost:5332/test_db`
- Test email recipient: `r6ty5r296it6tl4eg5m.constant214@passinbox.com`
- Mock API keys for testing
- SQLite for unit tests, PostgreSQL for integration tests

### Configuration

Test configuration is in `.env.test`:

- Database settings
- Email configuration with your test email
- Mock API keys
- Test-specific timeouts and intervals

## 📧 Email Testing

All test emails are configured to be sent to:

```
r6ty5r296it6tl4eg5m.constant214@passinbox.com
```

This includes:

- Test abuse reports
- CC notifications
- Escalation emails
- Integration test reports

## 🔍 Test Categories

### Unit Tests

- Fast, isolated tests
- Mock external dependencies
- Test individual components

### Integration Tests

- Test component interactions
- Use real database
- Mock external APIs

### Functional Tests

- End-to-end workflows
- Concurrent operations
- Error scenarios

## 🛠️ Adding New Tests

1. Create test file in `tests/` directory
2. Import main module:
   ```python
   module_path = Path(__file__).parent.parent / "src" / "main.py"
   spec = importlib.util.spec_from_file_location("src.main", str(module_path))
   main = importlib.util.module_from_spec(spec)
   spec.loader.exec_module(main)
   ```
3. Use fixtures for common setup
4. Mock external dependencies
5. Use your email for report testing

## 📊 Coverage Goals

- Unit test coverage: >80%
- Integration test coverage: >60%
- Critical paths: 100%

## 🐛 Debugging Tests

```bash
# Run with verbose output
pytest -v -s tests/

# Run specific test
pytest tests/test_multi_api_validation.py::TestMultiAPIValidation::test_virustotal_scan_success -v

# Debug with pdb
pytest --pdb tests/
```

## ✅ Test Checklist

- [x] Database operations
- [x] Multi-API validation
- [x] Abuse email detection
- [x] Email sending with attachments
- [x] Concurrent scanning
- [x] Error recovery
- [x] REST API endpoints
- [x] Auto-analysis workflow
- [x] Integration with your test email

---

**Note**: All test reports and notifications will be sent to `r6ty5r296it6tl4eg5m.constant214@passinbox.com`
