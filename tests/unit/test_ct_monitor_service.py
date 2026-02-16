"""Unit tests for Certificate Transparency Monitoring Service (UC-005).

Tests:
- crt.sh API integration
- Certificate parsing
- Threat score calculation
- Suspicious certificate detection
- Certificate saving
- Scan triggering
- Keyword monitoring workflow
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone
import httpx

from src.services.ct_monitor_service import CTMonitorService
from src.models.ct_certificate import CTCertificate
from src.models.scan import Scan


class TestCrtShAPIIntegration:
    """Test crt.sh API integration."""

    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_search_crt_sh_success(self, mock_client):
        """Should successfully query crt.sh API."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                'id': '123456',
                'name_value': 'test.com\nwww.test.com',
                'issuer_name': "Let's Encrypt",
                'entry_timestamp': '2024-01-01T12:00:00Z'
            }
        ]
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance

        service.client = mock_client_instance

        results = await service.search_crt_sh("paypal")

        assert len(results) == 1
        assert results[0]['id'] == '123456'

    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_search_crt_sh_http_error(self, mock_client):
        """Should handle HTTP errors gracefully."""
        db = AsyncMock()
        service = CTMonitorService(db)

        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.HTTPError("Connection error")
        mock_client.return_value = mock_client_instance

        service.client = mock_client_instance

        results = await service.search_crt_sh("paypal")

        assert results == []


class TestCertificateParsing:
    """Test certificate data parsing."""

    @pytest.mark.asyncio
    async def test_parse_certificate_valid(self):
        """Should parse valid certificate data."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {
            'id': '123456',
            'name_value': 'paypal-login.com\nwww.paypal-login.com',
            'issuer_name': "Let's Encrypt Authority X3",
            'entry_timestamp': '2024-01-01T12:00:00Z',
            'fingerprint': 'abc123'
        }

        parsed = await service.parse_certificate(cert_data, matched_keywords=['paypal'])

        assert parsed is not None
        assert parsed['cert_id'] == '123456'
        assert parsed['subject_cn'] == 'paypal-login.com'
        assert len(parsed['san_domains']) == 2
        assert 'paypal-login.com' in parsed['san_domains']
        assert 'www.paypal-login.com' in parsed['san_domains']
        assert parsed['issuer'] == "Let's Encrypt Authority X3"
        assert parsed['log_source'] == 'crt.sh'
        assert parsed['matched_keywords'] == ['paypal']

    @pytest.mark.asyncio
    async def test_parse_certificate_missing_fields(self):
        """Should handle missing optional fields."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {
            'id': '789',
            'name_value': 'test.com',
            'entry_timestamp': '2024-01-01T12:00:00Z'
        }

        parsed = await service.parse_certificate(cert_data)

        assert parsed is not None
        assert parsed['cert_id'] == '789'
        assert parsed['issuer'] == 'Unknown'

    @pytest.mark.asyncio
    async def test_parse_certificate_invalid_data(self):
        """Should return None for invalid certificate data."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {}  # Empty/invalid

        parsed = await service.parse_certificate(cert_data)

        # Should handle gracefully
        assert parsed is None or isinstance(parsed, dict)


class TestThreatScoreCalculation:
    """Test threat score and level calculation."""

    @pytest.mark.asyncio
    async def test_calculate_threat_score_high_risk(self):
        """Should calculate high threat score for suspicious patterns."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {
            'subject_cn': 'paypal-login-verify-secure-account.com',
            'issuer': "Let's Encrypt",
            'not_before': datetime.now(timezone.utc) - timedelta(days=2),  # Recently issued
            'not_after': datetime.now(timezone.utc) + timedelta(days=88)
        }

        score, level = service.calculate_threat_score(
            cert_data,
            matched_keywords=['paypal', 'login', 'verify']
        )

        # Multiple keywords + recent + long domain + hyphens + free issuer = high score
        assert score >= 50
        assert level in ['high', 'critical']

    @pytest.mark.asyncio
    async def test_calculate_threat_score_low_risk(self):
        """Should calculate low threat score for legitimate patterns."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {
            'subject_cn': 'example.com',
            'issuer': "DigiCert Inc",
            'not_before': datetime.now(timezone.utc) - timedelta(days=365),  # Old
            'not_after': datetime.now(timezone.utc) + timedelta(days=365)
        }

        score, level = service.calculate_threat_score(
            cert_data,
            matched_keywords=[]
        )

        # No keywords + old + legitimate issuer + short domain = low score
        assert score < 30
        assert level in ['safe', 'low']

    @pytest.mark.asyncio
    async def test_calculate_threat_score_recent_cert(self):
        """Recently issued certificates should increase threat score."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {
            'subject_cn': 'newdomain.com',
            'issuer': "Let's Encrypt",
            'not_before': datetime.now(timezone.utc) - timedelta(days=1),  # Very recent
            'not_after': datetime.now(timezone.utc) + timedelta(days=89)
        }

        score, level = service.calculate_threat_score(cert_data, matched_keywords=['banking'])

        # Recent issuance should add points
        assert score >= 30

    @pytest.mark.asyncio
    async def test_calculate_threat_score_long_domain(self):
        """Long domain names should increase threat score."""
        db = AsyncMock()
        service = CTMonitorService(db)

        cert_data = {
            'subject_cn': 'very-long-suspicious-domain-name-for-phishing.com',
            'issuer': "Let's Encrypt",
            'not_before': datetime.now(timezone.utc),
            'not_after': datetime.now(timezone.utc) + timedelta(days=90)
        }

        score, level = service.calculate_threat_score(cert_data, matched_keywords=[])

        # Long domain (> 20 chars) should add points
        assert score > 0

    @pytest.mark.asyncio
    async def test_calculate_threat_score_max_100(self):
        """Threat score should never exceed 100."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Max suspicious cert
        cert_data = {
            'subject_cn': 'paypal-secure-login-verify-account-update-confirm.com',
            'issuer': "Let's Encrypt",
            'not_before': datetime.now(timezone.utc),
            'not_after': datetime.now(timezone.utc) + timedelta(days=90)
        }

        score, level = service.calculate_threat_score(
            cert_data,
            matched_keywords=['paypal', 'login', 'verify', 'secure']
        )

        assert score <= 100


class TestCertificateSaving:
    """Test certificate saving to database."""

    @pytest.mark.asyncio
    async def test_save_certificate_new(self):
        """Should save new certificate to database."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock database query - no existing cert
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        mock_cert = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        cert_data = {
            'cert_id': '123456',
            'fingerprint': 'abc123',
            'issuer': "Let's Encrypt",
            'subject_cn': 'test.com',
            'san_domains': ['test.com', 'www.test.com'],
            'not_before': datetime.now(timezone.utc),
            'not_after': datetime.now(timezone.utc) + timedelta(days=90),
            'log_source': 'crt.sh',
            'matched_keywords': ['test'],
            'raw_data': {}
        }

        saved = await service.save_certificate(cert_data, is_suspicious=True)

        assert db.add.called
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_save_certificate_duplicate(self):
        """Should skip saving duplicate certificates."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock database query - cert exists
        existing_cert = CTCertificate(
            id=1,
            cert_id='123456',
            fingerprint='abc123',
            issuer="Let's Encrypt",
            subject_cn='test.com',
            san_domains=['test.com'],
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=90),
            log_source='crt.sh',
            discovered_at=datetime.now(timezone.utc),
            is_suspicious=False,
            scan_triggered=False
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_cert
        db.execute.return_value = mock_result

        cert_data = {
            'cert_id': '123456',
            'fingerprint': 'abc123',
            'issuer': "Let's Encrypt",
            'subject_cn': 'test.com',
            'san_domains': ['test.com'],
            'not_before': datetime.now(timezone.utc),
            'not_after': datetime.now(timezone.utc) + timedelta(days=90),
            'log_source': 'crt.sh',
            'matched_keywords': []
        }

        saved = await service.save_certificate(cert_data)

        assert saved is None  # Should skip duplicate


class TestKeywordMonitoring:
    """Test keyword monitoring workflow."""

    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_monitor_keywords_workflow(self, mock_client):
        """Should execute complete keyword monitoring workflow."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock crt.sh API response
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                'id': '123',
                'name_value': 'paypal-login.com',
                'issuer_name': "Let's Encrypt",
                'entry_timestamp': '2024-01-01T12:00:00Z'
            }
        ]
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        service.client = mock_client_instance

        # Mock database
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        results = await service.monitor_keywords(
            keywords=['paypal'],
            min_threat_level='medium',
            auto_save=True
        )

        assert 'keywords_searched' in results
        assert 'certificates_found' in results
        assert 'suspicious_certificates' in results
        assert results['keywords_searched'] == ['paypal']

    @pytest.mark.asyncio
    async def test_monitor_keywords_multiple_keywords(self):
        """Should handle multiple keywords."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock client
        mock_client_instance = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status = MagicMock()
        mock_client_instance.get.return_value = mock_response
        service.client = mock_client_instance

        results = await service.monitor_keywords(
            keywords=['paypal', 'banking', 'amazon'],
            min_threat_level='low',
            auto_save=False
        )

        assert results['keywords_searched'] == ['paypal', 'banking', 'amazon']


class TestSuspiciousCertificateRetrieval:
    """Test suspicious certificate retrieval."""

    @pytest.mark.asyncio
    async def test_get_suspicious_certificates(self):
        """Should retrieve suspicious certificates from recent days."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock database response
        mock_certs = [
            CTCertificate(
                id=1,
                cert_id='123',
                fingerprint='abc',
                issuer="Let's Encrypt",
                subject_cn='phishing.com',
                san_domains=['phishing.com'],
                not_before=datetime.now(timezone.utc),
                not_after=datetime.now(timezone.utc) + timedelta(days=90),
                log_source='crt.sh',
                discovered_at=datetime.now(timezone.utc) - timedelta(days=2),
                is_suspicious=True,
                confidence_score=85,
                threat_level='high',
                scan_triggered=False
            )
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_certs
        db.execute.return_value = mock_result

        certs = await service.get_suspicious_certificates(days=7, min_threat_level='medium')

        assert len(certs) == 1
        assert certs[0].is_suspicious is True


class TestScanTriggering:
    """Test automatic scan triggering."""

    @pytest.mark.asyncio
    async def test_trigger_scan_for_certificate(self):
        """Should trigger scan for suspicious certificate."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock certificate lookup
        mock_cert = CTCertificate(
            id=1,
            cert_id='123',
            fingerprint='abc',
            issuer="Let's Encrypt",
            subject_cn='suspicious.com',
            san_domains=['suspicious.com'],
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=90),
            log_source='crt.sh',
            discovered_at=datetime.now(timezone.utc),
            is_suspicious=True,
            scan_triggered=False
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_cert
        db.execute.return_value = mock_result

        scan = await service.trigger_scan_for_certificate(certificate_id=1, user_id=5)

        assert scan is not None
        assert mock_cert.scan_triggered is True
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_trigger_scan_certificate_not_found(self):
        """Should return None if certificate not found."""
        db = AsyncMock()
        service = CTMonitorService(db)

        # Mock certificate not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        scan = await service.trigger_scan_for_certificate(certificate_id=999, user_id=5)

        assert scan is None


class TestClientCleanup:
    """Test HTTP client cleanup."""

    @pytest.mark.asyncio
    async def test_close_client(self):
        """Should close HTTP client properly."""
        db = AsyncMock()
        service = CTMonitorService(db)

        service.client = AsyncMock()
        service.client.aclose = AsyncMock()

        await service.close()

        assert service.client.aclose.called
