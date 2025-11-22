"""
Unit tests for RedirectAnalyzer class.

Tests cover:
- Basic redirect following (1, 3, 5 hops)
- Loop detection
- Timeout enforcement
- Risk scoring algorithm
- Cloudflare detection
- Cross-domain detection
- URL shortener detection
- Suspicious TLD detection
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from src.detection.redirect_analyzer import (
    RedirectAnalyzer,
    RedirectChain,
    RedirectHop,
    REDIRECT_STATUS_CODES,
)


class TestRedirectAnalyzerBasic(unittest.TestCase):
    """Test basic redirect analyzer functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer(max_hops=5, timeout_per_hop=10)

    def test_init_default_values(self):
        """Test analyzer initializes with correct defaults."""
        analyzer = RedirectAnalyzer()
        self.assertEqual(analyzer.max_hops, 5)
        self.assertEqual(analyzer.timeout_per_hop, 10)
        self.assertFalse(analyzer.follow_redirects)

    def test_init_custom_values(self):
        """Test analyzer initializes with custom values."""
        analyzer = RedirectAnalyzer(max_hops=3, timeout_per_hop=5)
        self.assertEqual(analyzer.max_hops, 3)
        self.assertEqual(analyzer.timeout_per_hop, 5)

    def test_invalid_url_raises_error(self):
        """Test that invalid URLs raise ValueError."""
        with self.assertRaises(ValueError):
            self.analyzer.analyze("")

        with self.assertRaises(ValueError):
            self.analyzer.analyze("not-a-url")

        with self.assertRaises(ValueError):
            self.analyzer.analyze("ftp://example.com")


class TestRedirectFollowing(unittest.TestCase):
    """Test redirect chain following."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer(max_hops=5, timeout_per_hop=10)

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_no_redirect_single_hop(self, mock_get):
        """Test URL with no redirects (200 response)."""
        # Mock response with no redirect
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_get.return_value = mock_response

        chain = self.analyzer.analyze("https://example.com")

        self.assertEqual(chain.hop_count, 1)
        self.assertEqual(chain.original_url, "https://example.com")
        self.assertEqual(chain.final_url, "https://example.com")
        self.assertFalse(chain.has_loop)
        mock_get.assert_called_once()

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_single_redirect(self, mock_get):
        """Test single redirect (301 -> 200)."""
        # First call: 301 redirect
        mock_redirect = Mock()
        mock_redirect.status_code = 301
        mock_redirect.headers = {"Location": "https://example.com/new", "Server": "nginx"}

        # Second call: 200 final
        mock_final = Mock()
        mock_final.status_code = 200
        mock_final.headers = {"Content-Type": "text/html"}

        mock_get.side_effect = [mock_redirect, mock_final]

        chain = self.analyzer.analyze("https://example.com/old")

        self.assertEqual(chain.hop_count, 2)
        self.assertEqual(chain.original_url, "https://example.com/old")
        self.assertEqual(chain.final_url, "https://example.com/new")
        self.assertEqual(len(chain.chain_urls), 2)

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_multiple_redirects(self, mock_get):
        """Test multiple redirects (3 hops)."""
        responses = [
            Mock(status_code=302, headers={"Location": "https://example.com/step2"}),
            Mock(status_code=301, headers={"Location": "https://example.com/step3"}),
            Mock(status_code=200, headers={"Content-Type": "text/html"}),
        ]
        mock_get.side_effect = responses

        chain = self.analyzer.analyze("https://example.com/step1")

        self.assertEqual(chain.hop_count, 3)
        self.assertEqual(chain.final_url, "https://example.com/step3")

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_max_hops_limit(self, mock_get):
        """Test that analyzer respects max_hops limit."""
        analyzer = RedirectAnalyzer(max_hops=2)

        # Create infinite redirect chain
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "https://example.com/next"}
        mock_get.return_value = mock_response

        chain = analyzer.analyze("https://example.com/start")

        # Should stop at max_hops (2)
        self.assertEqual(chain.hop_count, 2)
        self.assertEqual(mock_get.call_count, 2)


class TestLoopDetection(unittest.TestCase):
    """Test redirect loop detection."""

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_detects_redirect_loop(self, mock_get):
        """Test detection of redirect loop."""
        analyzer = RedirectAnalyzer(max_hops=5)

        # Create loop: A -> B -> A
        responses = [
            Mock(status_code=302, headers={"Location": "https://example.com/b"}),
            Mock(status_code=302, headers={"Location": "https://example.com/a"}),
        ]
        mock_get.side_effect = responses

        chain = analyzer.analyze("https://example.com/a")

        self.assertTrue(chain.has_loop)
        self.assertLessEqual(chain.hop_count, 3)  # Should stop when loop detected


class TestCloudflareDetection(unittest.TestCase):
    """Test Cloudflare detection."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer()

    def test_detects_cloudflare_via_server_header(self):
        """Test Cloudflare detection via Server header."""
        headers = {"Server": "cloudflare"}
        self.assertTrue(self.analyzer._is_cloudflare(headers))

    def test_detects_cloudflare_via_cf_ray(self):
        """Test Cloudflare detection via CF-RAY header."""
        headers = {"CF-RAY": "1234567890-LAX"}
        self.assertTrue(self.analyzer._is_cloudflare(headers))

    def test_no_cloudflare(self):
        """Test non-Cloudflare response."""
        headers = {"Server": "nginx"}
        self.assertFalse(self.analyzer._is_cloudflare(headers))

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_chain_marks_cloudflare(self, mock_get):
        """Test that chain correctly marks Cloudflare presence."""
        # Cloudflare redirect
        mock_response = Mock()
        mock_response.status_code = 301
        mock_response.headers = {
            "Location": "https://example.com/final",
            "CF-RAY": "1234567890-LAX",
        }
        mock_final = Mock()
        mock_final.status_code = 200
        mock_final.headers = {"Server": "nginx"}

        mock_get.side_effect = [mock_response, mock_final]

        chain = self.analyzer.analyze("https://example.com/start")
        self.assertTrue(chain.has_cloudflare)


class TestSuspiciousTLDDetection(unittest.TestCase):
    """Test suspicious TLD detection."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer()

    def test_detects_suspicious_tld(self):
        """Test detection of suspicious TLDs."""
        urls = ["https://phishing.ru/page", "https://example.com"]
        self.assertTrue(self.analyzer._has_suspicious_tld(urls))

    def test_no_suspicious_tld(self):
        """Test legitimate TLDs."""
        urls = ["https://example.com", "https://google.com"]
        self.assertFalse(self.analyzer._has_suspicious_tld(urls))

    def test_multiple_suspicious_tlds(self):
        """Test multiple suspicious TLDs."""
        urls = ["https://site.tk", "https://phish.cn"]
        self.assertTrue(self.analyzer._has_suspicious_tld(urls))


class TestURLShortenerDetection(unittest.TestCase):
    """Test URL shortener detection."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer()

    def test_detects_url_shortener(self):
        """Test detection of URL shorteners."""
        urls = ["https://bit.ly/abc123", "https://example.com"]
        self.assertTrue(self.analyzer._has_url_shortener(urls))

    def test_no_url_shortener(self):
        """Test legitimate domains."""
        urls = ["https://example.com", "https://google.com"]
        self.assertFalse(self.analyzer._has_url_shortener(urls))

    def test_shortener_with_www(self):
        """Test shortener detection with www prefix."""
        urls = ["https://www.tinyurl.com/xyz"]
        self.assertTrue(self.analyzer._has_url_shortener(urls))


class TestCrossDomainDetection(unittest.TestCase):
    """Test cross-domain redirect detection."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer()

    def test_detects_cross_domain(self):
        """Test detection of cross-domain redirects."""
        urls = ["https://example.com/a", "https://different.com/b"]
        self.assertTrue(self.analyzer._has_cross_domain(urls))

    def test_same_domain(self):
        """Test same domain redirects."""
        urls = ["https://example.com/a", "https://example.com/b"]
        self.assertFalse(self.analyzer._has_cross_domain(urls))

    def test_subdomain_same_base(self):
        """Test subdomains of same base domain."""
        urls = ["https://www.example.com/a", "https://api.example.com/b"]
        self.assertFalse(self.analyzer._has_cross_domain(urls))

    def test_single_url(self):
        """Test single URL (no cross-domain possible)."""
        urls = ["https://example.com/a"]
        self.assertFalse(self.analyzer._has_cross_domain(urls))


class TestRiskScoring(unittest.TestCase):
    """Test risk score calculation."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = RedirectAnalyzer()

    def test_risk_score_no_redirects(self):
        """Test risk score with no redirects."""
        chain = Mock()
        chain.hop_count = 1
        chain.has_cloudflare = False
        chain.has_suspicious_tld = False
        chain.has_url_shortener = False
        chain.has_cross_domain = False
        chain.has_loop = False

        score = self.analyzer._calculate_risk_score(chain)
        self.assertEqual(score, 10)  # 1 hop * 10

    def test_risk_score_multiple_hops(self):
        """Test risk score increases with hops."""
        chain = Mock()
        chain.hop_count = 3
        chain.has_cloudflare = False
        chain.has_suspicious_tld = False
        chain.has_url_shortener = False
        chain.has_cross_domain = False
        chain.has_loop = False

        score = self.analyzer._calculate_risk_score(chain)
        self.assertEqual(score, 30)  # 3 hops * 10

    def test_risk_score_with_cloudflare(self):
        """Test risk score with Cloudflare intermediary."""
        chain = Mock()
        chain.hop_count = 2
        chain.has_cloudflare = True
        chain.has_suspicious_tld = False
        chain.has_url_shortener = False
        chain.has_cross_domain = False
        chain.has_loop = False

        score = self.analyzer._calculate_risk_score(chain)
        self.assertEqual(score, 35)  # 20 (hops) + 15 (CF)

    def test_risk_score_with_suspicious_tld(self):
        """Test risk score with suspicious TLD."""
        chain = Mock()
        chain.hop_count = 1
        chain.has_cloudflare = False
        chain.has_suspicious_tld = True
        chain.has_url_shortener = False
        chain.has_cross_domain = False
        chain.has_loop = False

        score = self.analyzer._calculate_risk_score(chain)
        self.assertEqual(score, 30)  # 10 (hop) + 20 (TLD)

    def test_risk_score_with_loop(self):
        """Test risk score with redirect loop."""
        chain = Mock()
        chain.hop_count = 2
        chain.has_cloudflare = False
        chain.has_suspicious_tld = False
        chain.has_url_shortener = False
        chain.has_cross_domain = False
        chain.has_loop = True

        score = self.analyzer._calculate_risk_score(chain)
        self.assertEqual(score, 50)  # 20 (hops) + 30 (loop)

    def test_risk_score_max_100(self):
        """Test risk score is capped at 100."""
        chain = Mock()
        chain.hop_count = 5
        chain.has_cloudflare = True
        chain.has_suspicious_tld = True
        chain.has_url_shortener = True
        chain.has_cross_domain = True
        chain.has_loop = True

        score = self.analyzer._calculate_risk_score(chain)
        self.assertEqual(score, 100)  # Capped at 100

    def test_risk_score_high_risk_scenario(self):
        """Test high-risk redirect scenario."""
        chain = Mock()
        chain.hop_count = 4
        chain.has_cloudflare = True
        chain.has_suspicious_tld = True
        chain.has_url_shortener = True
        chain.has_cross_domain = True
        chain.has_loop = False

        score = self.analyzer._calculate_risk_score(chain)
        # 40 (hops) + 15 (CF) + 20 (TLD) + 10 (shortener) + 15 (cross) = 100
        self.assertGreaterEqual(score, 90)


class TestTimeoutHandling(unittest.TestCase):
    """Test timeout handling."""

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_handles_timeout(self, mock_get):
        """Test that timeouts are handled gracefully."""
        import requests

        mock_get.side_effect = requests.Timeout("Connection timeout")

        analyzer = RedirectAnalyzer(timeout_per_hop=1)
        chain = analyzer.analyze("https://example.com")

        # Should return empty chain without crashing
        self.assertEqual(chain.hop_count, 0)
        self.assertFalse(chain.has_loop)

    @patch("src.detection.redirect_analyzer.requests.get")
    def test_timeout_stops_chain(self, mock_get):
        """Test that timeout stops redirect chain."""
        import requests

        # First hop succeeds, second times out
        mock_success = Mock()
        mock_success.status_code = 302
        mock_success.headers = {"Location": "https://example.com/next"}

        mock_get.side_effect = [mock_success, requests.Timeout()]

        analyzer = RedirectAnalyzer()
        chain = analyzer.analyze("https://example.com/start")

        self.assertEqual(chain.hop_count, 1)  # Only first hop recorded


if __name__ == "__main__":
    unittest.main()
