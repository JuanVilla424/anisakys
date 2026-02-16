"""Unit tests for Typosquatting Detection Service (UC-003, UC-004).

Tests:
- Homoglyph variant generation
- Keyboard typo variant generation
- TLD variation generation
- Subdomain trick generation
- Combo squatting generation
- DNS resolution checking
- Variant saving and retrieval
- Complete analysis workflow
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from src.services.typosquatting_service import TyposquattingService
from src.models.domain_variant import DomainVariant


class TestHomoglyphGeneration:
    """Test homoglyph (visual similarity) variant generation."""

    @pytest.mark.asyncio
    async def test_homoglyph_substitution(self):
        """Homoglyphs should substitute visually similar characters."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_homoglyphs("paypal", "com")

        # Should generate variants like paypa1.com (l -> 1), paypa0.com (l -> 0)
        variant_domains = [v for v in variants]

        assert len(variant_domains) > 0
        assert "paypa1.com" in variant_domains  # l -> 1
        assert "paypai.com" in variant_domains  # l -> i

    @pytest.mark.asyncio
    async def test_homoglyph_multiple_characters(self):
        """Homoglyphs should handle domains with multiple substitutable characters."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_homoglyphs("google", "com")

        variant_domains = [v for v in variants]

        # Should substitute 'o' with '0', 'O', etc.
        assert len(variant_domains) > 0
        # At least some variants should contain '0' instead of 'o'
        assert any('0' in v for v in variant_domains)


class TestKeyboardTypoGeneration:
    """Test keyboard typo (QWERTY adjacency) variant generation."""

    @pytest.mark.asyncio
    async def test_qwerty_adjacent_keys(self):
        """Typos should substitute with QWERTY-adjacent keys."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_typos("paypal", "com")

        variant_domains = [v for v in variants]

        assert len(variant_domains) > 0
        # 'p' adjacent to 'o', 'a' adjacent to 's', etc.
        assert "oaypal.com" in variant_domains  # p -> o
        assert "psypal.com" in variant_domains  # a -> s

    @pytest.mark.asyncio
    async def test_typo_all_positions(self):
        """Typos should be generated for all character positions."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_typos("test", "com")

        variant_domains = [v for v in variants]

        # Should have typos for each position
        assert len(variant_domains) > 0


class TestTLDVariationGeneration:
    """Test TLD variation generation."""

    @pytest.mark.asyncio
    async def test_tld_variations(self):
        """Should generate variants with different TLDs."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_tld_variations("paypal", "com")

        variant_domains = [v for v in variants]

        assert len(variant_domains) > 0
        assert "paypal.net" in variant_domains
        assert "paypal.org" in variant_domains
        assert "paypal.io" in variant_domains
        assert "paypal.com" not in variant_domains  # Should exclude original

    @pytest.mark.asyncio
    async def test_tld_variations_coverage(self):
        """Should cover common TLDs."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_tld_variations("example", "com")

        variant_domains = [v for v in variants]

        # Check for common phishing TLDs
        assert "example.info" in variant_domains
        assert "example.biz" in variant_domains
        assert "example.online" in variant_domains


class TestSubdomainTrickGeneration:
    """Test subdomain trick generation."""

    @pytest.mark.asyncio
    async def test_subdomain_prefixes(self):
        """Should generate variants with suspicious subdomain prefixes."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_subdomain_tricks("paypal", "com")

        variant_domains = [v for v in variants]

        assert len(variant_domains) > 0
        assert "paypal-secure.com" in variant_domains
        assert "secure-paypal.com" in variant_domains
        assert "login-paypal.com" in variant_domains
        assert "securepaypal.com" in variant_domains

    @pytest.mark.asyncio
    async def test_subdomain_phishing_keywords(self):
        """Should use common phishing keywords in subdomains."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_subdomain_tricks("banking", "com")

        variant_domains = [v for v in variants]

        # Common phishing keywords
        assert any("verify" in v for v in variant_domains)
        assert any("account" in v for v in variant_domains)
        assert any("update" in v for v in variant_domains)


class TestComboSquattingGeneration:
    """Test combo squatting (brand + keyword) generation."""

    @pytest.mark.asyncio
    async def test_combo_squatting_patterns(self):
        """Should combine brand with phishing keywords."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_combo_squatting("paypal", "com")

        variant_domains = [v for v in variants]

        assert len(variant_domains) > 0
        assert "paypalsecure.com" in variant_domains
        assert "paypal-login.com" in variant_domains
        assert "loginpaypal.com" in variant_domains

    @pytest.mark.asyncio
    async def test_combo_squatting_keywords(self):
        """Should use high-risk phishing keywords."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = service._generate_combo_squatting("bank", "com")

        variant_domains = [v for v in variants]

        # High-risk keywords
        assert any("verify" in v for v in variant_domains)
        assert any("account" in v for v in variant_domains)
        assert any("secure" in v for v in variant_domains)


class TestVariantGenerationWorkflow:
    """Test complete variant generation workflow."""

    @pytest.mark.asyncio
    async def test_generate_variants_all_techniques(self):
        """Should generate variants using all techniques."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = await service.generate_variants("test.com", max_variants=100)

        assert isinstance(variants, list)
        assert len(variants) > 0
        assert len(variants) <= 100

        # Check structure
        assert all('domain' in v for v in variants)
        assert all('type' in v for v in variants)

        # Check all techniques represented
        types = {v['type'] for v in variants}
        assert 'homoglyph' in types
        assert 'keyboard_typo' in types
        assert 'tld_variation' in types

    @pytest.mark.asyncio
    async def test_generate_variants_selective_techniques(self):
        """Should generate variants with only selected techniques."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = await service.generate_variants(
            "test.com",
            max_variants=50,
            techniques=['homoglyph', 'tld']
        )

        types = {v['type'] for v in variants}
        assert 'homoglyph' in types
        assert 'tld_variation' in types
        assert 'keyboard_typo' not in types  # Should not include excluded technique

    @pytest.mark.asyncio
    async def test_generate_variants_max_limit(self):
        """Should respect max_variants limit."""
        db = AsyncMock()
        service = TyposquattingService(db)

        variants = await service.generate_variants("test.com", max_variants=10)

        assert len(variants) <= 10

    @pytest.mark.asyncio
    async def test_generate_variants_invalid_domain(self):
        """Should raise ValueError for invalid domain format."""
        db = AsyncMock()
        service = TyposquattingService(db)

        with pytest.raises(ValueError, match="Invalid domain format"):
            await service.generate_variants("invalid", max_variants=10)


class TestDNSResolutionChecking:
    """Test DNS resolution checking for active variants."""

    @pytest.mark.asyncio
    @patch('dns.resolver.Resolver')
    async def test_check_dns_resolution_active(self, mock_resolver):
        """Should identify active domains that resolve."""
        db = AsyncMock()
        service = TyposquattingService(db)

        # Mock DNS resolver
        mock_resolver_instance = MagicMock()
        mock_resolver.return_value = mock_resolver_instance
        mock_resolver_instance.resolve.return_value = ['192.0.2.1']

        variants = [
            {'domain': 'active-domain.com', 'type': 'homoglyph'},
            {'domain': 'another-active.com', 'type': 'typo'}
        ]

        active = await service.check_dns_resolution(variants, timeout=3)

        assert len(active) == 2
        assert active[0]['domain'] == 'active-domain.com'
        assert active[1]['domain'] == 'another-active.com'

    @pytest.mark.asyncio
    @patch('dns.resolver.Resolver')
    async def test_check_dns_resolution_inactive(self, mock_resolver):
        """Should filter out inactive domains that don't resolve."""
        db = AsyncMock()
        service = TyposquattingService(db)

        # Mock DNS resolver to raise NXDOMAIN
        mock_resolver_instance = MagicMock()
        mock_resolver.return_value = mock_resolver_instance

        import dns.resolver
        mock_resolver_instance.resolve.side_effect = dns.resolver.NXDOMAIN()

        variants = [
            {'domain': 'nonexistent.com', 'type': 'homoglyph'}
        ]

        active = await service.check_dns_resolution(variants, timeout=3)

        assert len(active) == 0


class TestVariantSaving:
    """Test variant saving to database."""

    @pytest.mark.asyncio
    async def test_save_variants_new(self):
        """Should save new variants to database."""
        db = AsyncMock()
        service = TyposquattingService(db)

        # Mock database query - no existing variant
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        variants = [
            {'domain': 'paypa1.com', 'type': 'homoglyph'},
            {'domain': 'paypal.net', 'type': 'tld_variation'}
        ]

        saved = await service.save_variants("paypal.com", variants)

        assert len(saved) == 2
        assert db.add.call_count == 2
        assert db.commit.called

    @pytest.mark.asyncio
    async def test_save_variants_existing(self):
        """Should update existing variants."""
        db = AsyncMock()
        service = TyposquattingService(db)

        # Mock database query - variant exists
        existing_variant = DomainVariant(
            id=1,
            target_domain="paypal.com",
            variant_domain="paypa1.com",
            variant_type="homoglyph",
            is_active=False,
            detection_method="automated",
            first_seen=datetime.utcnow(),
            last_checked=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_variant
        db.execute.return_value = mock_result

        variants = [
            {'domain': 'paypa1.com', 'type': 'homoglyph'}
        ]

        saved = await service.save_variants("paypal.com", variants)

        # Should update existing variant
        assert len(saved) == 1
        assert saved[0].is_active == True
        assert db.commit.called


class TestCompleteAnalysis:
    """Test complete typosquatting analysis workflow."""

    @pytest.mark.asyncio
    @patch('dns.resolver.Resolver')
    async def test_analyze_domain_complete_workflow(self, mock_resolver):
        """Should execute complete analysis workflow."""
        db = AsyncMock()
        service = TyposquattingService(db)

        # Mock DNS - some domains resolve
        mock_resolver_instance = MagicMock()
        mock_resolver.return_value = mock_resolver_instance

        def resolve_side_effect(domain, record_type):
            if 'active' in domain:
                return ['192.0.2.1']
            raise Exception("NXDOMAIN")

        mock_resolver_instance.resolve.side_effect = resolve_side_effect

        # Mock database
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        # Run analysis
        results = await service.analyze_domain(
            target_domain="test.com",
            max_variants=50,
            check_active_only=True
        )

        assert 'target_domain' in results
        assert 'total_generated' in results
        assert 'active_variants' in results
        assert 'saved_variants' in results
        assert 'variants' in results

        assert results['target_domain'] == "test.com"
        assert results['total_generated'] > 0

    @pytest.mark.asyncio
    async def test_get_variants_for_domain(self):
        """Should retrieve saved variants for domain."""
        db = AsyncMock()
        service = TyposquattingService(db)

        # Mock database response
        mock_variants = [
            DomainVariant(
                id=1,
                target_domain="paypal.com",
                variant_domain="paypa1.com",
                variant_type="homoglyph",
                is_active=True,
                confidence_score=75,
                threat_level="medium",
                detection_method="automated",
                first_seen=datetime.utcnow(),
                last_checked=datetime.utcnow()
            )
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_variants
        db.execute.return_value = mock_result

        variants = await service.get_variants_for_domain("paypal.com", active_only=True)

        assert len(variants) == 1
        assert variants[0].variant_domain == "paypa1.com"
        assert variants[0].is_active is True
