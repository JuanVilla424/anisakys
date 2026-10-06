"""ASN enrichment: absent IPs and unannounced space stay absent, never fail."""

from src.capture.asn import asn_of


class TestAsnOf:
    def test_missing_ip_is_absent(self):
        assert asn_of(None) == (None, None)
        assert asn_of("") == (None, None)

    def test_private_and_invalid_ips_are_absent_not_errors(self):
        # RFC1918 space has no RDAP record: the lookup must return absent.
        assert asn_of("192.168.1.10") == (None, None)
        assert asn_of("not-an-ip") == (None, None)

    def test_lookups_are_memoised(self):
        asn_of.cache_clear()
        first = asn_of("10.0.0.1")
        second = asn_of("10.0.0.1")
        assert first == second == (None, None)
        info = asn_of.cache_info()
        assert info.hits >= 1  # the second call never left the cache
