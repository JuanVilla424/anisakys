"""Shared provider runtime: TTL cache and token buckets (src/intelligence/provider_runtime.py)."""

from typing import List

from src.intelligence import provider_runtime
from src.intelligence.provider_runtime import TokenBucket, TTLCache, cached_call


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: List[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class TestTTLCache:
    def test_entries_expire_and_least_recent_go_first(self):
        clock = FakeClock()
        cache = TTLCache(maxsize=2, clock=clock)
        cache.set("a", 1, ttl=10)
        cache.set("b", 2, ttl=10)
        cache.get("a")
        cache.set("c", 3, ttl=10)  # evicts b, the least recently used

        assert (cache.get("a"), cache.get("b"), cache.get("c")) == (1, None, 3)
        clock.now += 11
        assert cache.get("a") is None and len(cache) == 1


class TestTokenBucket:
    def test_burst_then_refill(self):
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=4, clock=clock, sleep=clock.sleep)

        assert all(bucket.acquire() for _ in range(4))
        assert not bucket.acquire(wait_seconds=0)
        assert bucket.acquire(wait_seconds=20)  # one token every 15 s
        assert clock.slept and abs(sum(clock.slept) - 15) < 1e-6

    def test_zero_rate_is_unlimited(self):
        assert all(TokenBucket(rate_per_minute=0).acquire() for _ in range(100))


class TestCachedCall:
    def setup_method(self):
        provider_runtime.reset()

    def test_answers_are_cached_errors_are_not(self):
        calls = []

        def provider(url):
            calls.append(url)
            return {"status": "listed"} if "bad" in url else {"status": "error", "error": "x"}

        assert cached_call("phishtank", "u-bad", provider, "u-bad") == ({"status": "listed"}, False)
        assert cached_call("phishtank", "u-bad", provider, "u-bad") == ({"status": "listed"}, True)
        cached_call("phishtank", "u-err", provider, "u-err")
        cached_call("phishtank", "u-err", provider, "u-err")

        assert calls == ["u-bad", "u-err", "u-err"]

    def test_whois_data_without_a_status_is_cached(self):
        calls = []
        result = {"registrar": "R", "domain_age_days": 10}

        def whois(domain):
            calls.append(domain)
            return result

        cached_call("whois", "d.com", whois, "d.com")
        cached_call("whois", "d.com", whois, "d.com")

        assert calls == ["d.com"]

    def test_an_exhausted_bucket_returns_no_data(self, monkeypatch):
        from src.config import settings

        monkeypatch.setattr(settings, "VIRUSTOTAL_REQUESTS_PER_MINUTE", 1)
        provider_runtime.reset()

        def provider(url):
            return {"status": "error"}

        cached_call("virustotal_url", "a", provider, "a", wait_seconds=0)
        result, cached = cached_call("virustotal_url", "b", provider, "b", wait_seconds=0)

        assert result["rate_limited"] and result["status"] == "no_data" and not cached

    def test_budgets_come_from_the_settings(self, monkeypatch):
        from src.config import settings

        monkeypatch.setattr(settings, "WHOIS_REQUESTS_PER_MINUTE", 7)
        monkeypatch.setattr(settings, "PHISHTANK_REQUESTS_PER_MINUTE", 9)
        provider_runtime.reset()

        # A bucket holds one minute of its budget.
        assert provider_runtime.bucket("whois").capacity == 7
        assert provider_runtime.bucket("phishtank").capacity == 9
        assert provider_runtime.bucket("virustotal_url").capacity == (
            settings.VIRUSTOTAL_REQUESTS_PER_MINUTE
        )
