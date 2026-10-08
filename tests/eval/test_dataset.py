"""Evaluation datasets: sanitisation, de-duplication, temporal split, manifest."""

import json

import pytest

from src.eval.dataset import (
    DatasetError,
    load_dataset,
    make_sample,
    sanitize_url,
    select_split,
    assign_splits,
    dedupe,
    sample_id,
    verify_dataset,
    write_dataset,
)


class TestSanitizeUrl:
    def test_keeps_scheme_host_and_path_only(self):
        assert (
            sanitize_url("HTTPS://User:Pw@Login.Example.COM:8443/a/b?email=x@y.com#frag")
            == "https://login.example.com/a/b"
        )

    def test_redacts_emails_and_tokens_in_the_path(self):
        url = "https://phish.example/victim@bank.com/9f86d081884c7d659a2feaa0c55ad015/a1B2c3D4e5F6g7H8i9J0k1L2m3/ok"
        assert sanitize_url(url) == "https://phish.example/[email]/[token]/[token]/ok"

    def test_adds_a_scheme_and_a_root_path(self):
        assert sanitize_url("example.org") == "http://example.org/"

    @pytest.mark.parametrize("raw", ["", "ftp://files.example/x", "https://", "not a url at all"])
    def test_rejects_unusable_urls(self, raw):
        assert sanitize_url(raw) is None

    def test_internationalised_hosts_become_punycode(self):
        assert sanitize_url("https://pаypal.com/login") == "https://xn--pypal-4ve.com/login"

    def test_words_are_not_tokens(self):
        assert sanitize_url("https://a.example/secure-account-verification-update/") == (
            "https://a.example/secure-account-verification-update/"
        )


def _s(url, category="feed_live_verified", first_seen="2026-10-01T00:00:00+00:00", kit=None):
    sample = make_sample(url, category, "test", first_seen=first_seen, kit=kit)
    assert sample is not None
    return sample


class TestMakeSample:
    def test_label_follows_the_category(self):
        assert _s("https://p.example/").label == "phishing"
        assert _s("https://b.example/", category="tranco_top").label == "benign"

    def test_id_is_derived_from_the_sanitised_url(self):
        sample = _s("https://p.example/x?session=1")
        assert sample.id == sample_id("https://p.example/x")
        assert sample.registrable_domain == "p.example"

    def test_unknown_category_is_an_error(self):
        with pytest.raises(ValueError):
            make_sample("https://p.example/", "rumour", "test")


class TestDedupe:
    def test_one_positive_per_registrable_domain_keeping_the_earliest(self):
        # Real suffix: reserved TLDs such as .example are not in the PSL, so
        # their hosts have no registrable part to group on.
        late = _s("https://a.evil-login.com/1", first_seen="2026-10-02T00:00:00+00:00")
        early = _s("https://b.evil-login.com/2", first_seen="2026-10-01T00:00:00+00:00")

        kept = dedupe([late, early])

        assert kept == [early]

    def test_negatives_keep_one_per_category_and_domain(self):
        official = _s("https://www.paypal.com/", category="official_brand")
        login = _s("https://www.paypal.com/signin", category="official_brand")
        tranco = _s("https://paypal.com/", category="tranco_top")

        kept = dedupe([official, login, tranco])

        assert {s.category for s in kept} == {"official_brand", "tranco_top"}
        assert len(kept) == 2

    def test_kit_cap_limits_positives_sharing_a_kit(self):
        samples = [_s(f"https://kit{i}.example/", kit="evilginx") for i in range(5)]

        assert len(dedupe(samples, max_per_kit=2)) == 2
        assert len(dedupe(samples)) == 5

    def test_analyst_label_wins_over_a_feed_copy_of_the_same_url(self):
        feed = _s("https://x.example/login", first_seen="2026-09-01T00:00:00+00:00")
        analyst = _s("https://x.example/login", category="analyst_confirmed")

        assert [s.category for s in dedupe([feed, analyst])] == ["analyst_confirmed"]


class TestSplits:
    def test_newest_groups_go_to_test_and_domains_never_cross(self):
        samples = [
            _s(f"https://d{i}.example/", first_seen=f"2026-10-{i + 1:02d}T00:00:00+00:00")
            for i in range(10)
        ] + [_s("https://d9.example/other", first_seen="2026-09-01T00:00:00+00:00")]

        split = assign_splits(samples, test_fraction=0.3)

        test_domains = {s.registrable_domain for s in split if s.split == "test"}
        train_domains = {s.registrable_domain for s in split if s.split == "train"}
        assert not test_domains & train_domains
        assert len(test_domains) == 3
        assert "d9.example" in train_domains  # its earliest sample is the oldest of all

    def test_is_deterministic_for_equal_times(self):
        samples = [_s(f"https://same{i}.example/") for i in range(20)]

        first = [(s.id, s.split) for s in assign_splits(samples)]
        second = [(s.id, s.split) for s in assign_splits(list(reversed(samples)))]

        assert first == second

    def test_fraction_must_be_a_proportion(self):
        with pytest.raises(ValueError):
            assign_splits([], test_fraction=1.0)

    def test_select_split(self):
        samples = assign_splits([_s(f"https://s{i}.example/") for i in range(10)])
        assert len(select_split(samples, "all")) == 10
        assert len(select_split(samples, "test")) + len(select_split(samples, "train")) == 10
        with pytest.raises(ValueError):
            select_split(samples, "holdout")


class TestManifest:
    def _write(self, tmp_path):
        samples = assign_splits(
            [_s("https://p1.example/"), _s("https://b1.example/", category="homonym")]
        )
        manifest = write_dataset(
            tmp_path,
            samples,
            name="unit",
            version="v1",
            sources=[{"name": "test"}],
            parameters={"x": 1},
            code_commit="abc1234",
        )
        return manifest, samples

    def test_round_trip(self, tmp_path):
        manifest, samples = self._write(tmp_path)

        loaded_manifest, loaded = load_dataset(tmp_path)

        assert verify_dataset(tmp_path) == []
        assert loaded_manifest["samples_sha256"] == manifest["samples_sha256"]
        assert manifest["counts"]["by_label"] == {"phishing": 1, "benign": 1}
        assert [s.to_dict() for s in loaded] == [s.to_dict() for s in samples]

    def test_tampering_is_detected(self, tmp_path):
        self._write(tmp_path)
        path = tmp_path / "samples.jsonl"
        record = json.loads(path.read_text().splitlines()[0])
        record["label"] = "benign" if record["label"] == "phishing" else "phishing"
        path.write_text(json.dumps(record) + "\n" + "\n".join(path.read_text().splitlines()[1:]))

        problems = verify_dataset(tmp_path)

        assert any("SHA-256" in problem for problem in problems)
        with pytest.raises(DatasetError):
            load_dataset(tmp_path)

    def test_missing_samples_file_is_reported(self, tmp_path):
        self._write(tmp_path)
        (tmp_path / "samples.jsonl").unlink()

        assert any("does not exist" in p for p in verify_dataset(tmp_path))
