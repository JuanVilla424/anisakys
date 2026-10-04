"""Form-only providers get an analyst web-form task, never an e-mail.

registrar_form_db marks GoDaddy, Cloudflare, Porkbun, OVH, Google and
Microsoft as form-only (their abuse mailboxes are ignored), yet the pipeline
e-mailed e.g. abuse@cloudflare.com for every Cloudflare-proxied site.
"""

from __future__ import annotations

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.data.registrar_form_db import lookup_form_by_email
from src.reporting.routing import plan_delivery

SITE = "https://login.phish-example.net/verify"


def test_lookup_form_by_email_matches_form_only_domains():
    assert lookup_form_by_email("abuse@cloudflare.com")["name"] == "Cloudflare Registrar"
    assert lookup_form_by_email("abuse@godaddy.com")["method"] == "form_only"
    assert lookup_form_by_email("Abuse@Mail.OVH.net")["name"] == "OVHcloud"
    assert lookup_form_by_email("abuse@namecheap.com") is None
    assert lookup_form_by_email("not-an-address") is None


def test_cloudflare_proxy_becomes_a_web_form_task_not_an_email():
    plan = plan_delivery(["abuse@cloudflare.com"], SITE, is_cloudflare=True)

    assert plan.emails == []
    assert [task.provider for task in plan.form_tasks] == ["Cloudflare Registrar"]
    assert plan.form_tasks[0].form_url == "https://abuse.cloudflare.com/phishing"


def test_form_only_registrar_gets_a_task_while_the_host_is_emailed():
    plan = plan_delivery(
        ["abuse@godaddy.com", "abuse@small-host.example"],
        SITE,
        registrar="GoDaddy.com, LLC",
        hosting_provider="Small Host Ltd",
    )

    assert plan.emails == ["abuse@small-host.example"]
    assert [task.provider for task in plan.form_tasks] == ["GoDaddy"]


def test_hosting_provider_name_routes_to_its_form():
    plan = plan_delivery([], SITE, hosting_provider="MICROSOFT-CORP-MSN-AS-BLOCK")

    assert [task.provider for task in plan.form_tasks] == ["Microsoft Azure"]
    assert not plan.is_empty


def test_form_and_email_providers_are_still_emailed():
    plan = plan_delivery(["abuse@namecheap.com"], SITE, registrar="Tucows Domains Inc.")

    assert plan.emails == ["abuse@namecheap.com"]
    assert plan.form_tasks == []


def test_policy_rejections_and_cap_are_reported():
    plan = plan_delivery(
        ["abuse@phish-example.net", "a@one.example", "b@two.example", "c@three.example"],
        SITE,
        max_recipients=2,
    )

    assert plan.emails == ["a@one.example", "b@two.example"]
    rejected = dict(plan.rejected)
    assert "abuse@phish-example.net" in rejected
    assert "c@three.example" in rejected


def test_failed_deliverability_check_is_rejected_not_dropped_silently():
    plan = plan_delivery(
        ["abuse@nomx.example", "abuse@ok.example"],
        SITE,
        validate_email=lambda email: email != "abuse@nomx.example",
    )

    assert plan.emails == ["abuse@ok.example"]
    assert plan.rejected == [("abuse@nomx.example", "address failed deliverability validation")]
