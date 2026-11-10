"""Stripe events -> ledger -> public API -> independent verifier, end to end (Stripe faked)."""

import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from vpp import pii
from vpp.config import get_settings
from vpp.db import get_session
from vpp.db.models import PiiRecord, Profile, StripeEvent
from vpp_verify.cli import main as verify_main

SECRET = "whsec_test"
ACCT = "acct_1RECIPIENT"


class FakeStripe:
    """Only what the webhook path calls; construct_event stays real (signature check)."""

    def __init__(self):
        import stripe

        self._real = stripe.StripeClient("sk_test_fake")
        self.refunds: list[SimpleNamespace] = []
        self.v1 = SimpleNamespace(
            refunds=SimpleNamespace(list=lambda params, opts: SimpleNamespace(data=self.refunds))
        )

    def construct_event(self, *a, **kw):
        return self._real.construct_event(*a, **kw)


@pytest.fixture
def app_client(ledger, key, monkeypatch):
    monkeypatch.setenv("VPP_STRIPE_WEBHOOK_SECRET", SECRET)
    get_settings.cache_clear()
    from vpp.api import webhooks
    from vpp.app import app

    fake = FakeStripe()
    monkeypatch.setattr(webhooks, "get_stripe", lambda: fake)
    monkeypatch.setattr(webhooks, "get_ledger_key", lambda: key)
    factory = sessionmaker(ledger, expire_on_commit=False)

    def session_override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = session_override
    with factory() as s:
        payer = pii.store_commitment(s, "Ada Lovelace")
        s.add(
            Profile(
                id="prof_c",
                slug="charity",
                display_name="Good Charity",
                stripe_account_id=ACCT,
                card_payments_status="active",
            )
        )
        s.commit()
    with TestClient(app) as client:
        client.fake = fake
        client.payer = payer
        client.factory = factory
        yield client
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def send(client, type_, obj, *, event_id=None, livemode=False, account=ACCT):
    event = {
        "id": event_id or f"evt_{time.time_ns()}",
        "object": "event",
        "type": type_,
        "livemode": livemode,
        "created": 1762689600,
        "account": account,
        "api_version": "2026-10-28.endive",
        "data": {"object": obj},
    }
    payload = json.dumps(event)
    ts = int(time.time())
    sig = hmac.new(SECRET.encode(), f"{ts}.{payload}".encode(), hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/stripe", content=payload, headers={"stripe-signature": f"t={ts},v1={sig}"}
    )


def checkout(client, pi="pi_1", amount=5000, status="paid", **md):
    return {
        "id": f"cs_{pi}",
        "object": "checkout.session",
        "payment_status": status,
        "payment_intent": pi,
        "amount_total": amount,
        "currency": "eur",
        "metadata": {"vpp_publish": "1", "vpp_profile": "prof_c", "vpp_payer": client.payer, **md},
    }


def test_bad_signature_rejected(app_client):
    r = app_client.post("/webhooks/stripe", content="{}", headers={"stripe-signature": "t=1,v1=00"})
    assert r.status_code == 400


def test_payment_flow_end_to_end(app_client):
    c = app_client
    assert (
        send(c, "checkout.session.completed", checkout(c)).json()["outcome"] == "recorded:payment"
    )
    # Same session reported again by the async event: must not double-record.
    assert send(c, "checkout.session.async_payment_succeeded", checkout(c)).json()["outcome"] == (
        "already_recorded"
    )

    # Partial refund, then the event is redelivered, then a second refund.
    c.fake.refunds = [SimpleNamespace(id="re_1", amount=1000, status="succeeded", created=1)]
    charge = {"id": "ch_1", "object": "charge", "payment_intent": "pi_1"}
    assert send(c, "charge.refunded", charge, event_id="evt_r1").json()["outcome"] == (
        "recorded:1_refunds"
    )
    assert send(c, "charge.refunded", charge, event_id="evt_r1").json()["outcome"] == "duplicate"
    c.fake.refunds.append(SimpleNamespace(id="re_2", amount=500, status="succeeded", created=2))
    assert send(c, "charge.refunded", charge).json()["outcome"] == "recorded:1_refunds"

    profile = c.get("/api/v1/profiles/charity").json()
    assert profile["net_by_currency"] == {"EUR": 3500}
    assert profile["payments"][0]["reversed"] == 1500

    page = c.get("/p/charity").text
    assert "Ada Lovelace" in page and "35.00 EUR" in page
    assert "35.00 EUR" in c.get("/badge/charity.svg").text
    assert c.get("/e/2").status_code == 200

    # The independent verifier, over HTTP, pinned to the genesis key.
    genesis_hash = c.get("/api/v1/entries/1").json()["hash"]
    assert verify_main(["--url", "http://testserver", "--pin-genesis", genesis_hash], client=c) == 0


def test_lost_dispute_capped_to_remaining(app_client):
    c = app_client
    send(c, "checkout.session.completed", checkout(c, amount=2000))
    c.fake.refunds = [SimpleNamespace(id="re_1", amount=1500, status="succeeded", created=1)]
    send(c, "charge.refunded", {"id": "ch_1", "object": "charge", "payment_intent": "pi_1"})
    dispute = {
        "id": "dp_1",
        "object": "dispute",
        "status": "lost",
        "amount": 2000,
        "payment_intent": "pi_1",
    }
    assert send(c, "charge.dispute.closed", dispute).json()["outcome"] == "recorded:dispute"
    assert c.get("/api/v1/profiles/charity").json()["net_by_currency"] == {"EUR": 0}


@pytest.mark.parametrize(
    "kwargs, outcome",
    [
        ({"status": "unpaid"}, "ignored:unpaid"),
        ({"vpp_publish": "0"}, "ignored:not_opted_in"),
        ({"vpp_profile": "prof_other"}, "ignored:profile_mismatch"),
    ],
)
def test_payments_not_recorded(app_client, kwargs, outcome):
    status = kwargs.pop("status", "paid")
    obj = checkout(app_client, status=status, **kwargs)
    assert send(app_client, "checkout.session.completed", obj).json()["outcome"] == outcome


def test_livemode_mismatch_ignored(app_client):
    obj = checkout(app_client)
    r = send(app_client, "checkout.session.completed", obj, livemode=True)
    assert r.json()["outcome"] == "ignored:livemode"


def test_failure_rolls_back_event_so_stripe_retries(app_client, monkeypatch):
    from vpp.stripe_connect import webhooks as wh

    def boom(*a, **kw):
        raise RuntimeError("db hiccup")

    monkeypatch.setattr(wh, "append", boom)
    with pytest.raises(RuntimeError):
        send(app_client, "checkout.session.completed", checkout(app_client), event_id="evt_x")
    with app_client.factory() as s:
        assert s.get(StripeEvent, "evt_x") is None


def test_erasure_keeps_chain_valid(app_client):
    c = app_client
    send(c, "checkout.session.completed", checkout(c))
    with c.factory() as s:
        assert pii.erase(s, c.payer)
        s.commit()
        assert s.get(PiiRecord, c.payer).cleartext is None
    assert "Ada Lovelace" not in c.get("/p/charity").text
    assert "Ada Lovelace" not in c.get("/e/2").text
    assert verify_main(["--url", "http://testserver"], client=c) == 0


def test_pay_form_validation(app_client):
    r = app_client.post("/pay/charity", data={"amount": "1.234", "consent": "1"})
    assert r.status_code == 400 and "between" in r.text
    r = app_client.post("/pay/charity", data={"amount": "10"})
    assert r.status_code == 400 and "confirm" in r.text


def test_entries_pagination(app_client):
    for i in range(3):
        send(app_client, "checkout.session.completed", checkout(app_client, pi=f"pi_{i}"))
    page = app_client.get("/api/v1/entries", params={"after": 0, "limit": 2}).json()
    assert [e["seq"] for e in page["entries"]] == [1, 2] and page["next_after"] == 2
    page = app_client.get("/api/v1/entries", params={"after": 2, "limit": 2}).json()
    assert [e["seq"] for e in page["entries"]] == [3, 4] and page["next_after"] == 4
    page = app_client.get("/api/v1/entries", params={"after": 4, "limit": 2}).json()
    assert page["entries"] == [] and page["next_after"] is None


def test_entry_page_shows_the_envelope_time_in_utc(app_client):
    import json as _json

    c = app_client
    env = c.get("/api/v1/entries/1").json()
    shown = _json.loads(base64_decode(env["envelope"]))["created_at"]  # e.g. 2026-11-09T13:51:35Z
    assert shown.replace("T", " ").replace("Z", " UTC") in c.get("/e/1").text


def base64_decode(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_ledger_page_lists_every_entry(app_client):
    c = app_client
    send(c, "checkout.session.completed", checkout(c, amount=5000))
    c.fake.refunds = [SimpleNamespace(id="re_1", amount=1000, status="succeeded", created=1)]
    send(c, "charge.refunded", {"id": "ch_1", "object": "charge", "payment_intent": "pi_1"})
    page = c.get("/ledger").text
    for text in (
        "data-entry-count>3</span> entries",
        "Ledger created",
        "Payment",
        "Refund",
        "10.00 EUR of payment #2",
        "Good Charity",
        'href="/e/3"',
        "recorded",
    ):
        assert text in page, text
    assert page.index('href="/e/3"') < page.index('href="/e/1"')  # newest first
    assert 'href="/ledger"' in c.get("/").text


def test_recipient_guide_page(app_client):
    page = app_client.get("/recipients").text
    for text in (
        "Before you start",
        "Photo ID",
        "two-step verification",
        "takes no cut",
        "/.well-known/vpp.json",
        'href="/recipient/login"',
    ):
        assert text in page, text
    assert 'href="/recipients">For recipients' in app_client.get("/").text
    assert "mailto:bee@theorycorner.com" in page  # how to ask for an invitation


def test_about_page_and_footer_link(app_client):
    page = app_client.get("/about").text
    for text in ("Dr. Ivo Iliev", "Sofia, Bulgaria", "mailto:bee@theorycorner.com",
                 'href="/#limits"', "github.com/HallowDance/donationbee"):
        assert text in page, text
    assert 'id="limits"' in app_client.get("/").text
    assert 'href="/about">Who runs this' in app_client.get("/ledger").text


def test_pay_page_shows_test_card_only_in_test_mode(app_client, monkeypatch):
    from vpp.config import get_settings

    monkeypatch.setenv("VPP_STRIPE_SECRET_KEY", "sk_test_fake")
    get_settings.cache_clear()
    assert "4242 4242 4242 4242" in app_client.get("/pay/charity").text
    monkeypatch.setenv("VPP_STRIPE_LIVEMODE", "true")
    get_settings.cache_clear()
    assert "4242" not in app_client.get("/pay/charity").text


def test_tip_is_not_recorded_as_part_of_the_donation(app_client):
    c = app_client
    obj = checkout(c, amount=5200, vpp_amount="5000")  # €50 donation + €2 tip
    assert send(c, "checkout.session.completed", obj).json()["outcome"] == "recorded:payment"
    assert c.get("/api/v1/profiles/charity").json()["net_by_currency"] == {"EUR": 5000}


def test_donation_larger_than_charge_is_refused(app_client):
    obj = checkout(app_client, amount=1000, vpp_amount="9999")
    assert send(app_client, "checkout.session.completed", obj).json()["outcome"] == (
        "ignored:amount_mismatch"
    )


def test_pay_form_rejects_made_up_tips(app_client):
    r = app_client.post("/pay/charity", data={"amount": "10", "consent": "1", "tip": "123"})
    assert r.status_code == 400 and "tip options" in r.text


class _FakeCheckoutStripe:
    def __init__(self):
        self.calls = []
        self.v1 = SimpleNamespace(
            checkout=SimpleNamespace(sessions=SimpleNamespace(create=self._create))
        )

    def _create(self, params, options):
        self.calls.append((params, options))
        return SimpleNamespace(url="https://checkout.stripe.test/x")


@pytest.mark.parametrize("tip", [0, 200])
def test_checkout_takes_exactly_the_tip_and_nothing_else(ledger, monkeypatch, tip):
    from sqlalchemy.orm import Session
    from vpp.stripe_connect import checkout as co

    monkeypatch.setattr(co, "refresh_status", lambda *a: "active")
    fake = _FakeCheckoutStripe()
    with Session(ledger) as s:
        p = Profile(id="prof_t", slug="t", display_name="T", stripe_account_id="acct_t")
        s.add(p)
        s.flush()
        co.create_checkout(
            s, fake, p, amount=2500, currency="EUR", payer_name=None, note=None, tip=tip
        )
    params, options = fake.calls[0]
    assert options == {"stripe_account": "acct_t"}
    assert [li["price_data"]["unit_amount"] for li in params["line_items"]] == (
        [2500, 200] if tip else [2500]
    )
    pid = params["payment_intent_data"]
    assert pid.get("application_fee_amount") == (200 if tip else None)  # no fee without a tip
    assert pid["metadata"]["vpp_amount"] == "2500"
