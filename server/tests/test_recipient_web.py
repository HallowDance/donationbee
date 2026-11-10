"""Recipient pages + JSON endpoints, driven like passkey.js would with a software passkey."""

import base64
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from vpp import domainproof
from vpp.config import get_settings
from vpp.db import get_session
from vpp.db.models import Profile
from vpp.ledger.entries import Money, Payment, StripePaymentEvidence
from vpp.ledger.store import append
from vpp.testing.ledger import ORIGIN
from vpp.testing.softauthn import SoftAuthenticator
from vpp_verify.cli import main as verify

SITE = "https://proofs.test"


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.fixture
def client(ledger, key, monkeypatch):
    monkeypatch.setenv("VPP_RP_ID", "proofs.test")
    monkeypatch.setenv("VPP_PUBLIC_BASE_URL", SITE)
    get_settings.cache_clear()
    from vpp.app import app
    from vpp.web import recipient

    monkeypatch.setattr(recipient, "get_ledger_key", lambda: key)
    factory = sessionmaker(ledger, expire_on_commit=False)

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override
    with Session(ledger) as s:
        s.add(Profile(id="prof_c", slug="charity", display_name="Good Charity"))
        s.flush()
        for n in (1, 2):
            append(
                s,
                Payment(
                    recipient="prof_c",
                    amount=Money(value=1500, currency="EUR"),
                    occurred_at="2026-11-09T12:00:00Z",
                    evidence=StripePaymentEvidence(
                        account="acct_1",
                        payment_intent=f"pi_{n}",
                        checkout_session=f"cs_{n}",
                        livemode=False,
                    ),
                ),
                key,
            )
        s.commit()
    with TestClient(app, base_url="https://testserver") as c:
        yield c
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def sign_in_as(client, profile_id="prof_c"):
    from vpp.web.recipient import COOKIE, _sign

    exp = int(time.time()) + 600
    client.cookies.set(COOKIE, f"{profile_id}.{exp}.{_sign(profile_id, exp)}")


def test_requires_session(client):
    assert client.post("/api/recipient/register/options").status_code == 401
    assert (
        client.get("/recipient", follow_redirects=False).headers["location"] == "/recipient/login"
    )


def test_forged_cookie_rejected(client):
    from vpp.web.recipient import COOKIE

    client.cookies.set(COOKIE, f"prof_c.{int(time.time()) + 600}.{'0' * 64}")
    assert client.post("/api/recipient/register/options").status_code == 401


def test_register_publish_confirm_over_http(client, monkeypatch):
    sign_in_as(client)
    auth = SoftAuthenticator("proofs.test", SITE)

    r = client.post("/api/recipient/register/options").json()
    fin = client.post(
        "/api/recipient/register/verify",
        json={
            "challenge_id": r["challenge_id"],
            "credential": auth.create(b64d(r["options"]["challenge"])),
        },
    ).json()
    page = client.get("/recipient").text
    assert fin["fingerprint"] in page and "pending domain proof" in page

    monkeypatch.setattr(
        domainproof,
        "fetch",
        lambda d: domainproof.well_known_document(ORIGIN, "prof_c", [fin["fingerprint"]]),
    )
    pub = client.post(
        "/api/recipient/publish",
        json={"credential_id": fin["credential_id"], "domain": "charity.test"},
    )
    assert pub.status_code == 200, pub.text

    r = client.post("/api/recipient/confirm/options", json={"ref_seqs": [2, 3]}).json()
    done = client.post(
        "/api/recipient/confirm/verify",
        json={
            "challenge_id": r["challenge_id"],
            "credential": auth.get(b64d(r["options"]["challenge"])),
        },
    )
    assert done.status_code == 200, done.text

    profile = client.get("/api/v1/profiles/charity").json()
    assert profile["confirmed_by_currency"] == {"EUR": 3000} and profile["domain"] == "charity.test"
    assert "all confirmed by charity.test" in client.get("/badge/charity.svg").text
    assert verify(["--url", "https://testserver"], client=client) == 0

    # Sign in later with the passkey alone.
    client.cookies.clear()
    r = client.post("/api/recipient/login/options").json()
    ok = client.post(
        "/api/recipient/login/verify",
        json={
            "challenge_id": r["challenge_id"],
            "credential": auth.get(b64d(r["options"]["challenge"])),
        },
    )
    assert ok.status_code == 200 and "Everything is confirmed" in client.get("/recipient").text


def test_publish_with_wrong_domain_file(client, monkeypatch):
    sign_in_as(client)
    auth = SoftAuthenticator("proofs.test", SITE)
    r = client.post("/api/recipient/register/options").json()
    fin = client.post(
        "/api/recipient/register/verify",
        json={
            "challenge_id": r["challenge_id"],
            "credential": auth.create(b64d(r["options"]["challenge"])),
        },
    ).json()
    monkeypatch.setattr(
        domainproof, "fetch", lambda d: {"vpp": 1, "log": ORIGIN, "profile": "prof_c", "keys": []}
    )
    r = client.post(
        "/api/recipient/publish",
        json={"credential_id": fin["credential_id"], "domain": "charity.test"},
    )
    assert r.status_code == 400 and "must include" in r.json()["error"]


def test_csp_allows_only_self_scripts(client):
    sign_in_as(client)
    r = client.get("/recipient")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert '<script type="module" src="/static/passkey.js">' in r.text
    assert client.get("/static/passkey.js").status_code == 200
