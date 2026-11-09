"""Real-browser passkey flow: Chromium + its virtual WebAuthn authenticator running passkey.js
against the live app (uvicorn). Skips if Playwright or Chromium is unavailable."""

import shutil
import socket
import threading
import time

import pytest
from sqlalchemy.orm import Session, sessionmaker

playwright = pytest.importorskip("playwright.sync_api")
CHROMIUM = shutil.which("chromium") or shutil.which("google-chrome")
pytestmark = pytest.mark.skipif(CHROMIUM is None, reason="no Chromium on PATH")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_app(ledger, key, monkeypatch):
    import uvicorn
    from vpp import domainproof
    from vpp.config import get_settings
    from vpp.db import get_session
    from vpp.db.models import Profile, RecipientCredential
    from vpp.ledger.entries import Money, Payment, StripePaymentEvidence
    from vpp.ledger.store import append
    from vpp.testing.ledger import ORIGIN

    port = free_port()
    base = f"http://localhost:{port}"  # localhost is a secure context, so WebAuthn works
    monkeypatch.setenv("VPP_RP_ID", "localhost")
    monkeypatch.setenv("VPP_PUBLIC_BASE_URL", base)
    get_settings.cache_clear()

    factory = sessionmaker(ledger, expire_on_commit=False)
    with factory() as s:
        s.add(Profile(id="prof_c", slug="charity", display_name="Good Charity"))
        s.flush()
        for n in (1, 2):
            append(
                s,
                Payment(
                    recipient="prof_c",
                    amount=Money(value=2500 * n, currency="EUR"),
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

    # The recipient's domain lists every fingerprint it registered (as a real one would).
    def fetch(domain):
        with factory() as s:
            fps = [c.fingerprint for c in s.query(RecipientCredential).all()]
        return domainproof.well_known_document(ORIGIN, "prof_c", fps)

    monkeypatch.setattr(domainproof, "fetch", fetch)
    from vpp.app import app
    from vpp.web import recipient

    monkeypatch.setattr(recipient, "get_ledger_key", lambda: key)

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield base, factory
    server.should_exit = True
    t.join(5)
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_passkey_register_publish_confirm_login_in_chromium(live_app):
    from vpp.web.recipient import COOKIE, _sign
    from vpp_verify.cli import main as verify

    base, factory = live_app
    problems: list[str] = []
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM, headless=True)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.on("console", lambda m: m.type in ("error", "warning") and problems.append(m.text))
        page.on("pageerror", lambda e: problems.append(str(e)))
        page.on("response", lambda r: r.status >= 400 and problems.append(f"{r.status} {r.url}"))

        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )

        # A session as the onboarding return link would create it.
        exp = int(time.time()) + 600
        ctx.add_cookies(
            [{"name": COOKIE, "value": f"prof_c.{exp}.{_sign('prof_c', exp)}", "url": base}]
        )

        page.goto(f"{base}/recipient")
        assert "No passkeys yet" in page.content()

        with page.expect_navigation():
            page.click("text=Add a passkey")
        assert "pending domain proof" in page.content()
        assert '"log": "proofs.test/log"' in page.inner_text("pre")

        page.fill("input[id^=domain-]", "charity.example")
        with page.expect_navigation():
            page.click("text=Check and publish")
        assert "published" in page.content()

        page.click("text=Confirm selected with passkey")
        page.wait_for_selector("#status.ok", timeout=10_000)
        assert "Confirmed in ledger entry" in page.inner_text("#status")

        # Sign in again with nothing but the passkey (discoverable credential).
        ctx.clear_cookies()
        page.goto(f"{base}/recipient/login")
        with page.expect_navigation(url=f"{base}/recipient"):
            page.click("text=Sign in with a passkey")
        page.wait_for_load_state()
        assert "Everything is confirmed" in page.content()

        page.goto(f"{base}/p/charity")
        assert "identity: charity.example" in page.content()
        assert "75.00 EUR confirmed by the recipient" in page.content()
        browser.close()

    assert problems == [], problems  # no JS errors, no CSP violations
    import httpx

    with httpx.Client() as c:
        assert verify(["--url", base], client=c) == 0
    with Session(factory.kw["bind"]) as s:
        from vpp.db.models import LedgerEntry

        types = [e.type for e in s.query(LedgerEntry).order_by(LedgerEntry.seq)]
    assert types == ["genesis", "payment", "payment", "recipient_key", "confirmation"]
