import json

import pytest
from sqlalchemy.orm import Session
from vpp import domainproof, passkeys
from vpp.config import get_settings
from vpp.db.models import Profile
from vpp.ledger.entries import Money, Payment, StripePaymentEvidence
from vpp.ledger.store import append, entries_after, to_entry
from vpp.ledger.wire import to_wire
from vpp.testing.ledger import ORIGIN
from vpp.testing.softauthn import SoftAuthenticator
from vpp_verify.core import VerificationError, verify_chain

SITE = "https://proofs.test"


@pytest.fixture
def site(monkeypatch):
    monkeypatch.setenv("VPP_RP_ID", "proofs.test")
    monkeypatch.setenv("VPP_PUBLIC_BASE_URL", SITE)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def world(ledger, key, site):
    s = Session(ledger, expire_on_commit=False)
    profile = Profile(id="prof_c", slug="charity", display_name="Good Charity")
    s.add(profile)
    s.flush()
    for n in (1, 2):
        append(
            s,
            Payment(
                recipient="prof_c",
                amount=Money(value=1000 * n, currency="EUR"),
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
    yield s, profile
    s.close()


def register(s, profile, auth):
    cid, opts = passkeys.registration_options(s, profile)
    challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
    return passkeys.finish_registration(s, profile, cid, auth.create(challenge))


def proof_for(cred, profile_id="prof_c"):
    return lambda domain: domainproof.well_known_document(ORIGIN, profile_id, [cred.fingerprint])


def chain(s):
    return [to_wire(to_entry(r)) for r in entries_after(s, 0, 1000)]


def test_register_publish_confirm_and_verify_independently(world, key):
    s, profile = world
    auth = SoftAuthenticator("proofs.test", SITE)
    cred = register(s, profile, auth)
    assert cred.key_seq is None  # pending until the domain lists it
    passkeys.publish_key(s, key, profile, cred, "Charity.Test", fetch=proof_for(cred))
    assert profile.domain == "charity.test" and cred.key_seq == 4

    cid, opts = passkeys.confirmation_options(s, profile, [2, 3])
    challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
    entry = passkeys.finish_confirmation(s, key, profile, cid, auth.get(challenge))
    s.commit()

    state = verify_chain(chain(s))
    assert state.confirmed == {2: [entry.seq], 3: [entry.seq]}
    assert state.recipient_keys["prof_c"][cred.credential_id]["domain"] == "charity.test"


def test_publish_requires_domain_listing(world, key):
    s, profile = world
    cred = register(s, profile, SoftAuthenticator("proofs.test", SITE))
    wrong = lambda d: domainproof.well_known_document(ORIGIN, "prof_c", ["k1:" + "0" * 64])  # noqa: E731
    with pytest.raises(domainproof.DomainProofError, match="must include"):
        passkeys.publish_key(s, key, profile, cred, "charity.test", fetch=wrong)
    with pytest.raises(domainproof.DomainProofError, match="profile"):
        passkeys.publish_key(s, key, profile, cred, "charity.test", fetch=proof_for(cred, "prof_x"))


def test_confirm_requires_published_key(world):
    s, profile = world
    register(s, profile, SoftAuthenticator("proofs.test", SITE))
    with pytest.raises(passkeys.PasskeyError, match="publish"):
        passkeys.confirmation_options(s, profile, [2])


def test_assertion_from_wrong_origin_rejected(world, key):
    s, profile = world
    auth = SoftAuthenticator("proofs.test", SITE)
    cred = register(s, profile, auth)
    passkeys.publish_key(s, key, profile, cred, "charity.test", fetch=proof_for(cred))
    cid, opts = passkeys.confirmation_options(s, profile, [2])
    challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
    with pytest.raises(passkeys.PasskeyError):
        passkeys.finish_confirmation(
            s, key, profile, cid, auth.get(challenge, origin="https://evil.test")
        )


def test_assertion_without_user_verification_rejected(world, key):
    s, profile = world
    auth = SoftAuthenticator("proofs.test", SITE)
    cred = register(s, profile, auth)
    passkeys.publish_key(s, key, profile, cred, "charity.test", fetch=proof_for(cred))
    cid, opts = passkeys.confirmation_options(s, profile, [2])
    challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
    with pytest.raises(passkeys.PasskeyError):
        passkeys.finish_confirmation(s, key, profile, cid, auth.get(challenge, flags=0x01))


def test_challenge_is_single_use(world, key):
    s, profile = world
    auth = SoftAuthenticator("proofs.test", SITE)
    cid, opts = passkeys.login_options(s)
    challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
    cred = register(s, profile, auth)
    assert passkeys.finish_login(s, cid, auth.get(challenge)).id == "prof_c"
    with pytest.raises(passkeys.PasskeyError, match="expired"):
        passkeys.finish_login(s, cid, auth.get(challenge))
    assert cred


def test_operator_forged_confirmation_fails_verifier(world, key):
    """The operator can't fake a recipient's confirmation: it lacks the passkey."""
    s, profile = world
    auth = SoftAuthenticator("proofs.test", SITE)
    cred = register(s, profile, auth)
    passkeys.publish_key(s, key, profile, cred, "charity.test", fetch=proof_for(cred))
    from vpp.ledger.entries import Confirmation

    forged_with = SoftAuthenticator("proofs.test", SITE, credential_id=auth.credential_id)
    from vpp.db.models import LedgerEntry
    from vpp.ledger.signing import confirmation_challenge

    challenge = confirmation_challenge(ORIGIN, [s.get(LedgerEntry, 2).hash])
    a = forged_with.get(challenge)["response"]
    append(
        s,
        Confirmation(
            recipient="prof_c",
            ref_seqs=[2],
            credential_id=cred.credential_id,
            authenticator_data=a["authenticatorData"],
            client_data_json=a["clientDataJSON"],
            signature=a["signature"],
        ),
        key,
    )
    s.commit()
    with pytest.raises(VerificationError, match="assertion invalid"):
        verify_chain(chain(s))


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1"])
def test_domain_fetch_blocks_private_addresses(addr):
    with pytest.raises(domainproof.DomainProofError, match="non-public"):
        domainproof.fetch("example.org", resolver=lambda h: [addr])


@pytest.mark.parametrize(
    "bad", ["localhost", "1.2.3.4", "example.org:8080", "http://example.org", "a b.org", ""]
)
def test_domain_must_be_plain_hostname(bad):
    with pytest.raises(domainproof.DomainProofError):
        domainproof.normalize_domain(bad)


def test_domain_fetch_does_not_follow_redirects():
    import httpx

    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with pytest.raises(domainproof.DomainProofError, match="302"):
        domainproof.fetch("example.org", resolver=lambda h: ["93.184.215.14"], client=client)
