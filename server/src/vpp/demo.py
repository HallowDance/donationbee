"""Seed a demo ledger for a public beta. Demo only: example names, a software passkey, and root
keys that are generated, used for genesis, and thrown away (so the demo ledger can never rotate
its key; that's fine for a demo and impossible to abuse later)."""

import json

from sqlalchemy.orm import Session

from . import domainproof, passkeys, pii
from .config import get_settings
from .db.models import Profile
from .ledger import LedgerKey
from .ledger.entries import (
    Money,
    Payment,
    Reversal,
    RootSig,
    StripePaymentEvidence,
    StripeReversalEvidence,
)
from .ledger.signing import Signer, genesis_statement
from .ledger.store import append, head, init_ledger
from .testing.softauthn import SoftAuthenticator

HIVES = [
    (
        "prof_demo_meadow",
        "open-meadow",
        "Open Meadow Food Bank",
        "openmeadow.example",
        [
            ("Ada Lovelace", 5000, "For the winter drive", True),
            ("Grace Hopper", 2500, None, True),
            (None, 12000, None, False),
            ("Indie Hacker Co.", 25000, "1% of October revenue", True),
            ("Radia Perlman", 1500, None, False),
        ],
    ),
    (
        "prof_demo_giveaway",
        "lucky-draw",
        "Lucky Draw Winner Fund",
        None,
        [
            ("Hackathon Crew", 10000, "Giveaway prize, round 3", False),
            ("Shipfast Weekly", 7500, None, False),
        ],
    ),
]


def seed(session: Session, signer: Signer) -> dict:
    if head(session) is not None:
        raise RuntimeError("ledger is not empty; demo-seed only runs on a fresh database")
    s = get_settings()
    roots = [LedgerKey.generate() for _ in range(3)]
    stmt = genesis_statement(s.origin, signer.public_key)
    sigs = [RootSig(key=r.public_key.hex(), sig=r.sign(stmt).hex()) for r in roots[:2]]
    g = init_ledger(session, signer, s.origin, [r.public_key.hex() for r in roots], 2, sigs)
    del roots  # discarded on purpose

    n = 0
    to_confirm: dict[str, list[int]] = {}
    for pid, slug, name, _domain, payments in HIVES:
        session.add(Profile(id=pid, slug=slug, display_name=name, card_payments_status="none"))
        session.flush()
        for payer, amount, note, confirm in payments:
            n += 1
            e = append(
                session,
                Payment(
                    recipient=pid,
                    amount=Money(value=amount, currency="EUR"),
                    occurred_at=f"2026-11-{n:02d}T1{n % 10}:20:00Z",
                    payer=pii.store_commitment(session, payer) if payer else None,
                    note=pii.store_commitment(session, note) if note else None,
                    evidence=StripePaymentEvidence(
                        account=f"acct_demo{pid[-6:]}",
                        payment_intent=f"pi_demo{n}",
                        checkout_session=f"cs_test_demo{n}",
                        livemode=False,
                    ),
                ),
                signer,
            )
            if confirm:
                to_confirm.setdefault(pid, []).append(e.seq)
            if amount == 12000:
                append(
                    session,
                    Reversal(
                        ref_seq=e.seq,
                        reason="refund",
                        amount=Money(value=2000, currency="EUR"),
                        evidence=StripeReversalEvidence(
                            account=f"acct_demo{pid[-6:]}", object=f"re_demo{n}"
                        ),
                    ),
                    signer,
                )

    # The demo recipient signs with a software passkey, behind a stand-in domain proof.
    for pid, _slug, _name, domain, _ in HIVES:
        if not domain or pid not in to_confirm:
            continue
        p = session.get(Profile, pid)
        auth = SoftAuthenticator(s.rp_id, s.public_base_url.rstrip("/"))
        cid, opts = passkeys.registration_options(session, p)
        challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
        cred = passkeys.finish_registration(session, p, cid, auth.create(challenge))
        passkeys.publish_key(
            session,
            signer,
            p,
            cred,
            domain,
            fetch=lambda d, c=cred, pid=pid: domainproof.well_known_document(
                s.origin, pid, [c.fingerprint]
            ),
        )
        cid, opts = passkeys.confirmation_options(session, p, to_confirm[pid])
        challenge = passkeys._b64url_decode(json.loads(opts)["challenge"])
        passkeys.finish_confirmation(session, signer, p, cid, auth.get(challenge))
    session.commit()
    return {"genesis": g.hash.hex(), "entries": head(session).seq}
