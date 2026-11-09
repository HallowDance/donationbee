"""Regenerate testvectors/ from fixed seeds. Run: uv run python server/scripts/gen_vectors.py

The output is committed; changing it means the format changed and LEDGER_SPEC must change too.
(ECDSA passkey signatures are randomized, so regenerating changes those bytes; that's fine.)
"""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vpp.ledger import GENESIS_PREV, LedgerKey, build_entry, merkle
from vpp.ledger.chain import entry_hash
from vpp.ledger.entries import (
    Confirmation,
    Correction,
    Genesis,
    KeyRotation,
    Money,
    Payment,
    RecipientKey,
    Reversal,
    RootSig,
    StripePaymentEvidence,
    StripeReversalEvidence,
)
from vpp.ledger.note import checkpoint_text, sign_note
from vpp.ledger.signing import confirmation_challenge, genesis_statement, rotation_statement
from vpp.ledger.wire import to_wire
from vpp.pii import commit
from vpp.testing.softauthn import SoftAuthenticator, b64url

OUT = Path(__file__).resolve().parents[2] / "testvectors"
T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
ORIGIN = "proofs.test/log"

online_a = LedgerKey.from_seed(bytes(range(32)))
online_b = LedgerKey.from_seed(bytes(range(32, 64)))
attacker = LedgerKey.from_seed(bytes(range(64, 96)))
roots = [LedgerKey.from_seed(bytes([0xA0 + i]) * 32) for i in range(3)]
ROOT_KEYS = [r.public_key.hex() for r in roots]
passkey = SoftAuthenticator.from_secret("charity.test", "https://proofs.test", 1234567)
payer_commitment, payer_salt = commit("Ada Lovelace", salt=bytes([7]) * 32)


def root_sigs(stmt: bytes, keys) -> list[RootSig]:
    return [RootSig(key=k.public_key.hex(), sig=k.sign(stmt).hex()) for k in keys]


def build(steps):
    """steps: list of (signer, body or callable(prev_entries) -> body)."""
    out, prev = [], GENESIS_PREV
    for i, (key, body) in enumerate(steps, start=1):
        if callable(body):
            body = body(out)
        e = build_entry(
            seq=i, prev_hash=prev, body=body, key=key, created_at=T0 + timedelta(minutes=i)
        )
        out.append(e)
        prev = e.hash
    return out


def confirm(refs, *, challenge_over=None):
    def make(prev):
        hashes = [prev[r - 1].hash for r in (challenge_over or refs)]
        a = passkey.get(confirmation_challenge(ORIGIN, hashes))["response"]
        return Confirmation(
            recipient="prof_charity",
            ref_seqs=refs,
            credential_id=b64url(passkey.credential_id),
            authenticator_data=a["authenticatorData"],
            client_data_json=a["clientDataJSON"],
            signature=a["signature"],
        )

    return make


genesis = Genesis(
    origin=ORIGIN,
    online_key=online_a.public_key.hex(),
    root_keys=ROOT_KEYS,
    root_threshold=2,
    root_sigs=root_sigs(genesis_statement(ORIGIN, online_a.public_key), roots[:2]),
)
recipient_key = RecipientKey(
    recipient="prof_charity",
    credential_id=b64url(passkey.credential_id),
    public_key_spki=b64url(passkey.spki),
    alg=-7,
    rp_id="charity.test",
    origin="https://proofs.test",
    domain="charity.test",
    fingerprint="k1:" + __import__("hashlib").sha256(passkey.spki).hexdigest(),
)
payment = Payment(
    recipient="prof_charity",
    amount=Money(value=500000, currency="EUR"),
    occurred_at="2026-11-09T11:59:41Z",
    payer=payer_commitment,
    evidence=StripePaymentEvidence(
        account="acct_1TEST",
        payment_intent="pi_1TEST",
        checkout_session="cs_test_1",
        livemode=False,
    ),
)
refund = Reversal(
    ref_seq=3,
    reason="refund",
    amount=Money(value=100000, currency="EUR"),
    evidence=StripeReversalEvidence(account="acct_1TEST", object="re_1TEST"),
)
rotation = KeyRotation(
    from_online_key=online_a.public_key.hex(),
    new_online_key=online_b.public_key.hex(),
    reason="scheduled",
    root_sigs=root_sigs(
        rotation_statement(ORIGIN, online_a.public_key, online_b.public_key), roots[1:]
    ),
)
correction = Correction(ref_seq=4, reason_code="duplicate")

steps = [
    (online_a, genesis),
    (online_a, recipient_key),
    (online_a, payment),
    (online_a, refund),
    (online_a, confirm([3])),
    (online_b, rotation),
    (online_b, correction),
]
entries = build(steps)


def checkpoint(es):
    store = merkle.MemoryStore()
    for i, e in enumerate(es):
        merkle.append_leaf(store, i, e.hash)
    n = len(es)
    signer = online_b if n >= 6 else online_a
    root = merkle.root(store, n)
    note = sign_note(checkpoint_text(ORIGIN, n, root), ORIGIN, signer.public_key, signer.sign)
    return {"size": n, "root": root.hex(), "note": note}


def wire(es):
    return [to_wire(e, convenience=False) for e in es]


valid = {
    "description": "Valid 7-entry chain: genesis (2-of-3 roots), passkey, payment, refund, "
    "recipient confirmation, root-authorized rotation, correction under the new key.",
    "origin": ORIGIN,
    "genesis_hash": entries[0].hash.hex(),
    "pii": {"commitment": payer_commitment, "value": "Ada Lovelace", "salt": payer_salt.hex()},
    "entries": wire(entries),
    "checkpoints": [checkpoint(entries[:5]), checkpoint(entries)],
}


def resign(e, envelope, key):
    h = entry_hash(e.prev_hash, envelope)
    return to_wire(replace(e, envelope=envelope, hash=h, sig=key.sign(h)), convenience=False)


altered = entries[2].envelope.replace(b"500000", b"900000")
lone_root = rotation.model_copy(update={"root_sigs": rotation.root_sigs[:1]})
stolen = KeyRotation(
    from_online_key=online_a.public_key.hex(),
    new_online_key=attacker.public_key.hex(),
    reason="compromise",
    root_sigs=[],
)

invalid = [
    {
        "name": "payload_byte_flip",
        "fail_seq": 3,
        "description": "Payment amount changed, hash left.",
        "entries": wire(entries[:2])
        + [
            {
                **wire(entries)[2],
                "envelope": to_wire(replace(entries[2], envelope=altered))["envelope"],
            }
        ]
        + wire(entries[3:]),
    },
    {
        "name": "resigned_but_unlinked",
        "fail_seq": 4,
        "description": "Amount changed and re-signed.",
        "entries": wire(entries[:2]) + [resign(entries[2], altered, online_a)] + wire(entries[3:]),
    },
    {
        "name": "deleted_entry",
        "fail_seq": 5,
        "description": "Refund entry removed.",
        "entries": wire(entries[:3]) + wire(entries[4:]),
    },
    {
        "name": "old_key_after_rotation",
        "fail_seq": 7,
        "description": "Entry 7 signed by retired key.",
        "entries": wire(entries[:6]) + [resign(entries[6], entries[6].envelope, online_a)],
    },
    {
        "name": "non_canonical",
        "fail_seq": 3,
        "description": "Same JSON value, different bytes.",
        "entries": wire(entries[:2])
        + [
            resign(
                entries[2], json.dumps(json.loads(entries[2].envelope), indent=1).encode(), online_a
            )
        ]
        + wire(entries[3:]),
    },
    {
        "name": "rotation_below_threshold",
        "fail_seq": 6,
        "description": "Only 1 of 2 root signatures.",
        "entries": wire(build(steps[:5] + [(online_b, lone_root)])),
    },
    {
        "name": "stolen_key_rotation",
        "fail_seq": 6,
        "description": "Attacker rotates to own key.",
        "entries": wire(build(steps[:5] + [(attacker, stolen)])),
    },
    {
        "name": "confirmation_wrong_payment",
        "fail_seq": 5,
        "description": "Passkey signed over a different entry than it claims to confirm.",
        "entries": wire(build(steps[:4] + [(online_a, confirm([3], challenge_over=[4]))])),
    },
]

OUT.mkdir(exist_ok=True)
(OUT / "chain_v1_valid.json").write_text(json.dumps(valid, indent=2) + "\n")
(OUT / "chain_v1_invalid.json").write_text(json.dumps(invalid, indent=2) + "\n")
print(f"wrote {len(entries)} entries, {len(invalid)} negative cases to {OUT}")
