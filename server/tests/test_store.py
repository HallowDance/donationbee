from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from vpp.db.models import Checkpoint
from vpp.ledger import LedgerKey
from vpp.ledger.entries import (
    KeyRotation,
    Money,
    Payment,
    Reversal,
    RootRotation,
    StripePaymentEvidence,
    StripeReversalEvidence,
)
from vpp.ledger.signing import root_rotation_statement, rotation_statement
from vpp.ledger.store import (
    LedgerError,
    append,
    consistency_proof,
    entries_after,
    inclusion_proof,
    latest_checkpoint,
    to_entry,
)
from vpp.ledger.wire import to_wire
from vpp.testing.ledger import ORIGIN, ROOTS, genesis, root_sigs
from vpp_verify import merkle as vm
from vpp_verify.core import VerificationError, checkpoint_key, verify_chain
from vpp_verify.note import Checkpoint as CP
from vpp_verify.note import Note, Verifier, verify_note_signature


def payment(n: int, value: int = 1000) -> Payment:
    return Payment(
        recipient="prof_x",
        amount=Money(value=value, currency="EUR"),
        occurred_at="2026-11-09T12:00:00Z",
        evidence=StripePaymentEvidence(
            account="acct_1", payment_intent=f"pi_{n}", checkout_session=f"cs_{n}", livemode=False
        ),
    )


def refund(ref_seq: int, n: int, value: int) -> Reversal:
    return Reversal(
        ref_seq=ref_seq,
        reason="refund",
        amount=Money(value=value, currency="EUR"),
        evidence=StripeReversalEvidence(account="acct_1", object=f"re_{n}"),
    )


def rotation(old: LedgerKey, new: LedgerKey, signers=ROOTS[:2], reason="scheduled"):
    stmt = rotation_statement(ORIGIN, old.public_key, new.public_key)
    return KeyRotation(
        from_online_key=old.public_key.hex(),
        new_online_key=new.public_key.hex(),
        reason=reason,
        root_sigs=root_sigs(stmt, signers),
    )


def all_wire(engine) -> list[dict]:
    with Session(engine) as s:
        return [to_wire(to_entry(r)) for r in entries_after(s, 0, 10_000)]


def test_appended_chain_passes_independent_verifier(ledger, key):
    with Session(ledger) as s:
        append(s, payment(1), key)
        append(s, refund(2, 1, 400), key)
        s.commit()
    assert verify_chain(all_wire(ledger)).seq == 3


def test_requires_genesis(engine, key):
    with Session(engine) as s, pytest.raises(LedgerError):
        append(s, payment(1), key)


def test_genesis_requires_root_threshold(engine, key):
    from vpp.ledger.signing import genesis_statement
    from vpp.ledger.store import init_ledger

    with Session(engine) as s, pytest.raises(LedgerError, match="threshold"):
        init_ledger(
            s,
            key,
            ORIGIN,
            [r.public_key.hex() for r in ROOTS],
            2,
            root_sigs(genesis_statement(ORIGIN, key.public_key), ROOTS[:1]),
        )


def test_rejects_foreign_key(ledger):
    with Session(ledger) as s, pytest.raises(LedgerError):
        append(s, payment(1), LedgerKey.generate())


def test_scheduled_rotation(ledger, key):
    new = LedgerKey.generate()
    with Session(ledger) as s:
        append(s, rotation(key, new), new)
        with pytest.raises(LedgerError):
            append(s, payment(1), key)
        append(s, payment(1), new)
        s.commit()
    assert verify_chain(all_wire(ledger)).seq == 3


def test_stolen_online_key_cannot_rotate(ledger, key):
    """A thief with the online key but no root keys can't take over the ledger."""
    mine = LedgerKey.generate()
    with Session(ledger) as s:
        with pytest.raises(LedgerError, match="threshold"):
            append(s, rotation(key, mine, signers=[]), mine)
        with pytest.raises(LedgerError, match="threshold"):
            append(s, rotation(key, mine, signers=ROOTS[:1]), mine)


def test_lost_online_key_can_be_replaced(ledger, key):
    """Root keys alone (2 of 3) replace a lost online key; the old key never signs."""
    new = LedgerKey.generate()
    with Session(ledger) as s:
        append(s, rotation(key, new, signers=ROOTS[1:], reason="lost"), new)
        s.commit()
    assert verify_chain(all_wire(ledger)).online_key == new.public_key


def test_online_key_reuse_rejected(ledger, key):
    new = LedgerKey.generate()
    with Session(ledger) as s:
        append(s, rotation(key, new), new)
        with pytest.raises(LedgerError, match="reused"):
            append(s, rotation(new, key), key)


def test_root_rotation(ledger, key):
    new_roots = [LedgerKey.generate() for _ in range(3)]
    new_hex = [r.public_key.hex() for r in new_roots]
    old_hex = [r.public_key.hex() for r in ROOTS]
    stmt = root_rotation_statement(ORIGIN, old_hex, 2, new_hex, 2)
    with Session(ledger) as s:
        append(
            s,
            RootRotation(new_root_keys=new_hex, new_root_threshold=2, root_sigs=root_sigs(stmt)),
            key,
        )
        # Old roots can no longer authorize rotations.
        nxt = LedgerKey.generate()
        with pytest.raises(LedgerError):
            append(s, rotation(key, nxt), nxt)
        append(s, rotation(key, nxt, signers=new_roots[:2]), nxt)
        s.commit()
    assert verify_chain(all_wire(ledger)).root_keys == new_hex


def test_reversals_cannot_exceed_payment(ledger, key):
    with Session(ledger) as s:
        append(s, payment(1, 1000), key)
        append(s, refund(2, 1, 600), key)
        with pytest.raises(LedgerError):
            append(s, refund(2, 2, 500), key)


def test_same_stripe_object_cannot_be_recorded_twice(ledger, key):
    with Session(ledger) as s:
        append(s, payment(1), key)
        s.commit()
        with pytest.raises(DBAPIError):
            append(s, payment(1), key)


def test_checkpoints_and_proofs_verify_independently(ledger, key):
    with Session(ledger) as s:
        for i in range(12):
            append(s, payment(i), key)
        s.commit()
        state = verify_chain(all_wire(ledger))
        for cp_row in s.query(Checkpoint).order_by(Checkpoint.size):
            note = Note.parse(cp_row.note)
            v = Verifier(ORIGIN, 0x01, checkpoint_key(state, cp_row.size))
            assert verify_note_signature(note, v)
            assert CP.parse(note.text).root == state.root_at(cp_row.size)
        latest = latest_checkpoint(s)
        assert latest.size == 13
        for seq in (1, 7, 13):
            proof = inclusion_proof(s, seq, 13)
            assert vm.verify_inclusion(state.leaves[seq - 1], seq - 1, 13, proof, latest.root)
        for old in (1, 5, 8, 13):
            proof = consistency_proof(s, old, 13)
            assert vm.verify_consistency(old, 13, state.root_at(old), latest.root, proof)


@pytest.mark.parametrize("table", ["ledger_entries", "merkle_nodes", "checkpoints"])
@pytest.mark.parametrize(
    "op", ["UPDATE {t} SET {c} = {c}", "DELETE FROM {t}", "TRUNCATE {t} CASCADE"]
)
def test_database_blocks_mutation(ledger, table, op):
    col = {"ledger_entries": "type", "merkle_nodes": "hash", "checkpoints": "note"}[table]
    with Session(ledger) as s, pytest.raises(DBAPIError, match="append-only"):
        s.execute(text(op.format(t=table, c=col)))


def test_database_rejects_unlinked_insert(ledger):
    with Session(ledger) as s, pytest.raises(DBAPIError, match="does not extend"):
        s.execute(
            text(
                "INSERT INTO ledger_entries (seq, prev_hash, envelope, hash, sig, type, key_id,"
                " created_at) VALUES (2, :z, '', :h, '', 'payment', 'k', now())"
            ),
            {"z": bytes(32), "h": bytes([1]) * 32},
        )


def test_concurrent_appends_form_one_chain(ledger, key):
    def worker(n: int) -> None:
        with Session(ledger) as s:
            append(s, payment(n), key)
            s.commit()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(40)))

    state = verify_chain(all_wire(ledger))
    assert state.seq == 41
    with Session(ledger) as s:
        assert latest_checkpoint(s).root == state.root


def test_tamper_detected_by_verifier(ledger, key):
    with Session(ledger) as s:
        append(s, payment(1, 1000), key)
        append(s, payment(2, 2000), key)
        s.commit()
        # Simulate a malicious superuser: bypass the trigger and edit stored bytes.
        s.execute(
            text("ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_update_delete")
        )
        s.execute(
            text(
                "UPDATE ledger_entries SET envelope = convert_to(replace("
                "convert_from(envelope, 'UTF8'), '1000', '9000'), 'UTF8') WHERE seq = 2"
            )
        )
        s.commit()

    with pytest.raises(VerificationError) as e:
        verify_chain(all_wire(ledger))
    assert e.value.seq == 2


def test_genesis_helper_is_used(engine, key):
    with Session(engine) as s:
        assert genesis(s, key).seq == 1
