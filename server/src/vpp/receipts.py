"""Payer receipts (LEDGER_SPEC §10): the entry, a (preferably witnessed) checkpoint that
includes it, and the inclusion proof. Held by the payer, checkable without trusting us."""

import base64

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db.models import Checkpoint, Cosignature, LedgerEntry
from .ledger.store import inclusion_proof, key_state, latest_checkpoint, to_entry
from .ledger.wire import to_wire
from .witnessing import cosigned_note


def build_receipt(session: Session, seq: int) -> dict | None:
    entry = session.get(LedgerEntry, seq)
    if entry is None:
        return None
    # The best checkpoint covering the entry: most cosignatures, then the earliest.
    best = session.execute(
        select(Cosignature.size, func.count().label("n"))
        .where(Cosignature.size >= seq)
        .group_by(Cosignature.size)
        .order_by(func.count().desc(), Cosignature.size)
        .limit(1)
    ).first()
    size = best.size if best else latest_checkpoint(session).size
    cp = session.get(Checkpoint, size)
    return {
        "vpp_receipt": 1,
        "origin": key_state(session).origin,
        "entry": to_wire(to_entry(entry), convenience=False),
        "checkpoint": cosigned_note(session, cp.size),
        "inclusion_proof": [
            base64.b64encode(h).decode() for h in inclusion_proof(session, seq, cp.size)
        ],
        "witness_cosignatures": best.n if best else 0,
    }


def seq_for_session(session: Session, checkout_session: str) -> int | None:
    return session.scalar(
        select(LedgerEntry.seq).where(
            LedgerEntry.type == "payment", LedgerEntry.checkout_session == checkout_session
        )
    )
