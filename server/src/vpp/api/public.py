"""Public JSON API. Everything the verifier needs; nothing here reveals erased personal data.

Note: the verifier never trusts this server for anchors or witness state. It checks witness
cosignatures itself and reads anchors from the independently hosted anchors repo.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_session
from ..db.models import Anchor, LedgerEntry, Profile
from ..ledger.store import consistency_proof, entries_after, head, inclusion_proof, to_entry
from ..ledger.wire import to_wire
from ..queries import key_history, profile_totals
from ..receipts import build_receipt, seq_for_session
from ..witnessing import cosigned_note

router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_session)]


def _b64(hashes: list[bytes]) -> list[str]:
    return [base64.b64encode(h).decode() for h in hashes]


@router.get("/entries")
def list_entries(db: DB, after: int = 0, limit: Annotated[int, Query(ge=1, le=1000)] = 500) -> dict:
    rows = entries_after(db, after, limit)
    return {
        "entries": [to_wire(to_entry(r)) for r in rows],
        "next_after": rows[-1].seq if len(rows) == limit else None,
    }


@router.get("/entries/{seq}")
def get_entry(db: DB, seq: int) -> dict:
    row = db.get(LedgerEntry, seq)
    if row is None:
        raise HTTPException(404)
    return to_wire(to_entry(row))


@router.get("/head")
def get_head(db: DB) -> dict:
    row = head(db)
    return {"seq": row.seq, "hash": row.hash.hex()} if row else {"seq": 0, "hash": None}


@router.get("/checkpoint", response_class=PlainTextResponse)
def get_checkpoint(db: DB) -> str:
    """Latest C2SP checkpoint with every witness cosignature we hold."""
    note = cosigned_note(db)
    if note is None:
        raise HTTPException(404)
    return note


@router.get("/checkpoint/{size}", response_class=PlainTextResponse)
def get_checkpoint_at(db: DB, size: int) -> str:
    note = cosigned_note(db, size)
    if note is None:
        raise HTTPException(404)
    return note


@router.get("/proof/inclusion")
def proof_inclusion(db: DB, seq: int, size: int) -> dict:
    if not 1 <= seq <= size or head(db) is None or size > head(db).seq:
        raise HTTPException(400, "need 1 <= seq <= size <= current size")
    return {"seq": seq, "size": size, "proof": _b64(inclusion_proof(db, seq, size))}


@router.get("/proof/consistency")
def proof_consistency(db: DB, old: int, new: int) -> dict:
    if not 0 <= old <= new or head(db) is None or new > head(db).seq:
        raise HTTPException(400, "need 0 <= old <= new <= current size")
    return {"old": old, "new": new, "proof": _b64(consistency_proof(db, old, new))}


@router.get("/receipts/{seq}")
def get_receipt(db: DB, seq: int) -> Response:
    receipt = build_receipt(db, seq)
    if receipt is None:
        raise HTTPException(404)
    import json

    return Response(
        json.dumps(receipt, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="vpp-receipt-{seq}.json"'},
    )


@router.get("/receipts/by-session/{checkout_session}")
def receipt_for_session(db: DB, checkout_session: str) -> dict:
    seq = seq_for_session(db, checkout_session)
    if seq is None:
        raise HTTPException(404, "not recorded yet")
    return {"seq": seq}


@router.get("/keys")
def get_keys(db: DB) -> dict:
    return key_history(db)


@router.get("/profiles/{slug}")
def get_profile(db: DB, slug: str) -> dict:
    profile = db.scalars(select(Profile).where(Profile.slug == slug)).first()
    if profile is None:
        raise HTTPException(404)
    totals = profile_totals(db, profile.id)
    return {
        "id": profile.id,
        "slug": profile.slug,
        "display_name": profile.display_name,
        "domain": profile.domain,
        "net_by_currency": totals.net_by_currency,
        "confirmed_by_currency": totals.confirmed_by_currency,
        "payment_count": totals.count,
        "payments": [
            {
                "seq": v.entry.seq,
                "amount": v.entry.amount_value,
                "currency": v.entry.currency,
                "reversed": v.reversed,
                "voided": v.voided,
                "confirmed_by": v.confirmed_by,
            }
            for v in totals.payments
        ],
    }


@router.get("/anchors")
def list_anchors(db: DB) -> dict:
    """Informational. Verifiers should read anchors from the public anchors repo instead."""
    return {
        "anchors": [
            {
                "id": a.id,
                "size": a.size,
                "created_at": a.created_at.isoformat(),
                "git_commit": a.git_commit,
                "git_path": a.git_path,
                "ots_status": a.ots_status,
            }
            for a in db.scalars(select(Anchor).order_by(Anchor.size))
        ]
    }
