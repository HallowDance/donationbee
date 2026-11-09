"""Read-side views over the ledger; anyone can derive these from the public entries."""

import json
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db.models import LedgerEntry
from .ledger.note import vkey
from .ledger.signing import key_id_for


@dataclass
class PaymentView:
    entry: LedgerEntry
    body: dict
    reversed: int = 0
    voided: bool = False
    confirmed_by: list[int] = field(default_factory=list)  # confirmation entry seqs

    @property
    def net(self) -> int:
        return 0 if self.voided else self.entry.amount_value - self.reversed


@dataclass
class ProfileTotals:
    payments: list[PaymentView] = field(default_factory=list)
    net_by_currency: dict[str, int] = field(default_factory=dict)
    confirmed_by_currency: dict[str, int] = field(default_factory=dict)
    count: int = 0


def profile_totals(session: Session, profile_id: str) -> ProfileTotals:
    payments = list(
        session.scalars(
            select(LedgerEntry)
            .where(LedgerEntry.type == "payment", LedgerEntry.recipient == profile_id)
            .order_by(LedgerEntry.seq.desc())
        )
    )
    views = {p.seq: PaymentView(p, json.loads(p.envelope)["body"]) for p in payments}
    if views:
        related = session.scalars(
            select(LedgerEntry).where(LedgerEntry.ref_seq.in_(views.keys()))
        ).all()
        voided_reversals = set(
            session.scalars(
                select(LedgerEntry.ref_seq).where(
                    LedgerEntry.type == "correction",
                    LedgerEntry.ref_seq.in_([r.seq for r in related] or [0]),
                )
            )
        )
        for r in related:
            if r.type == "reversal" and r.seq not in voided_reversals:
                views[r.ref_seq].reversed += r.amount_value
            elif r.type == "correction":
                views[r.ref_seq].voided = True
        for c in session.scalars(
            select(LedgerEntry).where(
                LedgerEntry.type == "confirmation", LedgerEntry.recipient == profile_id
            )
        ):
            for ref in json.loads(c.envelope)["body"]["ref_seqs"]:
                if ref in views:
                    views[ref].confirmed_by.append(c.seq)

    totals = ProfileTotals(payments=list(views.values()))
    net: dict[str, int] = defaultdict(int)
    confirmed: dict[str, int] = defaultdict(int)
    for v in totals.payments:
        if not v.voided:
            net[v.entry.currency] += v.net
            totals.count += 1
            if v.confirmed_by:
                confirmed[v.entry.currency] += v.net
    totals.net_by_currency = dict(net)
    totals.confirmed_by_currency = dict(confirmed)
    return totals


def key_history(session: Session) -> dict:
    """Online keys (with their C2SP checkpoint vkeys) and the current root key set."""
    rows = session.scalars(
        select(LedgerEntry)
        .where(LedgerEntry.type.in_(("genesis", "key_rotation", "root_rotation")))
        .order_by(LedgerEntry.seq)
    ).all()
    online: list[dict] = []
    root: dict = {}
    origin = None
    for r in rows:
        body = json.loads(r.envelope)["body"]
        if r.type == "root_rotation":
            root = {
                "keys": body["new_root_keys"],
                "threshold": body["new_root_threshold"],
                "since_seq": r.seq,
            }
            continue
        if r.type == "genesis":
            origin = body["origin"]
            pub = body["online_key"]
            root = {"keys": body["root_keys"], "threshold": body["root_threshold"], "since_seq": 1}
        else:
            pub = body["new_online_key"]
            online[-1]["retired_at_seq"] = r.seq
            online[-1]["retired_reason"] = body["reason"]
        online.append(
            {
                "key_id": key_id_for(bytes.fromhex(pub)),
                "public_key": pub,
                "checkpoint_vkey": vkey(origin, bytes.fromhex(pub)),
                # A rotation entry is itself signed by the new key.
                "first_seq": r.seq,
                "retired_at_seq": None,
                "retired_reason": None,
            }
        )
    return {"origin": origin, "online_keys": online, "root": root}


def format_money(value: int, currency: str) -> str:
    # Minor units -> display. Fine for 2-decimal currencies (EUR, USD, BGN...); extend if needed.
    return f"{value / 100:,.2f} {currency}"
