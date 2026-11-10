"""Read-side views over the ledger; anyone can derive these from the public entries."""

import json
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db.models import LedgerEntry
from .i18n import N_, money, ngettext
from .i18n import gettext as _
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


LABELS = {  # translated where they're shown
    "genesis": N_("Ledger created"),
    "payment": N_("Payment"),
    "reversal": N_("Refund"),
    "correction": N_("Correction"),
    "recipient_key": N_("Passkey added"),
    "confirmation": N_("Recipient confirmed"),
    "key_rotation": N_("Signing key changed"),
    "root_rotation": N_("Root keys changed"),
}


@dataclass
class LedgerRow:
    entry: LedgerEntry
    label: str
    recipient: object | None = None  # Profile
    detail: str = ""
    status: str | None = None  # confirmed | recorded | voided (payments only)
    refs: list[int] = field(default_factory=list)


def ledger_rows(session: Session, before: int | None, limit: int = 50) -> list[LedgerRow]:
    """Newest-first page of every entry, described in plain words in the page's language."""
    from .db.models import Profile

    q = select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(limit)
    if before:
        q = q.where(LedgerEntry.seq < before)
    entries = list(session.scalars(q))
    profiles = {p.id: p for p in session.scalars(select(Profile))}
    confirmed: set[int] = set()
    voided: set[int] = set()
    for c in session.scalars(select(LedgerEntry).where(LedgerEntry.type == "confirmation")):
        confirmed.update(json.loads(c.envelope)["body"]["ref_seqs"])
    for c in session.scalars(select(LedgerEntry).where(LedgerEntry.type == "correction")):
        voided.add(c.ref_seq)

    rows = []
    for e in entries:
        body = json.loads(e.envelope)["body"]
        label = LABELS.get(e.type)
        row = LedgerRow(e, _(label) if label else e.type, profiles.get(e.recipient))
        if e.type == "payment":
            row.detail = money(e.amount_value, e.currency)
            row.status = (
                "voided" if e.seq in voided else "confirmed" if e.seq in confirmed else "recorded"
            )
        elif e.type == "reversal":
            row.detail = _("{amount} of payment #{seq}").format(
                amount=money(e.amount_value, e.currency), seq=e.ref_seq
            )
            row.refs = [e.ref_seq]
            ref = session.get(LedgerEntry, e.ref_seq)
            row.recipient = profiles.get(ref.recipient) if ref else None
        elif e.type == "correction":
            row.detail = _("voids #{seq} ({reason})").format(
                seq=e.ref_seq, reason=body["reason_code"].replace("_", " ")
            )
            row.refs = [e.ref_seq]
        elif e.type == "confirmation":
            refs = body["ref_seqs"]
            row.detail = ngettext("{n} payment", "{n} payments", len(refs)).format(n=len(refs))
            row.refs = refs
        elif e.type == "recipient_key":
            row.detail = _("listed on {domain}").format(domain=body["domain"])
        elif e.type == "genesis":
            row.detail = _("{k} of {n} root keys").format(
                k=body["root_threshold"], n=len(body["root_keys"])
            )
        elif e.type == "key_rotation":
            row.detail = body["reason"]
        rows.append(row)
    return rows
