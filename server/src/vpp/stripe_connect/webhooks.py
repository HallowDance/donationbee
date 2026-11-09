"""Stripe events -> ledger entries.

Each event is processed in one transaction that also records its id, so a redelivered event is a
no-op and a failure rolls everything back for Stripe to retry. The ledger's unique evidence_ref
index is a second line of defence (e.g. the same session reported by two event types).
"""

import logging
from datetime import UTC, datetime

import stripe
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import LedgerEntry, Profile, StripeEvent
from ..ledger import LedgerKey
from ..ledger.canonical import format_ts
from ..ledger.entries import (
    Money,
    Payment,
    Reversal,
    StripePaymentEvidence,
    StripeReversalEvidence,
)
from ..ledger.store import append
from .onboarding import refresh_status

log = logging.getLogger(__name__)

PAYMENT_EVENTS = {"checkout.session.completed", "checkout.session.async_payment_succeeded"}
HANDLED = PAYMENT_EVENTS | {"charge.refunded", "charge.dispute.closed"}


def handle_event(
    session: Session, client: stripe.StripeClient, key: LedgerKey, event: stripe.Event
) -> str:
    """Returns a short outcome string (for logs/tests). The caller commits."""
    if event.type not in HANDLED:
        return "ignored:type"
    if bool(event.livemode) != get_settings().stripe_livemode:
        return "ignored:livemode"

    inserted = session.execute(
        insert(StripeEvent)
        .values(event_id=event.id, type=event.type, account=getattr(event, "account", None))
        .on_conflict_do_nothing()
        .returning(StripeEvent.event_id)
    ).first()
    if inserted is None:
        return "duplicate"

    obj = event.data.object
    account = getattr(event, "account", None)
    if not account:
        return "ignored:no_account"
    if event.type in PAYMENT_EVENTS:
        return _on_checkout_paid(session, key, event, obj, account)
    if event.type == "charge.refunded":
        return _on_refund(session, client, key, obj, account)
    return _on_dispute_closed(session, key, obj, account)


def _payment_for(session: Session, payment_intent: str | None) -> LedgerEntry | None:
    if not payment_intent:
        return None
    return session.scalars(
        select(LedgerEntry).where(
            LedgerEntry.type == "payment", LedgerEntry.evidence_ref == payment_intent
        )
    ).first()


def _recorded(session: Session, ref: str) -> bool:
    return (
        session.scalar(select(LedgerEntry.seq).where(LedgerEntry.evidence_ref == ref)) is not None
    )


def _remaining(session: Session, payment: LedgerEntry) -> int:
    reversed_ = session.scalar(
        select(func.coalesce(func.sum(LedgerEntry.amount_value), 0)).where(
            LedgerEntry.type == "reversal", LedgerEntry.ref_seq == payment.seq
        )
    )
    return payment.amount_value - int(reversed_)  # SUM(bigint) comes back as Decimal


def _on_checkout_paid(session, key, event, cs, account) -> str:
    # Stripe: the completed event can arrive unpaid for delayed methods; fulfil on paid only.
    if cs.payment_status == "unpaid":
        return "ignored:unpaid"
    md = cs.metadata.to_dict() if cs.metadata else {}  # StripeObject isn't a dict in v16
    if md.get("vpp_publish") != "1":
        return "ignored:not_opted_in"
    profile = session.scalars(select(Profile).where(Profile.stripe_account_id == account)).first()
    if profile is None or profile.id != md.get("vpp_profile"):
        log.warning("checkout %s: account %s does not match profile metadata", cs.id, account)
        return "ignored:profile_mismatch"
    if _recorded(session, cs.payment_intent):
        return "already_recorded"
    # The donation is what the ledger records; any optional tip on top is DonationBee's, not the
    # recipient's. Older sessions without vpp_amount were donation-only.
    donation = int(md["vpp_amount"]) if str(md.get("vpp_amount", "")).isdigit() else cs.amount_total
    if not 0 < donation <= cs.amount_total:
        log.warning(
            "checkout %s: donation %s doesn't fit total %s", cs.id, donation, cs.amount_total
        )
        return "ignored:amount_mismatch"

    append(
        session,
        Payment(
            recipient=profile.id,
            amount=Money(value=donation, currency=cs.currency.upper()),
            occurred_at=format_ts(datetime.fromtimestamp(event.created, UTC)),
            payer=md.get("vpp_payer"),
            note=md.get("vpp_note"),
            evidence=StripePaymentEvidence(
                account=account,
                payment_intent=cs.payment_intent,
                checkout_session=cs.id,
                livemode=bool(event.livemode),
            ),
        ),
        key,
    )
    return "recorded:payment"


def _on_refund(session, client, key, charge, account) -> str:
    payment = _payment_for(session, charge.payment_intent)
    if payment is None:
        return "ignored:unpublished_payment"
    # The event's charge doesn't reliably embed refunds, so list them. Recording per refund id
    # makes this idempotent and order-independent across partial refunds.
    refunds = client.v1.refunds.list(
        {"charge": charge.id, "limit": 100}, {"stripe_account": account}
    )
    recorded = 0
    for r in sorted(refunds.data, key=lambda r: r.created):
        if r.status != "succeeded" or _recorded(session, r.id):
            continue
        amount = min(r.amount, _remaining(session, payment))
        if amount <= 0:
            break
        append(
            session,
            Reversal(
                ref_seq=payment.seq,
                reason="refund",
                amount=Money(value=amount, currency=payment.currency),
                evidence=StripeReversalEvidence(account=account, object=r.id),
            ),
            key,
        )
        recorded += 1
    return f"recorded:{recorded}_refunds"


def _on_dispute_closed(session, key, dispute, account) -> str:
    if dispute.status != "lost":
        return f"ignored:dispute_{dispute.status}"
    payment = _payment_for(session, dispute.payment_intent)
    if payment is None:
        return "ignored:unpublished_payment"
    if _recorded(session, dispute.id):
        return "already_recorded"
    amount = min(dispute.amount, _remaining(session, payment))
    if amount <= 0:
        return "ignored:fully_reversed"
    append(
        session,
        Reversal(
            ref_seq=payment.seq,
            reason="dispute_lost",
            amount=Money(value=amount, currency=payment.currency),
            evidence=StripeReversalEvidence(account=account, object=dispute.id),
        ),
        key,
    )
    return "recorded:dispute"


def handle_thin_event(session: Session, client: stripe.StripeClient, notification) -> str:
    """v2 account capability changes: refetch the account rather than trusting the payload."""
    related = getattr(notification, "related_object", None)
    if related is None or not related.id.startswith("acct_"):
        return "ignored"
    profile = session.scalars(
        select(Profile).where(Profile.stripe_account_id == related.id)
    ).first()
    if profile is None:
        return "ignored:unknown_account"
    return "status:" + refresh_status(session, client, profile)
