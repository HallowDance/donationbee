import json
from decimal import Decimal, InvalidOperation
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import badge, pii
from ..config import get_settings
from ..db import get_session
from ..db.models import Anchor, Checkpoint, Cosignature, LedgerEntry, Profile
from ..queries import format_money, ledger_rows, profile_totals
from ..receipts import seq_for_session
from ..stripe_connect import get_stripe
from ..stripe_connect.checkout import TIP_CHOICES, NotReady, create_checkout
from ..stripe_connect.onboarding import check_link_token, onboarding_url, refresh_status
from ..witnessing import latest_cosigned_size
from .recipient import recipient_session_redirect
from .templating import templates

router = APIRouter()
DB = Annotated[Session, Depends(get_session)]

PAYMENTS_OFF = "Payments are switched off in this beta. You can browse the demo hives."
PAGE = 50
MIN_AMOUNT, MAX_AMOUNT = 100, 10_000_000  # minor units: 1.00 .. 100,000.00


def _profile(db: Session, slug: str) -> Profile:
    p = db.scalars(select(Profile).where(Profile.slug == slug)).first()
    if p is None:
        raise HTTPException(404, "no such profile")
    return p


@router.get("/")
def index(request: Request, db: DB):
    hives = []
    for p in db.scalars(select(Profile).order_by(Profile.created_at).limit(50)):
        hives.append({"profile": p, "totals": profile_totals(db, p.id)})
    hives.sort(key=lambda h: -sum(h["totals"].net_by_currency.values()))
    return templates.TemplateResponse(
        request,
        "index.html",
        {"hives": hives[:6], "base": get_settings().public_base_url.rstrip("/")},
    )


@router.get("/recipients")
def recipients_guide(request: Request):
    return templates.TemplateResponse(request, "recipients.html", {})


@router.get("/ledger")
def ledger_page(request: Request, db: DB, before: int | None = None):
    rows = ledger_rows(db, before, limit=PAGE)
    cp = db.scalars(select(Checkpoint).order_by(Checkpoint.size.desc()).limit(1)).first()
    cosigs = (
        db.scalar(select(func.count()).select_from(Cosignature).where(Cosignature.size == cp.size))
        if cp
        else 0
    )
    witnessed = latest_cosigned_size(db)
    anchor = db.scalars(select(Anchor).order_by(Anchor.size.desc()).limit(1)).first()
    return templates.TemplateResponse(
        request,
        "ledger.html",
        {
            "rows": rows,
            "cp": cp,
            "cosigs": cosigs,
            "witnessed": witnessed,
            "anchor": anchor,
            "older": rows[-1].entry.seq if len(rows) == PAGE and rows[-1].entry.seq > 1 else None,
            "newer": before is not None,
            "base": get_settings().public_base_url.rstrip("/"),
        },
    )


@router.get("/p/{slug}")
def profile_page(request: Request, db: DB, slug: str, paid: int = 0):
    p = _profile(db, slug)
    totals = profile_totals(db, p.id)
    payers = {
        v.entry.seq: pii.reveal(db, v.body["payer"]) if v.body.get("payer") else None
        for v in totals.payments
    }
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "profile": p,
            "totals": totals,
            "payers": payers,
            "paid": paid,
            "base": get_settings().public_base_url.rstrip("/"),
        },
    )


@router.get("/e/{seq}")
def entry_page(request: Request, db: DB, seq: int):
    e = db.get(LedgerEntry, seq)
    if e is None:
        raise HTTPException(404)
    envelope = json.loads(e.envelope)
    anchor = db.scalars(
        select(Anchor).where(Anchor.size >= seq).order_by(Anchor.size).limit(1)
    ).first()
    cosigned = latest_cosigned_size(db)
    revealed = {
        f: pii.reveal(db, envelope["body"][f]) for f in ("payer", "note") if envelope["body"].get(f)
    }
    recipient = None
    if e.recipient:
        recipient = db.get(Profile, e.recipient)
    return templates.TemplateResponse(
        request,
        "entry.html",
        {
            "e": e,
            "envelope_pretty": json.dumps(envelope, indent=2),
            "anchor": anchor,
            "witnessed": cosigned is not None and cosigned >= seq,
            "revealed": revealed,
            "recipient": recipient,
            "base": get_settings().public_base_url.rstrip("/"),
        },
    )


@router.get("/pay/{slug}")
def pay_form(request: Request, db: DB, slug: str):
    p = _profile(db, slug)
    error = None if get_settings().stripe_secret_key else PAYMENTS_OFF
    return templates.TemplateResponse(
        request, "pay.html", {"profile": p, "error": error, "tips": TIP_CHOICES}
    )


def _parse_amount(raw: str) -> int | None:
    try:
        d = Decimal(raw.replace(",", ".").strip())
    except InvalidOperation:
        return None
    if d != d.quantize(Decimal("0.01")):
        return None
    cents = int(d * 100)
    return cents if MIN_AMOUNT <= cents <= MAX_AMOUNT else None


@router.post("/pay/{slug}")
def pay_submit(
    request: Request,
    db: DB,
    slug: str,
    amount: Annotated[str, Form()],
    payer_name: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
    consent: Annotated[str, Form()] = "",
    tip: Annotated[str, Form()] = "0",
):
    p = _profile(db, slug)

    def fail(msg: str):
        return templates.TemplateResponse(
            request, "pay.html", {"profile": p, "error": msg, "tips": TIP_CHOICES}, status_code=400
        )

    cents = _parse_amount(amount)
    if cents is None:
        return fail("Enter an amount between 1.00 and 100,000.00 EUR.")
    tip_cents = int(tip) if tip.isdigit() else -1
    if tip_cents not in TIP_CHOICES:
        return fail("Choose one of the tip options.")
    if not consent:
        return fail("Please confirm that this payment will be published.")
    if not get_settings().stripe_secret_key:
        return fail(PAYMENTS_OFF)
    try:
        url = create_checkout(
            db,
            get_stripe(),
            p,
            amount=cents,
            currency="EUR",
            payer_name=payer_name.strip()[:100] or None,
            note=note.strip()[:280] or None,
            tip=tip_cents,
        )
    except NotReady as e:
        return fail(str(e))
    return RedirectResponse(url, status_code=303)


@router.get("/onboard/{profile_id}/refresh")
def onboard_refresh(db: DB, profile_id: str, expires: int, token: str):
    p = db.get(Profile, profile_id)
    if p is None or not check_link_token(profile_id, expires, token):
        raise HTTPException(403, "link expired; ask for a new onboarding link")
    return RedirectResponse(onboarding_url(get_stripe(), p), status_code=303)


@router.get("/onboard/{profile_id}/return")
def onboard_return(db: DB, profile_id: str, expires: int, token: str):
    p = db.get(Profile, profile_id)
    if p is None or not check_link_token(profile_id, expires, token):
        raise HTTPException(403)
    refresh_status(db, get_stripe(), p)
    db.commit()
    # Onboarding is also where the recipient sets up the passkey they confirm payments with.
    return recipient_session_redirect(p, "/recipient")


@router.get("/badge/{slug}.svg")
def badge_svg(db: DB, slug: str):
    p = _profile(db, slug)
    totals = profile_totals(db, p.id)
    value = (
        " + ".join(format_money(v, c) for c, v in sorted(totals.net_by_currency.items()))
        or "none yet"
    )
    all_confirmed = bool(totals.net_by_currency) and (
        totals.confirmed_by_currency == totals.net_by_currency
    )
    return Response(
        badge.render(
            value,
            confirmed_by=p.domain if all_confirmed else None,
            brand=get_settings().brand_name,
        ),
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=300"},
    )


@router.get("/receipt/{checkout_session}")
def receipt_page(request: Request, db: DB, checkout_session: str):
    """Stripe's success_url. Refreshes until the webhook has recorded the payment."""
    seq = seq_for_session(db, checkout_session) if checkout_session.startswith("cs_") else None
    entry = db.get(LedgerEntry, seq) if seq else None
    recipient = db.get(Profile, entry.recipient) if entry else None
    cosigned = latest_cosigned_size(db)
    return templates.TemplateResponse(
        request,
        "receipt.html",
        {
            "seq": seq,
            "e": entry,
            "recipient": recipient,
            "witnessed": seq is not None and cosigned is not None and cosigned >= seq,
            "base": get_settings().public_base_url.rstrip("/"),
        },
    )
