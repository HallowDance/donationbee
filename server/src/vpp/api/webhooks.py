import logging
from typing import Annotated

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_session
from ..deps import get_ledger_key
from ..stripe_connect import get_stripe
from ..stripe_connect.webhooks import handle_event, handle_thin_event

log = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks")
DB = Annotated[Session, Depends(get_session)]


@router.post("/stripe")
async def stripe_snapshot(request: Request, db: DB) -> dict:
    client = get_stripe()
    payload = await request.body()
    try:
        event = client.construct_event(
            payload, request.headers.get("stripe-signature"), get_settings().stripe_webhook_secret
        )
    except (ValueError, stripe.SignatureVerificationError):
        raise HTTPException(400, "invalid signature") from None
    # Any exception propagates as a 500: the transaction rolls back and Stripe retries.
    outcome = handle_event(db, client, get_ledger_key(), event)
    db.commit()
    log.info("stripe event %s %s -> %s", event.id, event.type, outcome)
    return {"outcome": outcome}


@router.post("/stripe/v2")
async def stripe_thin(request: Request, db: DB) -> dict:
    client = get_stripe()
    payload = await request.body()
    try:
        notification = client.parse_event_notification(
            payload,
            request.headers.get("stripe-signature"),
            get_settings().stripe_thin_webhook_secret,
        )
    except (ValueError, stripe.SignatureVerificationError):
        raise HTTPException(400, "invalid signature") from None
    outcome = handle_thin_event(db, client, notification)
    db.commit()
    return {"outcome": outcome}
