"""Checkout Sessions as direct charges on the recipient's connected account.

DonationBee takes no cut. A donor may add an optional tip: it's a separate line item, and exactly
that amount goes to the platform as the application fee. The ledger records the donation only.
"""

import secrets

import stripe
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Profile
from ..pii import store_commitment
from .onboarding import refresh_status

# The tip choices offered on the pay page, in minor units. 0 (no tip) is the default.
TIP_CHOICES = (0, 100, 200, 500)


class NotReady(RuntimeError):
    pass


def create_checkout(
    session: Session,
    client: stripe.StripeClient,
    profile: Profile,
    *,
    amount: int,
    currency: str,
    payer_name: str | None,
    note: str | None,
    tip: int = 0,
) -> str:
    settings = get_settings()
    # Stripe: re-check capability status before processing, don't trust a cached flag.
    if refresh_status(session, client, profile) != "active":
        raise NotReady(f"{profile.slug} cannot accept payments yet")

    # Personal data never goes to Stripe metadata or the ledger: only commitments do. The
    # openings live in pii_records (orphans from abandoned checkouts are harmless).
    if tip not in TIP_CHOICES:
        raise ValueError("unsupported tip")
    # vpp_amount tells the webhook which part of the total is the donation.
    metadata = {"vpp_publish": "1", "vpp_profile": profile.id, "vpp_amount": str(amount)}
    if payer_name:
        metadata["vpp_payer"] = store_commitment(session, payer_name)
    if note:
        metadata["vpp_note"] = store_commitment(session, note)

    line_items = [_item(currency, amount, f"Payment to {profile.display_name}")]
    payment_intent_data: dict = {"metadata": metadata}
    if tip:
        line_items.append(
            _item(currency, tip, "Optional tip for DonationBee (not part of the donation)")
        )
        payment_intent_data["application_fee_amount"] = tip

    base = settings.public_base_url.rstrip("/")
    checkout = client.v1.checkout.sessions.create(
        {
            "mode": "payment",
            "line_items": line_items,
            "payment_intent_data": payment_intent_data,
            "metadata": metadata,
            # Stripe substitutes the session id; the receipt page waits for the webhook.
            "success_url": f"{base}/receipt/{{CHECKOUT_SESSION_ID}}",
            "cancel_url": f"{base}/pay/{profile.slug}",
            "integration_identifier": "vpp-pay-"
            + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8)),
        },
        {"stripe_account": profile.stripe_account_id},
    )
    session.commit()
    return checkout.url


def _item(currency: str, amount: int, name: str) -> dict:
    return {
        "quantity": 1,
        "price_data": {
            "currency": currency.lower(),
            "unit_amount": amount,
            "product_data": {"name": name},
        },
    }
