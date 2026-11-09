"""Connected-account onboarding with Accounts v2.

Direct charges make the recipient the merchant of record, so we never hold funds. Per Stripe's
guidance for that pattern: merchant configuration, full dashboard, Stripe collects fees and
absorbs losses.
"""

import hashlib
import hmac
import secrets
import time

import stripe
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Profile

LINK_TTL = 7 * 24 * 3600


def new_profile_id() -> str:
    return "prof_" + secrets.token_hex(8)


def create_connected_account(client: stripe.StripeClient, profile: Profile) -> str:
    account = client.v2.core.accounts.create(
        {
            "display_name": profile.display_name,
            "dashboard": "full",
            "identity": {"country": get_settings().stripe_account_country},
            "configuration": {
                "merchant": {"capabilities": {"card_payments": {"requested": True}}},
            },
            "defaults": {
                "responsibilities": {"fees_collector": "stripe", "losses_collector": "stripe"},
            },
            "metadata": {"vpp_profile": profile.id},
        }
    )
    return account.id


def card_payments_status(client: stripe.StripeClient, account_id: str) -> str:
    account = client.v2.core.accounts.retrieve(account_id, {"include": ["configuration.merchant"]})
    try:
        return account.configuration.merchant.capabilities.card_payments.status
    except AttributeError:
        return "none"


def refresh_status(session: Session, client: stripe.StripeClient, profile: Profile) -> str:
    if profile.stripe_account_id:
        profile.card_payments_status = card_payments_status(client, profile.stripe_account_id)
    return profile.card_payments_status


def link_token(profile_id: str, expires: int) -> str:
    msg = f"onboard:{profile_id}:{expires}".encode()
    return hmac.new(get_settings().secret_key.encode(), msg, hashlib.sha256).hexdigest()


def check_link_token(profile_id: str, expires: int, token: str) -> bool:
    return expires > time.time() and hmac.compare_digest(link_token(profile_id, expires), token)


def onboarding_url(client: stripe.StripeClient, profile: Profile) -> str:
    """A Stripe-hosted onboarding link. Our return/refresh URLs carry an expiring HMAC so a
    leaked URL can't be used to mint links for someone else's account forever."""
    base = get_settings().public_base_url.rstrip("/")
    expires = int(time.time()) + LINK_TTL
    q = f"expires={expires}&token={link_token(profile.id, expires)}"
    link = client.v2.core.account_links.create(
        {
            "account": profile.stripe_account_id,
            "use_case": {
                "type": "account_onboarding",
                "account_onboarding": {
                    "refresh_url": f"{base}/onboard/{profile.id}/refresh?{q}",
                    "return_url": f"{base}/onboard/{profile.id}/return?{q}",
                    "collection_options": {"fields": "eventually_due"},
                },
            },
        }
    )
    return link.url
