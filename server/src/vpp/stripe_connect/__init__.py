from functools import lru_cache

import stripe

from ..config import get_settings


@lru_cache
def get_stripe() -> stripe.StripeClient:
    key = get_settings().stripe_secret_key
    if not key:
        raise RuntimeError("VPP_STRIPE_SECRET_KEY is not set")
    return stripe.StripeClient(key)
