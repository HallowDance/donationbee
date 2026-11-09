from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VPP_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://vpp@localhost/vpp"
    public_base_url: str = "http://localhost:8000"
    # Shown in the UI and on badges. The ledger format itself never mentions it.
    brand_name: str = "DonationBee"
    # Optional site-wide notice, e.g. "Beta: demo data, test payments only."
    banner: str = ""
    # C2SP log origin: also the checkpoint key name. Schema-less URL form, no spaces or '+'.
    origin: str = "localhost/vpp-dev"

    # Online signer. "file": a key file outside the database (dev). "gcpkms": Cloud KMS Ed25519.
    signer: str = "file"
    signing_key_path: Path = Path("ledger.key")
    kms_key_version: str = ""

    # WebAuthn relying party for recipient passkeys: must be this site's public hostname.
    rp_id: str = "localhost"
    rp_name: str = "Payment Proofs"

    # Witnesses: JSON list of {"vkey": "...", "url": "https://witness.example/"}.
    witnesses: str = "[]"

    # HMAC key for onboarding return/refresh links (they must not be usable if leaked).
    secret_key: str = "dev-insecure-change-me"

    # Prefer a restricted key (rk_...) scoped to Accounts, Account Links, Checkout, Refunds.
    stripe_secret_key: str = ""
    # Connect endpoint, snapshot events from connected accounts (checkout, charge, dispute).
    stripe_webhook_secret: str = ""
    # Event destination for v2 thin events (account capability changes).
    stripe_thin_webhook_secret: str = ""
    stripe_account_country: str = "bg"
    # Events whose livemode differs are ignored, so test payments never reach a live ledger.
    stripe_livemode: bool = False
    application_fee_bps: int = 100  # 1%

    anchors_repo_path: Path | None = None
    anchors_push: bool = True
    ots_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
