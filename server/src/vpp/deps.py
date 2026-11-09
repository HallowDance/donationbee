from functools import lru_cache

from .config import get_settings
from .ledger import LedgerKey
from .ledger.signing import Signer


@lru_cache
def get_ledger_key() -> Signer:
    """The online signer: a key file in dev, Cloud KMS in production (VPP_SIGNER)."""
    s = get_settings()
    if s.signer == "gcpkms":
        from .ledger.kms import GcpKmsSigner

        return GcpKmsSigner(s.kms_key_version)
    return LedgerKey.load(s.signing_key_path)
