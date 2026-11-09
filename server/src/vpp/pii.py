"""Personal-data commitments (LEDGER_SPEC §6) and their deletable openings."""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .db.models import PiiRecord


def commit(value: str, salt: bytes | None = None) -> tuple[str, bytes]:
    salt = salt if salt is not None else secrets.token_bytes(32)
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    digest = hashlib.sha256(salt + value.encode("utf-8")).hexdigest()
    return f"c1:{digest}", salt


def opens(commitment: str, value: str, salt: bytes) -> bool:
    return hmac.compare_digest(commit(value, salt)[0], commitment)


def store_commitment(session: Session, value: str) -> str:
    commitment, salt = commit(value)
    session.add(PiiRecord(commitment=commitment, salt=salt, cleartext=value))
    return commitment


def reveal(session: Session, commitment: str) -> str | None:
    rec = session.get(PiiRecord, commitment)
    return rec.cleartext if rec and rec.erased_at is None else None


def erase(session: Session, commitment: str) -> bool:
    """GDPR erasure: drop the opening. The ledger keeps an unopenable hash and still verifies."""
    rec = session.get(PiiRecord, commitment)
    if rec is None or rec.erased_at is not None:
        return False
    rec.salt = None
    rec.cleartext = None
    rec.erased_at = datetime.now(UTC)
    return True
