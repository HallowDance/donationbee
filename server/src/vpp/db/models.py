from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


TS = DateTime(timezone=True)


class LedgerEntry(Base):
    """Append-only; UPDATE/DELETE/TRUNCATE are blocked by triggers (see migration 0001).

    Only prev_hash/envelope/hash/sig are authoritative. The other columns are derived from the
    envelope at insert time so we can query without decoding JSON.
    """

    __tablename__ = "ledger_entries"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    envelope: Mapped[bytes] = mapped_column(LargeBinary)  # exact canonical bytes, not jsonb
    hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    sig: Mapped[bytes] = mapped_column(LargeBinary)

    type: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS)
    recipient: Mapped[str | None] = mapped_column(Text, index=True)
    ref_seq: Mapped[int | None] = mapped_column(BigInteger, index=True)
    evidence_ref: Mapped[str | None] = mapped_column(Text)
    checkout_session: Mapped[str | None] = mapped_column(Text, index=True)
    amount_value: Mapped[int | None] = mapped_column(BigInteger)
    currency: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        # A Stripe object (pi_/re_/dp_) can back at most one entry: a backstop under webhook
        # idempotency.
        Index(
            "uq_ledger_evidence_ref",
            "evidence_ref",
            unique=True,
            postgresql_where=text("evidence_ref IS NOT NULL"),
        ),
    )


class MerkleNode(Base):
    """Perfect subtrees of the RFC 6962 tree (LEDGER_SPEC §7). Append-only."""

    __tablename__ = "merkle_nodes"

    level: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    idx: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    hash: Mapped[bytes] = mapped_column(LargeBinary)


class Checkpoint(Base):
    """Signed C2SP checkpoints, one per append (LEDGER_SPEC §8). Append-only."""

    __tablename__ = "checkpoints"

    size: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    root: Mapped[bytes] = mapped_column(LargeBinary)
    note: Mapped[str] = mapped_column(Text)  # signed by the log key only
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class Cosignature(Base):
    __tablename__ = "cosignatures"

    size: Mapped[int] = mapped_column(ForeignKey("checkpoints.size"), primary_key=True)
    witness: Mapped[str] = mapped_column(Text, primary_key=True)  # witness vkey
    line: Mapped[str] = mapped_column(Text)  # full "— name base64\n" signature line
    timestamp: Mapped[int] = mapped_column(BigInteger)


class WitnessState(Base):
    """What each configured witness has cosigned so far (drives consistency proofs)."""

    __tablename__ = "witness_state"

    witness: Mapped[str] = mapped_column(Text, primary_key=True)  # witness vkey
    url: Mapped[str] = mapped_column(Text)
    size: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class PiiRecord(Base):
    """Openings for commitments in the ledger. Erasure nulls salt+cleartext (LEDGER_SPEC §6)."""

    __tablename__ = "pii_records"

    commitment: Mapped[str] = mapped_column(Text, primary_key=True)
    salt: Mapped[bytes | None] = mapped_column(LargeBinary)
    cleartext: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    erased_at: Mapped[datetime | None] = mapped_column(TS)


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # stable id used in the ledger
    slug: Mapped[str] = mapped_column(Text, unique=True)  # mutable, used in URLs
    display_name: Mapped[str] = mapped_column(Text)
    stripe_account_id: Mapped[str | None] = mapped_column(Text, unique=True)
    # Mirrors v2 configuration.merchant.capabilities.card_payments.status; "active" = can take
    # direct charges. Refreshed from webhooks and re-checked live before each checkout.
    card_payments_status: Mapped[str] = mapped_column(Text, server_default=text("'none'"))
    # Identity = a domain that publishes this profile's passkey fingerprints (LEDGER_SPEC §12).
    domain: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class RecipientCredential(Base):
    """Passkeys for signing in; each one is also published as a recipient_key entry."""

    __tablename__ = "recipient_credentials"

    credential_id: Mapped[str] = mapped_column(Text, primary_key=True)  # base64url
    profile_id: Mapped[str] = mapped_column(ForeignKey("profiles.id"), index=True)
    public_key_cose: Mapped[bytes] = mapped_column(LargeBinary)
    fingerprint: Mapped[str] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    # The recipient_key entry; NULL until the domain proof lists this key and it's published.
    key_seq: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class WebauthnChallenge(Base):
    __tablename__ = "webauthn_challenges"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    purpose: Mapped[str] = mapped_column(Text)  # register|login|confirm
    profile_id: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[str | None] = mapped_column(Text)  # e.g. JSON list of ref_seqs to confirm
    expires_at: Mapped[datetime] = mapped_column(TS)


class StripeEvent(Base):
    __tablename__ = "stripe_events"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    type: Mapped[str] = mapped_column(Text)
    account: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class Anchor(Base):
    """A checkpoint published to git and OpenTimestamps (LEDGER_SPEC §13)."""

    __tablename__ = "anchors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    size: Mapped[int] = mapped_column(ForeignKey("checkpoints.size"))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    git_commit: Mapped[str | None] = mapped_column(Text)
    git_path: Mapped[str | None] = mapped_column(Text)
    ots_proof: Mapped[bytes | None] = mapped_column(LargeBinary)
    ots_status: Mapped[str] = mapped_column(
        Text, server_default=text("'none'")
    )  # none|pending|complete
