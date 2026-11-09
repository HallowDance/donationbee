"""Typed entry bodies (LEDGER_SPEC §5, §6, §11). Unknown fields are rejected."""

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from .canonical import MAX_SAFE_INT

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
COMMITMENT_RE = re.compile(r"^c1:[0-9a-f]{64}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _ts(v: str) -> str:
    if not TS_RE.match(v):
        raise ValueError("timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    return v


def _commitment(v: str) -> str:
    if not COMMITMENT_RE.match(v):
        raise ValueError("commitment must be c1:<64 hex>")
    return v


def _b64url(v: str) -> str:
    if not B64URL_RE.match(v):
        raise ValueError("expected unpadded base64url")
    return v


Timestamp = Annotated[str, AfterValidator(_ts)]
Commitment = Annotated[str, AfterValidator(_commitment)]
Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
B64Url = Annotated[str, AfterValidator(_b64url)]
SafeInt = Annotated[int, Field(ge=0, le=MAX_SAFE_INT, strict=True)]
Seq = Annotated[int, Field(ge=1, le=MAX_SAFE_INT, strict=True)]
Origin = Annotated[str, Field(pattern=r"^[^\s+]{1,255}$")]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Money(_Body):
    value: SafeInt
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")]


class RootSig(_Body):
    key: Hex32
    sig: Hex64


class Genesis(_Body):
    origin: Origin
    online_key: Hex32
    root_keys: Annotated[list[Hex32], Field(min_length=1, max_length=16)]
    root_threshold: Annotated[int, Field(ge=1, le=16, strict=True)]
    root_sigs: list[RootSig]


class KeyRotation(_Body):
    from_online_key: Hex32
    new_online_key: Hex32
    reason: Literal["scheduled", "compromise", "lost"]
    root_sigs: list[RootSig]


class RootRotation(_Body):
    new_root_keys: Annotated[list[Hex32], Field(min_length=1, max_length=16)]
    new_root_threshold: Annotated[int, Field(ge=1, le=16, strict=True)]
    root_sigs: list[RootSig]


class StripePaymentEvidence(_Body):
    type: Literal["stripe_connect"] = "stripe_connect"
    account: Annotated[str, Field(pattern=r"^acct_")]
    payment_intent: Annotated[str, Field(pattern=r"^pi_")]
    checkout_session: Annotated[str, Field(pattern=r"^cs_")]
    livemode: bool


class Payment(_Body):
    recipient: str
    amount: Money
    occurred_at: Timestamp
    payer: Commitment | None = None
    note: Commitment | None = None
    evidence: StripePaymentEvidence


class StripeReversalEvidence(_Body):
    type: Literal["stripe_connect"] = "stripe_connect"
    account: Annotated[str, Field(pattern=r"^acct_")]
    object: Annotated[str, Field(pattern=r"^(re|dp)_")]


class Reversal(_Body):
    ref_seq: Seq
    reason: Literal["refund", "dispute_lost"]
    amount: Money
    evidence: StripeReversalEvidence


class Correction(_Body):
    ref_seq: Seq
    reason_code: Literal["wrong_recipient", "duplicate", "other"]


class RecipientKey(_Body):
    """A recipient's passkey. The public key is SPKI DER so verifiers need no CBOR/COSE."""

    recipient: str
    credential_id: B64Url
    public_key_spki: B64Url
    alg: Literal[-7, -8, -257]  # ES256, EdDSA, RS256
    rp_id: str
    origin: str
    domain: str
    fingerprint: Annotated[str, Field(pattern=r"^k1:[0-9a-f]{64}$")]


class Confirmation(_Body):
    """A WebAuthn assertion by the recipient over the referenced payments (LEDGER_SPEC §11)."""

    recipient: str
    ref_seqs: Annotated[list[Seq], Field(min_length=1, max_length=100)]
    credential_id: B64Url
    authenticator_data: B64Url
    client_data_json: B64Url
    signature: B64Url


BODY_TYPES: dict[str, type[_Body]] = {
    "genesis": Genesis,
    "key_rotation": KeyRotation,
    "root_rotation": RootRotation,
    "payment": Payment,
    "reversal": Reversal,
    "correction": Correction,
    "recipient_key": RecipientKey,
    "confirmation": Confirmation,
}


def type_of(body: _Body) -> str:
    for name, cls in BODY_TYPES.items():
        if isinstance(body, cls):
            return name
    raise TypeError(f"not an entry body: {body!r}")


def dump_body(body: _Body) -> dict:
    # exclude_none=False on purpose: payer/note nulls are part of the canonical body.
    return body.model_dump(mode="json")
