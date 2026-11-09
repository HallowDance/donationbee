"""Entry construction and hashing (LEDGER_SPEC §2–§4). Pure: no I/O."""

import hashlib
from dataclasses import dataclass
from datetime import datetime

from .canonical import canonicalize, format_ts
from .entries import _Body, dump_body, type_of
from .signing import Signer, key_id_for

DOMAIN = b"vpp:entry:v1\x00"
GENESIS_PREV = bytes(32)


def entry_hash(prev_hash: bytes, envelope: bytes) -> bytes:
    if len(prev_hash) != 32:
        raise ValueError("prev_hash must be 32 bytes")
    return hashlib.sha256(DOMAIN + prev_hash + envelope).digest()


@dataclass(frozen=True)
class Entry:
    seq: int
    type: str
    key_id: str
    created_at: str
    prev_hash: bytes
    envelope: bytes
    hash: bytes
    sig: bytes


def build_entry(
    *,
    seq: int,
    prev_hash: bytes,
    body: _Body,
    key: Signer,
    created_at: datetime,
) -> Entry:
    entry_type = type_of(body)
    if (entry_type == "genesis") != (seq == 1):
        raise ValueError("genesis must be exactly seq 1")
    if seq == 1 and prev_hash != GENESIS_PREV:
        raise ValueError("seq 1 must have the zero prev_hash")
    ts = format_ts(created_at)
    key_id = key_id_for(key.public_key)
    envelope = canonicalize(
        {
            "v": 1,
            "seq": seq,
            "type": entry_type,
            "key_id": key_id,
            "created_at": ts,
            "body": dump_body(body),
        }
    )
    digest = entry_hash(prev_hash, envelope)
    return Entry(
        seq=seq,
        type=entry_type,
        key_id=key_id,
        created_at=ts,
        prev_hash=prev_hash,
        envelope=envelope,
        hash=digest,
        sig=key.sign(digest),
    )
