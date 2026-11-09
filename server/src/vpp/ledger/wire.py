"""JSON wire form of an entry (LEDGER_SPEC §2)."""

import base64
import json

from .chain import Entry


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def to_wire(entry: Entry, *, convenience: bool = True) -> dict:
    wire = {
        "seq": entry.seq,
        "prev_hash": entry.prev_hash.hex(),
        "envelope": b64url(entry.envelope),
        "hash": entry.hash.hex(),
        "sig": entry.sig.hex(),
    }
    if convenience:
        env = json.loads(entry.envelope)
        wire |= {
            "type": env["type"],
            "key_id": env["key_id"],
            "created_at": env["created_at"],
            "body": env["body"],
        }
    return wire
