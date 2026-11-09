"""OpenTimestamps anchoring (LEDGER_SPEC §13). File digest = SHA-256 of the checkpoint file.

Stamping returns a *pending* proof within seconds; it only becomes Bitcoin-verifiable hours
later, after `upgrade()` fetches the calendar's completed attestation.
"""

import logging
import os
import urllib.error
from collections.abc import Callable, Iterable

from opentimestamps.calendar import (
    DEFAULT_AGGREGATORS,
    DEFAULT_CALENDAR_WHITELIST,
    CommitmentNotFoundError,
    RemoteCalendar,
)
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

log = logging.getLogger(__name__)

Submit = Callable[[str, bytes], Timestamp]


def _remote_submit(url: str, msg: bytes) -> Timestamp:
    return RemoteCalendar(url).submit(msg, timeout=10)


def _serialize(dtf: DetachedTimestampFile) -> bytes:
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _deserialize(proof: bytes) -> DetachedTimestampFile:
    return DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))


def stamp(
    digest: bytes, calendars: Iterable[str] = DEFAULT_AGGREGATORS, submit: Submit = _remote_submit
) -> bytes:
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    root = Timestamp(digest)
    # Nonce first (as the ots client does) so calendars never learn our hash.
    tip = root.ops.add(OpAppend(os.urandom(16))).ops.add(OpSHA256())
    accepted = 0
    for url in calendars:
        try:
            tip.merge(submit(url, tip.msg))
            accepted += 1
        except Exception as e:  # one dead calendar must not block anchoring
            log.warning("OTS calendar %s failed: %s", url, e)
    if accepted == 0:
        raise RuntimeError("no OpenTimestamps calendar accepted the digest")
    return _serialize(DetachedTimestampFile(OpSHA256(), root))


def is_complete(proof: bytes) -> bool:
    return any(
        isinstance(att, BitcoinBlockHeaderAttestation)
        for _, att in _deserialize(proof).timestamp.all_attestations()
    )


def upgrade(proof: bytes) -> tuple[bytes, bool]:
    """One pass over pending attestations. Returns (proof, complete)."""
    dtf = _deserialize(proof)

    def leaves(ts: Timestamp):
        if ts.attestations:
            yield ts
        for sub in ts.ops.values():
            yield from leaves(sub)

    for leaf in list(leaves(dtf.timestamp)):
        for att in list(leaf.attestations):
            if not isinstance(att, PendingAttestation) or att.uri not in DEFAULT_CALENDAR_WHITELIST:
                continue
            try:
                leaf.merge(RemoteCalendar(att.uri).get_timestamp(leaf.msg, timeout=10))
            except (CommitmentNotFoundError, urllib.error.URLError) as e:
                log.info("OTS %s not ready: %s", att.uri, e)
    new = _serialize(dtf)
    return new, is_complete(new)
