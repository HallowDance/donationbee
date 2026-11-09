"""Pushing checkpoints to C2SP tlog-witness witnesses and collecting their cosignatures.

Run `vpp witness-push` frequently (e.g. every minute). Pushes are serialized by an advisory
lock so each witness only ever sees growing sizes.
"""

import base64
import json
import logging
from dataclasses import dataclass

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from vpp_verify.note import Note, NoteError, Verifier, verify_cosignature

from .config import get_settings
from .db.models import Checkpoint, Cosignature, WitnessState
from .ledger.store import consistency_proof, latest_checkpoint

log = logging.getLogger(__name__)
WITNESS_LOCK = 0x767071


@dataclass(frozen=True)
class WitnessConfig:
    verifier: Verifier
    url: str


def configured() -> list[WitnessConfig]:
    return [
        WitnessConfig(Verifier.parse(w["vkey"]), w["url"].rstrip("/"))
        for w in json.loads(get_settings().witnesses)
    ]


def _request_body(session: Session, old: int, cp: Checkpoint) -> str:
    proof = consistency_proof(session, old, cp.size)
    lines = [f"old {old}", *(base64.b64encode(h).decode() for h in proof)]
    return "\n".join(lines) + "\n\n" + cp.note


def _store_cosignatures(session: Session, w: WitnessConfig, cp: Checkpoint, body: str) -> int:
    base = Note.parse(cp.note)
    stored = 0
    for line in body.splitlines(keepends=True):
        if not line.strip():
            continue
        try:
            candidate = Note.parse(cp.note + line)
            ts = verify_cosignature(candidate, w.verifier)
        except NoteError as e:
            log.warning("witness %s returned an invalid cosignature: %s", w.verifier.name, e)
            continue
        if ts is None:
            continue  # a line from another of the witness's keys
        assert candidate.text == base.text
        session.merge(Cosignature(size=cp.size, witness=str(w.verifier), line=line, timestamp=ts))
        stored += 1
    return stored


def push(
    session: Session, http: httpx.Client, witnesses: list[WitnessConfig] | None = None
) -> dict:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": WITNESS_LOCK})
    cp = latest_checkpoint(session)
    results: dict[str, str] = {}
    if cp is None:
        return results
    for w in witnesses if witnesses is not None else configured():
        key = str(w.verifier)
        state = session.get(WitnessState, key) or WitnessState(witness=key, url=w.url, size=0)
        session.add(state)
        if state.size == cp.size and session.get(Cosignature, (cp.size, key)):
            results[w.verifier.name] = "up to date"
            continue
        outcome = "error"
        for _ in range(2):  # a 409 tells us the witness's size; retry once with it
            if state.size > cp.size:
                outcome = f"witness is at size {state.size}, beyond our {cp.size}: possible fork!"
                break
            try:
                r = http.post(
                    f"{w.url}/add-checkpoint", content=_request_body(session, state.size, cp)
                )
            except httpx.HTTPError as e:
                outcome = f"unreachable: {e.__class__.__name__}"
                break
            if r.status_code == 409 and r.headers.get("content-type", "").startswith(
                "text/x.tlog.size"
            ):
                state.size = int(r.text.strip())
                continue
            if r.status_code == 200:
                n = _store_cosignatures(session, w, cp, r.text)
                state.size = cp.size
                outcome = f"cosigned size {cp.size}" if n else "200 without a valid cosignature"
            else:
                outcome = f"HTTP {r.status_code}: {r.text.strip()[:200]}"
            break
        state.last_error = None if outcome.startswith("cosigned") else outcome
        results[w.verifier.name] = outcome
    session.commit()
    return results


def cosigned_note(session: Session, size: int | None = None) -> str | None:
    """The checkpoint note with every stored witness cosignature appended."""
    cp = session.get(Checkpoint, size) if size else latest_checkpoint(session)
    if cp is None:
        return None
    lines = session.scalars(select(Cosignature.line).where(Cosignature.size == cp.size)).all()
    return cp.note + "".join(lines)


def latest_cosigned_size(session: Session, minimum: int = 1) -> int | None:
    """Largest checkpoint size with at least `minimum` cosignatures."""
    from sqlalchemy import func

    return session.scalar(
        select(Cosignature.size)
        .group_by(Cosignature.size)
        .having(func.count() >= minimum)
        .order_by(Cosignature.size.desc())
        .limit(1)
    )
