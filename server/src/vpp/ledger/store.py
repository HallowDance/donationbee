"""Postgres-backed ledger. append() runs inside the caller's transaction; the caller commits.

Each append also extends the Merkle tree and signs a checkpoint for the new size, all in the same
transaction, so the entries, tree and checkpoints can never disagree.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..db.models import Checkpoint, LedgerEntry, MerkleNode
from . import merkle
from .chain import GENESIS_PREV, Entry, build_entry
from .entries import (
    Confirmation,
    Correction,
    Genesis,
    KeyRotation,
    Payment,
    RecipientKey,
    Reversal,
    RootRotation,
    RootSig,
    _Body,
)
from .note import checkpoint_text, sign_note
from .signing import (
    Signer,
    count_root_sigs,
    genesis_statement,
    key_id_for,
    root_rotation_statement,
    rotation_statement,
)

# Arbitrary constant identifying "the ledger append lock" ('vpp' in ASCII).
LEDGER_LOCK = 0x767070


class LedgerError(RuntimeError):
    pass


@dataclass
class KeyState:
    """Signing authority as established by the chain itself (LEDGER_SPEC §5)."""

    origin: str
    online_key: bytes
    root_keys: list[str]
    root_threshold: int
    used_online_keys: set[bytes] = field(default_factory=set)
    used_root_sets: set[tuple] = field(default_factory=set)


def head(session: Session) -> LedgerEntry | None:
    return session.scalars(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(1)).first()


def key_state(session: Session) -> KeyState | None:
    rows = session.scalars(
        select(LedgerEntry)
        .where(LedgerEntry.type.in_(("genesis", "key_rotation", "root_rotation")))
        .order_by(LedgerEntry.seq)
    ).all()
    state: KeyState | None = None
    for r in rows:
        b = json.loads(r.envelope)["body"]
        if r.type == "genesis":
            state = KeyState(
                b["origin"], bytes.fromhex(b["online_key"]), b["root_keys"], b["root_threshold"]
            )
        elif r.type == "key_rotation":
            state.online_key = bytes.fromhex(b["new_online_key"])
        else:
            state.root_keys, state.root_threshold = b["new_root_keys"], b["new_root_threshold"]
        state.used_online_keys.add(state.online_key)
        state.used_root_sets.add((tuple(sorted(state.root_keys)), state.root_threshold))
    return state


def active_public_key(session: Session) -> bytes | None:
    state = key_state(session)
    return state.online_key if state else None


def _derived_columns(body: _Body) -> dict:
    match body:
        case Payment():
            return {
                "recipient": body.recipient,
                "evidence_ref": body.evidence.payment_intent,
                "checkout_session": body.evidence.checkout_session,
                "amount_value": body.amount.value,
                "currency": body.amount.currency,
            }
        case Reversal():
            return {
                "ref_seq": body.ref_seq,
                "evidence_ref": body.evidence.object,
                "amount_value": body.amount.value,
                "currency": body.amount.currency,
            }
        case Correction():
            return {"ref_seq": body.ref_seq}
        case RecipientKey() | Confirmation():
            return {"recipient": body.recipient}
    return {}


def _check_root_set(keys: list[str], threshold: int) -> None:
    if len(set(keys)) != len(keys):
        raise LedgerError("duplicate root keys")
    if not 1 <= threshold <= len(keys):
        raise LedgerError("root threshold must be between 1 and the number of root keys")


def _authorize(session: Session, state: KeyState | None, body: _Body, signer: Signer) -> None:
    """Enforce who may sign what. The verifier enforces the same rules independently."""
    pub = signer.public_key
    if state is None:
        if not isinstance(body, Genesis):
            raise LedgerError("ledger is empty; append a genesis entry first")
        _check_root_set(body.root_keys, body.root_threshold)
        if bytes.fromhex(body.online_key) != pub:
            raise LedgerError("genesis must be signed by its own online key")
        stmt = genesis_statement(body.origin, pub)
        if count_root_sigs(stmt, body.root_sigs, body.root_keys) < body.root_threshold:
            raise LedgerError("genesis lacks a root-key threshold of signatures")
        return

    match body:
        case KeyRotation():
            new = bytes.fromhex(body.new_online_key)
            if bytes.fromhex(body.from_online_key) != state.online_key:
                raise LedgerError("rotation does not replace the active online key")
            if new in state.used_online_keys:
                raise LedgerError("online keys may never be reused")
            stmt = rotation_statement(state.origin, state.online_key, new)
            if count_root_sigs(stmt, body.root_sigs, state.root_keys) < state.root_threshold:
                raise LedgerError("rotation lacks a root-key threshold of signatures")
            # Signed by the *new* key: proves possession, and works when the old key is lost.
            if pub != new:
                raise LedgerError("a key rotation must be signed by the new online key")
            return
        case RootRotation():
            _check_root_set(body.new_root_keys, body.new_root_threshold)
            if (tuple(sorted(body.new_root_keys)), body.new_root_threshold) in state.used_root_sets:
                raise LedgerError("root key sets may never be reused")
            stmt = root_rotation_statement(
                state.origin,
                state.root_keys,
                state.root_threshold,
                body.new_root_keys,
                body.new_root_threshold,
            )
            if count_root_sigs(stmt, body.root_sigs, state.root_keys) < state.root_threshold:
                raise LedgerError("root rotation lacks the old root threshold")
        case Genesis():
            raise LedgerError("ledger already has a genesis entry")
    if pub != state.online_key:
        raise LedgerError(f"key {key_id_for(pub)} is not the ledger's active signing key")


def recipient_keys(session: Session, recipient: str) -> dict[str, dict]:
    """credential_id -> recipient_key body, from the chain."""
    rows = session.scalars(
        select(LedgerEntry).where(
            LedgerEntry.type == "recipient_key", LedgerEntry.recipient == recipient
        )
    )
    keys = {}
    for r in rows:
        b = json.loads(r.envelope)["body"]
        keys[b["credential_id"]] = b
    return keys


def _validate_refs(session: Session, body: _Body) -> None:
    if isinstance(body, Reversal):
        ref = session.get(LedgerEntry, body.ref_seq)
        if ref is None or ref.type != "payment":
            raise LedgerError(f"reversal ref_seq {body.ref_seq} is not a payment")
        if ref.currency != body.amount.currency:
            raise LedgerError("reversal currency differs from payment")
        already = int(
            session.scalar(
                select(func.coalesce(func.sum(LedgerEntry.amount_value), 0)).where(
                    LedgerEntry.type == "reversal", LedgerEntry.ref_seq == body.ref_seq
                )
            )
        )
        if already + body.amount.value > ref.amount_value:
            raise LedgerError("reversals would exceed payment amount")
    elif isinstance(body, Correction):
        if session.get(LedgerEntry, body.ref_seq) is None:
            raise LedgerError(f"correction ref_seq {body.ref_seq} does not exist")
    elif isinstance(body, Confirmation):
        # The WebAuthn assertion itself is checked by the caller (vpp.passkeys) and by verifiers.
        if len(set(body.ref_seqs)) != len(body.ref_seqs):
            raise LedgerError("duplicate ref_seqs")
        for s in body.ref_seqs:
            ref = session.get(LedgerEntry, s)
            if ref is None or ref.type != "payment" or ref.recipient != body.recipient:
                raise LedgerError(f"seq {s} is not a payment to {body.recipient}")
        if body.credential_id not in recipient_keys(session, body.recipient):
            raise LedgerError("confirmation key is not a registered recipient key")


class DbNodeStore:
    """merkle.NodeStore over merkle_nodes, with a write-through cache for this transaction."""

    def __init__(self, session: Session):
        self.session = session
        self.cache: dict[tuple[int, int], bytes] = {}

    def get(self, level: int, idx: int) -> bytes:
        key = (level, idx)
        if key not in self.cache:
            node = self.session.get(MerkleNode, key)
            if node is None:
                raise LedgerError(f"missing merkle node {key}")
            self.cache[key] = node.hash
        return self.cache[key]

    def put(self, level: int, idx: int, h: bytes) -> None:
        self.cache[(level, idx)] = h
        self.session.add(MerkleNode(level=level, idx=idx, hash=h))


def append(
    session: Session, body: _Body, key: Signer, *, now: datetime | None = None
) -> LedgerEntry:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LEDGER_LOCK})

    last = head(session)
    state = key_state(session)
    _authorize(session, state, body, key)
    _validate_refs(session, body)

    entry: Entry = build_entry(
        seq=(last.seq + 1) if last else 1,
        prev_hash=last.hash if last else GENESIS_PREV,
        body=body,
        key=key,
        created_at=now or datetime.now(UTC),
    )
    row = LedgerEntry(
        seq=entry.seq,
        prev_hash=entry.prev_hash,
        envelope=entry.envelope,
        hash=entry.hash,
        sig=entry.sig,
        type=entry.type,
        key_id=entry.key_id,
        created_at=datetime.strptime(entry.created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        **_derived_columns(body),
    )
    session.add(row)

    nodes = DbNodeStore(session)
    merkle.append_leaf(nodes, entry.seq - 1, entry.hash)
    root = merkle.root(nodes, entry.seq)
    origin = body.origin if isinstance(body, Genesis) else state.origin
    note = sign_note(checkpoint_text(origin, entry.seq, root), origin, key.public_key, key.sign)
    session.add(Checkpoint(size=entry.seq, root=root, note=note))
    session.flush()
    return row


def init_ledger(
    session: Session,
    key: Signer,
    origin: str,
    root_keys: list[str],
    root_threshold: int,
    root_sigs: list[RootSig],
) -> LedgerEntry:
    return append(
        session,
        Genesis(
            origin=origin,
            online_key=key.public_key.hex(),
            root_keys=root_keys,
            root_threshold=root_threshold,
            root_sigs=root_sigs,
        ),
        key,
    )


def to_entry(row: LedgerEntry) -> Entry:
    return Entry(
        seq=row.seq,
        type=row.type,
        key_id=row.key_id,
        created_at=row.created_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        prev_hash=row.prev_hash,
        envelope=row.envelope,
        hash=row.hash,
        sig=row.sig,
    )


def entries_after(session: Session, after: int, limit: int) -> list[LedgerEntry]:
    return list(
        session.scalars(
            select(LedgerEntry)
            .where(LedgerEntry.seq > after)
            .order_by(LedgerEntry.seq)
            .limit(limit)
        )
    )


# --- tree views ---


def latest_checkpoint(session: Session) -> Checkpoint | None:
    return session.scalars(select(Checkpoint).order_by(Checkpoint.size.desc()).limit(1)).first()


def inclusion_proof(session: Session, seq: int, size: int) -> list[bytes]:
    return merkle.inclusion_proof(DbNodeStore(session), seq - 1, size)


def consistency_proof(session: Session, old: int, new: int) -> list[bytes]:
    return merkle.consistency_proof(DbNodeStore(session), old, new)
