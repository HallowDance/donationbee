"""Chain verification, implemented from docs/LEDGER_SPEC.md only. Must not import `vpp`."""

import base64
import hashlib
import json
from dataclasses import dataclass, field

import rfc8785
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from . import merkle
from .webauthn import WebAuthnError, b64url_decode, fingerprint, load_key, verify_assertion

DOMAIN = b"vpp:entry:v1\x00"
ZERO = bytes(32)
MAX_SAFE_INT = 2**53 - 1


class VerificationError(Exception):
    def __init__(self, seq: int, message: str):
        super().__init__(f"seq {seq}: {message}")
        self.seq = seq
        self.message = message


@dataclass
class ChainState:
    """Everything a verifier needs to resume from a trusted point."""

    seq: int = 0
    head: bytes = ZERO
    origin: str | None = None
    online_key: bytes | None = None
    root_keys: list[str] = field(default_factory=list)
    root_threshold: int = 0
    used_online_keys: set[bytes] = field(default_factory=set)
    used_root_sets: set[tuple] = field(default_factory=set)
    # seq -> online key that signed it; checkpoints of size n are signed by keys[n].
    signer_at: dict[int, bytes] = field(default_factory=dict)
    hashes: dict[int, bytes] = field(default_factory=dict)
    leaves: list[bytes] = field(default_factory=list)  # RFC 6962 leaf hashes
    payments: dict[int, dict] = field(default_factory=dict)
    recipient_keys: dict[str, dict[str, dict]] = field(default_factory=dict)  # rcpt -> cred -> body
    confirmed: dict[int, list[int]] = field(
        default_factory=dict
    )  # payment seq -> confirmation seqs

    @property
    def root(self) -> bytes:
        return merkle.root_from_leaves(self.leaves)

    def root_at(self, size: int) -> bytes:
        return merkle.root_from_leaves(self.leaves[:size])


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).digest()[:8].hex()


def _origin_hash(origin: str) -> bytes:
    return hashlib.sha256(origin.encode()).digest()


def _ed25519_ok(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(pub).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError):
        return False


def _root_sig_count(stmt: bytes, root_sigs: list[dict], allowed: list[str]) -> int:
    ok = set()
    for rs in root_sigs:
        k = rs["key"]
        if (
            k in allowed
            and k not in ok
            and _ed25519_ok(bytes.fromhex(k), stmt, bytes.fromhex(rs["sig"]))
        ):
            ok.add(k)
    return len(ok)


def confirmation_challenge(origin: str, entry_hashes: list[bytes]) -> bytes:
    return hashlib.sha256(
        b"vpp:confirm:v1\x00" + _origin_hash(origin) + b"".join(entry_hashes)
    ).digest()


def _no_floats(value, seq: int) -> None:
    if isinstance(value, float):
        raise VerificationError(seq, "envelope contains a float")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_SAFE_INT:
        raise VerificationError(seq, "envelope integer exceeds 2^53-1")
    if isinstance(value, dict):
        for v in value.values():
            _no_floats(v, seq)
    elif isinstance(value, list):
        for v in value:
            _no_floats(v, seq)


def verify_entry(state: ChainState, wire: dict) -> None:
    """Check one wire entry against the state and advance it. Raises VerificationError."""
    seq = wire.get("seq")
    expected_seq = state.seq + 1
    if seq != expected_seq:
        raise VerificationError(seq if isinstance(seq, int) else -1, f"expected seq {expected_seq}")

    prev_hash = bytes.fromhex(wire["prev_hash"])
    if prev_hash != state.head:
        raise VerificationError(seq, "prev_hash does not match previous entry's hash")

    envelope = _b64url_decode(wire["envelope"])
    try:
        env = json.loads(envelope)
    except ValueError as e:
        raise VerificationError(seq, f"envelope is not JSON: {e}") from None
    _no_floats(env, seq)
    if rfc8785.dumps(env) != envelope:
        raise VerificationError(seq, "envelope is not RFC 8785 canonical")
    if env.get("v") != 1:
        raise VerificationError(seq, f"unsupported version {env.get('v')!r}")
    if env.get("seq") != seq:
        raise VerificationError(seq, "envelope seq does not match position")

    computed = hashlib.sha256(DOMAIN + prev_hash + envelope).digest()
    if computed.hex() != wire["hash"]:
        raise VerificationError(seq, "hash mismatch")

    entry_type = env.get("type")
    body = env.get("body", {})
    try:
        signer = _authority(state, seq, entry_type, body)
        if env.get("key_id") != _key_id(signer):
            raise VerificationError(seq, "key_id is not the authorized key")
        if not _ed25519_ok(signer, computed, bytes.fromhex(wire["sig"])):
            raise VerificationError(seq, "bad signature")
        _check_semantics(state, seq, entry_type, body)
    except (KeyError, TypeError, ValueError) as e:
        raise VerificationError(seq, f"malformed {entry_type} body: {e!r}") from None

    state.seq = seq
    state.head = computed
    state.hashes[seq] = computed
    state.leaves.append(merkle.leaf_hash(computed))
    state.signer_at[seq] = signer
    state.used_online_keys.add(signer)


def _authority(state: ChainState, seq: int, entry_type: str, body: dict) -> bytes:
    """Return the key that must have signed this entry, applying key changes (LEDGER_SPEC §5)."""
    if seq == 1:
        if entry_type != "genesis":
            raise VerificationError(seq, "first entry must be genesis")
        keys, thr = body["root_keys"], body["root_threshold"]
        if len(set(keys)) != len(keys) or not 1 <= thr <= len(keys):
            raise VerificationError(seq, "invalid root key set")
        online = bytes.fromhex(body["online_key"])
        stmt = b"vpp:genesis:v1\x00" + _origin_hash(body["origin"]) + online
        if _root_sig_count(stmt, body["root_sigs"], keys) < thr:
            raise VerificationError(seq, "genesis lacks root-key threshold")
        state.origin, state.online_key = body["origin"], online
        state.root_keys, state.root_threshold = keys, thr
        state.used_root_sets.add((tuple(sorted(keys)), thr))
        return online
    if entry_type == "genesis":
        raise VerificationError(seq, "genesis after seq 1")

    if entry_type == "key_rotation":
        new = bytes.fromhex(body["new_online_key"])
        if bytes.fromhex(body["from_online_key"]) != state.online_key:
            raise VerificationError(seq, "rotation does not replace the active key")
        if new in state.used_online_keys:
            raise VerificationError(seq, "online key reused")
        stmt = b"vpp:rotate:v1\x00" + _origin_hash(state.origin) + state.online_key + new
        if _root_sig_count(stmt, body["root_sigs"], state.root_keys) < state.root_threshold:
            raise VerificationError(seq, "rotation lacks root-key threshold")
        state.online_key = new
        return new  # signed by the new key

    if entry_type == "root_rotation":
        keys, thr = body["new_root_keys"], body["new_root_threshold"]
        if len(set(keys)) != len(keys) or not 1 <= thr <= len(keys):
            raise VerificationError(seq, "invalid new root key set")
        if (tuple(sorted(keys)), thr) in state.used_root_sets:
            raise VerificationError(seq, "root key set reused")
        sets = {
            "from": {"keys": sorted(state.root_keys), "threshold": state.root_threshold},
            "to": {"keys": sorted(keys), "threshold": thr},
        }
        stmt = b"vpp:root-rotate:v1\x00" + _origin_hash(state.origin) + rfc8785.dumps(sets)
        if _root_sig_count(stmt, body["root_sigs"], state.root_keys) < state.root_threshold:
            raise VerificationError(seq, "root rotation lacks old root threshold")
        state.root_keys, state.root_threshold = keys, thr
        state.used_root_sets.add((tuple(sorted(keys)), thr))
    return state.online_key


def _check_semantics(state: ChainState, seq: int, entry_type: str, body: dict) -> None:
    if entry_type == "payment":
        amt = body["amount"]
        state.payments[seq] = {
            "currency": amt["currency"],
            "value": amt["value"],
            "reversed": 0,
            "recipient": body["recipient"],
        }
    elif entry_type == "reversal":
        ref = state.payments.get(body["ref_seq"])
        if ref is None:
            raise VerificationError(seq, "reversal does not reference an earlier payment")
        if body["amount"]["currency"] != ref["currency"]:
            raise VerificationError(seq, "reversal currency differs from payment")
        ref["reversed"] += body["amount"]["value"]
        if ref["reversed"] > ref["value"]:
            raise VerificationError(seq, "reversals exceed payment amount")
    elif entry_type == "correction":
        if not 1 <= body["ref_seq"] < seq:
            raise VerificationError(seq, "correction must reference an earlier entry")
    elif entry_type == "recipient_key":
        spki = b64url_decode(body["public_key_spki"])
        try:
            load_key(spki, body["alg"])
        except (WebAuthnError, ValueError) as e:
            raise VerificationError(seq, f"recipient key unusable: {e}") from None
        if body["fingerprint"] != fingerprint(spki):
            raise VerificationError(seq, "recipient key fingerprint mismatch")
        state.recipient_keys.setdefault(body["recipient"], {})[body["credential_id"]] = body
    elif entry_type == "confirmation":
        _check_confirmation(state, seq, body)
    elif entry_type not in ("genesis", "key_rotation", "root_rotation"):
        raise VerificationError(seq, f"unknown entry type {entry_type!r}")


def _check_confirmation(state: ChainState, seq: int, body: dict) -> None:
    rcpt = body["recipient"]
    key = state.recipient_keys.get(rcpt, {}).get(body["credential_id"])
    if key is None:
        raise VerificationError(seq, "confirmation by an unregistered recipient key")
    refs = body["ref_seqs"]
    if not refs or len(set(refs)) != len(refs):
        raise VerificationError(seq, "confirmation needs distinct ref_seqs")
    for r in refs:
        p = state.payments.get(r)
        if p is None or p["recipient"] != rcpt:
            raise VerificationError(seq, f"seq {r} is not a payment to {rcpt}")
    challenge = confirmation_challenge(state.origin, [state.hashes[r] for r in refs])
    try:
        verify_assertion(
            spki_der=b64url_decode(key["public_key_spki"]),
            alg=key["alg"],
            rp_id=key["rp_id"],
            origin=key["origin"],
            challenge=challenge,
            authenticator_data=b64url_decode(body["authenticator_data"]),
            client_data_json=b64url_decode(body["client_data_json"]),
            signature=b64url_decode(body["signature"]),
        )
    except WebAuthnError as e:
        raise VerificationError(seq, f"confirmation assertion invalid: {e}") from None
    for r in refs:
        state.confirmed.setdefault(r, []).append(seq)


def verify_chain(entries: list[dict], *, pinned_genesis: bytes | None = None) -> ChainState:
    state = ChainState()
    for wire in entries:
        verify_entry(state, wire)
        if state.seq == 1 and pinned_genesis is not None and state.head != pinned_genesis:
            raise VerificationError(1, "genesis hash does not match the pinned value")
    return state


def checkpoint_key(state: ChainState, size: int) -> bytes:
    """The online key that signed the checkpoint for `size` (the signer of entry `size`)."""
    if size not in state.signer_at:
        raise VerificationError(size, "checkpoint beyond verified entries")
    return state.signer_at[size]


def verify_commitment(commitment: str, value: str, salt: bytes) -> bool:
    return commitment == "c1:" + hashlib.sha256(salt + value.encode()).hexdigest()
