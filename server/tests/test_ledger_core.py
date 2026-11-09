import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from vpp.ledger import GENESIS_PREV, LedgerKey, build_entry, verify
from vpp.ledger.canonical import CanonicalError, canonicalize
from vpp.ledger.entries import Genesis, Money, Payment
from vpp.ledger.signing import genesis_statement
from vpp.ledger.wire import to_wire
from vpp.pii import commit, opens
from vpp.testing.ledger import ORIGIN, ROOTS, root_sigs


def genesis_body(key: LedgerKey) -> Genesis:
    return Genesis(
        origin=ORIGIN,
        online_key=key.public_key.hex(),
        root_keys=[r.public_key.hex() for r in ROOTS],
        root_threshold=2,
        root_sigs=root_sigs(genesis_statement(ORIGIN, key.public_key)),
    )


VECTORS = Path(__file__).resolve().parents[2] / "testvectors"
T = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def test_rejects_floats_and_big_ints():
    with pytest.raises(CanonicalError):
        canonicalize({"a": 1.5})
    with pytest.raises(CanonicalError):
        canonicalize({"a": 2**53})


def test_canonical_is_key_order_independent():
    assert canonicalize({"b": 1, "a": [1, {"d": 0, "c": None}]}) == canonicalize(
        {"a": [1, {"c": None, "d": 0}], "b": 1}
    )


def test_money_rejects_float():
    with pytest.raises(ValueError):
        Money(value=10.5, currency="EUR")


def test_payment_rejects_unknown_fields():
    with pytest.raises(ValueError):
        Payment.model_validate({"recipient": "x", "secret_name": "Bob"})


def test_genesis_only_at_seq_1():
    key = LedgerKey.generate()
    with pytest.raises(ValueError):
        build_entry(
            seq=2,
            prev_hash=GENESIS_PREV,
            body=genesis_body(key),
            key=key,
            created_at=T,
        )


def test_hash_matches_spec_formula():
    key = LedgerKey.generate()
    e = build_entry(
        seq=1,
        prev_hash=GENESIS_PREV,
        body=genesis_body(key),
        key=key,
        created_at=T,
    )
    assert e.hash == hashlib.sha256(b"vpp:entry:v1\x00" + bytes(32) + e.envelope).digest()
    assert verify(key.public_key, e.hash, e.sig)


def test_server_reproduces_committed_vectors():
    """The server must generate byte-identical vectors from the fixed seeds."""
    valid = json.loads((VECTORS / "chain_v1_valid.json").read_text())
    key = LedgerKey.from_seed(bytes(range(32)))
    genesis = build_entry(
        seq=1,
        prev_hash=GENESIS_PREV,
        body=genesis_body(key),
        key=key,
        created_at=datetime(2026, 11, 9, 12, 1, tzinfo=UTC),
    )
    assert to_wire(genesis, convenience=False) == valid["entries"][0]


def test_pii_commitment():
    c, salt = commit("Ada Lovelace")
    assert opens(c, "Ada Lovelace", salt)
    assert not opens(c, "Ada Lovelac", salt)
