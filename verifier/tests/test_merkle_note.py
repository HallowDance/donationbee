"""Verifier primitives against the RFC definitions, the C2SP vector, and the server's builder."""

import hashlib

import pytest
from nacl.signing import SigningKey
from vpp_verify import merkle as vm
from vpp_verify.note import (
    Checkpoint,
    Note,
    NoteError,
    Verifier,
    verify_cosignature,
    verify_note_signature,
)


def naive_mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 §2.1, literally."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return vm.node_hash(naive_mth(leaves[:k]), naive_mth(leaves[k:]))


LEAVES = [vm.leaf_hash(hashlib.sha256(bytes([i])).digest()) for i in range(70)]


@pytest.mark.parametrize("n", range(71))
def test_root_matches_naive(n):
    assert vm.root_from_leaves(LEAVES[:n]) == naive_mth(LEAVES[:n])


def test_server_proofs_verify_in_verifier():
    """Server builds proofs from stored nodes; the independent verifier must accept them."""
    from vpp.ledger import merkle as sm

    store = sm.MemoryStore()
    entry_hashes = [hashlib.sha256(bytes([i])).digest() for i in range(70)]
    for i, h in enumerate(entry_hashes):
        sm.append_leaf(store, i, h)
    for n in range(1, 71):
        r = sm.root(store, n)
        assert r == naive_mth(LEAVES[:n])
        for i in range(n):
            proof = sm.inclusion_proof(store, i, n)
            assert vm.verify_inclusion(LEAVES[i], i, n, proof, r)
            assert not vm.verify_inclusion(LEAVES[i], (i + 1) % n, n, proof, r) or n == 1
        for m in range(0, n + 1):
            proof = sm.consistency_proof(store, m, n)
            assert vm.verify_consistency(m, n, sm.root(store, m), r, proof), (m, n)
            if 0 < m < n:
                assert not vm.verify_consistency(m, n, bytes(32), r, proof)
                assert not vm.verify_consistency(m, n, sm.root(store, m), bytes(32), proof)


def test_consistency_edge_cases():
    r = LEAVES[0]
    assert vm.verify_consistency(0, 5, vm.EMPTY_ROOT, r, [])
    assert not vm.verify_consistency(0, 5, vm.EMPTY_ROOT, r, [r])  # tlog-witness: 422
    assert not vm.verify_consistency(3, 3, r, LEAVES[1], [])
    assert not vm.verify_consistency(4, 3, r, r, [])


# --- C2SP signed-note (vector from https://c2sp.org/signed-note) ---
C2SP_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
C2SP_NOTE = (
    "This is an example message.\n\n"
    "— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3"
    "mFXmRKuwHjG1Yu72IneyaQM=\n"
)


def test_c2sp_signed_note_vector():
    v = Verifier.parse(C2SP_VKEY)
    note = Note.parse(C2SP_NOTE)
    assert note.text == "This is an example message.\n"
    assert verify_note_signature(note, v)
    assert str(note) == C2SP_NOTE


def test_c2sp_vector_tampered():
    v = Verifier.parse(C2SP_VKEY)
    with pytest.raises(NoteError):
        verify_note_signature(
            Note.parse(C2SP_NOTE.replace("example message", "exemple message")), v
        )


def test_unknown_key_ignored():
    other = SigningKey.generate()
    v = Verifier("example.com/foo", 0x01, bytes(other.verify_key))
    assert not verify_note_signature(Note.parse(C2SP_NOTE), v)


def test_server_signed_checkpoint_and_cosignature_roundtrip():
    import struct

    from vpp.ledger.note import checkpoint_text, sign_note, vkey
    from vpp_verify.note import SIG_COSIGNATURE_ED25519, cosignature_message, key_id

    log = SigningKey.generate()
    text = checkpoint_text("proofs.example/log", 5, LEAVES[0])
    raw = sign_note(
        text, "proofs.example/log", bytes(log.verify_key), lambda m: log.sign(m).signature
    )
    note = Note.parse(raw)
    assert verify_note_signature(
        note, Verifier.parse(vkey("proofs.example/log", bytes(log.verify_key)))
    )
    cp = Checkpoint.parse(note.text)
    assert (cp.origin, cp.size, cp.root) == ("proofs.example/log", 5, LEAVES[0])

    # A witness cosignature per c2sp.org/tlog-cosignature, built by hand from the spec.
    w = SigningKey.generate()
    wpub = bytes(w.verify_key)
    ts = 1762689600
    sig = w.sign(cosignature_message(note.text, ts)).signature
    import base64

    blob = key_id("witness.example", SIG_COSIGNATURE_ED25519, wpub) + struct.pack(">Q", ts) + sig
    cosigned = Note.parse(raw + f"— witness.example {base64.b64encode(blob).decode()}\n")
    wv = Verifier("witness.example", SIG_COSIGNATURE_ED25519, wpub)
    assert verify_cosignature(cosigned, wv) == ts
    assert Verifier.parse(str(wv)) == wv


@pytest.mark.parametrize(
    "text",
    ["o\n5\n", "o\n05\nAAAA\n", "o\n5\nAAAA\n", "o\n5\n" + "A" * 43 + "=\nno-newline"],
)
def test_bad_checkpoints(text):
    with pytest.raises(NoteError):
        Checkpoint.parse(text)
