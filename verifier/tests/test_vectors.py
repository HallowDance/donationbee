import json
from pathlib import Path

import pytest
from vpp_verify.cli import main
from vpp_verify.core import VerificationError, checkpoint_key, verify_chain, verify_commitment
from vpp_verify.note import Checkpoint, Note, Verifier, verify_note_signature

VECTORS = Path(__file__).resolve().parents[2] / "testvectors"
VALID = json.loads((VECTORS / "chain_v1_valid.json").read_text())
INVALID = json.loads((VECTORS / "chain_v1_invalid.json").read_text())


def test_valid_chain():
    state = verify_chain(VALID["entries"], pinned_genesis=bytes.fromhex(VALID["genesis_hash"]))
    assert state.seq == 7
    assert state.head.hex() == VALID["entries"][-1]["hash"]
    assert state.confirmed == {3: [5]}
    assert state.root_threshold == 2


def test_pinned_genesis_mismatch():
    with pytest.raises(VerificationError) as e:
        verify_chain(VALID["entries"], pinned_genesis=bytes(32))
    assert e.value.seq == 1


@pytest.mark.parametrize("case", INVALID, ids=lambda c: c["name"])
def test_invalid_chains(case):
    with pytest.raises(VerificationError) as e:
        verify_chain(case["entries"])
    assert e.value.seq == case["fail_seq"], str(e.value)


@pytest.mark.parametrize("cp", VALID["checkpoints"], ids=lambda c: f"size{c['size']}")
def test_checkpoints_signed_by_key_active_at_that_size(cp):
    state = verify_chain(VALID["entries"])
    note = Note.parse(cp["note"])
    v = Verifier(VALID["origin"], 0x01, checkpoint_key(state, cp["size"]))
    assert verify_note_signature(note, v)
    parsed = Checkpoint.parse(note.text)
    assert parsed.root == state.root_at(cp["size"]) == bytes.fromhex(cp["root"])


def test_commitment():
    pii = VALID["pii"]
    assert verify_commitment(pii["commitment"], pii["value"], bytes.fromhex(pii["salt"]))
    assert not verify_commitment(pii["commitment"], "Someone Else", bytes.fromhex(pii["salt"]))


def test_cli_file(tmp_path):
    assert main(["--file", str(VECTORS / "chain_v1_valid.json")]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"entries": INVALID[0]["entries"]}))
    assert main(["--file", str(bad)]) == 1


def test_check_domains():
    import httpx
    from vpp_verify.cli import check_domains

    state = verify_chain(VALID["entries"])
    fp = state.recipient_keys["prof_charity"][next(iter(state.recipient_keys["prof_charity"]))][
        "fingerprint"
    ]

    def serve(keys):
        def handler(request):
            assert str(request.url) == "https://charity.test/.well-known/vpp.json"
            return httpx.Response(
                200,
                json={"vpp": 1, "log": VALID["origin"], "profile": "prof_charity", "keys": keys},
            )

        return httpx.Client(transport=httpx.MockTransport(handler))

    assert check_domains(state, serve([fp])) == ["prof_charity @ charity.test: key listed"]
    assert check_domains(state, serve([])) == ["prof_charity @ charity.test: KEY NOT LISTED"]


def _fake_ots(responses):
    """Stand in for the `ots` CLI: map the first distinguishing arg to (code, output)."""

    def run(*args):
        return responses["--no-bitcoin" if args[0] == "--no-bitcoin" else "verify"]

    return run


def _explorer(merkle_root):
    import httpx

    def handler(request):
        if "/block-height/" in str(request.url):
            return httpx.Response(200, text="00000000000000000001abc")
        return httpx.Response(200, json={"merkle_root": merkle_root})

    return httpx.Client(transport=httpx.MockTransport(handler))


ROOT = "ab" * 32
# Real output of opentimestamps-client 0.8.0 with no node configured, and an older wording.
NO_NODE_MESSAGES = [
    "Could not connect to Bitcoin node: Cookie file unusable ([Errno 2] No such file or "
    "directory: '/home/u/.bitcoin/.cookie') and rpcpassword not specified in the "
    "configuration file: '/home/u/.bitcoin/bitcoin.conf'",
    "Could not connect to local Bitcoin node: [Errno 111] Connection refused",
]
CLAIM = (
    1,
    "Not checking Bitcoin attestation; Bitcoin disabled\n"
    f"To verify manually, check that Bitcoin block 871234 has merkleroot {ROOT}",
)


@pytest.mark.parametrize("no_node", NO_NODE_MESSAGES)
@pytest.mark.parametrize(
    "merkle, expect",
    [(ROOT, "ok (in Bitcoin block 871234, checked with mempool.space)"), ("cd" * 32, None)],
)
def test_ots_without_local_node_checks_public_explorer(
    tmp_path, monkeypatch, merkle, expect, no_node
):
    from vpp_verify import cli

    target, proof = tmp_path / "13.checkpoint", tmp_path / "13.checkpoint.ots"
    target.write_text("x")
    proof.write_bytes(b"x")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/ots")
    monkeypatch.setattr(
        cli, "_ots", _fake_ots({"verify": (1, no_node), "--no-bitcoin": CLAIM})
    )
    if expect:
        assert cli._ots_verify(target, proof, explorer=_explorer(merkle)) == expect
    else:
        with pytest.raises(cli.Failure, match="doesn't match"):
            cli._ots_verify(target, proof, explorer=_explorer(merkle))


def test_ots_pending_and_node_success(tmp_path, monkeypatch):
    from vpp_verify import cli

    target, proof = tmp_path / "a", tmp_path / "a.ots"
    target.write_text("x")
    proof.write_bytes(b"x")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/ots")
    monkeypatch.setattr(
        cli,
        "_ots",
        _fake_ots(
            {"verify": (1, "Pending confirmation in Bitcoin blockchain"), "--no-bitcoin": CLAIM}
        ),
    )
    assert cli._ots_verify(target, proof).startswith("pending")
    monkeypatch.setattr(
        cli,
        "_ots",
        _fake_ots(
            {
                "verify": (
                    0,
                    "Success! Bitcoin block 871234 attests existence as of 2026-11-10 UTC",
                ),
                "--no-bitcoin": CLAIM,
            }
        ),
    )
    assert cli._ots_verify(target, proof).startswith(
        "ok (in Bitcoin, checked with your Bitcoin node)"
    )
