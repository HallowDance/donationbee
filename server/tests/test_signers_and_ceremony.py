"""Online signer backends and the offline root-key ceremony, driven through the real CLI."""

import json
from types import SimpleNamespace

import google_crc32c
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session
from typer.testing import CliRunner
from vpp.cli import app
from vpp.config import get_settings
from vpp.ledger import LedgerKey, verify
from vpp.ledger.kms import GcpKmsSigner
from vpp.ledger.signing import load_root_key, save_root_key
from vpp.ledger.store import key_state
from vpp_verify.core import verify_chain

runner = CliRunner()


class FakeKms:
    """The two KMS RPCs GcpKmsSigner uses, backed by a local key."""

    def __init__(self, name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"):
        self.name = name
        self.key = Ed25519PrivateKey.generate()
        self.corrupt = False

    def get_public_key(self, request):
        pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return SimpleNamespace(pem=pem.decode())

    def asymmetric_sign(self, request):
        assert request["data_crc32c"] == google_crc32c.value(request["data"])
        sig = self.key.sign(request["data"])
        if self.corrupt:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        return SimpleNamespace(
            name=request["name"],
            signature=sig,
            signature_crc32c=google_crc32c.value(self.key.sign(request["data"])),
            verified_data_crc32c=True,
        )


def test_kms_signer_signs_verifiably():
    kms = FakeKms()
    signer = GcpKmsSigner(kms.name, client=kms)
    assert verify(signer.public_key, b"msg", signer.sign(b"msg"))


def test_kms_signer_detects_corruption():
    kms = FakeKms()
    kms.corrupt = True
    with pytest.raises(RuntimeError, match="corrupted"):
        GcpKmsSigner(kms.name, client=kms).sign(b"msg")


def test_kms_signer_runs_a_ledger(engine):
    from vpp.testing.ledger import genesis

    signer = GcpKmsSigner(FakeKms().name, client=FakeKms())
    with Session(engine) as s:
        genesis(s, signer)
        s.commit()


def test_root_key_file_roundtrip(tmp_path):
    k = LedgerKey.generate()
    save_root_key(k, tmp_path / "r.json", b"correct horse")
    assert load_root_key(tmp_path / "r.json", b"correct horse").public_key == k.public_key
    from nacl.exceptions import CryptoError

    with pytest.raises(CryptoError):
        load_root_key(tmp_path / "r.json", b"wrong")
    assert bytes(k.signing_key).hex() not in (tmp_path / "r.json").read_text()


@pytest.fixture
def cli_env(engine, tmp_path, monkeypatch):
    monkeypatch.setenv("VPP_DATABASE_URL", engine.url.render_as_string(hide_password=False))
    monkeypatch.setenv("VPP_SIGNING_KEY_PATH", str(tmp_path / "online.key"))
    monkeypatch.setenv("VPP_ROOT_PASSPHRASE", "test-only")
    get_settings.cache_clear()
    from vpp import db, deps

    db.get_engine.cache_clear()
    deps.get_ledger_key.cache_clear()
    yield tmp_path
    db.get_engine.cache_clear()
    deps.get_ledger_key.cache_clear()
    get_settings.cache_clear()


def run(*args) -> str:
    r = runner.invoke(app, list(args))
    assert r.exit_code == 0, r.output
    return r.output.strip()


def test_full_ceremony(cli_env, engine):
    """3 root keys, 2-of-3 genesis, then a rotation signed by a different pair."""
    d = cli_env
    roots = [run("root", "keygen", str(d / f"root{i}.json")) for i in range(3)]
    run("keygen")
    online = LedgerKey.load(d / "online.key").public_key.hex()
    sigs = [run("root", "sign-genesis", str(d / f"root{i}.json"), online) for i in (0, 1)]
    out = run(
        "init-ledger",
        *sum((["--root-key", r] for r in roots), []),
        "--threshold",
        "2",
        *sum((["--root-sig", sg] for sg in sigs), []),
    )
    assert "genesis hash" in out

    info = json.loads(run("ceremony-info"))
    assert info["root_threshold"] == 2 and info["online_key"] == online

    new = LedgerKey.generate()
    new.save(d / "online2.key")
    rsigs = [
        run("root", "sign-rotation", str(d / f"root{i}.json"), online, new.public_key.hex())
        for i in (1, 2)
    ]
    run(
        "rotate-key",
        "--new-key-file",
        str(d / "online2.key"),
        "--reason",
        "lost",
        *sum((["--root-sig", sg] for sg in rsigs), []),
    )

    with Session(engine) as s:
        assert key_state(s).online_key == new.public_key
        from vpp.ledger.store import entries_after, to_entry
        from vpp.ledger.wire import to_wire

        state = verify_chain([to_wire(to_entry(r)) for r in entries_after(s, 0, 100)])
        assert state.online_key == new.public_key


def test_ceremony_rejects_single_root(cli_env):
    d = cli_env
    roots = [run("root", "keygen", str(d / f"root{i}.json")) for i in range(3)]
    run("keygen")
    online = LedgerKey.load(d / "online.key").public_key.hex()
    sig = run("root", "sign-genesis", str(d / "root0.json"), online)
    r = runner.invoke(
        app,
        [
            "init-ledger",
            *sum((["--root-key", x] for x in roots), []),
            "--threshold",
            "2",
            "--root-sig",
            sig,
        ],
    )
    assert r.exit_code != 0 and "threshold" in repr(r.exception)


def test_demo_seed_builds_a_verifiable_ledger(engine, key):
    from vpp import demo
    from vpp.ledger.store import entries_after, to_entry
    from vpp.ledger.wire import to_wire

    with Session(engine) as s:
        out = demo.seed(s, key)
        state = verify_chain([to_wire(to_entry(r)) for r in entries_after(s, 0, 100)])
    assert state.seq == out["entries"] and len(state.payments) == 7
    assert len(state.confirmed) == 3  # Ada, Grace, Indie Hacker Co.
    with Session(engine) as s, pytest.raises(RuntimeError, match="not empty"):
        demo.seed(s, key)
