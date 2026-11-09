"""The trust story end to end: a real witness over HTTP, an independent anchors repo, payer
receipts, and a log that tries to equivocate (show a fork). Nothing here trusts the server."""

import json
import subprocess
import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey
from sqlalchemy.orm import Session, sessionmaker
from vpp import anchoring
from vpp.config import get_settings
from vpp.db import get_session
from vpp.ledger.entries import Money, Payment, StripePaymentEvidence
from vpp.ledger.note import vkey
from vpp.ledger.store import append
from vpp.testing.ledger import ORIGIN, genesis
from vpp.witnessing import WitnessConfig, push
from vpp_verify.cli import main as verify
from vpp_verify.note import Verifier
from vpp_witness.server import Witness, make_handler


def pay(s, key, n, value=1000):
    append(
        s,
        Payment(
            recipient="prof_c",
            amount=Money(value=value, currency="EUR"),
            occurred_at="2026-11-09T12:00:00Z",
            evidence=StripePaymentEvidence(
                account="acct_1",
                payment_intent=f"pi_{n}",
                checkout_session=f"cs_{n}",
                livemode=False,
            ),
        ),
        key,
    )


@pytest.fixture
def witness(tmp_path, key):
    w = Witness(
        name="witness.test/w1",
        key=SigningKey(bytes([9]) * 32),
        logs={ORIGIN: [Verifier.parse(vkey(ORIGIN, key.public_key))]},
        state_dir=tmp_path / "witness",
    )
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(w))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    w.url = f"http://127.0.0.1:{srv.server_address[1]}"
    w.config = WitnessConfig(w.vkey, w.url)
    yield w
    srv.shutdown()


def ledger_with(engine, key, payments):
    with Session(engine) as s:
        genesis(s, key)
        for n, value in payments:
            pay(s, key, n, value)
        s.commit()
    return engine


def client_for(engine):
    from vpp.app import app

    factory = sessionmaker(engine, expire_on_commit=False)

    def override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = override
    return TestClient(app)


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    from vpp.app import app

    app.dependency_overrides.clear()


def do_push(engine, witness) -> str:
    with Session(engine) as s, httpx.Client() as http:
        return push(s, http, [witness.config])[witness.config.verifier.name]


def test_witnessed_ledger_verifies_and_fork_is_caught(make_engine, key, witness, tmp_path):
    honest = ledger_with(make_engine(), key, [(1, 1000), (2, 2000)])
    assert do_push(honest, witness) == "cosigned size 3"

    c = client_for(honest)
    w = str(witness.vkey)
    g = c.get("/api/v1/entries/1").json()["hash"]
    assert (
        verify(
            [
                "--url",
                "http://testserver",
                "--pin-genesis",
                g,
                "--witness",
                w,
                "--min-witnesses",
                "1",
            ],
            client=c,
        )
        == 0
    )

    # The payer of entry 2 keeps a witnessed receipt.
    receipt = tmp_path / "receipt.json"
    receipt.write_text(c.get("/api/v1/receipts/2").text)
    assert json.loads(receipt.read_text())["witness_cosignatures"] == 1

    # Later the log grows; the witness follows via a consistency proof.
    with Session(honest) as s:
        pay(s, key, 3, 500)
        s.commit()
    assert do_push(honest, witness) == "cosigned size 4"
    assert (
        verify(
            [
                "--url",
                "http://testserver",
                "--witness",
                w,
                "--min-witnesses",
                "1",
                "--receipt",
                str(receipt),
            ],
            client=c,
        )
        == 0
    )

    # The operator now serves a *different* history (payment 1 erased, amounts changed) from
    # the same key. The witness refuses to cosign it...
    fork = ledger_with(make_engine(), key, [(2, 2000), (3, 9000), (4, 1)])
    outcome = do_push(fork, witness)
    # (409 tells the fork the witness is at size 4; resubmitting from 4 with another root: 422.)
    assert outcome == "HTTP 422: same size, different root: the log is equivocating", outcome
    fc = client_for(fork)
    # ...so a verifier requiring a witness rejects the fork,
    assert (
        verify(["--url", "http://testserver", "--witness", w, "--min-witnesses", "1"], client=fc)
        == 1
    )
    # and the payer's receipt proves misbehaviour: the log signed a checkpoint containing
    # entry 2, but the history it now serves disagrees.
    assert verify(["--url", "http://testserver", "--receipt", str(receipt)], client=fc) == 1


def test_anchors_repo_is_checked_independently(make_engine, key, tmp_path, monkeypatch):
    repo = tmp_path / "anchors"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for k, v in (("user.name", "vpp"), ("user.email", "vpp@localhost")):
        subprocess.run(["git", "-C", str(repo), "config", k, v], check=True)
    monkeypatch.setenv("VPP_ANCHORS_REPO_PATH", str(repo))
    monkeypatch.setenv("VPP_OTS_ENABLED", "false")
    get_settings.cache_clear()

    honest = ledger_with(make_engine(), key, [(1, 1000)])
    with Session(honest) as s:
        anchoring.anchor_head(s)
        pay(s, key, 2, 2000)
        s.commit()
        anchoring.anchor_head(s)
    c = client_for(honest)
    assert verify(["--url", "http://testserver", "--anchors-repo", str(repo)], client=c) == 0

    # A rewritten history can't match anchors already published elsewhere.
    fork = ledger_with(make_engine(), key, [(1, 1000), (9, 1)])
    fc = client_for(fork)
    assert verify(["--url", "http://testserver", "--anchors-repo", str(repo)], client=fc) == 1


def test_receipt_offline_inclusion(make_engine, key, tmp_path):
    from vpp_verify.cli import verify_receipt

    honest = ledger_with(make_engine(), key, [(1, 1000), (2, 2000), (3, 3000)])
    r = client_for(honest).get("/api/v1/receipts/3").json()
    assert verify_receipt(r, None, [], 0, None, None)[0].startswith("receipt: entry 3")
    r["inclusion_proof"] = r["inclusion_proof"][::-1]
    with pytest.raises(Exception, match="inclusion proof"):
        verify_receipt(r, None, [], 0, None, None)
