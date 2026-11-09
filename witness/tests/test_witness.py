import base64
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer

import httpx
import pytest
from nacl.signing import SigningKey
from vpp.ledger import merkle
from vpp.ledger.note import checkpoint_text, sign_note, vkey
from vpp_verify.note import Note, Verifier, verify_cosignature
from vpp_witness.server import Reject, Witness, make_handler

ORIGIN = "proofs.test/log"


class FakeLog:
    def __init__(self, n_leaves: int = 0, key: SigningKey | None = None, salt: bytes = b""):
        self.key = key or SigningKey(bytes(32))
        self.store = merkle.MemoryStore()
        self.size = 0
        self.salt = salt
        self.extend(n_leaves)

    @property
    def vkey(self) -> str:
        return vkey(ORIGIN, bytes(self.key.verify_key))

    def extend(self, n: int) -> None:
        for _ in range(n):
            merkle.append_leaf(
                self.store, self.size, hashlib.sha256(self.salt + bytes([self.size])).digest()
            )
            self.size += 1

    def note(self, size: int | None = None) -> str:
        size = self.size if size is None else size
        text = checkpoint_text(ORIGIN, size, merkle.root(self.store, size))
        return sign_note(
            text, ORIGIN, bytes(self.key.verify_key), lambda m: self.key.sign(m).signature
        )

    def request(self, old: int, size: int | None = None) -> str:
        size = self.size if size is None else size
        proof = merkle.consistency_proof(self.store, old, size)
        lines = [f"old {old}", *(base64.b64encode(h).decode() for h in proof)]
        return "\n".join(lines) + "\n\n" + self.note(size)


@pytest.fixture
def log():
    return FakeLog(5)


@pytest.fixture
def witness(tmp_path, log):
    return Witness(
        name="witness.test/w1",
        key=SigningKey(bytes([9]) * 32),
        logs={ORIGIN: [Verifier.parse(log.vkey)]},
        state_dir=tmp_path / "state",
    )


def status(witness, body) -> int:
    try:
        witness.add_checkpoint(body)
        return 200
    except Reject as r:
        return r.status


def test_cosigns_and_cosignature_verifies(witness, log):
    line = witness.add_checkpoint(log.request(0))
    note = Note.parse(log.note() + line)
    assert verify_cosignature(note, witness.vkey) is not None


def test_extends_with_consistency_proof(witness, log):
    witness.add_checkpoint(log.request(0))
    log.extend(9)
    witness.add_checkpoint(log.request(5))
    assert witness.load(ORIGIN)["size"] == 14


def test_stale_old_size_gets_409_with_current_size(witness, log):
    witness.add_checkpoint(log.request(0))
    log.extend(1)
    with pytest.raises(Reject) as e:
        witness.add_checkpoint(log.request(0))
    assert (e.value.status, e.value.message, e.value.content_type) == (
        409,
        "5\n",
        "text/x.tlog.size",
    )


def test_fork_is_refused(witness, log):
    """The log shows the witness one history, then tries another of the same size."""
    witness.add_checkpoint(log.request(0))
    fork = FakeLog(5, key=log.key, salt=b"fork")
    assert status(witness, fork.request(5)) == 422
    fork.extend(3)
    # Extending a fork can't produce a valid consistency proof from the witnessed root.
    assert status(witness, fork.request(5)) == 422
    assert witness.load(ORIGIN)["size"] == 5


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda b: b.replace("old 0", "old 9"), 400),  # old > size
        (lambda b: b.replace("old 0", "old 00"), 400),  # malformed
        (lambda b: b.replace(ORIGIN, "other.test/log"), 404),  # unknown origin (sig irrelevant)
        (lambda b: b.replace("\n5\n", "\n6\n", 1), 403),  # tampered → signature fails
    ],
)
def test_error_codes(witness, log, mutate, code):
    assert status(witness, mutate(log.request(0))) == code


def test_untrusted_log_key_is_403(witness):
    impostor = FakeLog(5, key=SigningKey(bytes([1]) * 32))
    assert status(witness, impostor.request(0)) == 403


def test_nonempty_proof_with_old_zero_is_422(witness, log):
    body = log.request(0).replace(
        "old 0\n", "old 0\n" + base64.b64encode(bytes(32)).decode() + "\n"
    )
    assert status(witness, body) == 422


def test_concurrent_requests_cannot_roll_back(witness, log):
    """Two submissions racing from the same old size: exactly one wins."""
    witness.add_checkpoint(log.request(0))
    log.extend(4)
    body = log.request(5)
    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(lambda _: status(witness, body), range(8)))
    assert codes.count(200) == 1 and codes.count(409) == 7


def test_http_roundtrip(witness, log):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(witness))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        r = httpx.post(f"{base}/add-checkpoint", content=log.request(0))
        assert r.status_code == 200 and r.text.startswith("— witness.test/w1 ")
        r = httpx.post(f"{base}/add-checkpoint", content=log.request(0))
        assert r.status_code == 409 and r.text == "5\n"
        assert r.headers["content-type"].startswith("text/x.tlog.size")
        h = hashlib.sha256(ORIGIN.encode()).hexdigest()
        got = Note.parse(httpx.get(f"{base}/{h}/checkpoint").text)
        assert verify_cosignature(got, witness.vkey)
    finally:
        srv.shutdown()
