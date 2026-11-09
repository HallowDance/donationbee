import subprocess

import pytest
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.timestamp import Timestamp
from sqlalchemy.orm import Session
from vpp import anchoring
from vpp.anchoring import ots
from vpp.config import get_settings


def fake_submit(url: str, msg: bytes) -> Timestamp:
    t = Timestamp(msg)
    t.attestations.add(PendingAttestation(url))
    return t


def test_ots_stamp_is_pending_and_commits_to_digest():
    digest = bytes(range(32))
    proof = ots.stamp(digest, calendars=["https://a.example"], submit=fake_submit)
    dtf = ots._deserialize(proof)
    assert dtf.file_digest == digest
    assert not ots.is_complete(proof)


def test_ots_all_calendars_down():
    def down(url, msg):
        raise OSError("unreachable")

    with pytest.raises(RuntimeError):
        ots.stamp(bytes(32), calendars=["https://a.example"], submit=down)


@pytest.fixture
def anchors_repo(tmp_path, monkeypatch):
    repo = tmp_path / "anchors"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for k, v in (("user.name", "vpp"), ("user.email", "vpp@localhost")):
        subprocess.run(["git", "-C", str(repo), "config", k, v], check=True)
    monkeypatch.setenv("VPP_ANCHORS_REPO_PATH", str(repo))
    monkeypatch.setenv("VPP_OTS_ENABLED", "true")
    monkeypatch.setattr(ots, "stamp", lambda d: b"proof-" + d[:4])  # no network in tests
    get_settings.cache_clear()
    yield repo
    get_settings.cache_clear()


def test_anchor_head_writes_checkpoint_and_ots(ledger, anchors_repo):
    from vpp.ledger.store import latest_checkpoint

    with Session(ledger) as s:
        a = anchoring.anchor_head(s)
        cp = latest_checkpoint(s)
        assert a.size == cp.size == 1
        assert a.ots_status == "pending" and a.git_commit
        # Nothing new -> nothing to anchor.
        assert anchoring.anchor_head(s) is None

    files = sorted(p.name for p in anchors_repo.glob("anchors/*/*/*/*"))
    assert files == ["1.checkpoint", "1.checkpoint.ots"]
    assert next(anchors_repo.glob("anchors/*/*/*/1.checkpoint")).read_text() == cp.note
    log = subprocess.run(
        ["git", "-C", str(anchors_repo), "log", "--oneline"], capture_output=True, text=True
    ).stdout
    assert "checkpoint 1" in log
