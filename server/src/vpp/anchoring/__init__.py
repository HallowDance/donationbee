"""Hourly anchoring job: publish the latest (cosigned) checkpoint to git and OpenTimestamps.

The anchors repo holds `<size>.checkpoint` (the signed note, with witness cosignatures) and
`<size>.checkpoint.ots` side by side, so verifiers need nothing from our server to check them.
"""

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Anchor
from ..ledger.store import latest_checkpoint
from ..witnessing import cosigned_note
from . import git_anchor, ots

log = logging.getLogger(__name__)


def anchor_head(session: Session) -> Anchor | None:
    """Anchor the latest checkpoint if it isn't anchored yet. Commits."""
    settings = get_settings()
    cp = latest_checkpoint(session)
    if cp is None:
        return None
    if session.scalar(select(Anchor.id).where(Anchor.size == cp.size)) is not None:
        return None

    note = cosigned_note(session, cp.size).encode()
    anchor = Anchor(size=cp.size)
    session.add(anchor)
    if settings.ots_enabled:
        try:
            anchor.ots_proof = ots.stamp(hashlib.sha256(note).digest())
            anchor.ots_status = "pending"
        except RuntimeError as e:
            log.error("OTS stamping failed for size %s: %s", cp.size, e)
    if settings.anchors_repo_path:
        rel = git_anchor.checkpoint_path(cp.size, datetime.now(UTC))
        files = {rel: note}
        if anchor.ots_proof:
            files[rel.with_name(rel.name + ".ots")] = anchor.ots_proof
        anchor.git_path = str(rel)
        anchor.git_commit = git_anchor.commit_files(
            settings.anchors_repo_path, files, f"checkpoint {cp.size}", push=settings.anchors_push
        )
    session.commit()
    return anchor


def upgrade_pending(session: Session) -> int:
    """Upgrade pending OTS proofs; commit completed ones to the anchors repo."""
    settings = get_settings()
    done: dict[Path, bytes] = {}
    completed = 0
    for a in session.scalars(select(Anchor).where(Anchor.ots_status == "pending")):
        a.ots_proof, complete = ots.upgrade(a.ots_proof)
        if complete:
            a.ots_status = "complete"
            completed += 1
            if a.git_path:
                done[Path(a.git_path + ".ots")] = a.ots_proof
    if done and settings.anchors_repo_path:
        git_anchor.commit_files(
            settings.anchors_repo_path,
            done,
            f"complete {len(done)} OpenTimestamps proof(s)",
            push=settings.anchors_push,
        )
    session.commit()
    return completed
