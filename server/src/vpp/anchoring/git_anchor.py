"""Git anchoring (LEDGER_SPEC §13). Use a repo hosted where force-pushes are blocked (protected
branch), otherwise an anchor can be rewritten as easily as the ledger it protects."""

import subprocess
from datetime import datetime
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def checkpoint_path(size: int, when: datetime) -> Path:
    return Path("anchors") / f"{when:%Y/%m/%d}" / f"{size}.checkpoint"


def commit_files(repo: Path, files: dict[Path, bytes], message: str, push: bool) -> str:
    """Write `files` (repo-relative path -> bytes), commit, optionally push. Returns the sha."""
    for rel, data in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        _git(repo, "add", str(rel))
    _git(repo, "commit", "-q", "-m", message)
    if push and _git(repo, "remote"):
        _git(repo, "push", "-q")
    return _git(repo, "rev-parse", "HEAD")
