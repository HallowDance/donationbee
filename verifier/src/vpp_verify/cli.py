"""vpp-verify: check a VPP ledger without trusting the server that serves it.

Trust comes from: a pinned genesis hash, witness cosignatures (--witness), an independently
hosted anchors repo (--anchors-repo) and Bitcoin (--check-ots), and recipients' own domains
(--check-domains). The server only supplies data; every claim is recomputed here.
"""

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

from . import merkle
from .core import ChainState, VerificationError, checkpoint_key, verify_entry
from .note import Checkpoint, Note, NoteError, Verifier, verify_cosignature, verify_note_signature


class Failure(Exception):
    pass


# --- data sources ---


def _fetch_entries(client: httpx.Client, base: str, up_to: int | None = None):
    after = 0
    while up_to is None or after < up_to:
        page = client.get(f"{base}/api/v1/entries", params={"after": after, "limit": 500}).json()
        yield from page["entries"]
        if not page.get("next_after"):
            return
        after = page["next_after"]


def _fetch_checkpoint(client: httpx.Client, base: str) -> Note:
    r = client.get(f"{base}/api/v1/checkpoint")
    r.raise_for_status()
    return Note.parse(r.text)


# --- checks ---


def check_log_signature(state: ChainState, note: Note) -> Checkpoint:
    cp = Checkpoint.parse(note.text)
    if cp.origin != state.origin:
        raise Failure(f"checkpoint origin {cp.origin!r} is not this ledger ({state.origin!r})")
    if cp.size > state.seq:
        raise Failure(f"checkpoint size {cp.size} is beyond the {state.seq} verified entries")
    if cp.size == 0:
        raise Failure("empty checkpoint")
    v = Verifier(state.origin, 0x01, checkpoint_key(state, cp.size))
    try:
        if not verify_note_signature(note, v):
            raise Failure(f"checkpoint {cp.size} is not signed by the ledger key for that size")
    except NoteError as e:
        raise Failure(str(e)) from None
    if cp.root != state.root_at(cp.size):
        raise Failure(f"checkpoint {cp.size} root differs from the tree of the served entries")
    return cp


def count_witnesses(note: Note, witnesses: list[Verifier]) -> list[str]:
    ok = []
    for w in witnesses:
        try:
            if verify_cosignature(note, w) is not None:
                ok.append(w.name)
        except NoteError as e:
            raise Failure(f"witness {w.name}: {e}") from None
    return ok


def _anchors_dir(repo: str, workdir: Path) -> Path:
    p = Path(repo)
    if p.is_dir():
        return p
    dest = workdir / "anchors"
    subprocess.run(["git", "clone", "-q", "--depth", "1", repo, str(dest)], check=True)
    return dest


def check_anchors(state: ChainState, repo: Path, check_ots: bool) -> list[str]:
    lines = []
    files = sorted(repo.glob("anchors/**/*.checkpoint"), key=lambda f: int(f.stem))
    if not files:
        raise Failure(f"no anchors found in {repo}")
    for f in files:
        note = Note.parse(f.read_text())
        cp = check_log_signature(state, note)
        status = "matches chain"
        ots_file = f.with_name(f.name + ".ots")
        if check_ots:
            status += ", ots " + _ots_verify(f, ots_file)
        lines.append(f"anchor size {cp.size}: {status}")
    return lines


EXPLORER = "https://mempool.space/api"
_CLAIM = re.compile(r"Bitcoin block (\d+) has merkleroot ([0-9a-f]{64})")
# ots 0.8 says "Could not connect to Bitcoin node: ..."; older releases said "local Bitcoin node".
_NO_NODE = re.compile(r"Could not connect to (local )?Bitcoin node")


def _ots(*args: str) -> tuple[int, str]:
    r = subprocess.run(["ots", *args], capture_output=True, text=True)
    return r.returncode, (r.stderr + r.stdout).strip()


def _ots_verify(target: Path, proof: Path, explorer: httpx.Client | None = None) -> str:
    """Check a proof against a local Bitcoin node if there is one; otherwise against a public
    block explorer, which is independent of the ledger operator (and says so in the result)."""
    if not proof.exists():
        return "missing"
    if not shutil.which("ots"):
        return "skipped (ots not installed)"
    code, out = _ots("verify", "-f", str(target), str(proof))
    if code == 0 and "Success" in out:
        return "ok (in Bitcoin, checked with your Bitcoin node)"
    if "Pending confirmation" in out:
        return "pending (not yet in a Bitcoin block)"
    if not _NO_NODE.search(out):
        raise Failure(f"OpenTimestamps verification failed for {target.name}: {out[:200]}")

    # No local node: ask ots which block the proof claims, then check that block publicly.
    _, out = _ots("--no-bitcoin", "verify", "-f", str(target), str(proof))
    claims = _CLAIM.findall(out)
    if not claims:
        raise Failure(f"OpenTimestamps proof for {target.name} names no Bitcoin block: {out[:200]}")
    own = explorer is None
    explorer = explorer or httpx.Client(timeout=20)
    try:
        for height, merkleroot in claims:
            block_hash = explorer.get(f"{EXPLORER}/block-height/{height}").text.strip()
            block = explorer.get(f"{EXPLORER}/block/{block_hash}").json()
            if block.get("merkle_root") == merkleroot:
                return f"ok (in Bitcoin block {height}, checked with mempool.space)"
    except (httpx.HTTPError, ValueError) as e:
        return f"complete, but couldn't reach mempool.space to check it ({e.__class__.__name__})"
    finally:
        if own:
            explorer.close()
    raise Failure(f"{target.name}: Bitcoin block {claims[0][0]} doesn't match the proof")


def check_domains(state: ChainState, client: httpx.Client) -> list[str]:
    lines = []
    for rcpt, keys in state.recipient_keys.items():
        for body in keys.values():
            url = f"https://{body['domain']}/.well-known/vpp.json"
            try:
                doc = client.get(url, follow_redirects=False, timeout=10).json()
            except (httpx.HTTPError, ValueError) as e:
                lines.append(f"{rcpt} @ {body['domain']}: UNREACHABLE ({e.__class__.__name__})")
                continue
            listed = (
                doc.get("log") == state.origin
                and doc.get("profile") == rcpt
                and body["fingerprint"] in doc.get("keys", [])
            )
            lines.append(
                f"{rcpt} @ {body['domain']}: {'key listed' if listed else 'KEY NOT LISTED'}"
            )
    return lines


# --- receipts ---


def verify_receipt(
    receipt: dict,
    state: ChainState | None,
    witnesses: list[Verifier],
    min_witnesses: int,
    client: httpx.Client | None,
    base: str | None,
) -> list[str]:
    import hashlib

    wire = receipt["entry"]
    envelope = base64.urlsafe_b64decode(wire["envelope"] + "=" * (-len(wire["envelope"]) % 4))
    h = hashlib.sha256(b"vpp:entry:v1\x00" + bytes.fromhex(wire["prev_hash"]) + envelope).digest()
    if h.hex() != wire["hash"]:
        raise Failure("receipt entry hash does not match its envelope")
    note = Note.parse(receipt["checkpoint"])
    cp = Checkpoint.parse(note.text)
    proof = [base64.b64decode(p) for p in receipt["inclusion_proof"]]
    if not merkle.verify_inclusion(merkle.leaf_hash(h), wire["seq"] - 1, cp.size, proof, cp.root):
        raise Failure("receipt inclusion proof is invalid")
    lines = [f"receipt: entry {wire['seq']} is included in checkpoint size {cp.size}"]
    names = count_witnesses(note, witnesses)
    if len(names) < min_witnesses:
        raise Failure(
            f"receipt checkpoint has {len(names)} witness cosignatures, need {min_witnesses}"
        )
    if names:
        lines.append(f"receipt: cosigned by {', '.join(names)}")

    if state is None:
        return lines
    # Online: the ledger served now must still contain the entry, and agree with the receipt.
    try:
        check_log_signature(state, note)
        if state.hashes.get(wire["seq"]) != h:
            raise Failure(f"entry {wire['seq']} served now differs from the receipt")
    except Failure as e:
        lines.append(misbehaviour(note, client, base, str(e)))
        raise Failure("\n".join(lines)) from None
    lines.append("receipt: entry still present and consistent with the current ledger")
    return lines


def misbehaviour(signed: Note, client, base, reason: str) -> str:
    """A transferable bundle: a checkpoint the ledger signed, and what it serves now."""
    bundle = {"reason": reason, "signed_checkpoint": str(signed)}
    if client is not None:
        try:
            bundle["current_checkpoint"] = str(_fetch_checkpoint(client, base))
        except (httpx.HTTPError, NoteError):
            pass
    path = Path(tempfile.gettempdir()) / "vpp-misbehaviour.json"
    path.write_text(json.dumps(bundle, indent=2))
    return f"MISBEHAVIOUR: {reason}. Evidence bundle written to {path}"


# --- main ---


def main(argv: list[str] | None = None, client: httpx.Client | None = None) -> int:
    """`client` is injectable for tests; normally one is created for --url."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="ledger base URL, e.g. https://proofs.example")
    src.add_argument("--file", type=Path, help="JSON file with 'entries' (and 'checkpoints')")
    p.add_argument("--pin-genesis", help="expected genesis entry hash (hex); strongly recommended")
    p.add_argument("--witness", action="append", default=[], help="witness vkey (repeatable)")
    p.add_argument("--min-witnesses", type=int, default=0, help="cosignatures required")
    p.add_argument("--anchors-repo", help="path or git URL of the public anchors repo")
    p.add_argument("--check-ots", action="store_true", help="verify anchors' Bitcoin timestamps")
    p.add_argument("--check-domains", action="store_true", help="re-check recipients' domains")
    p.add_argument("--receipt", type=Path, help="also verify a payer receipt.json")
    args = p.parse_args(argv)

    owns_client = client is None and args.url is not None
    if owns_client:
        client = httpx.Client(timeout=30, follow_redirects=True)
    base = args.url.rstrip("/") if args.url else None
    pinned = bytes.fromhex(args.pin_genesis) if args.pin_genesis else None
    out: list[str] = []
    try:
        witnesses = [Verifier.parse(w) for w in args.witness]
        state = ChainState()
        latest: Note | None = None
        file_checkpoints: list[str] = []
        if args.file:
            data = json.loads(args.file.read_text())
            entries = data["entries"]
            file_checkpoints = [c["note"] for c in data.get("checkpoints", [])]
        else:
            latest = _fetch_checkpoint(client, base)  # first, so entries cover it
            entries = _fetch_entries(client, base)
        for wire in entries:
            verify_entry(state, wire)
            if state.seq == 1 and pinned is not None and state.head != pinned:
                raise VerificationError(1, "genesis hash does not match the pinned value")
        if state.seq == 0:
            raise Failure("ledger is empty")
        out.append(f"chain: {state.seq} entries verified, root {state.root.hex()[:16]}…")
        out.append(
            f"payments confirmed by recipients: {len(state.confirmed)}/{len(state.payments)}"
        )

        for raw in file_checkpoints:
            cp = check_log_signature(state, Note.parse(raw))
            out.append(f"checkpoint size {cp.size}: signed and matches chain")
        if latest is not None:
            cp = check_log_signature(state, latest)
            names = count_witnesses(latest, witnesses)
            out.append(
                f"latest checkpoint size {cp.size}: cosigned by {len(names)} of "
                f"{len(witnesses)} given witnesses {names}"
            )
        if len(witnesses) and latest is None:
            raise Failure("witness checks need --url")
        if args.min_witnesses:
            if latest is None or len(count_witnesses(latest, witnesses)) < args.min_witnesses:
                raise Failure(
                    f"fewer than {args.min_witnesses} witnesses cosigned the checkpoint;"
                    " the server may be showing you a private fork"
                )

        if args.anchors_repo:
            with tempfile.TemporaryDirectory() as tmp:
                out += check_anchors(
                    state, _anchors_dir(args.anchors_repo, Path(tmp)), args.check_ots
                )
        if args.check_domains:
            out += check_domains(state, client or httpx.Client(timeout=10))
        if args.receipt:
            out += verify_receipt(
                json.loads(args.receipt.read_text()),
                state,
                witnesses,
                args.min_witnesses,
                client,
                base,
            )
    except VerificationError as e:
        print("\n".join(out), file=sys.stderr)
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    except (Failure, NoteError, httpx.HTTPError) as e:
        print("\n".join(out), file=sys.stderr)
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    finally:
        if owns_client:
            client.close()

    print("\n".join(out))
    print("OK")
    if pinned is None:
        print("note: genesis not pinned; pass --pin-genesis to detect a substituted ledger")
    if not args.min_witnesses and args.url:
        print("note: no --min-witnesses; a server could show you a fork no one else sees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
