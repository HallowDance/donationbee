"""vpp-witness: a C2SP tlog-witness (https://c2sp.org/tlog-witness) with Ed25519 cosignatures.

A witness only cosigns a checkpoint that is consistent with the last one it cosigned for that
log. Anyone who checks for k witness cosignatures therefore sees the same history as everyone
else, or catches the log equivocating.

    vpp-witness keygen --name witness.example/w1 --out w1.key
    vpp-witness serve --config witness.json --port 8780

Config: {"name": "...", "key_file": "...", "state_dir": "...",
         "logs": [{"origin": "proofs.example/log", "vkeys": ["proofs.example/log+…+…"]}]}
"""

import argparse
import base64
import fcntl
import hashlib
import json
import os
import struct
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nacl.signing import SigningKey
from vpp_verify import merkle
from vpp_verify.note import (
    EM_DASH,
    SIG_COSIGNATURE_ED25519,
    Checkpoint,
    Note,
    NoteError,
    Verifier,
    b64decode_canonical,
    cosignature_message,
    key_id,
    verify_note_signature,
)

MAX_BODY = 1 << 20
MAX_PROOF_LINES = 63


class Reject(Exception):
    def __init__(self, status: int, message: str, content_type: str = "text/plain"):
        super().__init__(message)
        self.status, self.message, self.content_type = status, message, content_type


@dataclass
class Witness:
    name: str
    key: SigningKey
    logs: dict[str, list[Verifier]]  # origin -> trusted log keys
    state_dir: Path

    def __post_init__(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def vkey(self) -> Verifier:
        return Verifier(self.name, SIG_COSIGNATURE_ED25519, bytes(self.key.verify_key))

    # --- state: one JSON file per origin, replaced atomically ---

    def _path(self, origin: str) -> Path:
        return self.state_dir / (hashlib.sha256(origin.encode()).hexdigest() + ".json")

    def load(self, origin: str) -> dict:
        p = self._path(origin)
        if not p.exists():
            return {"size": 0, "root": base64.b64encode(merkle.EMPTY_ROOT).decode(), "note": None}
        return json.loads(p.read_text())

    def _save(self, origin: str, state: dict) -> None:
        p = self._path(origin)
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        dfd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    # --- protocol ---

    def cosign(self, checkpoint_text: str, ts: int | None = None) -> str:
        ts = int(time.time()) if ts is None else ts
        sig = self.key.sign(cosignature_message(checkpoint_text, ts)).signature
        kid = key_id(self.name, SIG_COSIGNATURE_ED25519, bytes(self.key.verify_key))
        blob = kid + struct.pack(">Q", ts) + sig
        return f"{EM_DASH} {self.name} {base64.b64encode(blob).decode()}\n"

    def add_checkpoint(self, body: str) -> str:
        old, proof, note = _parse_request(body)
        cp = Checkpoint.parse(note.text)
        trusted = self.logs.get(cp.origin)
        if trusted is None:
            raise Reject(404, "unknown log origin")
        try:
            if not any(verify_note_signature(note, v) for v in trusted):
                raise Reject(403, "no signature from a trusted log key")
        except NoteError as e:
            raise Reject(403, str(e)) from None
        if old > cp.size:
            raise Reject(400, "old size is larger than the checkpoint size")

        # The size check and the update must be atomic (process lock + file lock).
        with self._lock, open(self.state_dir / ".lock", "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            state = self.load(cp.origin)
            if old != state["size"]:
                raise Reject(409, f"{state['size']}\n", "text/x.tlog.size")
            old_root = base64.b64decode(state["root"])
            if cp.size == 0 and cp.root != merkle.EMPTY_ROOT:
                raise Reject(422, "size-0 checkpoint must have the empty-tree root")
            if old == 0 and proof:
                raise Reject(422, "proof must be empty when old size is 0")
            if old == cp.size and cp.root != old_root:
                raise Reject(422, "same size, different root: the log is equivocating")
            if not merkle.verify_consistency(old, cp.size, old_root, cp.root, proof):
                raise Reject(422, "consistency proof does not verify")
            line = self.cosign(note.text)
            self._save(
                cp.origin,
                {
                    "size": cp.size,
                    "root": base64.b64encode(cp.root).decode(),
                    "note": str(note) + line,
                },
            )
        return line

    def latest(self, origin_hash: str) -> str | None:
        for origin in self.logs:
            if hashlib.sha256(origin.encode()).hexdigest() == origin_hash:
                return self.load(origin)["note"]
        return None


def _parse_request(body: str) -> tuple[int, list[bytes], Note]:
    try:
        head, note_raw = body.split("\n\n", 1)
        lines = head.split("\n")
        if not lines[0].startswith("old "):
            raise ValueError("first line must be 'old <size>'")
        old_s = lines[0][4:]
        if not old_s.isdigit() or (old_s != "0" and old_s.startswith("0")):
            raise ValueError("bad old size")
        if len(lines) - 1 > MAX_PROOF_LINES:
            raise ValueError("too many proof lines")
        proof = [b64decode_canonical(ln) for ln in lines[1:]]
        if any(len(h) != 32 for h in proof):
            raise ValueError("proof hashes must be 32 bytes")
        return int(old_s), proof, Note.parse(note_raw)
    except (ValueError, NoteError) as e:
        raise Reject(400, f"malformed request: {e}") from None


def make_handler(witness: Witness):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vpp-witness/0.1"

        def _send(self, status: int, body: str, ctype: str = "text/plain; charset=utf-8"):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path.rstrip("/").split("/")[-1] != "add-checkpoint":
                return self._send(404, "not found\n")
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(400, "request too large\n")
            try:
                body = self.rfile.read(n).decode("utf-8")
                self._send(200, witness.add_checkpoint(body))
            except UnicodeDecodeError:
                self._send(400, "request is not UTF-8\n")
            except Reject as r:
                self._send(
                    r.status,
                    r.message if r.message.endswith("\n") else r.message + "\n",
                    r.content_type,
                )

        def do_GET(self):
            parts = self.path.strip("/").split("/")
            if len(parts) == 2 and parts[1] == "checkpoint":
                note = witness.latest(parts[0])
                if note:
                    return self._send(200, note)
            self._send(404, "not found\n")

        def log_message(self, fmt, *args):  # quieter, one line per request
            sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    return Handler


def load_witness(config_path: Path) -> Witness:
    cfg = json.loads(config_path.read_text())
    base = config_path.parent
    seed = bytes.fromhex((base / cfg["key_file"]).read_text().strip())
    return Witness(
        name=cfg["name"],
        key=SigningKey(seed),
        logs={log["origin"]: [Verifier.parse(v) for v in log["vkeys"]] for log in cfg["logs"]},
        state_dir=base / cfg.get("state_dir", "witness-state"),
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="create a witness key and print its vkey")
    kg.add_argument("--name", required=True)
    kg.add_argument("--out", type=Path, required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--config", type=Path, required=True)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8780)
    args = p.parse_args(argv)

    if args.cmd == "keygen":
        if args.out.exists():
            print(f"{args.out} exists", file=sys.stderr)
            return 1
        key = SigningKey.generate()
        args.out.write_text(bytes(key).hex() + "\n")
        args.out.chmod(0o600)
        print(Verifier(args.name, SIG_COSIGNATURE_ED25519, bytes(key.verify_key)))
        return 0

    w = load_witness(args.config)
    print(f"witness {w.vkey} on {args.host}:{args.port}", file=sys.stderr)
    ThreadingHTTPServer((args.host, args.port), make_handler(w)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
