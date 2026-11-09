"""C2SP signed-note, tlog-checkpoint and tlog-cosignature (Ed25519) verification.

Specs: https://c2sp.org/signed-note, /tlog-checkpoint, /tlog-cosignature. Written from them,
not from `vpp`.
"""

import base64
import binascii
import hashlib
import struct
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

EM_DASH = "—"
SIG_ED25519 = 0x01
SIG_COSIGNATURE_ED25519 = 0x04


class NoteError(ValueError):
    pass


def b64decode_canonical(s: str) -> bytes:
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise NoteError(f"invalid base64: {s[:20]}") from None
    if base64.b64encode(raw).decode() != s:
        raise NoteError("non-canonical base64")
    return raw


def key_id(name: str, sig_type: int, public_key: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + public_key).digest()[:4]


def check_name(name: str) -> None:
    if not name or len(name.encode()) > 255 or "+" in name:
        raise NoteError(f"invalid key name {name!r}")
    if any(c.isspace() or ord(c) < 0x20 for c in name):
        raise NoteError(f"invalid key name {name!r}")


@dataclass(frozen=True)
class Verifier:
    """A verifier key: `<name>+<hex key id>+<base64(type || pubkey)>`."""

    name: str
    sig_type: int
    public_key: bytes

    @property
    def key_id(self) -> bytes:
        return key_id(self.name, self.sig_type, self.public_key)

    @classmethod
    def parse(cls, vkey: str) -> "Verifier":
        try:
            # Names can't contain '+', but base64 can: only the first two '+' are separators.
            name, hex_id, b64 = vkey.split("+", 2)
        except ValueError:
            raise NoteError("vkey must be name+id+key") from None
        check_name(name)
        raw = b64decode_canonical(b64)
        if len(raw) != 33 or raw[0] not in (SIG_ED25519, SIG_COSIGNATURE_ED25519):
            raise NoteError("only Ed25519 (0x01) and Ed25519 cosignature (0x04) keys supported")
        v = cls(name, raw[0], raw[1:])
        if v.key_id.hex() != hex_id:
            raise NoteError("vkey id does not match key")
        return v

    def __str__(self) -> str:
        b64 = base64.b64encode(bytes([self.sig_type]) + self.public_key).decode()
        return f"{self.name}+{self.key_id.hex()}+{b64}"


@dataclass(frozen=True)
class Signature:
    name: str
    key_id: bytes
    sig: bytes  # everything after the 4-byte key id

    @property
    def line(self) -> str:
        return f"{EM_DASH} {self.name} {base64.b64encode(self.key_id + self.sig).decode()}\n"


@dataclass(frozen=True)
class Note:
    text: str  # includes its final newline
    signatures: tuple[Signature, ...]

    @classmethod
    def parse(cls, raw: str) -> "Note":
        if len(raw) > 1_000_000:
            raise NoteError("note too large")
        if any(ord(c) < 0x20 and c != "\n" for c in raw):
            raise NoteError("control character in note")
        idx = raw.rfind("\n\n")
        if idx < 0:
            raise NoteError("missing signature separator")
        text, sig_block = raw[: idx + 1], raw[idx + 2 :]
        if not sig_block.endswith("\n"):
            raise NoteError("signature block must end with newline")
        sigs = []
        for line in sig_block[:-1].split("\n"):
            if not line.startswith(EM_DASH + " "):
                raise NoteError(f"bad signature line {line[:40]!r}")
            try:
                name, b64 = line[2:].split(" ")
            except ValueError:
                raise NoteError("bad signature line") from None
            check_name(name)
            blob = b64decode_canonical(b64)
            if len(blob) < 5:
                raise NoteError("signature too short")
            sigs.append(Signature(name, blob[:4], blob[4:]))
        if not sigs:
            raise NoteError("note has no signatures")
        if len(sigs) > 64:
            raise NoteError("too many signatures")
        return cls(text, tuple(sigs))

    def __str__(self) -> str:
        return self.text + "\n" + "".join(s.line for s in self.signatures)

    def find(self, v: Verifier) -> Signature | None:
        for s in self.signatures:
            if s.name == v.name and s.key_id == v.key_id:
                return s
        return None


def _ed25519_ok(public_key: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError):
        return False


def verify_note_signature(note: Note, v: Verifier) -> bool:
    """True if `v` signed the note (type 0x01). A matching but invalid signature raises."""
    if v.sig_type != SIG_ED25519:
        raise NoteError("not a note-signing key")
    s = note.find(v)
    if s is None:
        return False
    if len(s.sig) != 64 or not _ed25519_ok(v.public_key, note.text.encode(), s.sig):
        raise NoteError(f"invalid signature from {v.name}")
    return True


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extensions: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> "Checkpoint":
        if not text.endswith("\n"):
            raise NoteError("checkpoint must end with newline")
        lines = text[:-1].split("\n")
        if len(lines) < 3 or any(not ln for ln in lines):
            raise NoteError("checkpoint needs origin, size, root")
        origin, size_s, root_b64, *ext = lines
        check_name(origin)
        if not size_s.isdigit() or (size_s != "0" and size_s.startswith("0")):
            raise NoteError("bad tree size")
        root = b64decode_canonical(root_b64)
        if len(root) != 32:
            raise NoteError("root must be 32 bytes")
        return cls(origin, int(size_s), root, tuple(ext))

    @property
    def text(self) -> str:
        lines = [
            self.origin,
            str(self.size),
            base64.b64encode(self.root).decode(),
            *self.extensions,
        ]
        return "\n".join(lines) + "\n"


def cosignature_message(checkpoint_text: str, timestamp: int) -> bytes:
    return f"cosignature/v1\ntime {timestamp}\n".encode() + checkpoint_text.encode()


def verify_cosignature(note: Note, v: Verifier) -> int | None:
    """Returns the cosignature timestamp if `v` cosigned this checkpoint (type 0x04)."""
    if v.sig_type != SIG_COSIGNATURE_ED25519:
        raise NoteError("not a cosigner key")
    s = note.find(v)
    if s is None:
        return None
    if len(s.sig) != 8 + 64:
        raise NoteError(f"bad cosignature length from {v.name}")
    (ts,) = struct.unpack(">Q", s.sig[:8])
    if not _ed25519_ok(v.public_key, cosignature_message(note.text, ts), s.sig[8:]):
        raise NoteError(f"invalid cosignature from {v.name}")
    return ts
