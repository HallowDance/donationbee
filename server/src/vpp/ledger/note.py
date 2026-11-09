"""Producing C2SP signed notes and checkpoints (verification lives in `vpp_verify.note`)."""

import base64
import hashlib

EM_DASH = "—"
SIG_ED25519 = 0x01


def note_key_id(name: str, public_key: bytes, sig_type: int = SIG_ED25519) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + public_key).digest()[:4]


def vkey(name: str, public_key: bytes, sig_type: int = SIG_ED25519) -> str:
    b64 = base64.b64encode(bytes([sig_type]) + public_key).decode()
    return f"{name}+{note_key_id(name, public_key, sig_type).hex()}+{b64}"


def checkpoint_text(origin: str, size: int, root: bytes) -> str:
    return f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"


def signature_line(name: str, public_key: bytes, sig: bytes) -> str:
    blob = note_key_id(name, public_key) + sig
    return f"{EM_DASH} {name} {base64.b64encode(blob).decode()}\n"


def sign_note(text: str, name: str, public_key: bytes, sign) -> str:
    """`sign(msg) -> 64-byte Ed25519 signature` (any Signer)."""
    if not text.endswith("\n"):
        raise ValueError("note text must end with a newline")
    return text + "\n" + signature_line(name, public_key, sign(text.encode()))
