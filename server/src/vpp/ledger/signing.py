"""Signers (online key) and offline root keys (LEDGER_SPEC §3, §4, §5)."""

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import rfc8785
from nacl import pwhash, secret, utils
from nacl.signing import SigningKey, VerifyKey


class Signer(Protocol):
    """Anything that can Ed25519-sign: a key file, Cloud KMS, an HSM."""

    @property
    def public_key(self) -> bytes: ...

    def sign(self, msg: bytes) -> bytes: ...


def key_id_for(public_key: bytes) -> str:
    return hashlib.sha256(public_key).digest()[:8].hex()


@dataclass(frozen=True)
class LedgerKey:
    """File-backed Ed25519 key: the dev online signer, and the in-memory form of a root key."""

    signing_key: SigningKey

    @classmethod
    def generate(cls) -> "LedgerKey":
        return cls(SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "LedgerKey":
        return cls(SigningKey(seed))

    @classmethod
    def load(cls, path: Path) -> "LedgerKey":
        return cls.from_seed(bytes.fromhex(path.read_text().strip()))

    def save(self, path: Path) -> None:
        path.write_text(bytes(self.signing_key).hex() + "\n")
        path.chmod(0o600)

    @property
    def public_key(self) -> bytes:
        return bytes(self.signing_key.verify_key)

    @property
    def key_id(self) -> str:
        return key_id_for(self.public_key)

    def sign(self, msg: bytes) -> bytes:
        return self.signing_key.sign(msg).signature


def verify(public_key: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(msg, sig)
        return True
    except Exception:
        return False


# --- root-key statements (signed offline; LEDGER_SPEC §5) ---


def _origin_hash(origin: str) -> bytes:
    return hashlib.sha256(origin.encode()).digest()


def genesis_statement(origin: str, online_key: bytes) -> bytes:
    return b"vpp:genesis:v1\x00" + _origin_hash(origin) + online_key


def rotation_statement(origin: str, from_key: bytes, new_key: bytes) -> bytes:
    return b"vpp:rotate:v1\x00" + _origin_hash(origin) + from_key + new_key


def root_rotation_statement(
    origin: str, old_keys: list[str], old_threshold: int, new_keys: list[str], new_threshold: int
) -> bytes:
    sets = {
        "from": {"keys": sorted(old_keys), "threshold": old_threshold},
        "to": {"keys": sorted(new_keys), "threshold": new_threshold},
    }
    return b"vpp:root-rotate:v1\x00" + _origin_hash(origin) + rfc8785.dumps(sets)


def count_root_sigs(statement: bytes, root_sigs, root_keys: list[str]) -> int:
    """Distinct valid signatures from keys in `root_keys`."""
    allowed = set(root_keys)
    ok = set()
    for rs in root_sigs:
        if rs.key in allowed and rs.key not in ok:
            if verify(bytes.fromhex(rs.key), statement, bytes.fromhex(rs.sig)):
                ok.add(rs.key)
    return len(ok)


# --- passphrase-encrypted root key files (kept offline) ---


def save_root_key(key: LedgerKey, path: Path, passphrase: bytes) -> None:
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    ops, mem = pwhash.argon2id.OPSLIMIT_MODERATE, pwhash.argon2id.MEMLIMIT_MODERATE
    box_key = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, passphrase, salt, ops, mem)
    ct = secret.SecretBox(box_key).encrypt(bytes(key.signing_key))
    doc = {
        "vpp_root_key": 1,
        "public_key": key.public_key.hex(),
        "kdf": "argon2id",
        "opslimit": ops,
        "memlimit": mem,
        "salt": base64.b64encode(salt).decode(),
        "box": base64.b64encode(bytes(ct)).decode(),
    }
    path.write_text(json.dumps(doc, indent=2) + "\n")
    path.chmod(0o600)


def load_root_key(path: Path, passphrase: bytes) -> LedgerKey:
    doc = json.loads(path.read_text())
    box_key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase,
        base64.b64decode(doc["salt"]),
        doc["opslimit"],
        doc["memlimit"],
    )
    seed = secret.SecretBox(box_key).decrypt(base64.b64decode(doc["box"]))
    key = LedgerKey.from_seed(seed)
    if key.public_key.hex() != doc["public_key"]:
        raise ValueError("root key file is corrupt")
    return key


def confirmation_challenge(origin: str, entry_hashes: list[bytes]) -> bytes:
    """What a recipient's passkey signs to confirm payments (LEDGER_SPEC §11)."""
    return hashlib.sha256(
        b"vpp:confirm:v1\x00" + _origin_hash(origin) + b"".join(entry_hashes)
    ).digest()
