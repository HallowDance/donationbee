"""A software WebAuthn authenticator (ES256) for tests and vector generation. Never use in prod."""

import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

FLAGS_UP_UV = 0x01 | 0x04
FLAG_AT = 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class SoftAuthenticator:
    rp_id: str
    origin: str
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    counter: int = 0

    @classmethod
    def from_secret(cls, rp_id: str, origin: str, n: int) -> "SoftAuthenticator":
        return cls(rp_id, origin, ec.derive_private_key(n, ec.SECP256R1()), n.to_bytes(16, "big"))

    @property
    def spki(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @property
    def cose_key(self) -> bytes:
        import cbor2

        nums = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    def _client_data(self, type_: str, challenge: bytes, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": type_,
                "challenge": b64url(challenge),
                "origin": origin or self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()

    def create(self, challenge: bytes) -> dict:
        """navigator.credentials.create() result as JSON (attestation 'none')."""
        import cbor2

        cdj = self._client_data("webauthn.create", challenge, None)
        cred_data = (
            bytes(16)
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self.cose_key
        )
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([FLAGS_UP_UV | FLAG_AT])
            + struct.pack(">I", self.counter)
            + cred_data
        )
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = b64url(self.credential_id)
        return {
            "id": cid,
            "rawId": cid,
            "type": "public-key",
            "response": {"clientDataJSON": b64url(cdj), "attestationObject": b64url(att)},
            "clientExtensionResults": {},
        }

    def get(self, challenge: bytes, *, origin: str | None = None, flags: int = FLAGS_UP_UV) -> dict:
        """navigator.credentials.get() result as JSON."""
        self.counter += 1
        cdj = self._client_data("webauthn.get", challenge, origin)
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", self.counter)
        )
        sig = self.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        cid = b64url(self.credential_id)
        return {
            "id": cid,
            "rawId": cid,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(cdj),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(sig),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
