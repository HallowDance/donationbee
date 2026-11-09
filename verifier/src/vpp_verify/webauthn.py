"""WebAuthn assertion verification (W3C WebAuthn L2 §7.2, steps relevant to a third party)."""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified


class WebAuthnError(ValueError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fingerprint(spki_der: bytes) -> str:
    return "k1:" + hashlib.sha256(spki_der).hexdigest()


def load_key(spki_der: bytes, alg: int):
    key = load_der_public_key(spki_der)
    expected = {-7: ec.EllipticCurvePublicKey, -8: Ed25519PublicKey, -257: rsa.RSAPublicKey}
    if alg not in expected or not isinstance(key, expected[alg]):
        raise WebAuthnError(f"key type does not match alg {alg}")
    if alg == -7 and not isinstance(key.curve, ec.SECP256R1):
        raise WebAuthnError("ES256 requires P-256")
    return key


def verify_assertion(
    *,
    spki_der: bytes,
    alg: int,
    rp_id: str,
    origin: str,
    challenge: bytes,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
) -> None:
    try:
        cd = json.loads(client_data_json)
    except ValueError:
        raise WebAuthnError("clientDataJSON is not JSON") from None
    if cd.get("type") != "webauthn.get":
        raise WebAuthnError("not an assertion")
    if cd.get("challenge") != b64url(challenge):
        raise WebAuthnError("challenge mismatch")
    if cd.get("origin") != origin:
        raise WebAuthnError(f"origin mismatch: {cd.get('origin')!r}")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("cross-origin assertion")

    if len(authenticator_data) < 37:
        raise WebAuthnError("authenticatorData too short")
    if authenticator_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("rpIdHash mismatch")
    flags = authenticator_data[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise WebAuthnError("user presence and verification are required")

    msg = authenticator_data + hashlib.sha256(client_data_json).digest()
    key = load_key(spki_der, alg)
    try:
        if alg == -7:
            key.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
        elif alg == -8:
            key.verify(signature, msg)
        else:
            key.verify(signature, msg, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise WebAuthnError("bad assertion signature") from None
