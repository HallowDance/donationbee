"""Recipient passkeys: registration, sign-in, and confirming payments (LEDGER_SPEC §11–§12).

Registration stores a *pending* credential. It becomes a public `recipient_key` entry only once
the recipient's domain lists its fingerprint. Confirmations are WebAuthn assertions over the
payment entry hashes, recorded verbatim so anyone can re-verify them.
"""

import json
import secrets
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from sqlalchemy import select
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    decode_credential_public_key,
    decoded_public_key_to_cryptography,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import domainproof
from .config import get_settings
from .db.models import LedgerEntry, Profile, RecipientCredential, WebauthnChallenge
from .ledger.entries import Confirmation, RecipientKey
from .ledger.signing import Signer, confirmation_challenge
from .ledger.store import append, key_state
from .ledger.wire import b64url

CHALLENGE_TTL = timedelta(minutes=5)


class PasskeyError(ValueError):
    pass


def _origin() -> str:
    return get_settings().public_base_url.rstrip("/")


def _b64url_decode(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _new_challenge(session: Session, purpose: str, challenge: bytes, profile_id=None, payload=None):
    cid = secrets.token_urlsafe(16)
    session.add(
        WebauthnChallenge(
            id=cid,
            challenge=challenge,
            purpose=purpose,
            profile_id=profile_id,
            payload=payload,
            expires_at=datetime.now(UTC) + CHALLENGE_TTL,
        )
    )
    return cid


def _take_challenge(session: Session, cid: str, purpose: str) -> WebauthnChallenge:
    ch = session.get(WebauthnChallenge, cid)
    if ch is None or ch.purpose != purpose or ch.expires_at < datetime.now(UTC):
        raise PasskeyError("challenge expired; try again")
    session.delete(ch)  # single use
    session.flush()  # without this, a get() in the same session still returns it
    return ch


def spki_of(cose_key: bytes) -> tuple[bytes, int]:
    decoded = decode_credential_public_key(cose_key)
    key = decoded_public_key_to_cryptography(decoded)
    spki = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return spki, int(decoded.alg)


def fingerprint(spki: bytes) -> str:
    import hashlib

    return "k1:" + hashlib.sha256(spki).hexdigest()


# --- registration ---


def registration_options(session: Session, profile: Profile) -> tuple[str, str]:
    s = get_settings()
    existing = session.scalars(
        select(RecipientCredential).where(RecipientCredential.profile_id == profile.id)
    ).all()
    opts = generate_registration_options(
        rp_id=s.rp_id,
        rp_name=s.rp_name,
        user_id=profile.id.encode(),
        user_name=profile.slug,
        user_display_name=profile.display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=_b64url_decode(c.credential_id)) for c in existing
        ],
    )
    cid = _new_challenge(session, "register", opts.challenge, profile.id)
    return cid, options_to_json(opts)


def finish_registration(
    session: Session, profile: Profile, challenge_id: str, credential: dict
) -> RecipientCredential:
    ch = _take_challenge(session, challenge_id, "register")
    if ch.profile_id != profile.id:
        raise PasskeyError("challenge belongs to another profile")
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=ch.challenge,
            expected_rp_id=get_settings().rp_id,
            expected_origin=_origin(),
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as e:
        raise PasskeyError(f"passkey registration failed: {e}") from None
    spki, _ = spki_of(v.credential_public_key)
    cred = RecipientCredential(
        credential_id=b64url(v.credential_id),
        profile_id=profile.id,
        public_key_cose=v.credential_public_key,
        fingerprint=fingerprint(spki),
        sign_count=v.sign_count,
        key_seq=None,
    )
    session.add(cred)
    return cred


def publish_key(
    session: Session,
    signer: Signer,
    profile: Profile,
    cred: RecipientCredential,
    domain: str,
    *,
    fetch=None,
) -> LedgerEntry:
    """Check the domain proof, then append the key as a public recipient_key entry."""
    state = key_state(session)
    domain = domainproof.normalize_domain(domain)
    domainproof.check(
        (fetch or domainproof.fetch)(domain),
        origin=state.origin,
        profile_id=profile.id,
        fingerprint=cred.fingerprint,
    )
    if profile.domain and profile.domain != domain:
        raise PasskeyError(
            f"this profile's identity is {profile.domain}; keys must be listed there"
        )
    spki, alg = spki_of(cred.public_key_cose)
    s = get_settings()
    entry = append(
        session,
        RecipientKey(
            recipient=profile.id,
            credential_id=cred.credential_id,
            public_key_spki=b64url(spki),
            alg=alg,
            rp_id=s.rp_id,
            origin=_origin(),
            domain=domain,
            fingerprint=cred.fingerprint,
        ),
        signer,
    )
    profile.domain = domain
    cred.key_seq = entry.seq
    return entry


# --- sign-in (discoverable credentials) ---


def login_options(session: Session) -> tuple[str, str]:
    opts = generate_authentication_options(
        rp_id=get_settings().rp_id, user_verification=UserVerificationRequirement.REQUIRED
    )
    return _new_challenge(session, "login", opts.challenge), options_to_json(opts)


def _verify_assertion(cred: RecipientCredential, challenge: bytes, credential: dict) -> None:
    try:
        v = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_settings().rp_id,
            expected_origin=_origin(),
            credential_public_key=cred.public_key_cose,
            credential_current_sign_count=cred.sign_count,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as e:
        raise PasskeyError(f"passkey check failed: {e}") from None
    # Passkeys often report sign_count 0 forever; py_webauthn only rejects real regressions.
    cred.sign_count = v.new_sign_count


def finish_login(session: Session, challenge_id: str, credential: dict) -> Profile:
    ch = _take_challenge(session, challenge_id, "login")
    cred = session.get(RecipientCredential, credential.get("id", ""))
    if cred is None:
        raise PasskeyError("unknown passkey")
    _verify_assertion(cred, ch.challenge, credential)
    return session.get(Profile, cred.profile_id)


# --- confirming payments ---


def confirmation_options(
    session: Session, profile: Profile, ref_seqs: list[int]
) -> tuple[str, str]:
    if not ref_seqs or len(ref_seqs) > 100 or len(set(ref_seqs)) != len(ref_seqs):
        raise PasskeyError("choose between 1 and 100 payments")
    entries = [session.get(LedgerEntry, s) for s in ref_seqs]
    if any(e is None or e.type != "payment" or e.recipient != profile.id for e in entries):
        raise PasskeyError("those are not all payments to this profile")
    published = session.scalars(
        select(RecipientCredential).where(
            RecipientCredential.profile_id == profile.id, RecipientCredential.key_seq.is_not(None)
        )
    ).all()
    if not published:
        raise PasskeyError("publish a passkey (domain proof) before confirming payments")
    challenge = confirmation_challenge(key_state(session).origin, [e.hash for e in entries])
    opts = generate_authentication_options(
        rp_id=get_settings().rp_id,
        challenge=challenge,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=_b64url_decode(c.credential_id)) for c in published
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    cid = _new_challenge(session, "confirm", challenge, profile.id, json.dumps(ref_seqs))
    return cid, options_to_json(opts)


def finish_confirmation(
    session: Session, signer: Signer, profile: Profile, challenge_id: str, credential: dict
) -> LedgerEntry:
    ch = _take_challenge(session, challenge_id, "confirm")
    if ch.profile_id != profile.id:
        raise PasskeyError("challenge belongs to another profile")
    cred = session.get(RecipientCredential, credential.get("id", ""))
    if cred is None or cred.profile_id != profile.id or cred.key_seq is None:
        raise PasskeyError("this passkey is not a published key of this profile")
    _verify_assertion(cred, ch.challenge, credential)
    resp = credential["response"]
    return append(
        session,
        Confirmation(
            recipient=profile.id,
            ref_seqs=json.loads(ch.payload),
            credential_id=cred.credential_id,
            authenticator_data=resp["authenticatorData"],
            client_data_json=resp["clientDataJSON"],
            signature=resp["signature"],
        ),
        signer,
    )
