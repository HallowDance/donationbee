"""Recipient area: passkey sign-in, key publication (domain proof), and payment confirmation.

Sessions are an HMAC-signed cookie (SameSite=Strict, HttpOnly). A session comes from the
Stripe onboarding return link or from signing in with a published passkey. Note that the
operator could also mint a session; what stops it from impersonating a recipient is the domain
proof (only keys the recipient's domain lists get published) and the verifier re-checking every
confirmation's WebAuthn signature.
"""

import hashlib
import hmac
import json
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import domainproof, passkeys
from ..config import get_settings
from ..db import get_session
from ..db.models import Profile, RecipientCredential
from ..deps import get_ledger_key
from ..ledger.store import key_state
from ..queries import profile_totals
from .templating import templates

router = APIRouter()
DB = Annotated[Session, Depends(get_session)]
COOKIE = "vpp_rcpt"
SESSION_TTL = 8 * 3600


def _sign(profile_id: str, exp: int) -> str:
    msg = f"rcpt:{profile_id}:{exp}".encode()
    return hmac.new(get_settings().secret_key.encode(), msg, hashlib.sha256).hexdigest()


def _set_session(resp, profile: Profile):
    exp = int(time.time()) + SESSION_TTL
    resp.set_cookie(
        COOKIE,
        f"{profile.id}.{exp}.{_sign(profile.id, exp)}",
        max_age=SESSION_TTL,
        httponly=True,
        samesite="strict",
        secure=get_settings().public_base_url.startswith("https://"),
    )
    return resp


def recipient_session_redirect(profile: Profile, to: str):
    return _set_session(RedirectResponse(to, status_code=303), profile)


def current_profile(request: Request, db: Session) -> Profile | None:
    raw = request.cookies.get(COOKIE, "")
    try:
        pid, exp_s, sig = raw.rsplit(".", 2)
        exp = int(exp_s)
    except ValueError:
        return None
    if exp < time.time() or not hmac.compare_digest(_sign(pid, exp), sig):
        return None
    return db.get(Profile, pid)


def _require(request: Request, db: Session) -> Profile:
    p = current_profile(request, db)
    if p is None:
        raise HTTPException(401, "sign in first")
    return p


def _err(e: Exception) -> JSONResponse:
    return JSONResponse({"error": str(e)}, status_code=400)


@router.get("/recipient")
def dashboard(request: Request, db: DB):
    p = current_profile(request, db)
    if p is None:
        return RedirectResponse("/recipient/login", status_code=303)
    creds = db.scalars(
        select(RecipientCredential).where(RecipientCredential.profile_id == p.id)
    ).all()
    totals = profile_totals(db, p.id)
    state = key_state(db)
    well_known = json.dumps(
        domainproof.well_known_document(state.origin, p.id, [c.fingerprint for c in creds]),
        indent=2,
    )
    return templates.TemplateResponse(
        request,
        "recipient.html",
        {
            "profile": p,
            "creds": creds,
            "published": [c for c in creds if c.key_seq],
            "unconfirmed": [v for v in totals.payments if not v.confirmed_by and not v.voided],
            "totals": totals,
            "well_known": well_known,
        },
    )


@router.get("/recipient/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "recipient_login.html", {})


@router.post("/recipient/logout")
def logout():
    resp = RedirectResponse("/recipient/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


# --- JSON endpoints used by /static/passkey.js ---


class Finish(BaseModel):
    challenge_id: str
    credential: dict[str, Any]


class Publish(BaseModel):
    credential_id: str
    domain: str


class ConfirmStart(BaseModel):
    ref_seqs: list[int]


@router.post("/api/recipient/register/options")
def register_options(request: Request, db: DB):
    p = _require(request, db)
    cid, opts = passkeys.registration_options(db, p)
    db.commit()
    return {"challenge_id": cid, "options": json.loads(opts)}


@router.post("/api/recipient/register/verify")
def register_verify(request: Request, db: DB, body: Finish):
    p = _require(request, db)
    try:
        cred = passkeys.finish_registration(db, p, body.challenge_id, body.credential)
    except passkeys.PasskeyError as e:
        return _err(e)
    db.commit()
    return {"credential_id": cred.credential_id, "fingerprint": cred.fingerprint}


@router.post("/api/recipient/publish")
def publish(request: Request, db: DB, body: Publish):
    p = _require(request, db)
    cred = db.get(RecipientCredential, body.credential_id)
    if cred is None or cred.profile_id != p.id:
        raise HTTPException(404)
    if cred.key_seq:
        return {"seq": cred.key_seq}
    try:
        entry = passkeys.publish_key(db, get_ledger_key(), p, cred, body.domain)
    except (domainproof.DomainProofError, passkeys.PasskeyError) as e:
        return _err(e)
    db.commit()
    return {"seq": entry.seq}


@router.post("/api/recipient/login/options")
def login_options(db: DB):
    cid, opts = passkeys.login_options(db)
    db.commit()
    return {"challenge_id": cid, "options": json.loads(opts)}


@router.post("/api/recipient/login/verify")
def login_verify(db: DB, body: Finish):
    try:
        p = passkeys.finish_login(db, body.challenge_id, body.credential)
    except passkeys.PasskeyError as e:
        db.rollback()
        return _err(e)
    db.commit()
    return _set_session(JSONResponse({"ok": True}), p)


@router.post("/api/recipient/confirm/options")
def confirm_options(request: Request, db: DB, body: ConfirmStart):
    p = _require(request, db)
    try:
        cid, opts = passkeys.confirmation_options(db, p, body.ref_seqs)
    except passkeys.PasskeyError as e:
        return _err(e)
    db.commit()
    return {"challenge_id": cid, "options": json.loads(opts)}


@router.post("/api/recipient/confirm/verify")
def confirm_verify(request: Request, db: DB, body: Finish):
    p = _require(request, db)
    try:
        entry = passkeys.finish_confirmation(
            db, get_ledger_key(), p, body.challenge_id, body.credential
        )
    except passkeys.PasskeyError as e:
        db.rollback()
        return _err(e)
    db.commit()
    return {"seq": entry.seq}
