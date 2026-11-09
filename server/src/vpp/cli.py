"""Operator CLI: `uv run vpp --help`.

Root-key commands (`vpp root …`) are meant to run on an offline machine: they need no
database, only the encrypted root key file. They print one-line JSON signatures that the
operator passes to `init-ledger`, `rotate-key` or `rotate-roots` with --root-sig.
"""

import json
import os
from pathlib import Path
from typing import Annotated

import httpx
import typer
from sqlalchemy import select

from . import anchoring, pii, witnessing
from .config import get_settings
from .db import session_factory
from .db.models import Profile
from .deps import get_ledger_key
from .ledger import LedgerKey
from .ledger.entries import KeyRotation, RootRotation, RootSig
from .ledger.signing import (
    Signer,
    genesis_statement,
    load_root_key,
    root_rotation_statement,
    rotation_statement,
    save_root_key,
)
from .ledger.store import append, head, init_ledger, key_state
from .stripe_connect import get_stripe
from .stripe_connect.onboarding import (
    create_connected_account,
    new_profile_id,
    onboarding_url,
    refresh_status,
)

app = typer.Typer(no_args_is_help=True)
root_app = typer.Typer(no_args_is_help=True, help="Offline root-key ceremony commands.")
app.add_typer(root_app, name="root")

RootSigOpt = Annotated[
    list[str], typer.Option("--root-sig", help='JSON {"key":…,"sig":…} from `vpp root sign-*`')
]


def _passphrase(confirm: bool = False) -> bytes:
    env = os.environ.get("VPP_ROOT_PASSPHRASE")  # for scripted test ceremonies only
    if env:
        return env.encode()
    return typer.prompt(
        "Root key passphrase", hide_input=True, confirmation_prompt=confirm
    ).encode()


def _parse_sigs(raw: list[str]) -> list[RootSig]:
    return [RootSig.model_validate(json.loads(r)) for r in raw]


def _sig_json(key: LedgerKey, stmt: bytes) -> str:
    return json.dumps({"key": key.public_key.hex(), "sig": key.sign(stmt).hex()})


def _new_online_key(key_file: Path | None, kms_version: str | None) -> Signer:
    if bool(key_file) == bool(kms_version):
        raise typer.BadParameter("give exactly one of --new-key-file / --new-kms-version")
    if kms_version:
        from .ledger.kms import GcpKmsSigner

        return GcpKmsSigner(kms_version)
    return LedgerKey.load(key_file)


# --- offline root ceremony ---


@root_app.command("keygen")
def root_keygen(out: Path) -> None:
    """Create a passphrase-encrypted root key. Keep it offline; print the public key."""
    if out.exists():
        raise typer.BadParameter(f"{out} already exists")
    key = LedgerKey.generate()
    save_root_key(key, out, _passphrase(confirm=True))
    typer.echo(key.public_key.hex())


@root_app.command("sign-genesis")
def root_sign_genesis(
    key_file: Path, online_key: str, origin: Annotated[str, typer.Option()] = ""
) -> None:
    """Authorize a new ledger's first online key."""
    origin = origin or get_settings().origin
    key = load_root_key(key_file, _passphrase())
    typer.echo(_sig_json(key, genesis_statement(origin, bytes.fromhex(online_key))))


@root_app.command("sign-rotation")
def root_sign_rotation(
    key_file: Path, from_key: str, to_key: str, origin: Annotated[str, typer.Option()] = ""
) -> None:
    """Authorize replacing online key FROM_KEY with TO_KEY (both hex public keys)."""
    origin = origin or get_settings().origin
    key = load_root_key(key_file, _passphrase())
    stmt = rotation_statement(origin, bytes.fromhex(from_key), bytes.fromhex(to_key))
    typer.echo(_sig_json(key, stmt))


@root_app.command("sign-root-rotation")
def root_sign_root_rotation(
    key_file: Path,
    old_keys: Annotated[list[str], typer.Option("--old-key")],
    old_threshold: int,
    new_keys: Annotated[list[str], typer.Option("--new-key")],
    new_threshold: int,
    origin: Annotated[str, typer.Option()] = "",
) -> None:
    """Authorize replacing the root key set."""
    origin = origin or get_settings().origin
    key = load_root_key(key_file, _passphrase())
    stmt = root_rotation_statement(origin, old_keys, old_threshold, new_keys, new_threshold)
    typer.echo(_sig_json(key, stmt))


# --- online key and ledger lifecycle ---


@app.command()
def keygen(path: Annotated[Path | None, typer.Option()] = None) -> None:
    """Generate an online signing key file (dev; use Cloud KMS in production)."""
    path = path or get_settings().signing_key_path
    if path.exists():
        raise typer.BadParameter(f"{path} already exists")
    key = LedgerKey.generate()
    key.save(path)
    typer.echo(f"wrote {path} public_key={key.public_key.hex()}")


@app.command("init-ledger")
def init_ledger_cmd(
    root_keys: Annotated[list[str], typer.Option("--root-key", help="root public key (hex)")],
    threshold: Annotated[int, typer.Option()],
    root_sig: RootSigOpt,
) -> None:
    """Append the genesis entry: online key + root key set, authorized by the roots."""
    key = get_ledger_key()
    with session_factory()() as s:
        if head(s) is not None:
            raise typer.BadParameter("ledger already initialised")
        e = init_ledger(s, key, get_settings().origin, root_keys, threshold, _parse_sigs(root_sig))
        s.commit()
        typer.echo(f"genesis hash {e.hash.hex()}")
        typer.echo("Publish it widely: verifiers pin it with --pin-genesis.")


@app.command("rotate-key")
def rotate_key(
    root_sig: RootSigOpt,
    new_key_file: Annotated[Path | None, typer.Option()] = None,
    new_kms_version: Annotated[str | None, typer.Option()] = None,
    reason: Annotated[str, typer.Option(help="scheduled|compromise|lost")] = "scheduled",
) -> None:
    """Replace the online key. Needs root signatures; works even if the old key is lost.
    Afterwards point VPP_SIGNING_KEY_PATH / VPP_KMS_KEY_VERSION at the new key, restart, and
    send witnesses the new checkpoint vkey (see `GET /api/v1/keys`)."""
    new = _new_online_key(new_key_file, new_kms_version)
    with session_factory()() as s:
        state = key_state(s)
        body = KeyRotation(
            from_online_key=state.online_key.hex(),
            new_online_key=new.public_key.hex(),
            reason=reason,
            root_sigs=_parse_sigs(root_sig),
        )
        e = append(s, body, new)
        s.commit()
        typer.echo(f"rotated at seq {e.seq} -> {new.public_key.hex()}")


@app.command("rotate-roots")
def rotate_roots(
    new_keys: Annotated[list[str], typer.Option("--new-key")],
    new_threshold: Annotated[int, typer.Option()],
    root_sig: RootSigOpt,
) -> None:
    """Replace the root key set (needs the *old* root threshold)."""
    with session_factory()() as s:
        body = RootRotation(
            new_root_keys=new_keys,
            new_root_threshold=new_threshold,
            root_sigs=_parse_sigs(root_sig),
        )
        e = append(s, body, get_ledger_key())
        s.commit()
        typer.echo(f"root keys rotated at seq {e.seq}")


@app.command("ceremony-info")
def ceremony_info() -> None:
    """Print what root holders need to sign a rotation (current keys and origin)."""
    with session_factory()() as s:
        st = key_state(s)
        typer.echo(
            json.dumps(
                {
                    "origin": st.origin,
                    "online_key": st.online_key.hex(),
                    "root_keys": st.root_keys,
                    "root_threshold": st.root_threshold,
                },
                indent=2,
            )
        )


# --- witnesses and anchoring ---


@app.command("witness-push")
def witness_push() -> None:
    """Send the latest checkpoint to every configured witness (run every minute)."""
    with session_factory()() as s, httpx.Client(timeout=15) as http:
        for name, outcome in witnessing.push(s, http).items():
            typer.echo(f"{name}: {outcome}")


@app.command()
def anchor() -> None:
    """Anchor the latest checkpoint to git + OpenTimestamps. Run hourly."""
    with session_factory()() as s:
        a = anchoring.anchor_head(s)
        if a is None:
            typer.echo("nothing new to anchor")
        else:
            typer.echo(f"anchored size {a.size} git={a.git_commit} ots={a.ots_status}")


@app.command("ots-upgrade")
def ots_upgrade() -> None:
    """Upgrade pending OpenTimestamps proofs once Bitcoin confirms (hours after stamping)."""
    with session_factory()() as s:
        typer.echo(f"{anchoring.upgrade_pending(s)} proof(s) completed")


# --- profiles and personal data ---


@app.command("create-profile")
def create_profile(slug: str, display_name: str) -> None:
    """Create a profile + Stripe connected account and print its onboarding link."""
    client = get_stripe()
    with session_factory()() as s:
        p = Profile(id=new_profile_id(), slug=slug, display_name=display_name)
        s.add(p)
        s.flush()
        p.stripe_account_id = create_connected_account(client, p)
        s.commit()
        typer.echo(f"profile {p.id} account {p.stripe_account_id}")
        typer.echo(f"onboarding: {onboarding_url(client, p)}")


@app.command("onboarding-link")
def onboarding_link(slug: str) -> None:
    with session_factory()() as s:
        p = s.scalars(select(Profile).where(Profile.slug == slug)).one()
        typer.echo(onboarding_url(get_stripe(), p))


@app.command("refresh-profile")
def refresh_profile(slug: str) -> None:
    with session_factory()() as s:
        p = s.scalars(select(Profile).where(Profile.slug == slug)).one()
        typer.echo(f"card_payments: {refresh_status(s, get_stripe(), p)}")
        s.commit()


@app.command("erase-pii")
def erase_pii(commitment: str) -> None:
    """GDPR erasure: delete the opening of a commitment. The ledger stays valid."""
    with session_factory()() as s:
        ok = pii.erase(s, commitment)
        s.commit()
        typer.echo("erased" if ok else "not found or already erased")
