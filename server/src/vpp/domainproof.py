"""Domain proofs (LEDGER_SPEC §12): a recipient lists its passkey fingerprints at
https://<domain>/.well-known/vpp.json. Fetching attacker-chosen URLs is an SSRF risk, so:
https only, port 443, a plain hostname, every resolved address must be public, no redirects,
a small size cap and a short timeout.

Residual risk: DNS can change between our check and the connection (rebinding). The fetched
document is only parsed as JSON and never echoed back, which limits what an attacker gains.
"""

import ipaddress
import json
import re
import socket
from collections.abc import Callable

import httpx

MAX_BYTES = 64 * 1024
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

Resolver = Callable[[str], list[str]]


class DomainProofError(ValueError):
    pass


def _resolve(host: str) -> list[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if not HOST_RE.match(d):
        raise DomainProofError("Enter a plain domain name, like example.org.")
    return d


def well_known_document(origin: str, profile_id: str, fingerprints: list[str]) -> dict:
    return {"vpp": 1, "log": origin, "profile": profile_id, "keys": sorted(fingerprints)}


def fetch(
    domain: str, *, resolver: Resolver = _resolve, client: httpx.Client | None = None
) -> dict:
    host = normalize_domain(domain)
    try:
        addrs = resolver(host)
    except OSError as e:
        raise DomainProofError(f"We couldn't find {host}. Check the spelling.") from e
    if not addrs:
        raise DomainProofError(f"We couldn't find {host}. Check the spelling.")
    for a in addrs:
        if not ipaddress.ip_address(a).is_global:
            raise DomainProofError(f"{host} points to a private address, so we can't check it.")

    own = client is None
    client = client or httpx.Client(timeout=5, follow_redirects=False)
    try:
        with client.stream("GET", f"https://{host}/.well-known/vpp.json") as r:
            if r.status_code != 200:
                raise DomainProofError(
                    f"https://{host}/.well-known/vpp.json returned {r.status_code}"
                )
            data = b""
            for chunk in r.iter_bytes():
                data += chunk
                if len(data) > MAX_BYTES:
                    raise DomainProofError("vpp.json is too large")
    except httpx.HTTPError as e:
        raise DomainProofError(f"could not fetch from {host}: {e.__class__.__name__}") from None
    finally:
        if own:
            client.close()
    try:
        doc = json.loads(data)
    except ValueError:
        raise DomainProofError("vpp.json is not valid JSON") from None
    if not isinstance(doc, dict):
        raise DomainProofError("vpp.json must be an object")
    return doc


def check(doc: dict, *, origin: str, profile_id: str, fingerprint: str) -> None:
    if doc.get("vpp") != 1 or doc.get("log") != origin:
        raise DomainProofError(f'vpp.json must have "vpp": 1 and "log": "{origin}"')
    if doc.get("profile") != profile_id:
        raise DomainProofError(f'vpp.json must have "profile": "{profile_id}"')
    keys = doc.get("keys")
    if not isinstance(keys, list) or fingerprint not in keys:
        raise DomainProofError(f'vpp.json "keys" must include {fingerprint}')
