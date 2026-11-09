"""Fixed test keys and a genesis helper (2-of-3 root keys). Never use these keys for real."""

from ..ledger import LedgerKey
from ..ledger.entries import RootSig
from ..ledger.signing import genesis_statement
from ..ledger.store import init_ledger

ORIGIN = "proofs.test/log"
ROOTS = [LedgerKey.from_seed(bytes([0xA0 + i]) * 32) for i in range(3)]


def root_sigs(stmt: bytes, keys=ROOTS[:2]) -> list[RootSig]:
    return [RootSig(key=k.public_key.hex(), sig=k.sign(stmt).hex()) for k in keys]


def genesis(session, key):
    return init_ledger(
        session,
        key,
        ORIGIN,
        [r.public_key.hex() for r in ROOTS],
        2,
        root_sigs(genesis_statement(ORIGIN, key.public_key)),
    )
