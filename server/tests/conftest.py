"""A throwaway Postgres cluster per test session (needs initdb/pg_ctl on PATH, no service).

Migrations run once into a template database; each test gets a fresh copy of it.
"""

import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from vpp.ledger import LedgerKey
from vpp.testing.ledger import ORIGIN, genesis

SERVER = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _url(sock: Path, db: str) -> str:
    return f"postgresql+psycopg://postgres@/{db}?host={sock}"


@pytest.fixture(scope="session")
def pg_cluster(tmp_path_factory):
    if not shutil.which("initdb"):
        pytest.skip("initdb not found; install PostgreSQL")
    base = tmp_path_factory.mktemp("pg")
    data, sock = base / "data", base / "sock"
    sock.mkdir()
    subprocess.run(
        ["initdb", "-D", str(data), "-U", "postgres", "--auth=trust", "--no-sync"],
        check=True,
        capture_output=True,
    )
    opts = f"-k {sock} -c listen_addresses='' -c fsync=off -c synchronous_commit=off"
    subprocess.run(
        ["pg_ctl", "-D", str(data), "-o", opts, "-l", str(base / "log"), "-w", "start"],
        check=True,
        capture_output=True,
    )
    try:
        cfg = Config(str(SERVER / "alembic.ini"))
        cfg.set_main_option("sqlalchemy.url", _url(sock, "vpp_template").replace("%", "%%"))
        admin = create_engine(_url(sock, "postgres"), isolation_level="AUTOCOMMIT")
        with admin.connect() as c:
            c.execute(text("CREATE DATABASE vpp_template"))
        command.upgrade(cfg, "head")
        yield sock, admin
    finally:
        subprocess.run(["pg_ctl", "-D", str(data), "-m", "immediate", "stop"], capture_output=True)


@pytest.fixture
def make_engine(pg_cluster):
    """Factory for fresh, migrated databases (several per test when needed)."""
    sock, admin = pg_cluster
    made = []

    def make():
        name = f"t_{uuid.uuid4().hex[:12]}"
        with admin.connect() as c:
            c.execute(text(f"CREATE DATABASE {name} TEMPLATE vpp_template"))
        eng = create_engine(_url(sock, name))
        made.append((name, eng))
        return eng

    yield make
    for name, eng in made:
        eng.dispose()
        with admin.connect() as c:
            c.execute(text(f"DROP DATABASE {name} WITH (FORCE)"))


@pytest.fixture
def engine(make_engine):
    return make_engine()


@pytest.fixture(autouse=True)
def _origin(monkeypatch):
    from vpp.config import get_settings

    monkeypatch.setenv("VPP_ORIGIN", ORIGIN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def key():
    return LedgerKey.from_seed(bytes(range(32)))


@pytest.fixture
def ledger(engine, key):
    """An engine whose ledger already has a genesis entry."""
    with Session(engine) as s:
        genesis(s, key)
        s.commit()
    return engine
