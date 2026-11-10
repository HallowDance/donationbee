"""Languages: how a page's language is chosen, that the Bulgarian catalogs are complete and match
the code, and that the scripts' dictionary covers every string the scripts show."""

import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from babel.messages.mofile import read_mo
from babel.messages.pofile import read_po
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from vpp import i18n

SERVER = Path(__file__).resolve().parents[1]
WEB = SERVER / "src" / "vpp" / "web"
PO = WEB / "locale" / "bg" / "LC_MESSAGES" / "messages.po"
MO = PO.with_suffix(".mo")
PLACEHOLDERS = re.compile(r"%\([a-z_]+\)s|%%|\{[a-z_]+\}|</?[a-z]+[^>]*>")


@pytest.fixture
def app_client(ledger):
    from vpp.app import app
    from vpp.db import get_session

    factory = sessionmaker(ledger, expire_on_commit=False)

    def session_override():
        with factory() as s:
            yield s

    app.dependency_overrides[get_session] = session_override
    yield TestClient(app)
    app.dependency_overrides.clear()


class _FakeCheckoutStripe:
    def __init__(self):
        self.calls = []
        self.v1 = SimpleNamespace(
            checkout=SimpleNamespace(sessions=SimpleNamespace(create=self._create))
        )

    def _create(self, params, options):
        self.calls.append((params, options))
        return SimpleNamespace(url="https://checkout.stripe.test/x")


@pytest.mark.parametrize(
    "query, cookie, accept, expected",
    [
        (None, None, None, "en"),
        (None, None, "bg-BG,bg;q=0.9,en;q=0.8", "bg"),
        (None, None, "de-DE,en;q=0.5,bg;q=0.9", "bg"),  # by q, not by order
        (None, None, "de,fr", "en"),
        (None, "bg", "en", "bg"),  # the switch beats the browser
        ("en", "bg", "bg", "en"),  # ?lang= beats both
        ("xx", None, "bg", "bg"),  # unknown values are ignored
    ],
)
def test_language_choice(query, cookie, accept, expected):
    assert i18n.choose(query, cookie, accept) == expected


def test_bulgarian_money():
    token = i18n.current.set("bg")
    try:
        assert i18n.money(123450, "EUR") == "1 234,50 €"
    finally:
        i18n.current.reset(token)
    assert i18n.money(123450, "EUR") == "1,234.50 EUR"


def test_pages_follow_the_switch_and_the_browser(app_client):
    en = app_client.get("/").text
    assert '<html lang="en">' in en and "Proof the money" in en and 'hreflang="bg"' in en

    r = app_client.get("/?lang=bg")
    assert '<html lang="bg">' in r.text and "Доказателство, че парите" in r.text
    assert r.cookies.get("lang") == "bg"
    assert "Accept-Language" in r.headers["vary"]
    # The cookie now keeps every page in Bulgarian, until switched back.
    assert "За получатели" in app_client.get("/recipients").text
    assert "Who runs this" in app_client.get("/about?lang=en").text
    assert '<html lang="en">' in app_client.get("/ledger").text

    app_client.cookies.clear()
    page = app_client.get("/about", headers={"Accept-Language": "bg"}).text
    assert "Кой стои зад това" in page and "д-р Иво Илиев" in page


def test_switch_link_keeps_the_page_and_its_query(app_client):
    page = app_client.get("/ledger?before=5").text
    assert 'href="/ledger?before=5&amp;lang=bg"' in page


@pytest.mark.parametrize("path", ["/", "/ledger", "/recipients", "/about", "/recipient/login"])
def test_every_page_renders_in_bulgarian(app_client, path):
    r = app_client.get(path, headers={"Accept-Language": "bg"})
    assert r.status_code == 200
    assert '<html lang="bg">' in r.text
    assert "%(" not in r.text and "{{" not in r.text  # no unfilled placeholders


def test_catalog_is_complete_and_compiled():
    po = read_po(PO.open("rb"), locale="bg")
    strings = lambda m: m.string if isinstance(m.string, tuple) else (m.string,)  # noqa: E731
    missing = [m.id for m in po if m.id and not all(strings(m))]
    assert missing == []
    assert not [m.id for m in po if m.id and m.fuzzy]
    for m in po:
        if not m.id:
            continue
        for src, out in zip(
            m.id if isinstance(m.id, tuple) else (m.id,),
            m.string if isinstance(m.string, tuple) else (m.string,),
            strict=True,
        ):
            assert sorted(PLACEHOLDERS.findall(src)) == sorted(PLACEHOLDERS.findall(out)), m.id
    # The .mo the server loads says the same as the .po (run scripts/i18n.sh after editing).
    mo = read_mo(MO.open("rb"))
    norm = lambda x: tuple(x) if isinstance(x, (list, tuple)) else x  # noqa: E731
    assert {norm(m.id): norm(m.string) for m in mo if m.id} == {
        norm(m.id): norm(m.string) for m in po if m.id
    }


def test_catalog_has_every_string_in_the_code(tmp_path):
    pot = tmp_path / "messages.pot"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "babel.messages.frontend",
            "-q",
            "extract",
            "-F",
            "babel.cfg",
            "-k",
            "_",
            "-k",
            "gettext",
            "-k",
            "ngettext:1,2",
            "-k",
            "N_",
            "--no-location",
            "-o",
            str(pot),
            "src/vpp",
        ],
        cwd=SERVER,
        check=True,
    )
    in_code = {m.id for m in read_po(pot.open("rb")) if m.id}
    in_catalog = {m.id for m in read_po(PO.open("rb")) if m.id}
    assert in_code - in_catalog == set(), "new text: run scripts/i18n.sh and translate it"
    assert in_catalog - in_code == set(), "stale text: run scripts/i18n.sh"


def _js_bg() -> dict[str, str]:
    src = (WEB / "static" / "js" / "i18n-bg.js").read_text()
    pairs = re.findall(r'^\s*"((?:[^"\\]|\\.)*)":\s*"((?:[^"\\]|\\.)*)",\s*$', src, re.M)
    return dict(pairs)


def _js_keys() -> set[str]:
    keys = set()
    scripts = [*(WEB / "static" / "js").glob("*.js"), WEB / "static" / "passkey.js"]
    for f in scripts:
        if f.name.startswith("i18n"):
            continue
        src = f.read_text()
        keys.update(re.findall(r'\bt\(\s*"((?:[^"\\]|\\.)*)"', src))
        for one, many in re.findall(r'\btn\(\s*"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"', src):
            keys.update((one, many))
        facts = re.search(r"const FACTS = \[(.*?)\];", src, re.S)
        if facts:
            keys.update(re.findall(r'"((?:[^"\\]|\\.)*)"', facts.group(1)))
    return keys


def test_scripts_have_a_bulgarian_string_for_every_text():
    bg, keys = _js_bg(), _js_keys()
    assert len(keys) > 40  # the regexes above still find the scripts' strings
    assert sorted(keys - bg.keys()) == []
    assert sorted(bg.keys() - keys) == [], "unused entries in i18n-bg.js"
    for k in keys:
        assert sorted(re.findall(r"\{\w+\}", k)) == sorted(re.findall(r"\{\w+\}", bg[k])), k


def test_checkout_page_and_line_items_follow_the_language(ledger, monkeypatch):
    from sqlalchemy.orm import Session
    from vpp.db.models import Profile
    from vpp.stripe_connect import checkout as co

    monkeypatch.setattr(co, "refresh_status", lambda *a: "active")
    fake = _FakeCheckoutStripe()
    token = i18n.current.set("bg")
    try:
        with Session(ledger) as s:
            p = Profile(id="prof_b", slug="b", display_name="Б", stripe_account_id="acct_b")
            s.add(p)
            s.flush()
            co.create_checkout(
                s, fake, p, amount=1000, currency="EUR", payer_name=None, note=None, tip=200
            )
    finally:
        i18n.current.reset(token)
    params, _ = fake.calls[0]
    assert params["locale"] == "bg"
    names = [li["price_data"]["product_data"]["name"] for li in params["line_items"]]
    assert names == [
        "Плащане към Б",
        "Незадължителен бакшиш за DonationBee (не е част от дарението)",
    ]
