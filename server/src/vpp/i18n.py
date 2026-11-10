"""Site languages. English is the source text; other languages come from gettext catalogs in
web/locale/<lang>/LC_MESSAGES/messages.mo (edit the .po next to it, then run scripts/i18n.sh).

The language of a request is, in order: ?lang=, the "lang" cookie that ?lang= sets, then the
browser's Accept-Language. It lives in a context variable for the duration of the request.
"""

import gettext as _gettext
from contextvars import ContextVar
from pathlib import Path

LANGS = ("en", "bg")
DEFAULT = "en"
COOKIE = "lang"
LOCALE_DIR = Path(__file__).parent / "web" / "locale"

_catalogs = {"en": _gettext.NullTranslations()} | {
    lang: _gettext.translation("messages", LOCALE_DIR, [lang]) for lang in LANGS if lang != "en"
}
current: ContextVar[str] = ContextVar("lang", default=DEFAULT)


def choose(query: str | None, cookie: str | None, accept_language: str | None) -> str:
    for explicit in (query, cookie):
        if explicit in LANGS:
            return explicit
    ranked = []
    for i, part in enumerate((accept_language or "").split(",")):
        tag, _, params = part.strip().partition(";")
        q = 1.0
        if params.strip().startswith("q="):
            try:
                q = float(params.strip()[2:])
            except ValueError:
                continue
        ranked.append((-q, i, tag.split("-")[0].lower()))
    for _q, _i, lang in sorted(ranked):
        if lang in LANGS:
            return lang
    return DEFAULT


def gettext(message: str) -> str:
    return _catalogs[current.get()].gettext(message)


def ngettext(singular: str, plural: str, n: int) -> str:
    return _catalogs[current.get()].ngettext(singular, plural, n)


def N_(message: str) -> str:
    """Marks a string for translation where it's defined; translate it with gettext() on use."""
    return message


# The beta banner is set in the deployment's env (VPP_BANNER); listed here so it gets translated.
KNOWN_BANNERS = [
    N_(
        "Beta: test mode only, no real money moves. Demo hives use example data, and the demo "
        "witness is run by us."
    ),
]


def money(value: int, currency: str) -> str:
    """Minor units -> display, the way the current language writes amounts."""
    if current.get() == "bg":
        # Bulgarian: 1 234,50 € (space between thousands, decimal comma, sign after).
        text = f"{value / 100:,.2f}".replace(",", " ").replace(".", ",")
        return f"{text} €" if currency == "EUR" else f"{text} {currency}"
    return f"{value / 100:,.2f} {currency}"
