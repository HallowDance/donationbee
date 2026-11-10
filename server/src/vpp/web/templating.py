"""The one Jinja environment for every page, so filters and globals can't drift apart."""

from datetime import UTC
from pathlib import Path
from urllib.parse import urlencode

from fastapi.templating import Jinja2Templates

from .. import i18n
from ..config import get_settings
from ..queries import LABELS
from ..receipts import receipt_filename

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
# {% trans %} blocks and _() follow the request's language (see vpp.i18n); "trimmed" folds the
# whitespace of multi-line blocks so the catalog holds clean sentences.
templates.env.add_extension("jinja2.ext.i18n")
templates.env.install_gettext_callables(i18n.gettext, i18n.ngettext, newstyle=True)
templates.env.policies["ext.i18n.trimmed"] = True
templates.env.globals["lang"] = lambda: i18n.current.get()


def _lang_url(request, lang: str) -> str:
    """This page in another language: same path and query, with ?lang= (which sets the cookie)."""
    params = [(k, v) for k, v in request.query_params.multi_items() if k != "lang"]
    return f"{request.url.path}?{urlencode([*params, ('lang', lang)])}"


templates.env.globals["lang_url"] = _lang_url
templates.env.filters["money"] = lambda v, cur: i18n.money(v, cur)
templates.env.globals["entry_label"] = lambda t: i18n.gettext(LABELS[t]) if t in LABELS else t
# DB timestamps come back in the server's local zone; always show UTC, as the envelope does.
templates.env.filters["utc"] = lambda dt: dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
templates.env.globals["brand"] = lambda: get_settings().brand_name
templates.env.globals["receipt_filename"] = lambda e: receipt_filename(e, get_settings().brand_name)
templates.env.globals["banner"] = lambda: get_settings().banner
templates.env.globals["contact_email"] = lambda: get_settings().contact_email
templates.env.globals["anchors_url"] = lambda: get_settings().anchors_public_url
templates.env.globals["stripe_test_mode"] = lambda: not get_settings().stripe_livemode
# Only promise hourly anchors when anchoring is actually configured.
templates.env.globals["anchoring_on"] = lambda: bool(
    get_settings().anchors_repo_path or get_settings().ots_enabled
)
