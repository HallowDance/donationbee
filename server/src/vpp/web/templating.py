"""The one Jinja environment for every page, so filters and globals can't drift apart."""

from datetime import UTC
from pathlib import Path

from fastapi.templating import Jinja2Templates

from ..config import get_settings
from ..queries import format_money

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
templates.env.filters["money"] = lambda v, cur: format_money(v, cur)
# DB timestamps come back in the server's local zone; always show UTC, as the envelope does.
templates.env.filters["utc"] = lambda dt: dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
templates.env.globals["brand"] = lambda: get_settings().brand_name
templates.env.globals["banner"] = lambda: get_settings().banner
templates.env.globals["stripe_test_mode"] = lambda: not get_settings().stripe_livemode
# Only promise hourly anchors when anchoring is actually configured.
templates.env.globals["anchoring_on"] = lambda: bool(
    get_settings().anchors_repo_path or get_settings().ots_enabled
)
