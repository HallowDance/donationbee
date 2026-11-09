"""Embeddable SVG badge: '[hex] DonationBee | <amount> recorded/confirmed'.

Per LEDGER_SPEC §1 the wording is "recorded" until the recipient confirmed every payment; only
then does it say "confirmed" and turn green.
"""

from html import escape

INK, HONEY, LEAF = "#1b1408", "#ffc93c", "#1f7a3e"


def _width(text: str, px: float) -> int:
    # Approximate advance for a bold sans at 11px; good enough without font metrics.
    return int(len(text) * px) + 14


def render(value: str, *, confirmed_by: str | None, brand: str = "DonationBee") -> str:
    state = "confirmed" if confirmed_by else "recorded"
    right = f"{value} {state}"
    lw = _width(brand, 7.6) + 22  # room for the hexagon
    rw = _width(right, 6.6)
    w = lw + rw
    bg, fg = (LEAF, "#ffffff") if confirmed_by else (HONEY, INK)
    suffix = (
        f" (all confirmed by {confirmed_by})"
        if confirmed_by
        else " (not all confirmed by recipient)"
    )
    title = escape(f"{brand}: {value} {state}{suffix}")
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="22" role="img"
 aria-label="{title}">
<title>{title}</title>
<rect width="{w}" height="22" rx="6" fill="{INK}"/>
<path d="M{lw} 0h{rw - 6}a6 6 0 0 1 6 6v10a6 6 0 0 1-6 6h-{rw - 6}z" fill="{bg}"/>
<path d="M14 4.5l5.2 3v6l-5.2 3-5.2-3v-6z" fill="{HONEY}"/>
<g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" font-weight="bold">
<text x="{(lw + 16) / 2 + 4}" y="15" fill="{HONEY}" text-anchor="middle">{escape(brand)}</text>
<text x="{lw + rw / 2}" y="15" fill="{fg}" text-anchor="middle">{escape(right)}</text>
</g>
</svg>"""
