"""Embeddable SVG badge: '<label> | <amount>' in a flat two-part pill."""

from html import escape

# Per LEDGER_SPEC §1: say "recorded", not "verified"/"proven", until counter-confirmation exists.
LEFT = "payments recorded"


def _width(text: str) -> int:
    # Approximate Verdana 11px advance; good enough without font metrics.
    return int(len(text) * 6.6) + 12


def render(value: str, *, confirmed_by: str | None) -> str:
    left, right = LEFT, value
    lw, rw = _width(left), _width(right)
    # Green only when every recorded payment is confirmed by the recipient's own passkey.
    color = "#2e7d32" if confirmed_by else "#8d6e00"
    suffix = (
        f" (all confirmed by {confirmed_by})"
        if confirmed_by
        else " (not all confirmed by recipient)"
    )
    title = escape(f"{left}: {right}{suffix}")
    w = lw + rw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img"
 aria-label="{title}">
<title>{title}</title>
<rect width="{lw}" height="20" rx="3" fill="#444"/>
<rect x="{lw}" width="{rw}" height="20" rx="3" fill="{color}"/>
<rect x="{lw}" width="4" height="20" fill="{color}"/>
<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
<text x="{lw / 2}" y="14">{escape(left)}</text>
<text x="{lw + rw / 2}" y="14">{escape(right)}</text>
</g>
</svg>"""
