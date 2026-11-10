#!/usr/bin/env bash
# Re-extract the site's text into the catalog and compile it.
#   scripts/i18n.sh            update messages.po files from the code, then compile .mo
# Translate by editing server/src/vpp/web/locale/<lang>/LC_MESSAGES/messages.po, then run this
# again. Script text (static/js) is translated in static/js/i18n-<lang>.js instead.
set -euo pipefail
cd "$(dirname "$0")/../server"
L=src/vpp/web/locale
uv run pybabel -q extract -F babel.cfg -k _ -k gettext -k ngettext:1,2 -k N_ \
  --no-location --sort-output --project DonationBee --copyright-holder "Ivo Iliev" \
  -o "$L/messages.pot" src/vpp
for po in "$L"/*/LC_MESSAGES/messages.po; do
  uv run pybabel -q update --no-fuzzy-matching -i "$L/messages.pot" -d "$L" -D messages \
    -l "$(basename "$(dirname "$(dirname "$po")")")"
done
uv run pybabel compile --statistics -d "$L" -D messages
