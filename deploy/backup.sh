#!/bin/sh
# Nightly backup (systemd/donationbee-backup.service runs it as user donationbee).
# Writes a database dump and the state directory (keys, witness config and state) to
# /var/backups/donationbee and keeps 14 days. The anchors clone is skipped: it lives on GitHub.
# Installed as /usr/local/lib/donationbee/backup.sh.
set -eu
dest=/var/backups/donationbee
stamp=$(date -u +%Y%m%dT%H%MZ)
pg_dump --format=custom --dbname=vpp_beta --file="$dest/vpp_beta-$stamp.dump.part"
mv "$dest/vpp_beta-$stamp.dump.part" "$dest/vpp_beta-$stamp.dump"
tar -C /var/lib/donationbee --exclude=./anchors --exclude=./.cache --exclude=./.ssh \
    -czf "$dest/state-$stamp.tar.gz.part" .
mv "$dest/state-$stamp.tar.gz.part" "$dest/state-$stamp.tar.gz"
find "$dest" -maxdepth 1 \( -name 'vpp_beta-*.dump' -o -name 'state-*.tar.gz' \) -mtime +13 -delete
echo "backed up vpp_beta and state as $stamp"
