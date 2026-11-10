# Running the beta on a server

The public beta at bee.theorycorner.com runs on one Ubuntu 24.04 machine with systemd, nginx and
PostgreSQL. Everything below runs as root unless noted.

| What | Where |
| --- | --- |
| Code (`git clone` of this repo, `uv sync --frozen --all-packages --no-dev`) | `/opt/donationbee` |
| Online signing key, witness key and state, anchors clone, deploy key | `/var/lib/donationbee` (user `donationbee`, mode 700) |
| Settings and secrets | `/etc/donationbee/env` (root:donationbee, 640), see `donationbee.env.example` |
| Database | PostgreSQL `vpp_beta`, owned by role `donationbee`, over the local socket |

## Services

| Unit | Does |
| --- | --- |
| `donationbee-web.service` | Runs migrations, then the app on 127.0.0.1:8092 (nginx proxies to it) |
| `donationbee-witness.service` | The demo witness on 127.0.0.1:8091 |
| `donationbee-witness-push.timer` | Asks the witnesses to cosign, every minute |
| `donationbee-anchor.timer` | Pushes a checkpoint to the anchors repo and upgrades Bitcoin proofs, hourly |

Logs: `journalctl -u 'donationbee-*'`.

## First-time setup

1. Create the user, directories and database:
   ```sh
   useradd --system --home-dir /var/lib/donationbee --create-home --shell /usr/sbin/nologin donationbee
   chmod 700 /var/lib/donationbee
   install -d -m 750 -o root -g donationbee /etc/donationbee
   runuser -u postgres -- createuser donationbee
   runuser -u postgres -- createdb -O donationbee vpp_beta
   ```
2. Clone the code into `/opt/donationbee` (owned by `donationbee`) and run `uv sync` as above.
3. As `donationbee`, in `/opt/donationbee`, with the settings from step 4 exported:
   ```sh
   .venv/bin/vpp keygen                       # online key at VPP_SIGNING_KEY_PATH
   .venv/bin/vpp-witness keygen --name bee.theorycorner.com/demo-witness \
       --out /var/lib/donationbee/witness.key > /var/lib/donationbee/witness.vkey
   (cd server && ../.venv/bin/alembic upgrade head)
   .venv/bin/vpp demo-seed                    # only for a demo ledger
   ```
   Write `/var/lib/donationbee/witness.json` (paths are relative to it):
   ```json
   {"name": "bee.theorycorner.com/demo-witness", "key_file": "witness.key", "state_dir": "witness-state",
    "logs": [{"origin": "bee.theorycorner.com/log", "vkeys": ["<log vkey>"]}]}
   ```
   The log vkey is `vkey(origin, online public key)` from `vpp.ledger.note`.
4. Fill in `/etc/donationbee/env` from `donationbee.env.example`.
5. Anchors: clone the anchors repo into `/var/lib/donationbee/anchors` with an SSH remote, give
   `donationbee` an SSH key (`/var/lib/donationbee/.ssh`), and add its public half to the anchors
   repo as a deploy key with write access.
6. Install the units from `systemd/`, then
   `systemctl enable --now donationbee-witness donationbee-web donationbee-witness-push.timer donationbee-anchor.timer`.
7. Install `nginx-bee.theorycorner.com.conf` and run certbot.

## Moving an existing ledger

Stop the old copy first and make sure it can't start again. Two copies signing with the same key
would publish two different histories, which is exactly the misbehaviour witnesses report. Then copy
the database (`pg_dump --no-owner --no-privileges`), the key files, `witness.json`, the
`witness-state` directory and the secrets, and check that `/api/v1/head` gives the same hash as
before.
