# Verified Payment Proofs

A public record of opt-in payments that you can check without trusting whoever runs it.

1. Payments made through Stripe Connect Checkout become entries in a hash-chained, signed ledger.
2. The entries form an RFC 6962 Merkle tree. Each new tree head is published as a signed C2SP
   checkpoint.
3. Independent witnesses cosign each checkpoint, so everyone sees the same history.
4. The checkpoints are also anchored to a public git repo and to Bitcoin.
5. Payers keep receipts that prove their payment was included.
6. Recipients confirm the payments they received, using their own passkeys. Those passkeys are
   tied to their real domain.

The normative format and the full trust model are in [`docs/LEDGER_SPEC.md`](docs/LEDGER_SPEC.md).

```
server/       vpp: FastAPI app, ledger, Stripe Connect, passkeys, anchoring, operator CLI
verifier/     vpp-verify: standalone checker; never imports vpp
witness/      vpp-witness: standalone C2SP tlog-witness; never imports vpp
testvectors/  fixtures both implementations must pass (regenerate: server/scripts/gen_vectors.py)
```

## What each party can check

| Party | Checks | Using |
|---|---|---|
| Anyone | The history wasn't rewritten, and each entry was signed by the key in force at that point | `vpp-verify --url … --pin-genesis …` |
| Anyone | They see the same history as everyone else, not a private fork | `--witness <vkey> --min-witnesses k` |
| Anyone | Nothing changed since an anchor time | `--anchors-repo <git url> --check-ots` |
| Payer | Their payment is still there, unchanged | `--receipt receipt.json` (from the receipt page) |
| Anyone | The recipient itself confirmed a payment | Checked automatically: every confirmation's WebAuthn signature is re-verified |
| Anyone | The recipient's passkey belongs to the domain it claims | `--check-domains` |

Not covered: the operator and a recipient working together to invent a payment, a payer and
recipient who know each other, and money sent back outside Stripe (see §1 of the spec).

## Develop

Needs `uv` and the PostgreSQL binaries (`initdb`, `pg_ctl`). No database service or Docker is
required.

```sh
uv sync --all-packages --all-extras
uv run pytest                      # starts its own throwaway Postgres

eval "$(scripts/devdb.sh start)"   # dev DB in ./.pgdata; exports VPP_DATABASE_URL
(cd server && uv run alembic upgrade head)
```

### Creating a ledger (root-key ceremony)

Root keys authorize the ledger's creation and every change of signing key. Keep them offline, on
separate machines, held by separate people. `vpp root …` needs no database.

```sh
# Each root holder, on an offline machine:
uv run vpp root keygen root-a.json          # prints the root public key
# Operator:
uv run vpp keygen                           # online key file (dev); use Cloud KMS in production
# Two root holders each sign the genesis statement for that online key:
uv run vpp root sign-genesis root-a.json <online public key>   # prints {"key":…,"sig":…}
# Operator:
uv run vpp init-ledger --root-key <a> --root-key <b> --root-key <c> --threshold 2 \
    --root-sig '<json from a>' --root-sig '<json from b>'
```

Publish the printed genesis hash widely. Verifiers pin it with `--pin-genesis`.

**To rotate the online key** (scheduled, after a compromise, or if it's lost), run
`vpp ceremony-info`, then have two root holders run `vpp root sign-rotation <file> <old> <new>`.
Then run `vpp rotate-key --new-key-file … --root-sig … --root-sig …`. A stolen online key can't
do this on its own. After rotating, send witnesses the new checkpoint vkey (from
`GET /api/v1/keys`).

### Cloud KMS (production online key)

1. Create an asymmetric-sign key with algorithm `EC_SIGN_ED25519`.
2. Set `VPP_SIGNER=gcpkms` and
   `VPP_KMS_KEY_VERSION=projects/…/cryptoKeys/…/cryptoKeyVersions/1`.
3. Install with `vpp[gcp]`.

The private key never leaves KMS.

### Witnesses

Ask independent people or organisations to run one. Ideally use several, and consider the public
transparency.dev witness network.

```sh
uv run vpp-witness keygen --name witness.example/w1 --out w1.key   # prints the witness vkey
cat > witness.json <<EOF
{"name": "witness.example/w1", "key_file": "w1.key",
 "logs": [{"origin": "proofs.example/log", "vkeys": ["<checkpoint vkey from /api/v1/keys>"]}]}
EOF
uv run vpp-witness serve --config witness.json --port 8780
```

On the server, set `VPP_WITNESSES='[{"vkey": "<witness vkey>", "url": "https://witness.example"}]'`
and run `vpp witness-push` every minute from cron.

### Stripe (sandbox)

1. Create a [sandbox](https://docs.stripe.com/sandboxes) and enable Connect. Set
   `VPP_STRIPE_SECRET_KEY`. Prefer a restricted key with access to Accounts, Account Links,
   Checkout Sessions and Refunds.
2. Run `stripe listen --forward-connect-to localhost:8000/webhooks/stripe`, then set
   `VPP_STRIPE_WEBHOOK_SECRET` to the secret it prints. For v2 account updates, add an event
   destination for `v2.core.account[configuration.merchant].capability_status_updated` pointing
   at `/webhooks/stripe/v2`, and set `VPP_STRIPE_THIN_WEBHOOK_SECRET`.
3. Run `uv run vpp create-profile acme "Acme Inc"` and open the onboarding link it prints. The
   return link leads to the recipient area, where the recipient:
   1. adds a passkey;
   2. publishes `/.well-known/vpp.json` on their domain;
   3. publishes the key.
4. Pay at `/pay/acme` with a test card. The payer lands on `/receipt/…`, and the recipient
   confirms at `/recipient`.

Set `VPP_RP_ID` to this site's hostname and `VPP_PUBLIC_BASE_URL` to its https origin. Passkeys
are bound to both.

### Anchoring (cron, hourly)

```sh
VPP_ANCHORS_REPO_PATH=/path/to/public-anchors-repo uv run vpp anchor
uv run vpp ots-upgrade             # completes Bitcoin proofs a few hours after stamping
```

The anchors repo should be public, hosted outside your control, with a protected branch that
blocks force-pushes.
