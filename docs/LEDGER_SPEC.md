# VPP Ledger Format — v1

This document is normative. The server (`server/`), the independent verifier (`verifier/`) and
the witness (`witness/`) are all implemented from it, and the server and verifier must both pass
the vectors in `testvectors/`.

Notation: `||` is byte concatenation, `SHA-256` returns 32 bytes, hex is lowercase, "b64" is
RFC 4648 base64 with padding, "b64url" is unpadded URL-safe base64.

## 1. Trust model

| Threat | What catches it | Who can check |
|---|---|---|
| Operator edits, deletes or reorders past entries | Hash chain (§4) + Merkle tree (§7) | Anyone holding an older checkpoint, a receipt, a witness, or an anchor |
| Operator shows different histories to different people | Witness cosignatures (§9) | Anyone requiring k cosignatures from witnesses they trust |
| Operator rewrites history before anyone looks | Anchors in an independent git repo + Bitcoin via OpenTimestamps (§13) | Anyone |
| Operator quietly drops a specific payment | Payer receipts (§10) | The payer, and anyone they show the receipt to |
| Operator invents payments to a recipient | Recipient confirmations signed with the recipient's own passkey (§11) | Anyone, for confirmed payments |
| Operator claims to be a recipient | Domain proof (§12): only keys listed on the recipient's own domain count | Anyone |
| Stolen online signing key used to take over | Key rotations require k-of-n offline root keys (§5) | Anyone |

What stays out of reach, and must be stated in UI copy:

- **Unconfirmed payments are attestations.** A payment the recipient hasn't confirmed rests only
  on the operator's word that Stripe reported it. UI copy says "recorded", not "verified" or
  "proven". "Confirmed by \<domain\>" is used only when §11 holds.
- **Collusion.** The operator and a recipient together can record and confirm a payment that
  never happened.
- **Self-dealing.** A payer and recipient who are the same person, or who know each other, look
  like strangers.
- **Money sent back.** A recipient can return funds outside Stripe; no ledger sees that.
- **A stolen online key can append entries** until it is rotated out. They are signed and
  witnessed like any other. After a `compromise` rotation, verifiers should treat entries since
  the last checkpoint that predates the compromise as suspect.

## 2. Entry (wire form)

| field        | wire (JSON API)          | meaning                                          |
|--------------|--------------------------|--------------------------------------------------|
| `seq`        | integer                  | 1-based position, no gaps                        |
| `prev_hash`  | hex, 64 chars            | `hash` of entry `seq-1`; 64 zeros for `seq = 1`   |
| `envelope`   | b64url                   | the exact canonical bytes that were hashed       |
| `hash`       | hex, 64 chars            | see §4                                           |
| `sig`        | hex, 128 chars           | Ed25519 signature over the 32 raw `hash` bytes   |

The API may also return convenience copies (`type`, `key_id`, `created_at`, `body`). Verifiers
must ignore them. Only `envelope` is authoritative.

## 3. Envelope

`envelope` is the RFC 8785 (JCS) canonical serialization, UTF-8, of:

```json
{"v": 1, "seq": 42, "type": "payment", "key_id": "3f9a1c0b7e2d4a65",
 "created_at": "2026-11-09T12:00:00Z", "body": {"...": "type-specific, §5–§6, §11"}}
```

- The bytes must be canonical: `JCS(parse(envelope)) == envelope`.
- **No floats.** Every number is an integer with `|n| <= 2^53 - 1`.
- Money is `{"value": <integer minor units>, "currency": "<ISO 4217 upper-case>"}`.
- Timestamps are UTC, `YYYY-MM-DDTHH:MM:SSZ`.
- `envelope.seq` equals the entry's position.
- `key_id` = hex of the first 8 bytes of `SHA-256(32-byte Ed25519 public key)` of the key that
  must sign this entry (§5).
- Unknown body fields are not allowed in v1.

## 4. Hash and signature

```
hash = SHA-256( "vpp:entry:v1" || 0x00 || prev_hash(32) || envelope )
sig  = Ed25519_sign(signing key, hash(32))
```

## 5. Signing authority

There are two kinds of key:

- **Online key.** One Ed25519 key that signs entries and checkpoints. It may live in a key file
  (development) or a KMS/HSM (production).
- **Root keys.** A set of Ed25519 keys and a threshold k. They are kept offline. Their only job is
  to authorize genesis, online-key rotations and root-set rotations.

Let `origin_hash = SHA-256(UTF-8 origin)`, where `origin` comes from genesis. A **root
signature** is `{"key": hex pubkey, "sig": hex Ed25519 signature over a statement}`. A statement
is authorized when **≥ threshold distinct keys from the current root set** have valid signatures
on it. Signatures from keys outside the set are ignored.

### `genesis` (seq 1 only)
```json
{"origin": "proofs.example/log", "online_key": "<hex>", "root_keys": ["<hex>", "…"],
 "root_threshold": 2, "root_sigs": [ … ]}
```
- `origin`: a C2SP origin (§8). Root keys must be distinct; `1 <= root_threshold <= len(root_keys)`.
- Statement: `"vpp:genesis:v1" || 0x00 || origin_hash || online_key(32)`.
- The entry is signed by `online_key`.

### `key_rotation`
```json
{"from_online_key": "<hex>", "new_online_key": "<hex>",
 "reason": "scheduled" | "compromise" | "lost", "root_sigs": [ … ]}
```
- `from_online_key` must be the active online key.
- `new_online_key` must never have been an online key of this ledger before.
- Statement: `"vpp:rotate:v1" || 0x00 || origin_hash || from(32) || new(32)`.
- The entry itself is signed by the **new** key. That proves the new key is held, and it means a
  lost key can be replaced. Every later entry uses the new key.
- Because the statement names `from` and keys are never reused, an old rotation statement can't
  be replayed.

### `root_rotation`
```json
{"new_root_keys": ["<hex>", "…"], "new_root_threshold": 2, "root_sigs": [ … ]}
```
- `root_sigs` must meet the **current** root threshold. The pair (sorted new keys, threshold)
  must not have been used before.
- Statement: `"vpp:root-rotate:v1" || 0x00 || origin_hash || JCS({"from": {"keys": sorted(old),
  "threshold": old_k}, "to": {"keys": sorted(new), "threshold": new_k}})`.
- Signed by the active online key.

All other entries are signed by the active online key.

## 6. Payment entries

### `payment`
```json
{"recipient": "<profile id>", "amount": {"value": 50000, "currency": "EUR"},
 "occurred_at": "2026-11-09T11:59:41Z", "payer": "<commitment>" | null,
 "note": "<commitment>" | null,
 "evidence": {"type": "stripe_connect", "account": "acct_…", "payment_intent": "pi_…",
              "checkout_session": "cs_…", "livemode": true}}
```

### `reversal`
```json
{"ref_seq": 42, "reason": "refund" | "dispute_lost", "amount": {"value": 50000, "currency": "EUR"},
 "evidence": {"type": "stripe_connect", "account": "acct_…", "object": "re_… | dp_…"}}
```
`ref_seq` must point to an earlier `payment`, with the same currency. The reversals of one payment
add up to at most its amount. Totals are net of reversals.

### `correction`
```json
{"ref_seq": 42, "reason_code": "wrong_recipient" | "duplicate" | "other"}
```
Marks an earlier entry as void. There is no free text, because free text could contain personal
data.

### Personal data commitments
Personal data never appears directly. Instead:
`commitment = "c1:" || hex(SHA-256(salt(32 random bytes) || UTF-8 value))`. The salt and
cleartext are kept in a deletable store. Erasing them makes the value impossible to recover, and
the chain still verifies.

## 7. Merkle tree

An RFC 6962 tree. Leaf `i` (0-based) is the 32-byte `hash` of entry `seq = i + 1`:

```
leaf_hash = SHA-256(0x00 || entry hash)
node_hash = SHA-256(0x01 || left || right)
MTH({})   = SHA-256("")
```

Inclusion and consistency proofs are RFC 6962 §2.1.1–2.1.2 (verified per RFC 9162 §2.1.3–2.1.4).

## 8. Checkpoints

After each append, the log signs a C2SP **tlog-checkpoint** (c2sp.org/tlog-checkpoint) as a
C2SP **signed note** (c2sp.org/signed-note):

```
<origin>\n<tree size>\n<b64 root>\n
\n
— <origin> <b64( key_id(4) || Ed25519 sig over the 3 lines )>\n
```

- The dash is U+2014.
- `key_id = SHA-256(origin || 0x0A || 0x01 || online key)[:4]`.
- The note is signed by the online key that signed entry `size`.
- The verifier key (vkey) for an online key is `<origin>+<hex key_id>+<b64(0x01 || key)>`.
  `GET /api/v1/keys` lists the vkey for each online key.

## 9. Witnesses

Witnesses implement C2SP **tlog-witness** (`POST <prefix>/add-checkpoint`). They only cosign a
checkpoint that is consistent with the last one they cosigned. Cosignatures are C2SP
**tlog-cosignature** Ed25519 (type `0x04`):

```
signed message = "cosignature/v1\ntime <unix seconds>\n" || checkpoint text
signature line = — <witness name> <b64( key_id(4) || u64 big-endian timestamp || sig(64) )>\n
key_id         = SHA-256(witness name || 0x0A || 0x04 || witness key)[:4]
```

`GET /api/v1/checkpoint` serves the latest checkpoint with every cosignature the log holds. A
verifier that requires k cosignatures from witnesses it chose itself sees the same tree as
everyone else, or catches the log presenting two different trees.

## 10. Receipts

```json
{"vpp_receipt": 1, "origin": "…", "entry": { wire entry },
 "checkpoint": "<signed note with cosignatures>",
 "inclusion_proof": ["<b64 hash>", "…"], "witness_cosignatures": 1}
```

A receipt is valid when:

1. the entry's hash recomputes from its envelope;
2. the inclusion proof places `leaf_hash(entry hash)` at index `seq - 1` under the checkpoint's
   root; and
3. the checkpoint carries the required cosignatures.

Checking a receipt against the live ledger also requires that:

- the checkpoint is signed by the ledger's key for that size; and
- the tree computed from the entries served now has the same root at that size.

**Misbehaviour proof.** A checkpoint signed by the log, plus a current history that contradicts
it, can be handed to third parties. Two contradicting checkpoints with valid witness
cosignatures also show that the witnesses misbehaved.

## 11. Recipient keys and confirmations

### `recipient_key`
```json
{"recipient": "<profile id>", "credential_id": "<b64url>", "public_key_spki": "<b64url DER>",
 "alg": -7 | -8 | -257, "rp_id": "proofs.example", "origin": "https://proofs.example",
 "domain": "charity.example", "fingerprint": "k1:<hex SHA-256(SPKI DER)>"}
```

- `alg` is ES256 (P-256), EdDSA (Ed25519) or RS256.
- `fingerprint` must equal the SPKI hash.
- The server publishes this entry only after the domain proof (§12) lists the fingerprint.

### `confirmation`
```json
{"recipient": "<profile id>", "ref_seqs": [42, 43], "credential_id": "<b64url>",
 "authenticator_data": "<b64url>", "client_data_json": "<b64url>", "signature": "<b64url>"}
```

The challenge is:

```
SHA-256( "vpp:confirm:v1" || 0x00 || origin_hash || hash(ref_seq_1) || hash(ref_seq_2) || … )
```

Requirements:

- `ref_seqs` are 1–100 distinct earlier `payment` entries to `recipient`.
- `credential_id` names an earlier `recipient_key` of `recipient`.
- The fields are a WebAuthn assertion with that key. Verifiers check:
  1. `clientDataJSON.type == "webauthn.get"`, `challenge == b64url(challenge)`,
     `origin == recipient_key.origin`, and `crossOrigin` is not true;
  2. `authenticatorData[0:32] == SHA-256(rp_id)`, and the UP (0x01) and UV (0x04) flags are set;
  3. the signature over `authenticatorData || SHA-256(clientDataJSON)` verifies under the key.

  The sign count is not checked, because synced passkeys report 0.

## 12. Domain proof

`https://<domain>/.well-known/vpp.json`:

```json
{"vpp": 1, "log": "<origin>", "profile": "<profile id>", "keys": ["k1:…", "…"]}
```

The server checks it before publishing a `recipient_key`, and records `domain` in the entry.
Verifiers can re-check the current file with `--check-domains`. That is a current-state check: a
key that has been removed from the file is shown as no longer listed. The profile's identity is
the domain. The UI shows "confirmed by \<domain\>" only for payments with a valid confirmation
from a key that file lists.

## 13. Anchors

The latest checkpoint is published hourly to a public git repo, outside the operator's control
and with force-pushes blocked:

- `anchors/YYYY/MM/DD/<size>.checkpoint`: the signed note (with cosignatures), byte-exact.
- `anchors/YYYY/MM/DD/<size>.checkpoint.ots`: an OpenTimestamps proof whose file digest is
  `SHA-256(<size>.checkpoint)`. Check it with `ots verify -f <size>.checkpoint <proof>`.

Anchor files are never modified, except that a pending `.ots` file is replaced by its upgraded
(complete) version. A verifier reads every `.checkpoint` file from the repo. For each one, it
checks the log signature for that size, and that the root matches the tree it computed from the
served entries.
