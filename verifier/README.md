# donationbee-verify

An independent checker for [DonationBee](https://bee.theorycorner.com) payment ledgers. It doesn't
take the server's word for anything: it downloads the public entries and redoes every check
itself.

```sh
pip install donationbee-verify
vpp-verify --url https://bee.theorycorner.com
```

## What it checks

- **The chain.** Every entry's hash, its link to the previous entry, and its signature by the key
  that was in charge at that point. Key changes count only when enough offline root keys signed
  them.
- **The Merkle tree.** It recomputes the tree and checks that the log's signed checkpoints match
  it.
- **Recipient confirmations.** Every passkey (WebAuthn) signature a recipient made to confirm a
  payment.
- **Witnesses** (`--witness <vkey> --min-witnesses k`). Independent witnesses must have cosigned
  the checkpoint you see, so you know you're seeing the same history as everyone else.
- **Anchors** (`--anchors-repo <git url> --check-ots`). Checkpoints published in a git repo the
  operator doesn't control, and their Bitcoin timestamps.
- **Domains** (`--check-domains`). Each recipient's website still lists the passkey they confirm
  with.
- **Receipts** (`--receipt receipt.json`). Your payment is still in the ledger, unchanged. If it
  isn't, the verifier writes out an evidence file you can show to others.

Pin the ledger you expect with `--pin-genesis <hash>`, so nobody can swap in a different one.

## Why it's separate

This package shares no code with the DonationBee server. It's written from the format
specification ([LEDGER_SPEC.md](https://github.com/HallowDance/donationbee/blob/master/docs/LEDGER_SPEC.md))
and tested against shared test vectors. That way a bug or a lie in the server can't hide inside the
tool meant to catch it.

Its dependencies are small: `pynacl` (Ed25519), `cryptography` (passkey signatures), `rfc8785`
(canonical JSON) and `httpx`.

## License

Apache-2.0.
