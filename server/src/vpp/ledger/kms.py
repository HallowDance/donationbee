"""GCP Cloud KMS online signer (EC_SIGN_ED25519). Install with `vpp[gcp]`.

The private key never leaves KMS; a stolen server can sign while it's stolen, but can't
exfiltrate the key, and (per LEDGER_SPEC §5) can't rotate the ledger to a key it controls.
"""

from functools import cached_property


class GcpKmsSigner:
    def __init__(self, key_version: str, client=None):
        """`key_version`: projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/N."""
        if client is None:
            from google.cloud import kms

            client = kms.KeyManagementServiceClient()
        self.key_version = key_version
        self.client = client

    @cached_property
    def public_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pem = self.client.get_public_key(request={"name": self.key_version}).pem
        key = serialization.load_pem_public_key(pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("KMS key is not Ed25519 (use algorithm EC_SIGN_ED25519)")
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, msg: bytes) -> bytes:
        import google_crc32c

        resp = self.client.asymmetric_sign(
            request={
                "name": self.key_version,
                "data": msg,
                "data_crc32c": google_crc32c.value(msg),
            }
        )
        # Integrity checks recommended by Google: request CRC seen, response CRC matches.
        if not resp.verified_data_crc32c or resp.name != self.key_version:
            raise RuntimeError("KMS did not verify the request integrity")
        if google_crc32c.value(resp.signature) != resp.signature_crc32c:
            raise RuntimeError("KMS signature corrupted in transit")
        return resp.signature
