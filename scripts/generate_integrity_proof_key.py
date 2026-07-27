from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.public_signing import b64encode_raw, public_key_fingerprint


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a VulnFlow Ed25519 integrity-proof key pair.")
    parser.add_argument("--key-id", default="proof-ed25519-v1")
    args = parser.parse_args()
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_b64 = b64encode_raw(private_raw)
    public_b64 = b64encode_raw(public_raw)
    print(json.dumps({
        "key_id": args.key_id,
        "private_keys_json": json.dumps({args.key_id: private_b64}, separators=(",", ":")),
        "public_keys_json": json.dumps({args.key_id: public_b64}, separators=(",", ":")),
        "public_key_fingerprint": public_key_fingerprint(public_b64),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
