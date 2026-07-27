from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.integrity_proofs import verify_integrity_proof_bundle


def _parse_mapping(value: str) -> tuple[str, str]:
    key_id, separator, material = str(value).partition("=")
    if not separator or not key_id.strip() or not material:
        raise argparse.ArgumentTypeError("KEY_ID=VALUE 형식이어야 합니다.")
    return key_id.strip(), material


def _json_mapping(raw: str, *, option: str) -> dict[str, str]:
    if not str(raw or "").strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise SystemExit(f"{option} must be a JSON object")
    return {str(key): str(value) for key, value in parsed.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a VulnFlow portable integrity proof ZIP.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--key", action="append", default=[], type=_parse_mapping,
        help="Legacy HMAC signing key in KEY_ID=SECRET form. May be repeated.",
    )
    parser.add_argument(
        "--signing-keys-json", default=os.getenv("VULNFLOW_SIGNING_KEYS_JSON", ""),
        help="Legacy HMAC key JSON. Defaults to VULNFLOW_SIGNING_KEYS_JSON.",
    )
    parser.add_argument(
        "--public-key", action="append", default=[], type=_parse_mapping,
        help="Trusted Ed25519 public key in KEY_ID=URLSAFE_BASE64 form. May be repeated.",
    )
    parser.add_argument(
        "--public-keys-json",
        default=os.getenv("VULNFLOW_INTEGRITY_PROOF_PUBLIC_KEYS_JSON", ""),
        help="Trusted Ed25519 public-key JSON object.",
    )
    parser.add_argument(
        "--revocations", type=Path,
        help="External emergency key-revocation JSON array for checking older proof bundles.",
    )
    parser.add_argument("--transitions", type=Path, help="External key-transition JSON array.")
    parser.add_argument("--checkpoints", type=Path, help="External revocation-checkpoint JSON array.")
    parser.add_argument("--witnesses", type=Path, help="External checkpoint-witness JSON array.")
    parser.add_argument(
        "--witness-public-key", action="append", default=[], type=_parse_mapping,
        help="Trusted witness Ed25519 public key in KEY_ID=URLSAFE_BASE64 form. May be repeated.",
    )
    parser.add_argument("--witness-public-keys-json", default="", help="Trusted witness public-key JSON object.")
    parser.add_argument("--minimum-witness-quorum", type=int, default=0, help="Minimum distinct trusted witness keys.")
    parser.add_argument("--transparency-entries", type=Path, help="External transparency-entry JSON array.")
    parser.add_argument("--transparency-heads", type=Path, help="External signed transparency-head JSON array.")
    parser.add_argument(
        "--transparency-public-key", action="append", default=[], type=_parse_mapping,
        help="Trusted transparency-log Ed25519 public key in KEY_ID=URLSAFE_BASE64 form.",
    )
    parser.add_argument(
        "--transparency-public-keys-json",
        default=os.getenv("VULNFLOW_INTEGRITY_TRANSPARENCY_PUBLIC_KEYS_JSON", ""),
        help="Trusted transparency-log public-key JSON object.",
    )
    parser.add_argument("--minimum-transparency-tree-size", type=int, default=0)
    parser.add_argument("--trusted-transparency-head-sha256", default="")
    parser.add_argument("--mirror-receipts", type=Path, help="External transparency mirror-receipt JSON array.")
    parser.add_argument(
        "--mirror-public-key", action="append", default=[], type=_parse_mapping,
        help="Trusted transparency-mirror Ed25519 public key in KEY_ID=URLSAFE_BASE64 form.",
    )
    parser.add_argument(
        "--mirror-public-keys-json",
        default=os.getenv("VULNFLOW_INTEGRITY_MIRROR_PUBLIC_KEYS_JSON", ""),
        help="Trusted transparency-mirror public-key JSON object.",
    )
    parser.add_argument("--minimum-mirror-quorum", type=int, default=0)
    parser.add_argument("--trusted-mirror-receipt-sha256", default="")
    parser.add_argument("--mirror-consistency-checkpoints", type=Path, help="External mirror consistency-checkpoint JSON array.")
    parser.add_argument("--minimum-mirror-consistency-quorum", type=int, default=0)
    parser.add_argument("--trusted-mirror-consistency-checkpoint-sha256", default="")
    parser.add_argument("--minimum-checkpoint", type=int, default=0, help="Minimum accepted checkpoint sequence.")
    parser.add_argument("--trusted-checkpoint-sha256", default="", help="Expected latest checkpoint document SHA-256.")
    parser.add_argument(
        "--allow-embedded-public-key", action="store_true",
        help="Verify with the embedded public key without establishing external trust.",
    )
    args = parser.parse_args()
    keys = _json_mapping(args.signing_keys_json, option="--signing-keys-json")
    keys.update(dict(args.key))
    public_keys = _json_mapping(args.public_keys_json, option="--public-keys-json")
    public_keys.update(dict(args.public_key))
    revocations = []
    if args.revocations:
        loaded = json.loads(args.revocations.read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            raise SystemExit("--revocations must point to a JSON array")
        revocations = loaded
    transitions = []
    if args.transitions:
        transitions = json.loads(args.transitions.read_text(encoding="utf-8"))
        if not isinstance(transitions, list):
            raise SystemExit("--transitions must point to a JSON array")
    checkpoints = []
    if args.checkpoints:
        checkpoints = json.loads(args.checkpoints.read_text(encoding="utf-8"))
        if not isinstance(checkpoints, list):
            raise SystemExit("--checkpoints must point to a JSON array")
    witnesses = []
    if args.witnesses:
        witnesses = json.loads(args.witnesses.read_text(encoding="utf-8"))
        if not isinstance(witnesses, list):
            raise SystemExit("--witnesses must point to a JSON array")
    witness_public_keys = _json_mapping(args.witness_public_keys_json, option="--witness-public-keys-json")
    witness_public_keys.update(dict(args.witness_public_key))
    transparency_entries = []
    if args.transparency_entries:
        transparency_entries = json.loads(args.transparency_entries.read_text(encoding="utf-8"))
        if not isinstance(transparency_entries, list):
            raise SystemExit("--transparency-entries must point to a JSON array")
    transparency_heads = []
    if args.transparency_heads:
        transparency_heads = json.loads(args.transparency_heads.read_text(encoding="utf-8"))
        if not isinstance(transparency_heads, list):
            raise SystemExit("--transparency-heads must point to a JSON array")
    transparency_public_keys = _json_mapping(
        args.transparency_public_keys_json, option="--transparency-public-keys-json"
    )
    transparency_public_keys.update(dict(args.transparency_public_key))
    mirror_receipts = []
    if args.mirror_receipts:
        mirror_receipts = json.loads(args.mirror_receipts.read_text(encoding="utf-8"))
        if not isinstance(mirror_receipts, list):
            raise SystemExit("--mirror-receipts must point to a JSON array")
    mirror_public_keys = _json_mapping(args.mirror_public_keys_json, option="--mirror-public-keys-json")
    mirror_public_keys.update(dict(args.mirror_public_key))
    mirror_consistency_checkpoints = []
    if args.mirror_consistency_checkpoints:
        mirror_consistency_checkpoints = json.loads(args.mirror_consistency_checkpoints.read_text(encoding="utf-8"))
        if not isinstance(mirror_consistency_checkpoints, list):
            raise SystemExit("--mirror-consistency-checkpoints must point to a JSON array")
    result = verify_integrity_proof_bundle(
        args.bundle,
        signing_keys=keys,
        ed25519_public_keys=public_keys,
        external_key_revocations=revocations,
        external_key_transitions=transitions,
        external_revocation_checkpoints=checkpoints,
        external_checkpoint_witnesses=witnesses,
        witness_public_keys=witness_public_keys,
        external_transparency_entries=transparency_entries,
        external_transparency_heads=transparency_heads,
        transparency_public_keys=transparency_public_keys,
        minimum_transparency_tree_size=max(0, int(args.minimum_transparency_tree_size)),
        trusted_transparency_head_sha256=str(args.trusted_transparency_head_sha256 or ""),
        external_transparency_mirror_receipts=mirror_receipts,
        mirror_public_keys=mirror_public_keys,
        minimum_mirror_quorum=max(0, int(args.minimum_mirror_quorum)),
        trusted_mirror_receipt_sha256=str(args.trusted_mirror_receipt_sha256 or ""),
        external_mirror_consistency_checkpoints=mirror_consistency_checkpoints,
        minimum_mirror_consistency_quorum=max(0, int(args.minimum_mirror_consistency_quorum)),
        trusted_mirror_consistency_checkpoint_sha256=str(args.trusted_mirror_consistency_checkpoint_sha256 or ""),
        minimum_checkpoint_sequence=max(0, int(args.minimum_checkpoint)),
        minimum_witness_quorum=max(0, int(args.minimum_witness_quorum)),
        trusted_checkpoint_sha256=str(args.trusted_checkpoint_sha256 or ""),
        allow_embedded_public_key=bool(args.allow_embedded_public_key),
        require_signature=True,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
