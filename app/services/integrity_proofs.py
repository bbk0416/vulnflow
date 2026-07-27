from __future__ import annotations

"""Compatibility facade for integrity proof creation and verification."""

from app.services.integrity_proof_bundle import create_integrity_proof_bundle
from app.services.integrity_proof_common import (
    BASE_PROOF_FILES,
    MAX_PROOF_FILES,
    MAX_PROOF_UNCOMPRESSED,
    PROOF_FORMAT,
    PROOF_FORMAT_ED25519,
    PROOF_FORMAT_ED25519_CHECKPOINTED,
    PROOF_FORMAT_ED25519_CONSISTENT,
    PROOF_FORMAT_ED25519_MIRRORED,
    PROOF_FORMAT_ED25519_RECOVERED,
    PROOF_FORMAT_ED25519_ROTATED,
    PROOF_FORMAT_ED25519_TRANSPARENT,
    PROOF_FORMAT_ED25519_WITNESSED,
    PROOF_FORMAT_HMAC,
)
from app.services.integrity_proof_verifier import verify_integrity_proof_bundle

__all__ = [
    "BASE_PROOF_FILES",
    "MAX_PROOF_FILES",
    "MAX_PROOF_UNCOMPRESSED",
    "PROOF_FORMAT",
    "PROOF_FORMAT_HMAC",
    "PROOF_FORMAT_ED25519",
    "PROOF_FORMAT_ED25519_ROTATED",
    "PROOF_FORMAT_ED25519_RECOVERED",
    "PROOF_FORMAT_ED25519_CHECKPOINTED",
    "PROOF_FORMAT_ED25519_WITNESSED",
    "PROOF_FORMAT_ED25519_TRANSPARENT",
    "PROOF_FORMAT_ED25519_MIRRORED",
    "PROOF_FORMAT_ED25519_CONSISTENT",
    "create_integrity_proof_bundle",
    "verify_integrity_proof_bundle",
]
