from __future__ import annotations

"""Compatibility facade for proof transition and trust-resolution APIs.

Application code imports the owning modules directly.  This facade preserves
older integrations and tests that import ``app.services.proof_trust``.
"""

from app.services.proof_transitions import (
    MAX_TRANSITIONS_PER_PROOF,
    MAX_TRUST_CHAIN_DEPTH,
    TRANSITION_FORMAT,
    create_integrity_proof_key_transition,
    export_integrity_proof_key_transitions,
    list_integrity_proof_key_transitions,
    transition_document_from_values,
    validate_transition_document,
)
from app.services.proof_trust_resolver import resolve_trusted_proof_signer

__all__ = [
    "TRANSITION_FORMAT",
    "MAX_TRANSITIONS_PER_PROOF",
    "MAX_TRUST_CHAIN_DEPTH",
    "create_integrity_proof_key_transition",
    "export_integrity_proof_key_transitions",
    "list_integrity_proof_key_transitions",
    "transition_document_from_values",
    "validate_transition_document",
    "resolve_trusted_proof_signer",
]
