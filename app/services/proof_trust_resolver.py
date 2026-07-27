from __future__ import annotations

"""Resolve portable-proof signers through rotation and emergency recovery.

The resolver is read-only: it validates transition and revocation documents,
applies incident cutoffs, and traverses the bounded trust graph.
"""

from collections import deque
from datetime import datetime
from typing import Any, Mapping, Sequence

from app.core.db import utc_now
from app.core.public_signing import public_key_fingerprint
from app.services.proof_revocation import emergency_recovery_edges, trusted_revocation_state
from app.services.proof_transitions import (
    MAX_TRUST_CHAIN_DEPTH,
    _normalize_timestamp,
    validate_transition_document,
)

def resolve_trusted_proof_signer(
    *,
    target_key_id: str,
    target_public_key: str,
    transitions: Sequence[Mapping[str, Any]],
    pinned_public_keys: Mapping[str, str] | None,
    proof_created_at: str,
    revocations: Sequence[Mapping[str, Any]] | None = None,
    verification_time: str = "",
    max_depth: int = MAX_TRUST_CHAIN_DEPTH,
) -> dict[str, Any] | None:
    """Resolve a proof signer through planned rotations or emergency recovery.

    Revocation statements are trusted only when their recovery root is directly
    pinned by the verifier.  A revoked signer is rejected for proofs created at
    or after ``invalid_after``.  The replacement key may be trusted through the
    recovery-root edge once the emergency statement is effective.
    """
    pinned = dict(pinned_public_keys or {})
    target_fingerprint = public_key_fingerprint(target_public_key)
    proof_time = datetime.fromisoformat(_normalize_timestamp(proof_created_at, field="proof created_at"))
    checked_at = verification_time or utc_now()
    validated_revocations, revoked_at = trusted_revocation_state(
        list(revocations or []), pinned_public_keys=pinned, verification_time=checked_at
    )

    target_node = (str(target_key_id), target_fingerprint)
    target_invalid_after = revoked_at.get(target_node)
    if target_invalid_after is not None and proof_time >= target_invalid_after:
        raise ValueError(
            "무결성 증명 서명키가 비상 폐기되었으며 proof 생성 시각이 invalid_after 이후입니다."
        )

    directly_pinned = str(pinned.get(target_key_id, ""))
    if directly_pinned:
        if public_key_fingerprint(directly_pinned) != target_fingerprint:
            raise ValueError("고정된 Ed25519 공개키가 proof manifest의 fingerprint와 일치하지 않습니다.")
        return {
            "verification_key": directly_pinned,
            "trust_status": "pinned-public-key",
            "trust_path": [target_key_id],
            "transition_ids": [],
            "revocation_ids": [],
        }

    validated = [validate_transition_document(item) for item in transitions]
    edges: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in validated:
        effective = datetime.fromisoformat(item["effective_at"])
        created = datetime.fromisoformat(item["created_at"])
        if effective > proof_time or created > proof_time:
            continue
        source_node = (item["from_key_id"], item["from_public_key_sha256"])
        source_invalid_after = revoked_at.get(source_node)
        if source_invalid_after is not None and effective >= source_invalid_after:
            continue
        edges.setdefault(source_node, []).append(item | {"edge_kind": "transition"})

    for node, items in emergency_recovery_edges(
        validated_revocations, proof_time=proof_time
    ).items():
        edges.setdefault(node, []).extend(items)

    queue: deque[tuple[tuple[str, str], list[str], list[str], list[str], int]] = deque()
    visited: set[tuple[str, str]] = set()
    for key_id, public_key in sorted(pinned.items()):
        fingerprint = public_key_fingerprint(public_key)
        node = (str(key_id), fingerprint)
        # A pinned compromised key remains valid only for proofs created before
        # the incident cutoff.  It may still anchor a pre-incident rotation.
        invalid_after = revoked_at.get(node)
        if invalid_after is not None and proof_time >= invalid_after:
            # Keep a pinned recovery root even if a separate unrelated record
            # happens to use the same ID with a different fingerprint.
            if node != target_node:
                continue
        queue.append((node, [str(key_id)], [], [], 0))
        visited.add(node)

    while queue:
        node, key_path, transition_path, revocation_path, depth = queue.popleft()
        if node == target_node:
            return {
                "verification_key": target_public_key,
                "trust_status": "recovered-public-key" if revocation_path else "rotated-public-key",
                "trust_path": key_path,
                "transition_ids": transition_path,
                "revocation_ids": revocation_path,
            }
        if depth >= max(1, int(max_depth)):
            continue
        for edge in edges.get(node, []):
            next_node = (edge["to_key_id"], edge["to_public_key_sha256"])
            if next_node in visited:
                continue
            next_invalid_after = revoked_at.get(next_node)
            if next_invalid_after is not None and proof_time >= next_invalid_after:
                continue
            visited.add(next_node)
            if edge.get("edge_kind") == "revocation":
                queue.append((
                    next_node,
                    key_path + [edge["to_key_id"]],
                    transition_path,
                    revocation_path + [edge["transition_id"]],
                    depth + 1,
                ))
            else:
                queue.append((
                    next_node,
                    key_path + [edge["to_key_id"]],
                    transition_path + [edge["transition_id"]],
                    revocation_path,
                    depth + 1,
                ))
    return None
