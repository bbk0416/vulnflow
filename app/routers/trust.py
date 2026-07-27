from __future__ import annotations

"""Integrity-proof key transition, revocation, and checkpoint routes."""

from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.api.models import (
    ApiIntegrityProofKeyRevocation,
    ApiIntegrityProofKeyTransition,
    ApiIntegrityProofRevocationCheckpoint,
)

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = (
    "create_integrity_proof_key_transition_ui",
    "api_list_integrity_proof_key_transitions",
    "api_create_integrity_proof_key_transition",
    "create_integrity_proof_key_revocation_ui",
    "api_list_integrity_proof_key_revocations",
    "api_create_integrity_proof_key_revocation",
    "create_integrity_proof_revocation_checkpoint_ui",
    "api_list_integrity_proof_revocation_checkpoints",
    "api_create_integrity_proof_revocation_checkpoint",
)


@router.post("/audit/proof-key-transitions")
def create_integrity_proof_key_transition_ui(
    request: Request,
    from_key_id: str = Form(...),
    to_key_id: str = Form(...),
    effective_at: str = Form(""),
    reason: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_proof_signing_config()
    try:
        create_integrity_proof_key_transition(
            DB_PATH,
            from_key_id=from_key_id,
            to_key_id=to_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
            reason=reason,
            effective_at=effective_at,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit?notice=integrity_proof_key_transition_created", status_code=303)

@router.get("/api/v1/audit/proof-key-transitions")
def api_list_integrity_proof_key_transitions(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_key_transitions(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/audit/proof-key-transitions")
def api_create_integrity_proof_key_transition(
    request: Request, payload: ApiIntegrityProofKeyTransition
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_proof_signing_config()
    try:
        return create_integrity_proof_key_transition(
            DB_PATH,
            from_key_id=payload.from_key_id,
            to_key_id=payload.to_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
            reason=payload.reason,
            effective_at=payload.effective_at,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/audit/proof-key-revocations")
def create_integrity_proof_key_revocation_ui(
    request: Request,
    revoked_key_id: str = Form(...),
    replacement_key_id: str = Form(...),
    recovery_key_id: str = Form(...),
    invalid_after: str = Form(...),
    effective_at: str = Form(""),
    reason: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_proof_signing_config()
    try:
        create_integrity_proof_key_revocation(
            DB_PATH,
            revoked_key_id=revoked_key_id,
            replacement_key_id=replacement_key_id,
            recovery_key_id=recovery_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
            reason=reason,
            invalid_after=invalid_after,
            effective_at=effective_at,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit?notice=integrity_proof_key_revocation_created", status_code=303)

@router.get("/api/v1/audit/proof-key-revocations")
def api_list_integrity_proof_key_revocations(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_key_revocations(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/audit/proof-key-revocations")
def api_create_integrity_proof_key_revocation(
    request: Request, payload: ApiIntegrityProofKeyRevocation
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_proof_signing_config()
    try:
        return create_integrity_proof_key_revocation(
            DB_PATH,
            revoked_key_id=payload.revoked_key_id,
            replacement_key_id=payload.replacement_key_id,
            recovery_key_id=payload.recovery_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
            reason=payload.reason,
            invalid_after=payload.invalid_after,
            effective_at=payload.effective_at,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/audit/proof-revocation-checkpoints")
def create_integrity_proof_revocation_checkpoint_ui(
    request: Request,
    recovery_key_id: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_proof_signing_config()
    try:
        create_integrity_proof_revocation_checkpoint(
            DB_PATH,
            recovery_key_id=recovery_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit?notice=integrity_proof_revocation_checkpoint_created", status_code=303)

@router.get("/api/v1/audit/proof-revocation-checkpoints")
def api_list_integrity_proof_revocation_checkpoints(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_revocation_checkpoints(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/audit/proof-revocation-checkpoints")
def api_create_integrity_proof_revocation_checkpoint(
    request: Request, payload: ApiIntegrityProofRevocationCheckpoint
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_proof_signing_config()
    try:
        return create_integrity_proof_revocation_checkpoint(
            DB_PATH,
            recovery_key_id=payload.recovery_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
