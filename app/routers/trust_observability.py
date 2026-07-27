from __future__ import annotations

"""Integrity-proof witness, transparency, mirror, and consistency routes."""

from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.api.models import (
    ApiIntegrityProofCheckpointWitness,
    ApiIntegrityProofTransparencyPublish,
    ApiIntegrityProofTransparencyMirrorReceipt,
    ApiIntegrityProofMirrorConsistencyCheckpoint,
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
    "integrity_proof_checkpoint_witness_page",
    "create_integrity_proof_checkpoint_witness_ui",
    "api_list_integrity_proof_checkpoint_witnesses",
    "api_create_integrity_proof_checkpoint_witness",
    "publish_integrity_proof_transparency_head_ui",
    "api_list_integrity_proof_transparency_entries",
    "api_list_integrity_proof_transparency_heads",
    "api_publish_integrity_proof_transparency_head",
    "create_integrity_proof_transparency_mirror_receipt_ui",
    "api_list_integrity_proof_transparency_mirror_receipts",
    "api_create_integrity_proof_transparency_mirror_receipt",
    "create_integrity_proof_mirror_consistency_checkpoint_ui",
    "api_list_integrity_proof_mirror_consistency_checkpoints",
    "api_create_integrity_proof_mirror_consistency_checkpoint",
)


@router.get("/audit/proof-checkpoint-witnesses", response_class=HTMLResponse)
def integrity_proof_checkpoint_witness_page(request: Request, notice: str = ""):
    _require_role(request, "approver")
    config = _integrity_witness_signing_config()
    mirror_config = _integrity_mirror_signing_config()
    return templates.TemplateResponse(request=request, name="proof_witnesses.html", context={
        "witnesses": list_integrity_proof_checkpoint_witnesses(DB_PATH, limit=200),
        "checkpoints": list_integrity_proof_revocation_checkpoints(DB_PATH, limit=50),
        "witness_private_key_ids": sorted(config.private_keys),
        "witness_public_key_fingerprints": config.public_summary()["public_key_fingerprints"],
        "minimum_quorum": INTEGRITY_WITNESS_MIN_QUORUM,
        "transparency_heads": list_integrity_proof_transparency_heads(DB_PATH, limit=50),
        "mirror_receipts": list_integrity_proof_transparency_mirror_receipts(DB_PATH, limit=200),
        "mirror_private_key_ids": sorted(mirror_config.private_keys),
        "mirror_public_key_fingerprints": mirror_config.public_summary()["public_key_fingerprints"],
        "minimum_mirror_quorum": INTEGRITY_MIRROR_MIN_QUORUM,
        "mirror_consistency_checkpoints": list_integrity_proof_mirror_consistency_checkpoints(DB_PATH, limit=100),
        "require_mirror_consistency": INTEGRITY_MIRROR_REQUIRE_CONSISTENCY,
        "notice": notice,
    })

@router.post("/audit/proof-checkpoint-witnesses")
def create_integrity_proof_checkpoint_witness_ui(
    request: Request,
    witness_key_id: str = Form(...),
    checkpoint_id: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_witness_signing_config()
    try:
        create_integrity_proof_checkpoint_witness(
            DB_PATH,
            witness_key_id=witness_key_id,
            checkpoint_id=checkpoint_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit/proof-checkpoint-witnesses?notice=checkpoint_witness_created", status_code=303)

@router.get("/api/v1/audit/proof-checkpoint-witnesses")
def api_list_integrity_proof_checkpoint_witnesses(
    request: Request, checkpoint_id: str = "", limit: int = 100
):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_checkpoint_witnesses(DB_PATH, checkpoint_id=checkpoint_id, limit=limit)
    return {"count": len(items), "items": items, "minimum_quorum": INTEGRITY_WITNESS_MIN_QUORUM}

@router.post("/api/v1/audit/proof-checkpoint-witnesses")
def api_create_integrity_proof_checkpoint_witness(
    request: Request, payload: ApiIntegrityProofCheckpointWitness
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_witness_signing_config()
    try:
        return create_integrity_proof_checkpoint_witness(
            DB_PATH,
            witness_key_id=payload.witness_key_id,
            checkpoint_id=payload.checkpoint_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/audit/proof-transparency-heads")
def publish_integrity_proof_transparency_head_ui(
    request: Request,
    log_key_id: str = Form(...),
    checkpoint_id: str = Form(""),
    minimum_witness_quorum: int = Form(1),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_transparency_signing_config()
    try:
        publish_integrity_proof_transparency_head(
            DB_PATH,
            log_key_id=log_key_id,
            checkpoint_id=checkpoint_id,
            minimum_witness_quorum=minimum_witness_quorum,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit?notice=integrity_proof_transparency_head_published", status_code=303)

@router.get("/api/v1/audit/proof-transparency-entries")
def api_list_integrity_proof_transparency_entries(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_transparency_entries(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.get("/api/v1/audit/proof-transparency-heads")
def api_list_integrity_proof_transparency_heads(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_transparency_heads(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/audit/proof-transparency-heads")
def api_publish_integrity_proof_transparency_head(
    request: Request, payload: ApiIntegrityProofTransparencyPublish
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_transparency_signing_config()
    try:
        return publish_integrity_proof_transparency_head(
            DB_PATH,
            log_key_id=payload.log_key_id,
            checkpoint_id=payload.checkpoint_id,
            minimum_witness_quorum=payload.minimum_witness_quorum,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/audit/proof-transparency-mirror-receipts")
def create_integrity_proof_transparency_mirror_receipt_ui(
    request: Request,
    mirror_key_id: str = Form(...),
    head_id: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_mirror_signing_config()
    try:
        create_integrity_proof_transparency_mirror_receipt(
            DB_PATH,
            mirror_key_id=mirror_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
            head_id=head_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit?notice=integrity_proof_transparency_head_mirrored", status_code=303)

@router.get("/api/v1/audit/proof-transparency-mirror-receipts")
def api_list_integrity_proof_transparency_mirror_receipts(
    request: Request, head_id: str = "", limit: int = 100
):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_transparency_mirror_receipts(DB_PATH, head_id=head_id, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/audit/proof-transparency-mirror-receipts")
def api_create_integrity_proof_transparency_mirror_receipt(
    request: Request, payload: ApiIntegrityProofTransparencyMirrorReceipt
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_mirror_signing_config()
    try:
        return create_integrity_proof_transparency_mirror_receipt(
            DB_PATH,
            mirror_key_id=payload.mirror_key_id,
            private_keys=config.private_keys,
            public_keys=config.public_keys,
            actor=_actor(request),
            head_id=payload.head_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/audit/proof-mirror-consistency-checkpoints")
def create_integrity_proof_mirror_consistency_checkpoint_ui(
    request: Request,
    mirror_key_ids: str = Form(...),
    minimum_quorum: int = Form(1),
    head_id: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    config = _integrity_mirror_signing_config()
    keys = [item.strip() for item in mirror_key_ids.split(",") if item.strip()]
    try:
        create_integrity_proof_mirror_consistency_checkpoint(
            DB_PATH, mirror_key_ids=keys, minimum_quorum=minimum_quorum,
            private_keys=config.private_keys, public_keys=config.public_keys,
            actor=_actor(request), head_id=head_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/audit?notice=integrity_proof_mirror_consistency_created", status_code=303)

@router.get("/api/v1/audit/proof-mirror-consistency-checkpoints")
def api_list_integrity_proof_mirror_consistency_checkpoints(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "approver")
    items = list_integrity_proof_mirror_consistency_checkpoints(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/audit/proof-mirror-consistency-checkpoints")
def api_create_integrity_proof_mirror_consistency_checkpoint(
    request: Request, payload: ApiIntegrityProofMirrorConsistencyCheckpoint
):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _integrity_mirror_signing_config()
    try:
        return create_integrity_proof_mirror_consistency_checkpoint(
            DB_PATH, mirror_key_ids=payload.mirror_key_ids,
            minimum_quorum=payload.minimum_quorum,
            private_keys=config.private_keys, public_keys=config.public_keys,
            actor=_actor(request), head_id=payload.head_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
