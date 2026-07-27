from __future__ import annotations

"""Governance routes extracted from :mod:`app.main`.

The module is dependency-injected by :mod:`app.routers` so compatibility exports
remain available while each application instance keeps isolated route globals.
"""

from datetime import date
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.api.models import *  # noqa: F403 - route request models

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}

ROUTE_NAMES = (
    "audit_page",
    "audit_checkpoint",
    "create_integrity_proof_ui",
    "verify_integrity_proof_ui",
    "export_audit_integrity",
    "export_audit_csv",
    "api_audit",
    "api_audit_integrity",
    "api_audit_checkpoint",
    "api_create_integrity_proof",
    "api_verify_integrity_proof",
)

@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, notice: str = ""):
    signing, audit_key_id, audit_key = _audit_signing()
    proof_signing = _integrity_proof_signing_config()
    proof_key_id, proof_private_key, _proof_public_key = proof_signing.active()
    integrity = verify_audit_integrity(DB_PATH, signing_keys=signing.keys)
    return templates.TemplateResponse(request=request, name="audit.html", context={
            "events": list_audit_events(DB_PATH, limit=200),
            "integrity": integrity,
            "checkpoints": list_audit_checkpoints(DB_PATH, limit=20),
            "prune_history": list_audit_prune_history(DB_PATH, limit=20),
            "signing_configured": bool(audit_key),
            "active_signing_key_id": audit_key_id,
            "proof_signature_algorithm": "Ed25519" if proof_private_key else "HMAC-SHA256",
            "proof_public_key_id": proof_key_id,
            "proof_public_key_fingerprints": proof_signing.public_summary()["public_key_fingerprints"],
            "proof_private_key_ids": sorted(proof_signing.private_keys),
            "proof_public_signature_required": INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE,
            "proof_key_transitions": list_integrity_proof_key_transitions(DB_PATH, limit=50),
            "proof_key_revocations": list_integrity_proof_key_revocations(DB_PATH, limit=50), "proof_revocation_checkpoints": list_integrity_proof_revocation_checkpoints(DB_PATH, limit=50),
            "proof_artifacts": [
                item for item in list_export_artifacts(DB_PATH, status="READY", limit=200)
                if str(item.get("export_type") or "") == "INTEGRITY_PROOF_ZIP"
            ][:20],
            "notice": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/audit/checkpoint")
def audit_checkpoint(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    signing, audit_key_id, audit_key = _audit_signing()
    if not audit_key:
        raise HTTPException(400, "감사 체크포인트 활성 서명 키가 설정되지 않았습니다.")
    create_audit_checkpoint(
        DB_PATH, signing_key=audit_key, signing_key_id=audit_key_id, actor=_actor(request)
    )
    return RedirectResponse(url="/audit?notice=audit_checkpoint", status_code=303)

@router.post("/audit/proofs")
def create_integrity_proof_ui(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    signing, audit_key_id, audit_key = _audit_signing()
    proof_signing = _integrity_proof_signing_config()
    proof_key_id, proof_private_key, proof_public_key = proof_signing.active()
    if not audit_key or not audit_key_id:
        raise HTTPException(400, "활성 감사 서명 키와 key ID가 필요합니다.")
    create_integrity_proof_bundle(
        DB_PATH, EXPORT_DIR, actor=_actor(request), app_version=CURRENT_APP_VERSION,
        schema_version=CURRENT_SCHEMA_VERSION, signing_key=audit_key,
        signing_key_id=audit_key_id, signing_keys=signing.keys,
        ed25519_private_key=proof_private_key, ed25519_public_key=proof_public_key,
        ed25519_key_id=proof_key_id or "",
        require_public_signature=INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE, minimum_witness_quorum=INTEGRITY_WITNESS_MIN_QUORUM, require_transparency_log=INTEGRITY_TRANSPARENCY_REQUIRE_LOG, minimum_mirror_quorum=INTEGRITY_MIRROR_MIN_QUORUM, require_mirror_gossip=INTEGRITY_MIRROR_REQUIRE_GOSSIP, require_mirror_consistency=INTEGRITY_MIRROR_REQUIRE_CONSISTENCY,
        retention_days=EXPORT_RETENTION_DAYS, max_storage_bytes=EXPORT_QUOTA_BYTES,
        min_free_bytes=EXPORT_MIN_FREE_BYTES,
    )
    return RedirectResponse(url="/audit?notice=integrity_proof_created", status_code=303)

@router.get("/audit/proofs/{artifact_id}/verify")
def verify_integrity_proof_ui(request: Request, artifact_id: str):
    _require_role(request, "approver")
    artifact = get_export_artifact(DB_PATH, artifact_id)
    if not artifact or str(artifact.get("export_type") or "") != "INTEGRITY_PROOF_ZIP":
        raise HTTPException(404, "무결성 증명 산출물을 찾을 수 없습니다.")
    if str(artifact.get("status") or "") != "READY":
        raise HTTPException(409, "READY 상태의 무결성 증명만 검증할 수 있습니다.")
    path = resolve_export_artifact_path(EXPORT_DIR, artifact)
    return verify_integrity_proof_bundle(
        path, signing_keys=_signing_config().keys, ed25519_public_keys=_integrity_proof_signing_config().public_keys,
        external_key_revocations=export_integrity_proof_key_revocations(DB_PATH), external_key_transitions=export_integrity_proof_key_transitions(DB_PATH), external_revocation_checkpoints=export_integrity_proof_revocation_checkpoints(DB_PATH), external_checkpoint_witnesses=export_integrity_proof_checkpoint_witnesses(DB_PATH), witness_public_keys=_integrity_witness_signing_config().public_keys,
        external_transparency_entries=export_integrity_proof_transparency_entries(DB_PATH), external_transparency_heads=export_integrity_proof_transparency_heads(DB_PATH), transparency_public_keys=_integrity_transparency_signing_config().public_keys, external_transparency_mirror_receipts=export_integrity_proof_transparency_mirror_receipts(DB_PATH), mirror_public_keys=_integrity_mirror_signing_config().public_keys,
        require_signature=True,
    )

@router.get("/export/audit-integrity.json")
def export_audit_integrity(request: Request):
    _require_role(request, "approver")
    payload = verify_audit_integrity(DB_PATH, signing_keys=_signing_config().keys)
    return JSONResponse(
        payload,
        headers={"Content-Disposition": "attachment; filename=vulnflow_audit_integrity.json"},
    )

@router.get("/export/audit.csv")
def export_audit_csv():
    events = list_audit_events(DB_PATH, limit=10000)
    output = io.StringIO()
    fields = ["id", "chain_seq", "finding_id", "event_type", "actor", "summary", "details_json", "created_at", "prev_hash", "event_hash"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for event in events:
        writer.writerow({
            "id": event.get("id"),
            "chain_seq": event.get("chain_seq"),
            "finding_id": _csv_safe(event.get("finding_id") or ""),
            "event_type": _csv_safe(event.get("event_type") or ""),
            "actor": _csv_safe(event.get("actor") or ""),
            "summary": _csv_safe(event.get("summary") or ""),
            "details_json": _csv_safe(json.dumps(event.get("details") or {}, ensure_ascii=False)),
            "created_at": event.get("created_at") or "",
            "prev_hash": event.get("prev_hash") or "",
            "event_hash": event.get("event_hash") or "",
        })
    return Response(
        output.getvalue().encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnflow_audit_events.csv"},
    )


@router.get("/api/v1/audit")
def api_audit(finding_id: str = "", limit: int = 200):
    events = list_audit_events(DB_PATH, finding_id or None, limit=max(1, min(limit, 1000)))
    return {"count": len(events), "items": events}

@router.get("/api/v1/audit/integrity")
def api_audit_integrity(request: Request):
    _require_role(request, "approver")
    return verify_audit_integrity(DB_PATH, signing_keys=_signing_config().keys)

@router.post("/api/v1/audit/checkpoints")
def api_audit_checkpoint(request: Request):
    _require_role(request, "admin")
    _require_api_token(request)
    signing, audit_key_id, audit_key = _audit_signing()
    if not audit_key:
        raise HTTPException(400, "감사 체크포인트 활성 서명 키가 설정되지 않았습니다.")
    return create_audit_checkpoint(
        DB_PATH, signing_key=audit_key, signing_key_id=audit_key_id, actor=_actor(request)
    )

@router.post("/api/v1/audit/proofs")
def api_create_integrity_proof(request: Request):
    _require_role(request, "admin")
    _require_api_token(request)
    signing, audit_key_id, audit_key = _audit_signing()
    proof_signing = _integrity_proof_signing_config()
    proof_key_id, proof_private_key, proof_public_key = proof_signing.active()
    if not audit_key or not audit_key_id:
        raise HTTPException(400, "활성 감사 서명 키와 key ID가 필요합니다.")
    return create_integrity_proof_bundle(
        DB_PATH, EXPORT_DIR, actor=_actor(request), app_version=CURRENT_APP_VERSION,
        schema_version=CURRENT_SCHEMA_VERSION, signing_key=audit_key,
        signing_key_id=audit_key_id, signing_keys=signing.keys,
        ed25519_private_key=proof_private_key, ed25519_public_key=proof_public_key,
        ed25519_key_id=proof_key_id or "",
        require_public_signature=INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE, minimum_witness_quorum=INTEGRITY_WITNESS_MIN_QUORUM, require_transparency_log=INTEGRITY_TRANSPARENCY_REQUIRE_LOG, minimum_mirror_quorum=INTEGRITY_MIRROR_MIN_QUORUM, require_mirror_gossip=INTEGRITY_MIRROR_REQUIRE_GOSSIP, require_mirror_consistency=INTEGRITY_MIRROR_REQUIRE_CONSISTENCY,
        retention_days=EXPORT_RETENTION_DAYS, max_storage_bytes=EXPORT_QUOTA_BYTES,
        min_free_bytes=EXPORT_MIN_FREE_BYTES,
    )

@router.get("/api/v1/audit/proofs/{artifact_id}/verify")
def api_verify_integrity_proof(request: Request, artifact_id: str):
    _require_role(request, "approver")
    artifact = get_export_artifact(DB_PATH, artifact_id)
    if not artifact or str(artifact.get("export_type") or "") != "INTEGRITY_PROOF_ZIP":
        raise HTTPException(404, "무결성 증명 산출물을 찾을 수 없습니다.")
    if str(artifact.get("status") or "") != "READY":
        raise HTTPException(409, "READY 상태의 무결성 증명만 검증할 수 있습니다.")
    path = resolve_export_artifact_path(EXPORT_DIR, artifact)
    return verify_integrity_proof_bundle(
        path, signing_keys=_signing_config().keys, ed25519_public_keys=_integrity_proof_signing_config().public_keys,
        external_key_revocations=export_integrity_proof_key_revocations(DB_PATH), external_key_transitions=export_integrity_proof_key_transitions(DB_PATH), external_revocation_checkpoints=export_integrity_proof_revocation_checkpoints(DB_PATH), external_checkpoint_witnesses=export_integrity_proof_checkpoint_witnesses(DB_PATH), witness_public_keys=_integrity_witness_signing_config().public_keys,
        external_transparency_entries=export_integrity_proof_transparency_entries(DB_PATH), external_transparency_heads=export_integrity_proof_transparency_heads(DB_PATH), transparency_public_keys=_integrity_transparency_signing_config().public_keys, external_transparency_mirror_receipts=export_integrity_proof_transparency_mirror_receipts(DB_PATH), mirror_public_keys=_integrity_mirror_signing_config().public_keys,
        require_signature=True,
    )
