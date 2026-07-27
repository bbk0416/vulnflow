from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, BinaryIO, Iterable

from app.core.database_schema import CURRENT_APP_VERSION
from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event

MAX_COMPONENTS = 10_000
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
VEX_STATES = {
    "IN_TRIAGE",
    "EXPLOITABLE",
    "NOT_AFFECTED",
    "RESOLVED",
    "FALSE_POSITIVE",
}
VEX_JUSTIFICATIONS = {
    "",
    "CODE_NOT_PRESENT",
    "CODE_NOT_REACHABLE",
    "REQUIRES_CONFIGURATION",
    "REQUIRES_DEPENDENCY",
    "REQUIRES_ENVIRONMENT",
    "PROTECTED_BY_COMPILER",
    "PROTECTED_AT_RUNTIME",
    "PROTECTED_AT_PERIMETER",
    "PROTECTED_BY_MITIGATING_CONTROL",
}
VEX_RESPONSES = {
    "CAN_NOT_FIX",
    "ROLLBACK",
    "UPDATE",
    "WILL_NOT_FIX",
    "WORKAROUND_AVAILABLE",
}
FINAL_VEX_STATES = {"NOT_AFFECTED", "RESOLVED", "FALSE_POSITIVE"}


class SbomError(ValueError):
    pass


def _read_payload(file_obj: BinaryIO) -> tuple[dict[str, Any], bytes]:
    raw = file_obj.read()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SbomError(f"유효한 JSON 파일이 아닙니다: {exc}") from exc
    if not isinstance(payload, dict):
        raise SbomError("CycloneDX 문서는 JSON 객체여야 합니다.")
    return payload, raw


def _component_identity(item: dict[str, Any]) -> str:
    purl = str(item.get("purl") or "").strip()
    if purl:
        base = purl.split("?", 1)[0].split("#", 1)[0]
        if "@" in base:
            base = base.rsplit("@", 1)[0]
        return f"purl:{base.lower()}"
    return "name:{type}:{group}:{name}".format(
        type=str(item.get("type") or "").lower(),
        group=str(item.get("group") or "").lower(),
        name=str(item.get("name") or "").lower(),
    )


def _normalize_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _normalize_state(value: Any) -> str:
    raw = str(value or "").strip().replace("-", "_").upper()
    aliases = {
        "AFFECTED": "EXPLOITABLE",
        "EXPLOITABLE": "EXPLOITABLE",
        "IN_TRIAGE": "IN_TRIAGE",
        "UNDER_INVESTIGATION": "IN_TRIAGE",
        "NOT_AFFECTED": "NOT_AFFECTED",
        "RESOLVED": "RESOLVED",
        "RESOLVED_WITH_PEDIGREE": "RESOLVED",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
    }
    return aliases.get(raw, "IN_TRIAGE")


def _normalize_justification(value: Any) -> str:
    raw = str(value or "").strip().replace("-", "_").upper()
    return raw if raw in VEX_JUSTIFICATIONS else ""


def _normalize_responses(values: Any) -> list[str]:
    if not isinstance(values, list):
        values = [values] if values else []
    out: list[str] = []
    for value in values:
        item = str(value or "").strip().replace("-", "_").upper()
        if item in VEX_RESPONSES and item not in out:
            out.append(item)
    return out


def _parse_embedded_vulnerabilities(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    items = payload.get("vulnerabilities", [])
    if not isinstance(items, list):
        return result
    for item in items:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("id") or "").strip().upper()
        if not CVE_RE.fullmatch(cve_id):
            continue
        affects = []
        for affected in item.get("affects", []) if isinstance(item.get("affects"), list) else []:
            if isinstance(affected, dict) and str(affected.get("ref") or "").strip():
                affects.append(str(affected.get("ref")).strip())
        analysis = item.get("analysis", {}) if isinstance(item.get("analysis"), dict) else {}
        result.append({
            "cve_id": cve_id,
            "affects": affects,
            "analysis_state": _normalize_state(analysis.get("state")),
            "justification": _normalize_justification(analysis.get("justification")),
            "responses": _normalize_responses(analysis.get("response")),
            "detail": str(analysis.get("detail") or "").strip(),
            "source_name": str((item.get("source") or {}).get("name") or "") if isinstance(item.get("source"), dict) else "",
        })
    return result


def parse_cyclonedx_json(file_obj: BinaryIO) -> dict[str, Any]:
    payload, raw = _read_payload(file_obj)
    if payload.get("bomFormat") != "CycloneDX":
        raise SbomError("현재 버전은 CycloneDX JSON만 지원합니다.")
    items = payload.get("components", [])
    if not isinstance(items, list):
        raise SbomError("components는 배열이어야 합니다.")
    if len(items) > MAX_COMPONENTS:
        raise SbomError(f"구성요소는 최대 {MAX_COMPONENTS:,}개까지 확인할 수 있습니다.")

    components: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    duplicates = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        hashes = {h.get("alg", "unknown"): h.get("content", "") for h in item.get("hashes", []) if isinstance(h, dict)}
        licenses = []
        for lic in item.get("licenses", []):
            if isinstance(lic, dict):
                license_obj = lic.get("license", {}) if isinstance(lic.get("license", {}), dict) else {}
                licenses.append(license_obj.get("id") or license_obj.get("name", ""))
        identity = _component_identity(item)
        occurrence = seen.get(identity, 0) + 1
        seen[identity] = occurrence
        if occurrence > 1:
            duplicates += 1
        components.append({
            "identity": identity,
            "identity_occurrence": occurrence,
            "component_key": f"{identity}#{occurrence}",
            "bom_ref": item.get("bom-ref", ""),
            "type": item.get("type", ""),
            "group": item.get("group", ""),
            "name": item.get("name", ""),
            "version": item.get("version", ""),
            "purl": item.get("purl", ""),
            "licenses": ", ".join(filter(None, licenses)),
            "hash_count": len(hashes),
            "scope": item.get("scope", ""),
        })

    metadata = payload.get("metadata", {}) if isinstance(payload.get("metadata", {}), dict) else {}
    target = metadata.get("component", {}) if isinstance(metadata.get("component", {}), dict) else {}
    return {
        "spec_version": str(payload.get("specVersion") or ""),
        "serial_number": str(payload.get("serialNumber") or ""),
        "target_name": str(target.get("name") or "").strip(),
        "target_version": str(target.get("version") or "").strip(),
        "components": components,
        "duplicate_identities": duplicates,
        "embedded_vulnerabilities": _parse_embedded_vulnerabilities(payload),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "scope_notice": "구성요소 인벤토리, finding 자동 연결, VEX 검토·승인 및 CycloneDX VEX 내보내기를 지원합니다. 자동 연결은 제품·구성요소·버전의 명시적 일치만 사용하며 최종 영향판정을 대체하지 않습니다.",
    }


def compare_cyclonedx(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_map = {c["component_key"]: c for c in left.get("components", [])}
    right_map = {c["component_key"]: c for c in right.get("components", [])}
    # For the common case without duplicate identities, compare by identity so version changes are visible.
    if not left.get("duplicate_identities") and not right.get("duplicate_identities"):
        left_map = {c["identity"]: c for c in left.get("components", [])}
        right_map = {c["identity"]: c for c in right.get("components", [])}
    left_keys = set(left_map)
    right_keys = set(right_map)

    added = [right_map[key] for key in sorted(right_keys - left_keys)]
    removed = [left_map[key] for key in sorted(left_keys - right_keys)]
    changed = []
    unchanged = 0
    for key in sorted(left_keys & right_keys):
        before = left_map[key]
        after = right_map[key]
        if str(before.get("version", "")) != str(after.get("version", "")):
            changed.append({"identity": key, "before": before, "after": after})
        else:
            unchanged += 1
    return {
        "left": left,
        "right": right,
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": unchanged,
    }


def _validate_vex(*, state: str, justification: str, responses: Iterable[str], impact_statement: str,
                  action_statement: str, detail: str) -> tuple[str, str, list[str], str, str, str]:
    raw_state = str(state or "").strip().replace("-", "_").upper()
    accepted_states = VEX_STATES | {"AFFECTED", "UNDER_INVESTIGATION", "RESOLVED_WITH_PEDIGREE"}
    if raw_state not in accepted_states:
        raise SbomError("지원하지 않는 VEX 상태입니다.")
    normalized_state = _normalize_state(raw_state)
    normalized_justification = _normalize_justification(justification)
    normalized_responses = _normalize_responses(list(responses))
    impact = str(impact_statement or "").strip()
    action = str(action_statement or "").strip()
    detail = str(detail or "").strip()
    if normalized_state in {"NOT_AFFECTED", "FALSE_POSITIVE"} and not normalized_justification:
        raise SbomError(f"{normalized_state}에는 justification이 필요합니다.")
    if normalized_state == "NOT_AFFECTED" and not (impact or detail):
        raise SbomError("NOT_AFFECTED에는 영향 분석 또는 상세 근거가 필요합니다.")
    if normalized_state == "RESOLVED" and not (action or detail):
        raise SbomError("RESOLVED에는 조치 내용 또는 상세 근거가 필요합니다.")
    return normalized_state, normalized_justification, normalized_responses, impact, action, detail


def _latest_vex_rows(conn, sbom_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT v.*,c.name AS component_name,c.version AS component_version,c.purl,c.bom_ref
             FROM vex_statements v JOIN sbom_components c ON c.component_id=v.component_id
            WHERE v.sbom_id=?
              AND v.revision_no=(SELECT MAX(v2.revision_no) FROM vex_statements v2
                                  WHERE v2.sbom_id=v.sbom_id AND v2.component_id=v.component_id AND v2.cve_id=v.cve_id)
            ORDER BY c.name,c.version,v.cve_id""",
        (sbom_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _reconcile_in_connection(conn, sbom_id: str, *, actor: str) -> dict[str, int]:
    doc = conn.execute("SELECT * FROM sbom_documents WHERE sbom_id=?", (sbom_id,)).fetchone()
    if doc is None:
        raise KeyError(sbom_id)
    components = [dict(row) for row in conn.execute("SELECT * FROM sbom_components WHERE sbom_id=?", (sbom_id,)).fetchall()]
    findings = [dict(row) for row in conn.execute("SELECT * FROM findings WHERE record_state!='ARCHIVED'").fetchall()]
    inserted = 0
    candidates = 0
    now = utc_now()
    product_norm = _normalize_name(doc["product_name"])
    product_version = str(doc["product_version"] or "").strip()
    for component in components:
        component_norm = _normalize_name(component["name"])
        component_version = str(component["version"] or "").strip()
        if not component_norm:
            continue
        for finding in findings:
            if _normalize_name(finding.get("component")) != component_norm:
                continue
            finding_component_version = str(finding.get("component_version") or "").strip()
            if component_version and finding_component_version and component_version != finding_component_version:
                continue
            confidence = 55
            methods = ["COMPONENT_NAME"]
            if component_version and finding_component_version == component_version:
                confidence += 25
                methods.append("COMPONENT_VERSION")
            finding_product_norm = _normalize_name(finding.get("product"))
            if product_norm and finding_product_norm and finding_product_norm != product_norm:
                continue
            if product_norm and finding_product_norm == product_norm:
                confidence += 12
                methods.append("PRODUCT")
            finding_product_version = str(finding.get("product_version") or "").strip()
            if product_version and finding_product_version and finding_product_version != product_version:
                continue
            if product_version and finding_product_version == product_version:
                confidence += 8
                methods.append("PRODUCT_VERSION")
            if confidence < 80:
                continue
            candidates += 1
            link_id = f"LNK-{uuid.uuid4().hex[:16].upper()}"
            cur = conn.execute(
                """INSERT OR IGNORE INTO sbom_finding_links(
                       link_id,sbom_id,component_id,finding_id,match_method,match_confidence,status,linked_by,linked_at
                   ) VALUES(?,?,?,?,?,?,'CANDIDATE',?,?)""",
                (link_id, sbom_id, component["component_id"], finding["finding_id"], "+".join(methods), confidence, actor, now),
            )
            inserted += int(cur.rowcount or 0)
    return {"candidates": candidates, "inserted": inserted}


def store_cyclonedx_document(db_path: str, parsed: dict[str, Any], *, source_filename: str, actor: str,
                             notes: str = "") -> dict[str, Any]:
    target_name = str(parsed.get("target_name") or "").strip()
    if not target_name:
        raise SbomError("metadata.component.name이 필요합니다.")
    document_sha256 = str(parsed.get("sha256") or "")
    with connect(db_path) as conn:
        existing = conn.execute("SELECT sbom_id FROM sbom_documents WHERE document_sha256=?", (document_sha256,)).fetchone()
        if existing:
            result = get_sbom_document(db_path, str(existing["sbom_id"])) or {}
            result["duplicate_document"] = True
            return result
        conn.execute("BEGIN IMMEDIATE")
        sbom_id = f"SBOM-{uuid.uuid4().hex[:16].upper()}"
        now = utc_now()
        components = list(parsed.get("components") or [])
        conn.execute(
            """INSERT INTO sbom_documents(
                   sbom_id,serial_number,spec_version,product_name,product_version,document_sha256,
                   source_filename,uploaded_by,uploaded_at,component_count,duplicate_identities,status,notes
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',?)""",
            (sbom_id, parsed.get("serial_number", ""), parsed.get("spec_version", ""), target_name,
             parsed.get("target_version", ""), document_sha256, str(source_filename or "sbom.cdx.json"), actor,
             now, len(components), int(parsed.get("duplicate_identities") or 0), str(notes or "").strip()),
        )
        ref_to_component: dict[str, str] = {}
        for item in components:
            component_id = f"CMP-{uuid.uuid4().hex[:16].upper()}"
            conn.execute(
                """INSERT INTO sbom_components(
                       component_id,sbom_id,component_key,identity,identity_occurrence,bom_ref,component_type,
                       component_group,name,version,purl,licenses,hash_count,scope
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (component_id, sbom_id, item.get("component_key"), item.get("identity"),
                 int(item.get("identity_occurrence") or 1), item.get("bom_ref", ""), item.get("type", ""),
                 item.get("group", ""), item.get("name", ""), item.get("version", ""), item.get("purl", ""),
                 item.get("licenses", ""), int(item.get("hash_count") or 0), item.get("scope", "")),
            )
            if str(item.get("bom_ref") or ""):
                ref_to_component[str(item.get("bom_ref"))] = component_id
        imported_vex = 0
        for vuln in parsed.get("embedded_vulnerabilities") or []:
            for ref in vuln.get("affects") or []:
                component_id = ref_to_component.get(str(ref))
                if not component_id:
                    continue
                state, justification, responses, impact, action, detail = _validate_vex(
                    state=vuln.get("analysis_state"), justification=vuln.get("justification"),
                    responses=vuln.get("responses") or [], impact_statement="", action_statement="",
                    detail=vuln.get("detail") or "Embedded CycloneDX vulnerability analysis",
                )
                vex_id = f"VEX-{uuid.uuid4().hex[:16].upper()}"
                conn.execute(
                    """INSERT INTO vex_statements(
                           vex_id,sbom_id,component_id,cve_id,finding_id,revision_no,analysis_state,justification,
                           response_json,impact_statement,action_statement,detail,review_status,created_by,created_at
                       ) VALUES(?,?,?,?,NULL,1,?,?,?,?,?,?,'DRAFT',?,?)""",
                    (vex_id, sbom_id, component_id, vuln["cve_id"], state, justification,
                     json.dumps(responses, ensure_ascii=False), impact, action, detail, actor, now),
                )
                imported_vex += 1
        reconciliation = _reconcile_in_connection(conn, sbom_id, actor=actor)
        add_audit_event(
            db_path, finding_id=None, event_type="sbom_imported",
            summary=f"SBOM 제품 릴리스 등록: {target_name} {parsed.get('target_version','')}",
            details={"sbom_id": sbom_id, "components": len(components), "embedded_vex": imported_vex,
                     "linked_findings": reconciliation["inserted"], "sha256": document_sha256},
            actor=actor, conn=conn,
        )
        conn.commit()
    result = get_sbom_document(db_path, sbom_id) or {}
    result["duplicate_document"] = False
    return result


def list_sbom_documents(db_path: str, *, status: str = "ACTIVE", limit: int = 500) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if status:
        clauses.append("d.status=?")
        params.append(str(status).upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT d.*,
                       COUNT(DISTINCT CASE WHEN l.status='CONFIRMED' THEN l.finding_id END) AS linked_finding_count,
                       COUNT(DISTINCT CASE WHEN l.status='CANDIDATE' THEN l.link_id END) AS candidate_link_count,
                       COUNT(DISTINCT CASE WHEN v.review_status='APPROVED' THEN v.component_id||':'||v.cve_id END) AS approved_vex_count,
                       COUNT(DISTINCT CASE WHEN v.review_status='PENDING' THEN v.component_id||':'||v.cve_id END) AS pending_vex_count,
                       COUNT(DISTINCT CASE WHEN om.status='CANDIDATE' THEN om.match_id END) AS osv_candidate_count,
                       COUNT(DISTINCT CASE WHEN om.status='CONFIRMED' THEN om.match_id END) AS osv_confirmed_count,
                       MAX(os.created_at) AS latest_osv_scan_at
                  FROM sbom_documents d
                  LEFT JOIN sbom_finding_links l ON l.sbom_id=d.sbom_id
                  LEFT JOIN vex_statements v ON v.sbom_id=d.sbom_id
                  LEFT JOIN sbom_osv_matches om ON om.sbom_id=d.sbom_id
                  LEFT JOIN osv_scan_runs os ON os.sbom_id=d.sbom_id AND os.status='SUCCEEDED'
                  {where}
                 GROUP BY d.sbom_id
                 ORDER BY d.uploaded_at DESC LIMIT ?""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def get_sbom_document(db_path: str, sbom_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM sbom_documents WHERE sbom_id=?", (sbom_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        components = conn.execute(
            """SELECT c.*,
                       COUNT(DISTINCT CASE WHEN l.status='CONFIRMED' THEN l.finding_id END) AS linked_finding_count,
                       COUNT(DISTINCT CASE WHEN l.status='CANDIDATE' THEN l.link_id END) AS candidate_link_count,
                       COUNT(DISTINCT CASE WHEN l.status='CONFIRMED' AND f.kev=1 THEN l.finding_id END) AS linked_kev_count,
                       MAX(CASE WHEN l.status='CONFIRMED' THEN f.score END) AS max_finding_score
                  FROM sbom_components c
                  LEFT JOIN sbom_finding_links l ON l.component_id=c.component_id
                  LEFT JOIN findings f ON f.finding_id=l.finding_id
                 WHERE c.sbom_id=? GROUP BY c.component_id ORDER BY c.name,c.version,c.identity_occurrence""",
            (sbom_id,),
        ).fetchall()
        item["components"] = [dict(r) for r in components]
        links = conn.execute(
            """SELECT l.*,f.cve_id,f.status AS finding_status,f.score,f.decision_label,f.kev,f.epss,
                       f.asset_name,f.asset_id,c.name AS component_name,c.version AS component_version
                  FROM sbom_finding_links l
                  JOIN findings f ON f.finding_id=l.finding_id
                  JOIN sbom_components c ON c.component_id=l.component_id
                 WHERE l.sbom_id=? AND l.status!='REJECTED'
                 ORDER BY f.score DESC,f.kev DESC,f.epss DESC""",
            (sbom_id,),
        ).fetchall()
        item["links"] = [dict(r) for r in links]
        item["vex_statements"] = _latest_vex_rows(conn, sbom_id)
        osv_rows = conn.execute(
            """SELECT m.*,c.name AS component_name,c.version AS component_version,c.purl,
                       r.summary,r.modified,r.published,r.withdrawn,r.details,
                       f.status AS finding_status,f.score AS finding_score,f.decision_label
                  FROM sbom_osv_matches m
                  JOIN sbom_components c ON c.component_id=m.component_id
                  JOIN osv_vulnerability_records r ON r.osv_id=m.osv_id
                  LEFT JOIN findings f ON f.finding_id=m.finding_id
                 WHERE m.sbom_id=?
                 ORDER BY CASE m.status WHEN 'CANDIDATE' THEN 0 WHEN 'CONFIRMED' THEN 1 ELSE 2 END,
                          m.severity_numeric DESC,m.cve_id,m.osv_id""",
            (sbom_id,),
        ).fetchall()
        item["osv_matches"] = []
        for raw in osv_rows:
            candidate = dict(raw)
            candidate["aliases"] = _json_list(candidate.pop("aliases_json", "[]"))
            candidate["fixed_versions"] = _json_list(candidate.pop("fixed_versions_json", "[]"))
            item["osv_matches"].append(candidate)
        scans = conn.execute(
            "SELECT * FROM osv_scan_runs WHERE sbom_id=? ORDER BY created_at DESC LIMIT 20", (sbom_id,)
        ).fetchall()
        item["osv_scans"] = []
        for raw in scans:
            scan = dict(raw)
            scan["errors"] = _json_list(scan.pop("errors_json", "[]"))
            item["osv_scans"].append(scan)
        return item


def reconcile_sbom_findings(db_path: str, sbom_id: str, *, actor: str) -> dict[str, int]:
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        result = _reconcile_in_connection(conn, sbom_id, actor=actor)
        add_audit_event(
            db_path, finding_id=None, event_type="sbom_reconciled",
            summary="SBOM 구성요소와 finding 자동 연결",
            details={"sbom_id": sbom_id, **result}, actor=actor, conn=conn,
        )
        conn.commit()
    return result


def decide_sbom_finding_link(db_path: str, link_id: str, *, decision: str, actor: str) -> dict[str, Any]:
    normalized = str(decision or "").strip().upper()
    if normalized not in {"CONFIRM", "REJECT"}:
        raise SbomError("decision은 CONFIRM 또는 REJECT여야 합니다.")
    target = "CONFIRMED" if normalized == "CONFIRM" else "REJECTED"
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM sbom_finding_links WHERE link_id=?", (link_id,)).fetchone()
        if not row:
            raise KeyError(link_id)
        if row["status"] == target:
            return dict(row)
        if row["status"] not in {"CANDIDATE", "CONFIRMED", "REJECTED"}:
            raise SbomError("지원하지 않는 연결 상태입니다.")
        conn.execute("UPDATE sbom_finding_links SET status=?,linked_by=?,linked_at=? WHERE link_id=?",
                     (target, actor, utc_now(), link_id))
        add_audit_event(
            db_path, finding_id=row["finding_id"], event_type="sbom_finding_link_decided",
            summary=f"SBOM finding 연결 {target}",
            details={"link_id": link_id, "sbom_id": row["sbom_id"], "component_id": row["component_id"],
                     "decision": normalized}, actor=actor, conn=conn,
        )
        conn.commit()
    with connect(db_path) as conn:
        updated = conn.execute("SELECT * FROM sbom_finding_links WHERE link_id=?", (link_id,)).fetchone()
        return dict(updated)


def create_vex_revision(db_path: str, *, sbom_id: str, component_id: str, cve_id: str,
                        analysis_state: str, justification: str = "", responses: Iterable[str] = (),
                        impact_statement: str = "", action_statement: str = "", detail: str = "",
                        finding_id: str | None = None, actor: str) -> dict[str, Any]:
    cve_id = str(cve_id or "").strip().upper()
    if not CVE_RE.fullmatch(cve_id):
        raise SbomError("유효한 CVE ID가 아닙니다.")
    state, justification, responses, impact, action, detail = _validate_vex(
        state=analysis_state, justification=justification, responses=responses,
        impact_statement=impact_statement, action_statement=action_statement, detail=detail,
    )
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        component = conn.execute(
            "SELECT component_id FROM sbom_components WHERE component_id=? AND sbom_id=?", (component_id, sbom_id)
        ).fetchone()
        if not component:
            raise KeyError(component_id)
        if finding_id:
            linked = conn.execute(
                "SELECT 1 FROM sbom_finding_links WHERE sbom_id=? AND component_id=? AND finding_id=? AND status='CONFIRMED'",
                (sbom_id, component_id, finding_id),
            ).fetchone()
            if not linked:
                raise SbomError("선택한 finding은 해당 SBOM 구성요소에 연결되어 있지 않습니다.")
        latest = conn.execute(
            """SELECT vex_id,revision_no FROM vex_statements
                 WHERE sbom_id=? AND component_id=? AND cve_id=? ORDER BY revision_no DESC LIMIT 1""",
            (sbom_id, component_id, cve_id),
        ).fetchone()
        revision_no = int(latest["revision_no"] if latest else 0) + 1
        vex_id = f"VEX-{uuid.uuid4().hex[:16].upper()}"
        now = utc_now()
        conn.execute(
            """INSERT INTO vex_statements(
                   vex_id,sbom_id,component_id,cve_id,finding_id,revision_no,analysis_state,justification,
                   response_json,impact_statement,action_statement,detail,review_status,created_by,created_at,
                   supersedes_vex_id
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'DRAFT',?,?,?)""",
            (vex_id, sbom_id, component_id, cve_id, finding_id or None, revision_no, state, justification,
             json.dumps(responses, ensure_ascii=False), impact, action, detail, actor, now,
             latest["vex_id"] if latest else None),
        )
        add_audit_event(
            db_path, finding_id=finding_id, event_type="vex_revision_created",
            summary=f"VEX 초안 생성: {cve_id} {state}",
            details={"vex_id": vex_id, "sbom_id": sbom_id, "component_id": component_id,
                     "revision_no": revision_no, "state": state}, actor=actor, conn=conn,
        )
        conn.commit()
    return get_vex_statement(db_path, vex_id) or {}


def get_vex_statement(db_path: str, vex_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT v.*,d.product_name,d.product_version,c.name AS component_name,c.version AS component_version,
                       c.purl,c.bom_ref
                  FROM vex_statements v JOIN sbom_documents d ON d.sbom_id=v.sbom_id
                  JOIN sbom_components c ON c.component_id=v.component_id WHERE v.vex_id=?""",
            (vex_id,),
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            item["responses"] = json.loads(item.get("response_json") or "[]")
        except json.JSONDecodeError:
            item["responses"] = []
        return item


def request_vex_approval(db_path: str, vex_id: str, *, actor: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM vex_statements WHERE vex_id=?", (vex_id,)).fetchone()
        if not row:
            raise KeyError(vex_id)
        if row["review_status"] not in {"DRAFT", "REJECTED"}:
            raise SbomError("DRAFT 또는 REJECTED VEX만 승인 요청할 수 있습니다.")
        now = utc_now()
        conn.execute(
            "UPDATE vex_statements SET review_status='PENDING',requested_by=?,requested_at=?,decided_by=NULL,decision_note=NULL,decided_at=NULL WHERE vex_id=?",
            (actor, now, vex_id),
        )
        add_audit_event(
            db_path, finding_id=row["finding_id"], event_type="vex_approval_requested",
            summary=f"VEX 승인 요청: {row['cve_id']}", details={"vex_id": vex_id}, actor=actor, conn=conn,
        )
        conn.commit()
    return get_vex_statement(db_path, vex_id) or {}


def decide_vex_statement(db_path: str, vex_id: str, *, decision: str, decision_note: str, actor: str) -> dict[str, Any]:
    normalized = str(decision or "").strip().upper()
    if normalized not in {"APPROVE", "REJECT"}:
        raise SbomError("decision은 APPROVE 또는 REJECT여야 합니다.")
    note = str(decision_note or "").strip()
    if normalized == "REJECT" and not note:
        raise SbomError("반려 사유가 필요합니다.")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM vex_statements WHERE vex_id=?", (vex_id,)).fetchone()
        if not row:
            raise KeyError(vex_id)
        if row["review_status"] != "PENDING":
            raise SbomError("대기 중인 VEX만 처리할 수 있습니다.")
        status = "APPROVED" if normalized == "APPROVE" else "REJECTED"
        now = utc_now()
        conn.execute(
            "UPDATE vex_statements SET review_status=?,decided_by=?,decision_note=?,decided_at=? WHERE vex_id=?",
            (status, actor, note, now, vex_id),
        )
        add_audit_event(
            db_path, finding_id=row["finding_id"], event_type="vex_approval_decided",
            summary=f"VEX {status}: {row['cve_id']}",
            details={"vex_id": vex_id, "decision": normalized, "note": note}, actor=actor, conn=conn,
        )
        conn.commit()
    return get_vex_statement(db_path, vex_id) or {}


def list_vex_approval_requests(db_path: str, *, status: str = "PENDING", limit: int = 500) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if status:
        where = " WHERE v.review_status=?"
        params.append(str(status).upper())
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT v.*,d.product_name,d.product_version,c.name AS component_name,c.version AS component_version
                  FROM vex_statements v JOIN sbom_documents d ON d.sbom_id=v.sbom_id
                  JOIN sbom_components c ON c.component_id=v.component_id
                  {where} ORDER BY COALESCE(v.requested_at,v.created_at) DESC LIMIT ?""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def export_cyclonedx_vex(db_path: str, sbom_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        doc = conn.execute("SELECT * FROM sbom_documents WHERE sbom_id=?", (sbom_id,)).fetchone()
        if not doc:
            raise KeyError(sbom_id)
        components = [dict(row) for row in conn.execute(
            "SELECT * FROM sbom_components WHERE sbom_id=? ORDER BY name,version,identity_occurrence", (sbom_id,)
        ).fetchall()]
        statements = conn.execute(
            """SELECT v.*,c.bom_ref,c.purl,c.name,c.version
                  FROM vex_statements v JOIN sbom_components c ON c.component_id=v.component_id
                 WHERE v.sbom_id=? AND v.review_status='APPROVED'
                   AND v.revision_no=(SELECT MAX(v2.revision_no) FROM vex_statements v2
                                       WHERE v2.sbom_id=v.sbom_id AND v2.component_id=v.component_id
                                         AND v2.cve_id=v.cve_id AND v2.review_status='APPROVED')
                 ORDER BY v.cve_id,c.name""",
            (sbom_id,),
        ).fetchall()
    component_payload = []
    refs: dict[str, str] = {}
    for component in components:
        ref = str(component.get("bom_ref") or component.get("purl") or component["component_id"])
        refs[component["component_id"]] = ref
        item: dict[str, Any] = {
            "bom-ref": ref,
            "type": component.get("component_type") or "library",
            "name": component.get("name") or "unknown",
        }
        for key, source in (("group", "component_group"), ("version", "version"), ("purl", "purl")):
            if component.get(source):
                item[key] = component[source]
        component_payload.append(item)
    vulnerabilities = []
    for row in statements:
        try:
            responses = [str(v).lower() for v in json.loads(row["response_json"] or "[]")]
        except json.JSONDecodeError:
            responses = []
        analysis: dict[str, Any] = {"state": str(row["analysis_state"]).lower()}
        if row["justification"]:
            analysis["justification"] = str(row["justification"]).lower()
        if responses:
            analysis["response"] = responses
        detail_parts = []
        if row["impact_statement"]:
            detail_parts.append("Impact: " + row["impact_statement"])
        if row["action_statement"]:
            detail_parts.append("Action: " + row["action_statement"])
        if row["detail"]:
            detail_parts.append(row["detail"])
        if detail_parts:
            analysis["detail"] = "\n".join(detail_parts)
        vulnerabilities.append({
            "id": row["cve_id"],
            "source": {"name": "VulnFlow"},
            "analysis": analysis,
            "affects": [{"ref": refs[row["component_id"]]}],
            "properties": [
                {"name": "vulnflow:vex_id", "value": row["vex_id"]},
                {"name": "vulnflow:revision", "value": str(row["revision_no"])},
                {"name": "vulnflow:approved_by", "value": str(row["decided_by"] or "")},
            ],
        })
    serial = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'vulnflow:{sbom_id}:vex')}"
    document_version = max([int(row["revision_no"]) for row in statements] or [1])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": document_version,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": "VulnFlow", "version": CURRENT_APP_VERSION}]},
            "component": {
                "type": "application",
                "name": doc["product_name"],
                "version": doc["product_version"],
            },
            "properties": [
                {"name": "vulnflow:source_sbom_id", "value": sbom_id},
                {"name": "vulnflow:source_serial_number", "value": str(doc["serial_number"] or "")},
            ],
        },
        "components": component_payload,
        "vulnerabilities": vulnerabilities,
    }

# --- OSV supply-chain discovery (introduced in VulnFlow 21.0; maintained in 22.0) ---

def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(str(value or "[]"))
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def _cached_osv_records(db_path: str) -> dict[str, dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT osv_id,modified,raw_json FROM osv_vulnerability_records").fetchall()
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            raw = json.loads(row["raw_json"] or "{}")
        except json.JSONDecodeError:
            raw = {}
        result[str(row["osv_id"])] = {"modified": row["modified"], "raw_record": raw}
    return result


def _osv_record_values(record: dict[str, Any]) -> tuple[Any, ...]:
    from app.services.osv import record_digest

    return (
        str(record.get("id") or "").strip(), str(record.get("modified") or ""),
        str(record.get("published") or ""), str(record.get("withdrawn") or ""),
        str(record.get("summary") or "")[:4000], str(record.get("details") or "")[:20000],
        json.dumps(record.get("aliases") or [], ensure_ascii=False, separators=(",", ":")),
        json.dumps(record.get("severity") or [], ensure_ascii=False, separators=(",", ":")),
        json.dumps(record.get("affected") or [], ensure_ascii=False, separators=(",", ":")),
        json.dumps(record.get("references") or [], ensure_ascii=False, separators=(",", ":")),
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        record_digest(record), utc_now(),
    )


def run_osv_scan(
    db_path: str,
    sbom_id: str,
    *,
    actor: str,
    api_base: str,
    timeout: int = 15,
    retries: int = 3,
    batch_size: int = 100,
    session=None,
    source_job_id: str | None = None,
) -> dict[str, Any]:
    from app.services.osv import cve_aliases, fixed_versions, query_components, severity_summary

    with connect(db_path) as conn:
        document = conn.execute("SELECT * FROM sbom_documents WHERE sbom_id=?", (sbom_id,)).fetchone()
        if not document:
            raise KeyError(sbom_id)
        existing = None
        if source_job_id:
            existing = conn.execute("SELECT * FROM osv_scan_runs WHERE source_job_id=?", (source_job_id,)).fetchone()
            if existing and existing["status"] == "SUCCEEDED":
                item = dict(existing)
                item["errors"] = _json_list(item.pop("errors_json", "[]"))
                return item
        components = [dict(row) for row in conn.execute(
            "SELECT * FROM sbom_components WHERE sbom_id=? ORDER BY component_id", (sbom_id,)
        ).fetchall()]
        now = utc_now()
        if existing:
            scan_id = str(existing["scan_id"])
            conn.execute(
                """UPDATE osv_scan_runs SET status='RUNNING',source_url=?,requested_by=?,started_at=?,completed_at='',
                       component_total=?,eligible_components=0,skipped_components=0,vulnerability_matches=0,
                       new_candidates=0,cache_hits=0,api_requests=0,error_count=0,errors_json='[]'
                     WHERE scan_id=?""",
                (str(api_base).rstrip("/"), actor, now, len(components), scan_id),
            )
        else:
            scan_id = f"OSVSCAN-{uuid.uuid4().hex[:16].upper()}"
            conn.execute(
                """INSERT INTO osv_scan_runs(
                       scan_id,sbom_id,status,source_name,source_url,requested_by,created_at,started_at,
                       component_total,source_job_id
                   ) VALUES(?,?,'RUNNING','OSV.dev',?,?,?,?,?,?)""",
                (scan_id, sbom_id, str(api_base).rstrip("/"), actor, now, now, len(components), source_job_id),
            )
        conn.commit()
    try:
        query_result = query_components(
            components, api_base=api_base, timeout=timeout, retries=retries, batch_size=batch_size,
            session=session, cached_records=_cached_osv_records(db_path),
        )
        query_by_component = {query.component_id: query for query in query_result["queries"]}
        component_ids = query_result["component_vulnerability_ids"]
        records = query_result["records"]
        inserted = matches = 0
        with connect(db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            for record in records.values():
                if not str(record.get("id") or "").strip():
                    continue
                conn.execute(
                    """INSERT INTO osv_vulnerability_records(
                           osv_id,modified,published,withdrawn,summary,details,aliases_json,severity_json,
                           affected_json,references_json,raw_json,content_sha256,fetched_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(osv_id) DO UPDATE SET
                           modified=excluded.modified,published=excluded.published,withdrawn=excluded.withdrawn,
                           summary=excluded.summary,details=excluded.details,aliases_json=excluded.aliases_json,
                           severity_json=excluded.severity_json,affected_json=excluded.affected_json,
                           references_json=excluded.references_json,raw_json=excluded.raw_json,
                           content_sha256=excluded.content_sha256,fetched_at=excluded.fetched_at""",
                    _osv_record_values(record),
                )
            component_map = {str(c["component_id"]): c for c in components}
            now = utc_now()
            for component_id, vuln_ids in component_ids.items():
                component = component_map.get(component_id)
                query = query_by_component.get(component_id)
                if not component or not query:
                    continue
                for osv_id in sorted(vuln_ids):
                    record = records.get(osv_id)
                    if not record:
                        continue
                    cves = cve_aliases(record)
                    cve_id = cves[0] if cves else ""
                    label, vector, numeric = severity_summary(record)
                    fixed = fixed_versions(record)
                    match_id = "OSVM-" + hashlib.sha256(
                        f"{sbom_id}|{component_id}|{osv_id}".encode("utf-8")
                    ).hexdigest()[:20].upper()
                    existing = conn.execute(
                        "SELECT status FROM sbom_osv_matches WHERE sbom_id=? AND component_id=? AND osv_id=?",
                        (sbom_id, component_id, osv_id),
                    ).fetchone()
                    conn.execute(
                        """INSERT INTO sbom_osv_matches(
                               match_id,scan_id,sbom_id,component_id,osv_id,cve_id,aliases_json,severity_label,
                               severity_vector,severity_numeric,fixed_versions_json,match_method,status,created_by,created_at
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'OSV_PURL_VERSION','CANDIDATE',?,?)
                           ON CONFLICT(sbom_id,component_id,osv_id) DO UPDATE SET
                               scan_id=excluded.scan_id,cve_id=excluded.cve_id,aliases_json=excluded.aliases_json,
                               severity_label=excluded.severity_label,severity_vector=excluded.severity_vector,
                               severity_numeric=excluded.severity_numeric,fixed_versions_json=excluded.fixed_versions_json""",
                        (match_id, scan_id, sbom_id, component_id, osv_id, cve_id,
                         json.dumps(cves, ensure_ascii=False), label, vector, numeric,
                         json.dumps(fixed, ensure_ascii=False), actor, now),
                    )
                    matches += 1
                    if existing is None:
                        inserted += 1
            errors = list(query_result.get("errors") or [])
            conn.execute(
                """UPDATE osv_scan_runs SET status='SUCCEEDED',completed_at=?,eligible_components=?,
                       skipped_components=?,vulnerability_matches=?,new_candidates=?,cache_hits=?,api_requests=?,
                       error_count=?,errors_json=? WHERE scan_id=?""",
                (utc_now(), len(query_result["queries"]), int(query_result["skipped_components"]), matches,
                 inserted, int(query_result["cache_hits"]), int(query_result["api_requests"]), len(errors),
                 json.dumps(errors, ensure_ascii=False), scan_id),
            )
            add_audit_event(
                db_path, finding_id=None, event_type="osv_scan_completed",
                summary=f"OSV 공급망 취약점 탐색 완료: {document['product_name']} {document['product_version']}",
                details={"scan_id": scan_id, "sbom_id": sbom_id, "matches": matches,
                         "new_candidates": inserted, "cache_hits": query_result["cache_hits"],
                         "api_requests": query_result["api_requests"], "errors": errors},
                actor=actor, conn=conn,
            )
            conn.commit()
        return get_osv_scan(db_path, scan_id) or {}
    except Exception as exc:
        with connect(db_path) as conn:
            conn.execute(
                "UPDATE osv_scan_runs SET status='FAILED',completed_at=?,error_count=1,errors_json=? WHERE scan_id=?",
                (utc_now(), json.dumps([str(exc)], ensure_ascii=False), scan_id),
            )
            add_audit_event(
                db_path, finding_id=None, event_type="osv_scan_failed", summary="OSV 공급망 취약점 탐색 실패",
                details={"scan_id": scan_id, "sbom_id": sbom_id, "error": str(exc)}, actor=actor, conn=conn,
            )
            conn.commit()
        raise


def get_osv_scan(db_path: str, scan_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM osv_scan_runs WHERE scan_id=?", (scan_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["errors"] = _json_list(item.pop("errors_json", "[]"))
        return item


def list_osv_scans(db_path: str, *, sbom_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
    where = " WHERE sbom_id=?" if sbom_id else ""
    params: list[Any] = [sbom_id] if sbom_id else []
    params.append(max(1, min(int(limit), 1000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM osv_scan_runs{where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["errors"] = _json_list(item.pop("errors_json", "[]"))
        output.append(item)
    return output


def list_osv_matches(db_path: str, *, sbom_id: str = "", status: str = "", limit: int = 1000) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if sbom_id:
        clauses.append("m.sbom_id=?")
        params.append(sbom_id)
    if status:
        clauses.append("m.status=?")
        params.append(str(status).upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT m.*,c.name AS component_name,c.version AS component_version,c.purl,
                       r.summary,r.modified,r.published,r.withdrawn,r.details,
                       f.status AS finding_status,f.score AS finding_score,f.decision_label
                  FROM sbom_osv_matches m
                  JOIN sbom_components c ON c.component_id=m.component_id
                  JOIN osv_vulnerability_records r ON r.osv_id=m.osv_id
                  LEFT JOIN findings f ON f.finding_id=m.finding_id
                  {where}
                 ORDER BY CASE m.status WHEN 'CANDIDATE' THEN 0 WHEN 'CONFIRMED' THEN 1 ELSE 2 END,
                          m.severity_numeric DESC,m.cve_id,m.osv_id LIMIT ?""",
            params,
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["aliases"] = _json_list(item.pop("aliases_json", "[]"))
        item["fixed_versions"] = _json_list(item.pop("fixed_versions_json", "[]"))
        output.append(item)
    return output


def _osv_finding_row(db_path: str, match: dict[str, Any]) -> dict[str, Any]:
    from datetime import date
    from app.repositories.reconciliation import FIELDS

    with connect(db_path) as conn:
        doc = conn.execute("SELECT * FROM sbom_documents WHERE sbom_id=?", (match["sbom_id"],)).fetchone()
        component = conn.execute("SELECT * FROM sbom_components WHERE component_id=?", (match["component_id"],)).fetchone()
        record = conn.execute("SELECT * FROM osv_vulnerability_records WHERE osv_id=?", (match["osv_id"],)).fetchone()
    if not doc or not component or not record:
        raise SbomError("OSV 후보의 SBOM 또는 취약점 레코드가 없습니다.")
    cve_id = str(match.get("cve_id") or "")
    if not CVE_RE.fullmatch(cve_id):
        raise SbomError("CVE alias가 없는 OSV 레코드는 finding으로 확정할 수 없습니다.")
    finding_id = "AUTO-OSV-" + hashlib.sha256(
        f"{match['sbom_id']}|{match['component_id']}|{cve_id}".encode("utf-8")
    ).hexdigest()[:16].upper()
    today = date.today().isoformat()
    defaults: dict[str, Any] = {field: "" for field in FIELDS}
    for field in ["cvss", "epss", "epss_percentile", "kev", "internet_exposed", "patch_available",
                  "compensating_control", "score", "threat_score", "asset_context_score",
                  "remediation_urgency_score", "sla_days", "mitigation_required"]:
        defaults[field] = 0
    defaults.update({
        "finding_id": finding_id,
        "product": doc["product_name"], "product_version": doc["product_version"],
        "asset_id": f"SBOM:{match['sbom_id']}", "asset_name": f"{doc['product_name']} {doc['product_version']}".strip(),
        "environment": "software-supply-chain", "cve_id": cve_id,
        "component": component["name"], "component_version": component["version"],
        "cvss": float(match.get("severity_numeric") or 0), "patch_available": 1 if _json_list(match.get("fixed_versions_json")) else 0,
        "asset_criticality": 3, "data_sensitivity": 2, "status": "OPEN",
        "notes": f"OSV candidate {match['osv_id']}: {record['summary']}",
        "intel_source": "OSV.dev", "intel_updated_at": utc_now(),
        "scanner_source": "osv", "record_state": "ACTIVE",
        "first_seen_at": today, "first_scored_at": today, "last_scored_at": today,
        "source_last_seen_at": utc_now(), "row_version": 1,
    })
    return defaults


def decide_osv_match(db_path: str, match_id: str, *, decision: str, reason: str, actor: str) -> dict[str, Any]:
    from app.repositories.finding_ingestion import upsert_findings

    normalized = str(decision or "").strip().upper()
    if normalized not in {"CONFIRM", "REJECT"}:
        raise SbomError("decision은 CONFIRM 또는 REJECT여야 합니다.")
    reason = str(reason or "").strip()
    with connect(db_path) as conn:
        raw = conn.execute("SELECT * FROM sbom_osv_matches WHERE match_id=?", (match_id,)).fetchone()
        if not raw:
            raise KeyError(match_id)
        match = dict(raw)
    if normalized == "REJECT":
        with connect(db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE sbom_osv_matches SET status='REJECTED',decided_by=?,decided_at=?,decision_reason=? WHERE match_id=?",
                (actor, utc_now(), reason, match_id),
            )
            add_audit_event(
                db_path, finding_id=match.get("finding_id"), event_type="osv_candidate_decided",
                summary=f"OSV 후보 제외: {match['osv_id']}",
                details={"match_id": match_id, "decision": normalized, "reason": reason}, actor=actor, conn=conn,
            )
            conn.commit()
    else:
        if match.get("status") == "CONFIRMED" and match.get("finding_id"):
            return next(item for item in list_osv_matches(db_path, limit=5000) if item["match_id"] == match_id)
        row = _osv_finding_row(db_path, match)
        upsert_findings(db_path, [row], actor=actor, audit=False)
        finding_id = row["finding_id"]
        link_id = "LNK-" + hashlib.sha256(
            f"{match['sbom_id']}|{match['component_id']}|{finding_id}".encode("utf-8")
        ).hexdigest()[:16].upper()
        with connect(db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO sbom_finding_links(
                       link_id,sbom_id,component_id,finding_id,match_method,match_confidence,status,linked_by,linked_at
                   ) VALUES(?,?,?,?, 'OSV_CONFIRMED',95,'CONFIRMED',?,?)
                   ON CONFLICT(sbom_id,component_id,finding_id) DO UPDATE SET status='CONFIRMED',
                       match_method='OSV_CONFIRMED',match_confidence=95,linked_by=excluded.linked_by,linked_at=excluded.linked_at""",
                (link_id, match["sbom_id"], match["component_id"], finding_id, actor, utc_now()),
            )
            conn.execute(
                "UPDATE sbom_osv_matches SET status='CONFIRMED',finding_id=?,decided_by=?,decided_at=?,decision_reason=? WHERE match_id=?",
                (finding_id, actor, utc_now(), reason, match_id),
            )
            add_audit_event(
                db_path, finding_id=finding_id, event_type="osv_candidate_decided",
                summary=f"OSV 후보 확정: {match['osv_id']} → {match['cve_id']}",
                details={"match_id": match_id, "decision": normalized, "reason": reason,
                         "sbom_id": match["sbom_id"], "component_id": match["component_id"]},
                actor=actor, conn=conn,
            )
            conn.commit()
    return next(item for item in list_osv_matches(db_path, limit=5000) if item["match_id"] == match_id)
