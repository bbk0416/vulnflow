import io
import json
import sqlite3
from pathlib import Path

import pytest

from app.core.storage import CURRENT_SCHEMA_VERSION, init_db, upsert_findings
from app.services.sbom import (
    SbomError,
    create_vex_revision,
    decide_sbom_finding_link,
    decide_vex_statement,
    export_cyclonedx_vex,
    get_sbom_document,
    parse_cyclonedx_json,
    request_vex_approval,
    store_cyclonedx_document,
)


def payload(*, embedded=False):
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "metadata": {"component": {"type": "application", "name": "Customer Portal", "version": "5.8"}},
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "group": "org.apache.logging.log4j",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            }
        ],
    }
    if embedded:
        data["vulnerabilities"] = [{
            "id": "CVE-2021-44228",
            "affects": [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
            "analysis": {"state": "in_triage", "detail": "upstream analysis pending"},
        }]
    return data


def parsed(*, embedded=False):
    return parse_cyclonedx_json(io.BytesIO(json.dumps(payload(embedded=embedded)).encode()))


def finding():
    return {
        "finding_id": "F-SBOM-1", "product": "Customer Portal", "product_version": "5.8",
        "asset_id": "A-WEB-1", "asset_name": "portal", "environment": "production",
        "cve_id": "CVE-2021-44228", "component": "log4j-core", "component_version": "2.14.1",
        "cvss": 10.0, "epss": 0.97, "epss_percentile": 0.99, "kev": 1,
        "internet_exposed": 1, "asset_criticality": 5, "data_sensitivity": 5,
        "patch_available": 1, "compensating_control": 0, "status": "OPEN",
        "owner": "dev", "due_date": "", "notes": "", "intel_source": "test",
    }


def test_schema_v18_has_supply_chain_tables(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert {"sbom_documents", "sbom_components", "sbom_finding_links", "vex_statements"} <= tables


def test_v17_database_migrates_supply_chain_tables(tmp_path: Path):
    db = tmp_path / "legacy.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        for table in ["vex_statements", "sbom_finding_links", "sbom_components", "sbom_documents"]:
            conn.execute(f"DROP TABLE {table}")
        conn.execute("PRAGMA user_version=17")
        conn.commit()
    init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == 40
    assert {"sbom_documents", "sbom_components", "sbom_finding_links", "vex_statements"} <= tables


def test_parse_embedded_vulnerability_analysis():
    result = parsed(embedded=True)
    assert result["embedded_vulnerabilities"][0]["cve_id"] == "CVE-2021-44228"
    assert result["embedded_vulnerabilities"][0]["analysis_state"] == "IN_TRIAGE"


def test_sbom_import_links_exact_finding_and_is_idempotent(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    upsert_findings(db, [finding()], actor="tester")
    first = store_cyclonedx_document(str(db), parsed(), source_filename="portal.cdx.json", actor="tester")
    assert len(first["components"]) == 1
    assert len(first["links"]) == 1
    assert first["links"][0]["finding_id"] == "F-SBOM-1"
    assert first["links"][0]["status"] == "CANDIDATE"
    second = store_cyclonedx_document(str(db), parsed(), source_filename="duplicate.cdx.json", actor="tester")
    assert second["sbom_id"] == first["sbom_id"]
    assert second["duplicate_document"] is True


def test_weak_component_name_only_match_is_not_linked(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    weak = finding() | {"product": "Other Product", "product_version": "5.8", "component_version": "2.14.1"}
    upsert_findings(db, [weak], actor="tester")
    item = store_cyclonedx_document(str(db), parsed(), source_filename="portal.cdx.json", actor="tester")
    assert item["links"] == []


def test_vex_revision_approval_and_export(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    upsert_findings(db, [finding()], actor="tester")
    item = store_cyclonedx_document(str(db), parsed(), source_filename="portal.cdx.json", actor="tester")
    component = item["components"][0]
    decide_sbom_finding_link(str(db), item["links"][0]["link_id"], decision="CONFIRM", actor="operator")
    draft = create_vex_revision(
        str(db), sbom_id=item["sbom_id"], component_id=component["component_id"],
        cve_id="CVE-2021-44228", analysis_state="NOT_AFFECTED",
        justification="CODE_NOT_REACHABLE", impact_statement="vulnerable code path is disabled",
        detail="configuration review completed", finding_id="F-SBOM-1", actor="operator",
    )
    assert draft["review_status"] == "DRAFT"
    pending = request_vex_approval(str(db), draft["vex_id"], actor="operator")
    assert pending["review_status"] == "PENDING"
    approved = decide_vex_statement(str(db), draft["vex_id"], decision="APPROVE", decision_note="reviewed", actor="approver")
    assert approved["review_status"] == "APPROVED"
    exported = export_cyclonedx_vex(str(db), item["sbom_id"])
    assert exported["vulnerabilities"][0]["id"] == "CVE-2021-44228"
    assert exported["vulnerabilities"][0]["analysis"]["state"] == "not_affected"
    assert exported["vulnerabilities"][0]["affects"][0]["ref"].startswith("pkg:maven/")


def test_link_candidate_can_be_confirmed_or_rejected(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    upsert_findings(db, [finding()], actor="tester")
    item = store_cyclonedx_document(str(db), parsed(), source_filename="portal.cdx.json", actor="tester")
    link_id = item["links"][0]["link_id"]
    confirmed = decide_sbom_finding_link(str(db), link_id, decision="CONFIRM", actor="operator")
    assert confirmed["status"] == "CONFIRMED"
    rejected = decide_sbom_finding_link(str(db), link_id, decision="REJECT", actor="operator")
    assert rejected["status"] == "REJECTED"
    assert get_sbom_document(str(db), item["sbom_id"])["links"] == []


def test_candidate_link_cannot_be_used_as_vex_finding_evidence(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    upsert_findings(db, [finding()], actor="tester")
    item = store_cyclonedx_document(str(db), parsed(), source_filename="portal.cdx.json", actor="tester")
    with pytest.raises(SbomError, match="연결"):
        create_vex_revision(
            str(db), sbom_id=item["sbom_id"], component_id=item["components"][0]["component_id"],
            cve_id="CVE-2021-44228", analysis_state="EXPLOITABLE",
            impact_statement="candidate link is not reviewed", finding_id="F-SBOM-1", actor="operator",
        )


def test_vex_final_states_require_evidence_text(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    item = store_cyclonedx_document(str(db), parsed(), source_filename="portal.cdx.json", actor="tester")
    with pytest.raises(SbomError):
        create_vex_revision(
            str(db), sbom_id=item["sbom_id"], component_id=item["components"][0]["component_id"],
            cve_id="CVE-2021-44228", analysis_state="NOT_AFFECTED", actor="operator",
        )


def test_embedded_vex_is_imported_as_draft(tmp_path: Path):
    db = tmp_path / "v18.sqlite3"
    init_db(db)
    item = store_cyclonedx_document(str(db), parsed(embedded=True), source_filename="portal.cdx.json", actor="tester")
    assert item["vex_statements"][0]["review_status"] == "DRAFT"
    assert item["vex_statements"][0]["analysis_state"] == "IN_TRIAGE"
