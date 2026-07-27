from __future__ import annotations

import io
import json
import os
import tempfile
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    with tempfile.TemporaryDirectory(prefix="vulnflow-sbom-vex-") as tmp:
        os.environ["VULNFLOW_DB"] = str(Path(tmp) / "vulnflow.db")
        os.environ["VULNFLOW_COORDINATION_DB"] = str(Path(tmp) / "coordination.db")
        os.environ["VULNFLOW_EVIDENCE_DIR"] = str(Path(tmp) / "evidence")
        os.environ["VULNFLOW_RECOVERY_DIR"] = str(Path(tmp) / "recovery")
        os.environ["VULNFLOW_DISABLE_BACKGROUND_WORKER"] = "1"

        from app.core.storage import init_db, upsert_findings
        from app.services.sbom import (
            create_vex_revision,
            decide_sbom_finding_link,
            decide_vex_statement,
            export_cyclonedx_vex,
            parse_cyclonedx_json,
            request_vex_approval,
            store_cyclonedx_document,
        )

        db_path = Path(os.environ["VULNFLOW_DB"])
        init_db(db_path)
        upsert_findings(
            db_path,
            [{
                "finding_id": "SBOM-SMOKE-1",
                "product": "Customer Portal",
                "product_version": "5.8",
                "asset_id": "portal-prod",
                "asset_name": "Customer Portal Production",
                "environment": "production",
                "cve_id": "CVE-2021-44228",
                "component": "log4j-core",
                "component_version": "2.14.1",
                "cvss": 10.0,
                "epss": 0.97,
                "epss_percentile": 0.99,
                "kev": 1,
                "internet_exposed": 1,
                "asset_criticality": 5,
                "data_sensitivity": 4,
                "patch_available": 1,
                "compensating_control": 0,
                "status": "OPEN",
                "owner": "product-security",
                "due_date": "",
                "notes": "",
                "intel_source": "smoke",
            }],
            actor="sbom-smoke",
        )

        parsed = parse_cyclonedx_json(io.BytesIO((root / "data" / "sample_product_release.cdx.json").read_bytes()))
        item = store_cyclonedx_document(
            str(db_path), parsed, source_filename="sample_product_release.cdx.json",
            actor="sbom-smoke", notes="SBOM VEX smoke",
        )
        if len(item["links"]) != 1 or item["links"][0]["status"] != "CANDIDATE":
            raise SystemExit("candidate correlation failed")
        link = decide_sbom_finding_link(
            str(db_path), item["links"][0]["link_id"], decision="CONFIRM", actor="sbom-smoke",
        )
        if link["status"] != "CONFIRMED":
            raise SystemExit("candidate confirmation failed")

        component = next(c for c in item["components"] if c["name"] == "log4j-core")
        draft = create_vex_revision(
            str(db_path), sbom_id=item["sbom_id"], component_id=component["component_id"],
            cve_id="CVE-2021-44228", analysis_state="EXPLOITABLE",
            responses=["UPDATE", "WORKAROUND_AVAILABLE"],
            impact_statement="Affected component is present in the production release.",
            action_statement="Upgrade and verify the fixed release.",
            detail="SBOM/VEX release smoke", finding_id="SBOM-SMOKE-1", actor="sbom-smoke",
        )
        request_vex_approval(str(db_path), draft["vex_id"], actor="sbom-smoke")
        approved = decide_vex_statement(
            str(db_path), draft["vex_id"], decision="APPROVE",
            decision_note="SBOM/VEX smoke approved", actor="sbom-approver",
        )
        exported = export_cyclonedx_vex(str(db_path), item["sbom_id"])
        vulnerabilities = exported.get("vulnerabilities", [])
        if approved["review_status"] != "APPROVED" or len(vulnerabilities) != 1:
            raise SystemExit("VEX approval or export failed")
        if vulnerabilities[0].get("analysis", {}).get("state") != "exploitable":
            raise SystemExit("unexpected VEX state")

        print(json.dumps({
            "sbom_id": item["sbom_id"],
            "candidate_links": 1,
            "confirmed_links": 1,
            "approved_vex": 1,
            "exported_vulnerabilities": 1,
        }, ensure_ascii=False, indent=2))
        print("SBOM/VEX smoke passed: candidate -> confirmed -> approved -> exported")


if __name__ == "__main__":
    main()
