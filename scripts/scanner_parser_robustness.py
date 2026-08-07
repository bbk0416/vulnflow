from __future__ import annotations

"""Run deterministic scanner parser mutation and safety checks."""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Callable

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.finding_imports import parse_import_file  # noqa: E402
from app.services.scanner_compatibility import (  # noqa: E402
    build_scanner_compatibility_report,
    evaluate_scanner_file,
)

FIXTURES = ROOT / "tests" / "fixtures" / "scanners"


def _case(name: str, action: Callable[[], tuple[bool, dict[str, Any]]]) -> dict[str, Any]:
    try:
        passed, details = action()
        return {"name": name, "passed": bool(passed), "details": details}
    except Exception as exc:  # boundary script reports parser failures as data
        return {"name": name, "passed": False, "details": {"error": str(exc)}}


def _expect_error(payload: bytes, *, filename: str, contains: str) -> tuple[bool, dict[str, Any]]:
    try:
        parse_import_file(payload, filename=filename)
    except ValueError as exc:
        message = str(exc)
        return contains in message, {"message": message, "expected_fragment": contains}
    return False, {"message": "parser accepted a document that should be blocked"}


def run_robustness_matrix() -> dict[str, Any]:
    refs = (FIXTURES / "openvas-refs.xml").read_bytes()
    duplicate = (FIXTURES / "openvas-duplicate.xml").read_bytes()
    cpe22 = (FIXTURES / "nessus-cpe22.nessus").read_bytes()

    def bom_extensionless() -> tuple[bool, dict[str, Any]]:
        parsed = parse_import_file(b"\xef\xbb\xbf" + refs, filename="customer-export")
        observed = {
            "detected_format": parsed["detected_format"],
            "cve_id": parsed["rows"][0]["cve_id"],
        }
        return observed == {
            "detected_format": "openvas_xml",
            "cve_id": "CVE-2026-96002",
        }, observed

    def cpe22_contract() -> tuple[bool, dict[str, Any]]:
        parsed = parse_import_file(cpe22, filename="customer.nessus")
        row = parsed["rows"][0]
        observed = {
            "product": row["product"],
            "product_version": row["product_version"],
            "cvss": row["cvss"],
            "asset_id": row["asset_id"],
        }
        expected = {
            "product": "acme widget_server",
            "product_version": "1.2.3",
            "cvss": "9.3",
            "asset_id": "fixture-host-uuid",
        }
        return observed == expected, observed

    def duplicate_contract() -> tuple[bool, dict[str, Any]]:
        report = build_scanner_compatibility_report(
            evaluate_scanner_file(duplicate, filename="duplicate.xml"),
            filename="duplicate.xml",
        )
        observed = {
            "status": report["status"],
            "duplicate_rows": report["duplicate_rows"],
            "warning_count": report["warning_count"],
        }
        return observed == {"status": "REVIEW", "duplicate_rows": 1, "warning_count": 1}, observed

    cases = [
        _case("utf8_bom_extensionless_xml", bom_extensionless),
        _case("nessus_cpe22_cvss4", cpe22_contract),
        _case("duplicate_canonical_rows_review", duplicate_contract),
        _case(
            "doctype_entity_blocked",
            lambda: _expect_error(
                b"<?xml version='1.0'?><!DOCTYPE report [<!ENTITY x 'boom'>]><report>&x;</report>",
                filename="unsafe.xml",
                contains="DOCTYPE 또는 ENTITY",
            ),
        ),
        _case(
            "excessive_xml_depth_blocked",
            lambda: _expect_error(
                ("<get_reports_response>" + "<x>" * 129 + "</x>" * 129 + "</get_reports_response>").encode(),
                filename="deep.xml",
                contains="중첩 깊이",
            ),
        ),
        _case(
            "truncated_xml_blocked",
            lambda: _expect_error(
                b"<get_reports_response><report><result>",
                filename="truncated.xml",
                contains="XML 형식 오류",
            ),
        ),
    ]
    return {
        "format": "vulnflow-scanner-parser-robustness/1",
        "passed": all(item["passed"] for item in cases),
        "cases": cases,
        "scope": "deterministic synthetic mutations; not a vendor-version certification",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    report = run_robustness_matrix()
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    for item in report["cases"]:
        print(f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']}")
    print(
        f"scanner parser robustness: {'PASS' if report['passed'] else 'FAIL'} "
        f"({len(report['cases'])} cases)"
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
