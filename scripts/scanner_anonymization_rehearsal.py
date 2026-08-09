from __future__ import annotations

"""Verify that shareable scanner bundles remove source identifiers and remain parseable."""

import io
import json
from pathlib import Path
import sys
import zipfile
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.finding_imports import parse_import_file  # noqa: E402
from app.services.scanner_anonymization import build_scanner_collection_bundle  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "scanners"
CASES = (
    "nessus-basic.nessus",
    "nessus-cpe22.nessus",
    "openvas-refs.xml",
    "openvas-greenbone.csv",
    "generic.xlsx",
)


def run_anonymization_rehearsal() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for filename in CASES:
        source = FIXTURES / filename
        try:
            bundle, summary = build_scanner_collection_bundle(
                source.read_bytes(), filename=f"confidential-{filename}", profile="compatibility",
            )
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                names = archive.namelist()
                sample_name = next(name for name in names if name.startswith("sample/"))
                sample = archive.read(sample_name)
                anonymization = json.loads(archive.read("reports/anonymization.json"))
                parsed = parse_import_file(sample, filename=Path(sample_name).name)
                combined = b"\n".join(archive.read(name) for name in names)
            passed = bool(
                anonymization.get("residual_source_identifiers") == []
                and anonymization.get("mapping_included") is False
                and f"confidential-{filename}".encode() not in combined
                and parsed.get("rows")
                and summary.get("importable_rows", 0) >= 1
            )
            details = {
                "sample": sample_name,
                "status": summary.get("compatibility_status"),
                "importable_rows": summary.get("importable_rows"),
                "identifiers_replaced": summary.get("source_identifier_tokens_replaced"),
            }
        except Exception as exc:  # boundary script reports failures as data
            passed = False
            details = {"error": str(exc)}
        results.append({"filename": filename, "passed": passed, "details": details})
    strict = build_scanner_collection_bundle(
        (FIXTURES / "nessus-cpe22.nessus").read_bytes(),
        filename="confidential-cpe.nessus", profile="strict",
    )[0]
    strict_text = b""
    with zipfile.ZipFile(io.BytesIO(strict)) as archive:
        strict_text = archive.read("sample/sanitized-scanner-sample.nessus").lower()
    strict_passed = b"acme" not in strict_text and b"widget_server" not in strict_text
    results.append({"filename": "strict-product-redaction", "passed": strict_passed, "details": {}})
    return {
        "format": "vulnflow-scanner-anonymization-rehearsal/1",
        "passed": all(item["passed"] for item in results),
        "cases": results,
        "scope": "synthetic fixtures; generated bundles must still receive human review",
    }


def main() -> int:
    report = run_anonymization_rehearsal()
    for item in report["cases"]:
        print(f"{'PASS' if item['passed'] else 'FAIL'}: {item['filename']}")
    print(f"scanner anonymization rehearsal: {'PASS' if report['passed'] else 'FAIL'} ({len(report['cases'])} cases)")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
