"""Create shareable, original-format scanner samples without source identifiers."""
from __future__ import annotations

import hashlib
import io
import json
import secrets
import zipfile
from typing import Any

from app.services.finding_imports import detect_import_format
from app.services.scanner_anonymization_common import AliasVault, residual_tokens
from app.services.scanner_anonymization_tabular import sanitize_csv, sanitize_xlsx
from app.services.scanner_anonymization_xml import sanitize_xml
from app.services.scanner_compatibility import build_scanner_compatibility_report, evaluate_scanner_file

PROFILES = {"compatibility", "strict"}


def _sample_name(detected_format: str) -> str:
    suffix = {"nessus": ".nessus", "openvas_xml": ".xml", "openvas_csv": ".csv", "csv": ".csv", "xlsx": ".xlsx"}[detected_format]
    return f"sanitized-scanner-sample{suffix}"


def anonymize_scanner_file(
    content: bytes,
    *,
    filename: str,
    format_hint: str = "auto",
    profile: str = "compatibility",
    key: bytes | None = None,
) -> dict[str, Any]:
    selected = str(profile or "compatibility").strip().casefold()
    if selected not in PROFILES:
        raise ValueError("익명화 프로필은 compatibility 또는 strict여야 합니다.")
    detected = detect_import_format(filename, content, format_hint)
    vault = AliasVault(key=key or secrets.token_bytes(32))
    if detected == "xlsx":
        sanitized, format_metadata = sanitize_xlsx(content, vault=vault, profile=selected)
    elif detected in {"csv", "openvas_csv"}:
        sanitized, format_metadata = sanitize_csv(content, vault=vault, profile=selected)
    else:
        sanitized, format_metadata = sanitize_xml(
            content, detected_format=detected, vault=vault, profile=selected,
        )
    residuals = residual_tokens(sanitized, vault.source_tokens)
    if residuals:
        raise ValueError("익명화 결과에 원본 식별자가 남아 번들 생성을 중단했습니다.")
    output_name = _sample_name(detected)
    evaluation = evaluate_scanner_file(sanitized, filename=output_name)
    compatibility = build_scanner_compatibility_report(evaluation, filename=output_name)
    report = {
        "format": "vulnflow-scanner-anonymization/1",
        "profile": selected,
        "detected_format": detected,
        "output_filename": output_name,
        "source_filename_included": False,
        "source_bytes": len(content),
        "output_bytes": len(sanitized),
        "output_sha256": hashlib.sha256(sanitized).hexdigest(),
        "source_identifier_tokens_replaced": len(vault.source_tokens),
        "aliases_by_category": dict(sorted(vault.counts.items())),
        "residual_source_identifiers": residuals,
        "free_text_redacted": True,
        "mapping_included": False,
        "retained_for_compatibility": [
            "CVE identifiers", "CVSS and severity values", "ports and protocols",
            "scanner field and XML structure",
        ] + (["product, plugin, version and CPE values"] if selected == "compatibility" else []),
        "limitations": [
            "구조화된 자산·네트워크·계정 식별자와 자유서술 텍스트를 대상으로 합니다.",
            "암호·토큰처럼 임의 형식으로 숨은 값은 자동 탐지 보증 대상이 아닙니다.",
            "공유 전 익명화 보고서와 샘플 파일을 사람이 한 번 더 검토해야 합니다.",
        ],
        "format_metadata": format_metadata,
    }
    return {"filename": output_name, "content": sanitized, "report": report, "compatibility": compatibility}


def build_scanner_collection_bundle(
    content: bytes,
    *,
    filename: str,
    format_hint: str = "auto",
    profile: str = "compatibility",
) -> tuple[bytes, dict[str, Any]]:
    result = anonymize_scanner_file(
        content, filename=filename, format_hint=format_hint, profile=profile,
    )
    readme = """VulnFlow scanner compatibility collection bundle

This archive contains only an anonymized scanner sample and generated reports.
It does not contain the original filename, source-to-alias mapping, or original file.
Review the anonymization report and sanitized sample before sharing.
READY/REVIEW describes parser compatibility, not vendor certification.
"""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr(f"sample/{result['filename']}", result["content"])
        archive.writestr(
            "reports/anonymization.json",
            json.dumps(result["report"], ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
        archive.writestr(
            "reports/compatibility.json",
            json.dumps(result["compatibility"], ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
        archive.writestr("README.txt", readme)
    bundle = output.getvalue()
    summary = {
        "bundle_filename": "vulnflow-scanner-collection-bundle.zip",
        "bundle_bytes": len(bundle),
        "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        "sample_filename": result["filename"],
        "profile": profile,
        "compatibility_status": result["compatibility"]["status"],
        "importable_rows": result["compatibility"]["importable_rows"],
        "source_identifier_tokens_replaced": result["report"]["source_identifier_tokens_replaced"],
    }
    return bundle, summary


__all__ = ["PROFILES", "anonymize_scanner_file", "build_scanner_collection_bundle"]
