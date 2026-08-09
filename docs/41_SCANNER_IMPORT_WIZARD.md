# Scanner Import Wizard

## Purpose

The guided import workflow reduces the spreadsheet preprocessing required before findings enter VulnFlow. It accepts selected scanner exports and generic tabular files, shows the normalized result before mutation, and keeps full-snapshot reconciliation fail-closed.

## Supported formats

| Format | Detection | Notes |
|---|---|---|
| Nessus `.nessus` | XML root and report structure | Expands CVEs, supports CPE 2.2/2.3 and CVSS v4 fields, and preserves host UUID/plugin/service context |
| OpenVAS/Greenbone CSV | Header signatures | Maps host, port, CVE/NVT, severity, product and description where present |
| OpenVAS/Greenbone XML | XML report/result structure | Supports CVE text and `<ref type="cve" id="…">` references; rejects unsafe or excessive XML structure |
| Generic CSV | Delimiter and encoding detection | Supports UTF-8 variants plus CP949/EUC-KR fallback |
| Excel `.xlsx` | ZIP/XLSX structure | Reads the first non-empty worksheet in read-only mode |

The adapters normalize source rows into VulnFlow's canonical finding fields. They do not certify that every scanner version or customized export template is supported.

## Workflow

```text
파일 선택
  → 형식 자동 판별
  → 원본 열·정규화 결과 미리보기
  → 자동 매핑 확인 또는 수정
  → 행별 오류 검토·다운로드
  → 최종 반영
```

Preview sessions are bound to the authenticated actor. Recheck, error download, and apply operations reject another actor's session. Sessions expire after `VULNFLOW_IMPORT_PREVIEW_TTL_SECONDS` and are stored under `VULNFLOW_IMPORT_PREVIEW_DIR`, outside static web content.

## Snapshot safety

An incremental import changes only findings represented by accepted rows. When some rows are invalid, an operator may explicitly apply valid rows only and download the failures for correction.

A full snapshot also treats missing findings as lifecycle information. Therefore VulnFlow rejects partial full-snapshot application: one invalid or skipped row could otherwise make a still-present finding appear absent and mark it stale or archived.

## Limits

- Default upload maximum: 20 MiB; configurable from 1 to 100 MiB.
- Canonical normalized rows remain subject to the existing row and field-length limits.
- XLSX archive metadata is checked before workbook parsing to reduce decompression abuse.
- XML DTD and entity declarations are not supported. XML is also bounded to 128 levels, 250,000 elements, 16 MiB of text, 256 attributes per element, and the configured upload size.
- Macro-enabled Excel files and legacy `.xls` files are not accepted.
- Scanner-specific parser behavior is covered by 9 synthetic regression files and 6 deterministic robustness mutations, not vendor certification.

## Operations

Temporary previews should be placed on the same protected local storage boundary as the application database. They must not be exposed by a reverse proxy, included in public artifacts, or treated as long-term scanner-file retention. Successful application removes the preview. Expired sessions are pruned during subsequent preview activity.

## Parser robustness contract

```bash
python scripts/scanner_fixture_matrix.py --json-output reports/scanner_fixture_matrix.json
python scripts/scanner_parser_robustness.py --json-output reports/scanner_parser_robustness.json
```

The robustness matrix checks UTF-8 BOM extensionless XML, Nessus CPE 2.2/CVSS4 extraction, duplicate canonical rows, blocked DTD/entity declarations, excessive XML depth, and truncated XML. Compatibility reports expose parser warnings and duplicate counts instead of silently treating those conditions as clean imports.
