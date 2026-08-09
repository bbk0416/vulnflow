from __future__ import annotations

"""Create JSON compatibility reports for customer scanner export files."""

import argparse
import json
from pathlib import Path
import sys
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.settings import MAX_IMPORT_UPLOAD_BYTES  # noqa: E402
from app.services.scanner_compatibility import (  # noqa: E402
    build_scanner_compatibility_report,
    evaluate_scanner_file,
)


def inspect_content(
    content: bytes,
    *,
    filename: str,
    format_hint: str = "auto",
) -> dict[str, Any]:
    if len(content) > MAX_IMPORT_UPLOAD_BYTES:
        raise ValueError(
            f"가져오기 파일은 최대 {MAX_IMPORT_UPLOAD_BYTES // (1024 * 1024)}MB입니다."
        )
    evaluation = evaluate_scanner_file(
        content, filename=filename, format_hint=format_hint,
    )
    report = build_scanner_compatibility_report(evaluation, filename=filename)
    report["bytes"] = len(content)
    return report


def inspect_file(path: Path, *, format_hint: str = "auto") -> dict[str, Any]:
    content = path.read_bytes()
    report = inspect_content(content, filename=path.name, format_hint=format_hint)
    report["path"] = str(path.resolve())
    return report


def _text(reports: list[dict[str, Any]]) -> str:
    lines = ["VulnFlow scanner compatibility report", ""]
    for report in reports:
        lines.extend([
            f"[{report['status']}] {report['filename']}",
            f"  format: {report['detected_format']}",
            f"  source/importable/unsupported/errors: "
            f"{report['source_items']}/{report['importable_rows']}/"
            f"{report['unsupported_source_items']}/{report['error_count']}",
            f"  conclusion: {report['conclusion']}",
        ])
    return "\n".join(lines) + "\n"




def _console_write(text: str, *, stream: Any) -> None:
    """Write CLI text without crashing on legacy Windows console encodings."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        rendered = text.encode(encoding).decode(encoding)
    except (LookupError, UnicodeEncodeError):
        try:
            rendered = text.encode(encoding, errors="backslashreplace").decode(encoding)
        except LookupError:
            rendered = text.encode("ascii", errors="backslashreplace").decode("ascii")
    stream.write(rendered)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--format", default="auto", choices=("auto", "csv", "xlsx", "nessus", "openvas"))
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()

    reports: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for path in args.files:
        try:
            reports.append(inspect_file(path, format_hint=args.format))
        except (OSError, ValueError) as exc:
            failures.append({"path": str(path), "error": str(exc)})

    result = {
        "format": "vulnflow-scanner-compatibility-batch/1",
        "reports": reports,
        "failures": failures,
        "summary": {
            "files": len(args.files),
            "ready": sum(1 for item in reports if item["status"] == "READY"),
            "review": sum(1 for item in reports if item["status"] == "REVIEW"),
            "blocked": sum(1 for item in reports if item["status"] == "BLOCKED") + len(failures),
        },
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    _console_write(_text(reports), stream=sys.stdout)
    for failure in failures:
        _console_write(f"[BLOCKED] {failure['path']}: {failure['error']}\n", stream=sys.stderr)
    if failures:
        return 2
    if args.require_ready and any(item["status"] != "READY" for item in reports):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
