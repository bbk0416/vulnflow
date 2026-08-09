from __future__ import annotations

"""Create an anonymized scanner sample bundle for compatibility triage."""

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.settings import MAX_IMPORT_UPLOAD_BYTES  # noqa: E402
from app.services.scanner_anonymization import build_scanner_collection_bundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--output", type=Path, default=Path("vulnflow-scanner-collection-bundle.zip"))
    parser.add_argument("--format-hint", default="auto", choices=("auto", "csv", "xlsx", "nessus", "openvas"))
    parser.add_argument("--profile", default="compatibility", choices=("compatibility", "strict"))
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error(f"file not found: {args.file}")
    if args.file.stat().st_size > MAX_IMPORT_UPLOAD_BYTES:
        parser.error(f"file exceeds {MAX_IMPORT_UPLOAD_BYTES // (1024 * 1024)}MB limit")
    try:
        bundle, summary = build_scanner_collection_bundle(
            args.file.read_bytes(), filename=args.file.name,
            format_hint=args.format_hint, profile=args.profile,
        )
    except ValueError as exc:
        print(f"scanner collection bundle: FAIL: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bundle)
    print(f"scanner collection bundle: PASS ({summary['compatibility_status']})")
    print(f"sample: {summary['sample_filename']}")
    print(f"importable_rows: {summary['importable_rows']}")
    print(f"identifiers_replaced: {summary['source_identifier_tokens_replaced']}")
    print(f"output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
