from __future__ import annotations

import csv
import io
import json
import statistics
import sys
import tempfile
import tracemalloc
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import FIELDS, list_findings
from app.services.exports import create_findings_csv_export, verify_export_artifact
from scripts.query_performance_smoke import N, _seed


def _measure_legacy(db: Path) -> dict[str, float | int]:
    tracemalloc.start()
    started = perf_counter()
    rows = list_findings(db)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    elapsed = perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    size = len(output.getvalue().encode("utf-8"))
    return {
        "rows": len(rows),
        "seconds": round(elapsed, 3),
        "peak_mib": round(peak / 1024 / 1024, 3),
        "size_bytes": size,
    }


def _measure_snapshot(db: Path, export_dir: Path) -> tuple[dict[str, float | int | str], dict]:
    tracemalloc.start()
    started = perf_counter()
    artifact = create_findings_csv_export(
        db,
        export_dir,
        filters={"record_state": "ALL"},
        actor="export-performance-smoke",
        retention_days=1,
    )
    elapsed = perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    verification = verify_export_artifact(export_dir, artifact)
    return (
        {
            "rows": int(artifact["row_count"]),
            "seconds": round(elapsed, 3),
            "peak_mib": round(peak / 1024 / 1024, 3),
            "size_bytes": int(artifact["size_bytes"]),
            "sha256": str(artifact["sha256"]),
        },
        verification,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow-export-perf-") as td:
        root = Path(td)
        db = root / "performance.sqlite3"
        export_dir = root / "exports"
        seed_ms = _seed(db)
        snapshot, verification = _measure_snapshot(db, export_dir)
        legacy = _measure_legacy(db)

        assert snapshot["rows"] == legacy["rows"] == N
        assert verification["valid"] is True
        assert snapshot["peak_mib"] < legacy["peak_mib"]
        assert snapshot["size_bytes"] > 0
        memory_reduction = 1.0 - (float(snapshot["peak_mib"]) / float(legacy["peak_mib"]))
        payload = {
            "dataset_rows": N,
            "seed_ms": round(seed_ms, 3),
            "snapshot_export": snapshot,
            "legacy_materialize": legacy,
            "peak_memory_reduction_percent": round(memory_reduction * 100, 2),
            "artifact_verification": {
                "valid": bool(verification["valid"]),
                "actual_sha256": verification["actual_sha256"],
                "actual_size_bytes": int(verification["actual_size_bytes"]),
            },
            "scope": "synthetic local SQLite snapshot-export verification; not production throughput or SLA evidence",
        }

    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "export_snapshot_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "VulnFlow 72.0.98 snapshot export verification",
        f"Synthetic findings: {payload['dataset_rows']}",
        f"Snapshot CSV rows: {snapshot['rows']}",
        f"Snapshot CSV bytes: {snapshot['size_bytes']}",
        f"Snapshot export time: {snapshot['seconds']:.3f} s",
        f"Snapshot export tracemalloc peak: {snapshot['peak_mib']:.3f} MiB",
        f"Legacy materialize time: {legacy['seconds']:.3f} s",
        f"Legacy materialize tracemalloc peak: {legacy['peak_mib']:.3f} MiB",
        f"Peak Python allocation reduction: {payload['peak_memory_reduction_percent']:.2f}%",
        f"Artifact SHA-256 verification: {'PASS' if verification['valid'] else 'FAIL'}",
        "Limit: synthetic local SQLite measurement; not a production SLA or maximum-capacity benchmark.",
    ]
    (reports / "export_snapshot_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
