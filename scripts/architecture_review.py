from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.architecture import write_architecture_report



def main() -> None:
    report = write_architecture_report(
        ROOT,
        ROOT / "reports" / "architecture_review.txt",
        ROOT / "reports" / "architecture_review.json",
    )
    print((ROOT / "reports" / "architecture_review.txt").read_text(encoding="utf-8"), end="")
    if report["violations"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
