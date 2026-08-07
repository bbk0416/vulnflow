from __future__ import annotations

"""Fail when concurrent application assembly emits Pydantic field warnings."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import gc
import sys
import tempfile
import warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--rounds", type=int, default=12)
    args = parser.parse_args()
    project_root = args.project_root.resolve()
    if args.rounds < 2:
        raise ValueError("rounds must be at least 2")
    sys.path.insert(0, str(project_root))

    from pydantic.warnings import UnsupportedFieldAttributeWarning
    from app.core.context import get_application_context
    from app.effective_routes import effective_api_routes
    from app.routers import release_runtime_application
    from tests.test_context_router_di_v126 import _application

    warnings.simplefilter("error", UnsupportedFieldAttributeWarning)
    with tempfile.TemporaryDirectory(prefix="vulnflow-warning-gate-") as temporary:
        root = Path(temporary)
        warmup = _application(root / "warmup")
        if len(effective_api_routes(warmup)) != 276:
            raise AssertionError("warmup effective route count is not 276")
        del warmup
        gc.collect()

        for round_index in range(args.rounds):
            with ThreadPoolExecutor(max_workers=2) as executor:
                applications = tuple(
                    executor.map(
                        lambda label: _application(root / f"round-{round_index}-{label}"),
                        ("alpha", "beta"),
                    )
                )
            try:
                counts = tuple(len(effective_api_routes(app)) for app in applications)
                if counts != (276, 276):
                    raise AssertionError(
                        f"round {round_index}: effective route counts were {counts}, expected (276, 276)"
                    )
            finally:
                for application in applications:
                    release_runtime_application(get_application_context(application))
                del applications
                gc.collect()

    print(f"CONCURRENT_APP_BUILD_WARNING_GATE=PASS rounds={args.rounds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
