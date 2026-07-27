from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import CURRENT_APP_VERSION


def main() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    manifest = json.loads((ROOT / "reports/release_manifest.json").read_text(encoding="utf-8"))
    base = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
    main_text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    osv = (ROOT / "app/services/osv.py").read_text(encoding="utf-8")
    evidence = (ROOT / "app/services/evidence.py").read_text(encoding="utf-8")
    full_pytest = (ROOT / "reports/full_pytest_verification.txt").read_text(encoding="utf-8")
    full_ci = ROOT / ".github/workflows/full-release.yml"
    coverage_script = ROOT / "scripts/coverage_verification.py"
    checks = [
        ("canonical_version", version == CURRENT_APP_VERSION == str(manifest.get("version"))),
        ("dynamic_template_version", "{{ app_version }}" in base),
        ("stale_ui_version_absent", "<span>44.0</span>" not in base),
        ("template_global", 'templates.env.globals["app_version"] = CURRENT_APP_VERSION' in main_text),
        ("dynamic_osv_user_agent", 'f"VulnFlow/{CURRENT_APP_VERSION}"' in osv and "VulnFlow/21.0" not in osv),
        ("runtime_lock_header", (ROOT / "requirements.lock").read_text().startswith(f"# VulnFlow {version}")),
        ("dev_lock_header", (ROOT / "requirements-dev.lock").read_text().startswith(f"# VulnFlow {version}")),
        ("current_pytest_report", f"VulnFlow {version} full pytest verification" in full_pytest),
        ("pytest_count", f"{manifest['tests']['passed']} passed" in full_pytest),
        ("baseline_not_clean", '"BASELINE_ONLY"' in evidence),
        ("full_ci_workflow", full_ci.exists() and "verify_release.py --full" in full_ci.read_text()),
        ("coverage_workflow", coverage_script.exists() and full_ci.exists() and "coverage_verification.py" in full_ci.read_text()),
    ]
    failed = [name for name, passed in checks if not passed]
    lines = [f"VulnFlow {version} submission readiness verification", ""]
    lines.extend(f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks)
    lines.extend(["", f"passed: {len(checks)-len(failed)}/{len(checks)}"])
    output = "\n".join(lines) + "\n"
    (ROOT / "reports/submission_readiness_verification.txt").write_text(output, encoding="utf-8")
    print(output, end="")
    if failed:
        raise SystemExit("submission readiness failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
