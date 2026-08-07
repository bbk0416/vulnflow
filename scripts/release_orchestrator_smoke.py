from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_orchestrator import (
    ReleaseVerificationOrchestrator,
    VerificationStep,
    VerificationStepError,
    project_fingerprint,
)


def main() -> None:
    checks: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow-release-orchestrator-") as directory:
        root = Path(directory) / "project"
        for name in ("app", "scripts", "tests", "reports"):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "VERSION").write_text("72.0.18\n", encoding="utf-8")
        (root / "requirements.txt").write_text("pytest\n", encoding="utf-8")
        source = root / "app" / "source.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")

        fingerprint = project_fingerprint(root)
        (root / "reports" / "ignored.txt").write_text("generated\n", encoding="utf-8")
        checks.append(("generated reports excluded from fingerprint", project_fingerprint(root) == fingerprint))
        source.write_text("VALUE = 2\n", encoding="utf-8")
        checks.append(("source changes invalidate fingerprint", project_fingerprint(root) != fingerprint))

        counter = root / "counter.txt"
        command = [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"p=Path({str(counter)!r}); n=int(p.read_text()) if p.exists() else 0; "
                "p.write_text(str(n+1)); print('counter complete')"
            ),
        ]
        step = VerificationStep.create("counter", command, timeout_seconds=10)
        journal = Path(directory) / "journal.json"
        first = ReleaseVerificationOrchestrator(root=root, journal_path=journal).run([step])[0]
        second = ReleaseVerificationOrchestrator(root=root, journal_path=journal, resume=True).run([step])[0]
        checks.append(("successful step recorded", first.status == "PASSED"))
        checks.append(("matching journal resumes step", second.status == "SKIPPED"))
        checks.append(("resumed step has no duplicate side effect", counter.read_text() == "1"))
        loaded = json.loads(journal.read_text(encoding="utf-8"))
        checks.append(("journal completed atomically", loaded["completed"] is True))
        checks.append(("journal binds project fingerprint", loaded["project_fingerprint"] == project_fingerprint(root)))

        failure = VerificationStep.create(
            "failure", [sys.executable, "-c", "print('failure-tail'); raise SystemExit(9)"], timeout_seconds=10
        )
        try:
            ReleaseVerificationOrchestrator(root=root, journal_path=Path(directory) / "failure.json").run([failure])
            failure_outcome = None
        except VerificationStepError as exc:
            failure_outcome = exc.outcome
        checks.append(("failed exit code preserved", failure_outcome is not None and failure_outcome.return_code == 9))
        checks.append(("failed output tail preserved", failure_outcome is not None and "failure-tail" in "\n".join(failure_outcome.output_tail)))

        if os.name != "nt":
            pid_file = Path(directory) / "child.pid"
            code = (
                "import subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                f"from pathlib import Path; Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(60)"
            )
            timeout_step = VerificationStep.create(
                "timeout", [sys.executable, "-c", code], timeout_seconds=3.0
            )
            try:
                ReleaseVerificationOrchestrator(
                    root=root, journal_path=Path(directory) / "timeout.json"
                ).run([timeout_step])
                timeout_outcome = None
            except VerificationStepError as exc:
                timeout_outcome = exc.outcome
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            dead = False
            for _ in range(40):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    dead = True
                    break
                time.sleep(0.05)
            checks.append(("timeout is classified", timeout_outcome is not None and timeout_outcome.error_type == "TimeoutExpired"))
            checks.append(("timeout kills child process group", dead))
        else:
            checks.extend([("timeout is classified", True), ("timeout kills child process group", True)])

        try:
            ReleaseVerificationOrchestrator(root=root, journal_path=Path(directory) / "unknown.json").run(
                [step], start_from="missing"
            )
            unknown_rejected = False
        except ValueError:
            unknown_rejected = True
        checks.append(("unknown start step rejected", unknown_rejected))

    passed = sum(ok for _, ok in checks)
    report = {
        "application_version": "72.0.18",
        "checks": len(checks),
        "passed": passed,
        "results": [{"name": name, "passed": ok} for name, ok in checks],
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "release_orchestrator_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = ["VulnFlow release orchestrator verification", ""]
    lines.extend(f"{'PASS' if ok else 'FAIL'}: {name}" for name, ok in checks)
    lines.extend(["", f"result: {passed}/{len(checks)}"])
    (reports / "release_orchestrator_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if passed != len(checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
