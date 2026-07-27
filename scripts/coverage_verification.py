from __future__ import annotations

"""Measure application line coverage using bounded, isolated pytest groups."""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
FAIL_UNDER = 75.0
GROUP_COUNT = 6
GROUP_TIMEOUT_SECONDS = 900


def _env(runtime_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "1",
        "VULNFLOW_DB": str(runtime_root / "vulnflow.db"),
        "VULNFLOW_COORDINATION_DB": str(runtime_root / "coordination.db"),
        "VULNFLOW_EVIDENCE_DIR": str(runtime_root / "evidence"),
        "VULNFLOW_EXPORT_DIR": str(runtime_root / "exports"),
        "VULNFLOW_RECOVERY_DIR": str(runtime_root / "recovery"),
        "VULNFLOW_INSTANCE_ID": f"coverage-{runtime_root.name}",
    })
    return env


def _completed(output: str) -> bool:
    return bool(re.search(r"\d+ passed", output)) and not bool(re.search(r"\d+ failed", output))


def _stop_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name != "nt":
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def _run_group(files: list[str], index: int, runtime_root: Path) -> dict[str, object]:
    output = REPORTS / f"coverage_pytest_group_{index}.txt"
    command = [
        sys.executable, "-m", "coverage", "run", "--parallel-mode",
        "--save-signal=USR1", "--source=app", "-m", "pytest", "-q",
        "-p", "no:cacheprovider", *files,
    ]
    with output.open("w", encoding="utf-8") as handle:
        process = subprocess.Popen(
            command, cwd=ROOT, env=_env(runtime_root), text=True,
            stdout=handle, stderr=subprocess.STDOUT,
            start_new_session=(os.name != "nt"),
        )
    forced = False
    deadline = time.monotonic() + GROUP_TIMEOUT_SECONDS
    captured = ""
    while time.monotonic() < deadline:
        time.sleep(1.0)
        captured = output.read_text(encoding="utf-8")
        if _completed(captured):
            if process.poll() is None:
                if os.name == "nt":
                    _stop_group(process)
                    raise RuntimeError("pytest completed but coverage process did not exit on Windows")
                os.kill(process.pid, signal.SIGUSR1)
                time.sleep(1.0)
                _stop_group(process)
                forced = True
            break
        code = process.poll()
        if code is not None:
            if code != 0:
                raise RuntimeError(f"coverage group {index} failed ({code})\n{captured[-6000:]}")
            raise RuntimeError(f"coverage group {index} exited without a pytest pass summary\n{captured[-4000:]}")
    else:
        _stop_group(process)
        raise RuntimeError(f"coverage group {index} timed out\n{captured[-4000:]}")
    lines = [line for line in captured.splitlines() if line.strip()]
    return {"group": index, "files": len(files), "summary": lines[-1] if lines else "", "forced_cleanup": forced}


def _capture(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(result.stdout[-6000:])
    return result.stdout


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    for path in ROOT.glob(".coverage*"):
        if path.is_file(): path.unlink()
    files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("test_*.py"))
    groups = [files[offset::GROUP_COUNT] for offset in range(GROUP_COUNT)]
    results=[]
    with tempfile.TemporaryDirectory(prefix="vulnflow-coverage-") as temporary:
        base=Path(temporary)
        for index, group in enumerate(groups, 1):
            runtime=base/f"group-{index}"; runtime.mkdir()
            result=_run_group(group,index,runtime)
            results.append(result)
            print(f"coverage group {index}/{GROUP_COUNT}: {result['summary']}", flush=True)
    _capture([sys.executable,"-m","coverage","combine"])
    report=_capture([sys.executable,"-m","coverage","report","--show-missing",f"--fail-under={FAIL_UNDER}"])
    (REPORTS/"coverage_verification.txt").write_text(report,encoding="utf-8")
    _capture([sys.executable,"-m","coverage","json","-o","reports/coverage.json"])
    _capture([sys.executable,"-m","coverage","xml","-o","reports/coverage.xml"])
    payload=json.loads((REPORTS/"coverage.json").read_text())
    totals=payload["totals"]
    summary={
        "format":"vulnflow-coverage-verification/1",
        "version":(ROOT/"VERSION").read_text().strip(),
        "test_files":len(files), "groups":results,
        "statements":int(totals["num_statements"]),
        "covered_lines":int(totals["covered_lines"]),
        "missing_lines":int(totals["missing_lines"]),
        "line_coverage_percent":float(totals["percent_covered"]),
        "fail_under_percent":FAIL_UNDER,
        "passed":float(totals["percent_covered"])>=FAIL_UNDER,
    }
    (REPORTS/"coverage_verification_summary.json").write_text(json.dumps(summary,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
    (REPORTS/"coverage_verification_summary.txt").write_text(
        f"VulnFlow {summary['version']} coverage verification\n\n"
        f"test_files: {summary['test_files']}\nstatements: {summary['statements']}\n"
        f"covered_lines: {summary['covered_lines']}\nmissing_lines: {summary['missing_lines']}\n"
        f"line_coverage_percent: {summary['line_coverage_percent']:.2f}\n"
        f"fail_under_percent: {FAIL_UNDER:.2f}\nresult: {'PASS' if summary['passed'] else 'FAIL'}\n"
    )
    print(report.rstrip())


if __name__ == "__main__": main()
