from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

JOURNAL_VERSION = 1
DEFAULT_TAIL_LINES = 80
FINGERPRINT_ROOTS = ("app", "scripts", "tests", "rules", "docs")
FINGERPRINT_FILES = (
    "VERSION",
    "requirements.txt",
    "Dockerfile",
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "bom.cdx.json",
    ".env.example",
)
IGNORED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".git",
    ".venv",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _fingerprint_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for name in FINGERPRINT_FILES:
        path = root / name
        if path.is_file():
            paths.append(path)
    for name in FINGERPRINT_ROOTS:
        base = root / name
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if any(part in IGNORED_PARTS for part in relative.parts):
                continue
            if path.suffix in {".pyc", ".db", ".sqlite", ".sqlite3"} or path.name.endswith(("-wal", "-shm")):
                continue
            paths.append(path)
    return sorted(set(paths), key=lambda item: item.relative_to(root).as_posix())


def project_fingerprint(root: str | Path) -> str:
    root_path = Path(root).resolve()
    digest = hashlib.sha256()
    for path in _fingerprint_paths(root_path):
        relative = path.relative_to(root_path).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


@dataclass(frozen=True)
class VerificationStep:
    name: str
    command: tuple[str, ...]
    timeout_seconds: float = 240.0
    required: bool = True

    @classmethod
    def create(
        cls,
        name: str,
        command: Sequence[str],
        *,
        timeout_seconds: float = 240.0,
        required: bool = True,
    ) -> "VerificationStep":
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("verification step name is required")
        normalized_command = tuple(str(item) for item in command)
        if not normalized_command:
            raise ValueError("verification command is required")
        if timeout_seconds <= 0:
            raise ValueError("verification timeout must be positive")
        return cls(
            name=normalized_name,
            command=normalized_command,
            timeout_seconds=float(timeout_seconds),
            required=bool(required),
        )

    def signature(self) -> str:
        return sha256_text(
            canonical_json(
                {
                    "name": self.name,
                    "command": list(self.command),
                    "timeout_seconds": self.timeout_seconds,
                    "required": self.required,
                }
            )
        )


@dataclass
class VerificationOutcome:
    name: str
    status: str
    command: list[str]
    command_signature: str
    started_at: str
    completed_at: str
    duration_ms: float
    return_code: int | None
    output_tail: list[str]
    error_type: str | None = None
    skipped_from_journal: bool = False


class VerificationStepError(RuntimeError):
    def __init__(self, outcome: VerificationOutcome):
        self.outcome = outcome
        summary = "\n".join(outcome.output_tail[-20:])
        super().__init__(f"verification step failed: {outcome.name}\n{summary}".rstrip())


class ReleaseVerificationOrchestrator:
    def __init__(
        self,
        *,
        root: str | Path,
        journal_path: str | Path,
        resume: bool = False,
        env: Mapping[str, str] | None = None,
        tail_lines: int = DEFAULT_TAIL_LINES,
    ) -> None:
        self.root = Path(root).resolve()
        self.journal_path = Path(journal_path)
        if not self.journal_path.is_absolute():
            self.journal_path = self.root / self.journal_path
        self.resume = bool(resume)
        self.tail_lines = max(1, int(tail_lines))
        self.env = os.environ.copy()
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        if env:
            self.env.update({str(key): str(value) for key, value in env.items()})
        self.fingerprint = project_fingerprint(self.root)
        self._active_process: subprocess.Popen[str] | None = None
        self._previous_handlers: dict[int, object] = {}
        self.journal = self._load_or_create_journal()

    def _new_journal(self) -> dict[str, object]:
        now = utc_now()
        return {
            "journal_version": JOURNAL_VERSION,
            "project_fingerprint": self.fingerprint,
            "root_name": self.root.name,
            "created_at": now,
            "updated_at": now,
            "completed": False,
            "steps": {},
        }

    def _load_or_create_journal(self) -> dict[str, object]:
        if not self.resume or not self.journal_path.exists():
            return self._new_journal()
        try:
            loaded = json.loads(self.journal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._new_journal()
        if loaded.get("journal_version") != JOURNAL_VERSION:
            return self._new_journal()
        if loaded.get("project_fingerprint") != self.fingerprint:
            return self._new_journal()
        if not isinstance(loaded.get("steps"), dict):
            return self._new_journal()
        loaded["completed"] = False
        loaded["updated_at"] = utc_now()
        return loaded

    def _persist(self) -> None:
        self.journal["updated_at"] = utc_now()
        atomic_write_json(self.journal_path, self.journal)

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen[str], *, grace_seconds: float = 3.0) -> None:
        if process.poll() is not None:
            return
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            try:
                process.wait(timeout=grace_seconds)
                return
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    return
        else:
            process.terminate()
            try:
                process.wait(timeout=grace_seconds)
                return
            except subprocess.TimeoutExpired:
                process.kill()
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass

    def _signal_handler(self, signum: int, _frame: object) -> None:
        process = self._active_process
        if process is not None:
            self._terminate_process_group(process)
        raise SystemExit(128 + signum)

    def _install_signal_handlers(self) -> None:
        if os.name == "nt":
            return
        for signum in (signal.SIGINT, signal.SIGTERM):
            self._previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._signal_handler)

    def _restore_signal_handlers(self) -> None:
        for signum, handler in self._previous_handlers.items():
            signal.signal(signum, handler)
        self._previous_handlers.clear()

    def _cached_outcome(self, step: VerificationStep) -> VerificationOutcome | None:
        if not self.resume:
            return None
        record = (self.journal.get("steps") or {}).get(step.name)
        if not isinstance(record, dict):
            return None
        if record.get("status") != "PASSED":
            return None
        if record.get("command_signature") != step.signature():
            return None
        return VerificationOutcome(
            name=step.name,
            status="SKIPPED",
            command=list(step.command),
            command_signature=step.signature(),
            started_at=utc_now(),
            completed_at=utc_now(),
            duration_ms=0.0,
            return_code=0,
            output_tail=list(record.get("output_tail") or []),
            skipped_from_journal=True,
        )

    def run_step(self, step: VerificationStep) -> VerificationOutcome:
        cached = self._cached_outcome(step)
        if cached is not None:
            print(f"= {step.name}: resumed from verified journal")
            return cached

        print("+", step.name, "::", " ".join(step.command), flush=True)
        started_at = utc_now()
        started = time.perf_counter()
        return_code: int | None = None
        error_type: str | None = None
        lines: list[str] = []

        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
            process = subprocess.Popen(
                list(step.command),
                cwd=self.root,
                env=self.env,
                stdout=output,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=(os.name != "nt"),
            )
            self._active_process = process
            try:
                return_code = process.wait(timeout=step.timeout_seconds)
            except subprocess.TimeoutExpired:
                error_type = "TimeoutExpired"
                self._terminate_process_group(process)
                return_code = process.poll()
            finally:
                self._active_process = None
                output.seek(0)
                lines = output.read().splitlines()

        completed_at = utc_now()
        duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
        status = "PASSED" if return_code == 0 and error_type is None else "FAILED"
        outcome = VerificationOutcome(
            name=step.name,
            status=status,
            command=list(step.command),
            command_signature=step.signature(),
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            return_code=return_code,
            output_tail=lines[-self.tail_lines :],
            error_type=error_type,
        )
        steps = self.journal.setdefault("steps", {})
        assert isinstance(steps, dict)
        steps[step.name] = asdict(outcome)
        self._persist()

        if lines:
            print("\n".join(lines[-40:]))
        if status != "PASSED" and step.required:
            raise VerificationStepError(outcome)
        return outcome

    def run(
        self,
        steps: Iterable[VerificationStep],
        *,
        only: set[str] | None = None,
        start_from: str | None = None,
    ) -> list[VerificationOutcome]:
        selected: list[VerificationStep] = []
        reached_start = start_from is None
        for step in steps:
            if not reached_start:
                reached_start = step.name == start_from
                if not reached_start:
                    continue
            if only is not None and step.name not in only:
                continue
            selected.append(step)
        if start_from is not None and not reached_start:
            raise ValueError(f"unknown verification step: {start_from}")

        self._install_signal_handlers()
        outcomes: list[VerificationOutcome] = []
        try:
            for step in selected:
                outcomes.append(self.run_step(step))
            self.journal["completed"] = all(
                outcome.status in {"PASSED", "SKIPPED"} for outcome in outcomes
            )
            self._persist()
            return outcomes
        finally:
            process = self._active_process
            if process is not None:
                self._terminate_process_group(process)
                self._active_process = None
            self._restore_signal_handlers()


def summarize_outcomes(outcomes: Sequence[VerificationOutcome]) -> dict[str, object]:
    return {
        "total": len(outcomes),
        "passed": sum(outcome.status == "PASSED" for outcome in outcomes),
        "skipped": sum(outcome.status == "SKIPPED" for outcome in outcomes),
        "failed": sum(outcome.status == "FAILED" for outcome in outcomes),
        "duration_ms": round(sum(outcome.duration_ms for outcome in outcomes), 3),
        "steps": [asdict(outcome) for outcome in outcomes],
    }
