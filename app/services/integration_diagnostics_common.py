from __future__ import annotations

from dataclasses import asdict, dataclass
import time
from typing import Any


@dataclass(frozen=True, slots=True)
class DiagnosticResult:
    channel: str
    ok: bool
    stage: str
    message: str
    elapsed_ms: int
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))
