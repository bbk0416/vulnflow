"""Owner-isolated temporary preview storage for finding imports."""
from __future__ import annotations

import gzip
import json
import os
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

def create_preview_session(
    directory: str | Path,
    *,
    content: bytes,
    filename: str,
    format_hint: str,
    actor: str,
    ttl_seconds: int,
    max_sessions: int = 20,
) -> str:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    prune_preview_sessions(root, ttl_seconds=ttl_seconds, max_sessions=max_sessions - 1)
    token = secrets.token_urlsafe(32)
    session_dir = root / token
    session_dir.mkdir(mode=0o700)
    metadata = {
        "filename": Path(filename or "upload").name,
        "format_hint": str(format_hint or "auto"),
        "actor": str(actor),
        "created_at": int(time.time()),
        "size": len(content),
    }
    payload_path = session_dir / "payload.bin"
    metadata_path = session_dir / "metadata.json.gz"
    payload_path.write_bytes(content)
    with gzip.open(metadata_path, "wt", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, sort_keys=True)
    try:
        os.chmod(payload_path, 0o600)
        os.chmod(metadata_path, 0o600)
    except OSError:
        pass
    return token

def _session_directory(root: Path, token: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", str(token or "")):
        raise KeyError("가져오기 미리보기를 찾을 수 없습니다.")
    candidate = (root / token).resolve()
    resolved_root = root.resolve()
    if candidate.parent != resolved_root:
        raise KeyError("가져오기 미리보기를 찾을 수 없습니다.")
    return candidate

def load_preview_session(
    directory: str | Path,
    token: str,
    *,
    actor: str,
    ttl_seconds: int,
) -> tuple[dict[str, Any], bytes]:
    root = Path(directory)
    session_dir = _session_directory(root, token)
    metadata_path = session_dir / "metadata.json.gz"
    payload_path = session_dir / "payload.bin"
    if not metadata_path.is_file() or not payload_path.is_file():
        raise KeyError("가져오기 미리보기가 만료되었거나 존재하지 않습니다.")
    with gzip.open(metadata_path, "rt", encoding="utf-8") as handle:
        metadata = json.load(handle)
    if int(time.time()) - int(metadata.get("created_at") or 0) > ttl_seconds:
        delete_preview_session(root, token)
        raise KeyError("가져오기 미리보기가 만료되었습니다. 파일을 다시 선택하세요.")
    if str(metadata.get("actor") or "") != str(actor):
        raise PermissionError("다른 사용자의 가져오기 미리보기에는 접근할 수 없습니다.")
    content = payload_path.read_bytes()
    if len(content) != int(metadata.get("size") or -1):
        delete_preview_session(root, token)
        raise ValueError("임시 업로드 파일 크기가 변경되었습니다.")
    return metadata, content

def delete_preview_session(directory: str | Path, token: str) -> None:
    root = Path(directory)
    try:
        session_dir = _session_directory(root, token)
    except KeyError:
        return
    shutil.rmtree(session_dir, ignore_errors=True)

def prune_preview_sessions(directory: str | Path, *, ttl_seconds: int, max_sessions: int = 20) -> int:
    root = Path(directory)
    if not root.exists():
        return 0
    now = int(time.time())
    sessions: list[tuple[int, Path]] = []
    removed = 0
    for candidate in root.iterdir():
        if not candidate.is_dir():
            continue
        created_at = int(candidate.stat().st_mtime)
        metadata_path = candidate / "metadata.json.gz"
        try:
            with gzip.open(metadata_path, "rt", encoding="utf-8") as handle:
                created_at = int(json.load(handle).get("created_at") or created_at)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        if now - created_at > ttl_seconds:
            shutil.rmtree(candidate, ignore_errors=True)
            removed += 1
        else:
            sessions.append((created_at, candidate))
    sessions.sort(reverse=True)
    for _, candidate in sessions[max(0, max_sessions):]:
        shutil.rmtree(candidate, ignore_errors=True)
        removed += 1
    return removed

