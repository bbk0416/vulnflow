from __future__ import annotations

"""Atomic activation helpers for the signed offline deployment bootstrap.

The helper keeps the existing deployment untouched while a replacement is
built and validated in a sibling staging directory.  Only a same-filesystem
rename may publish the staged tree.  A failed post-activation verification
restores the previous tree before the exception is returned to the operator.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
from typing import Callable, Generic, Iterator, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class ActivationResult(Generic[T]):
    target: Path
    previous_target: Path | None
    verification: T


def absolute_path(path: Path) -> Path:
    """Return an absolute path without resolving symbolic links."""

    return Path(os.path.abspath(os.fspath(path)))


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_parent_directory(parent: Path) -> None:
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("deployment target parent must be a real directory")
    if os.name == "posix" and parent.stat().st_mode & 0o022:
        raise ValueError("deployment target parent must not be group- or world-writable")




@contextmanager
def deployment_operation_lock(target: Path) -> Iterator[Path]:
    """Serialize offline deployment mutations beside *target*.

    POSIX advisory locks are released automatically if the process crashes.
    The small lock file may remain on disk, but an unlocked stale file never
    blocks a future operation.
    """

    target = absolute_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _validate_parent_directory(target.parent)
    lock_path = target.parent / f".{target.name}.deployment.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RuntimeError("offline deployment lock file is unsafe or inaccessible") from exc
    try:
        if os.name != "posix":
            raise RuntimeError("offline deployment operation locking currently requires POSIX")
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("offline deployment lock must be a regular file")
        if metadata.st_mode & 0o077:
            os.fchmod(descriptor, 0o600)
        import fcntl

        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another offline deployment operation is already in progress") from exc
        payload = json.dumps({"pid": os.getpid(), "target": str(target)}, sort_keys=True) + "\n"
        os.ftruncate(descriptor, 0)
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
        yield lock_path
    finally:
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def sibling_staging_directory(target: Path) -> Path:
    """Create a private empty staging directory beside *target*.

    Keeping both paths on the same filesystem is required for atomic rename.
    """

    target = absolute_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _validate_parent_directory(target.parent)
    for _ in range(32):
        candidate = target.parent / f".{target.name}.staging-{secrets.token_hex(8)}"
        try:
            candidate.mkdir(mode=0o700)
            _fsync_directory(target.parent)
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate a unique offline deployment staging directory")


def _unique_sibling(target: Path, label: str) -> Path:
    for _ in range(32):
        candidate = target.parent / f".{target.name}.{label}-{secrets.token_hex(8)}"
        if not _lexists(candidate):
            return candidate
    raise RuntimeError(f"could not allocate a unique {label} path beside deployment target")


def remove_tree(path: Path) -> None:
    if not _lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def rollback_activated_directory(target: Path, previous_target: Path | None) -> None:
    """Remove a newly activated tree and restore the previous deployment."""

    target = absolute_path(target)
    previous = absolute_path(previous_target) if previous_target is not None else None
    failed_tree: Path | None = None
    try:
        if _lexists(target):
            failed_tree = _unique_sibling(target, "failed")
            os.replace(target, failed_tree)
            _fsync_directory(target.parent)
        if previous is not None and _lexists(previous):
            os.replace(previous, target)
            _fsync_directory(target.parent)
        if failed_tree is not None:
            remove_tree(failed_tree)
            _fsync_directory(target.parent)
    except BaseException as exc:
        raise RuntimeError("could not rollback the activated offline deployment") from exc


def activate_staged_directory(
    staging: Path,
    target: Path,
    *,
    allow_replace: bool,
    verify: Callable[[Path], T],
    restore_staging_on_failure: bool = False,
) -> ActivationResult[T]:
    """Publish *staging* at *target* and rollback on verification failure.

    On successful replacement the old deployment is intentionally retained in
    a private sibling directory.  The caller may remove it only after its own
    retention policy or an operator-approved backup has been satisfied.
    """

    staging = absolute_path(staging)
    target = absolute_path(target)
    if staging.parent != target.parent:
        raise ValueError("staging and deployment target must share the same parent directory")
    _validate_parent_directory(target.parent)
    if not staging.is_dir() or staging.is_symlink():
        raise ValueError("deployment staging path must be a real directory")
    if target == target.parent or str(target) in {"/", ""}:
        raise ValueError("refusing to activate a deployment at the filesystem root")
    if _lexists(target) and target.is_symlink():
        raise ValueError("deployment target must not be a symbolic link")
    if _lexists(target) and not target.is_dir():
        raise ValueError("deployment target must be a directory")
    if _lexists(target) and not allow_replace:
        raise FileExistsError(f"deployment target already exists: {target}")

    previous: Path | None = None
    activated = False
    failed_tree: Path | None = None
    try:
        if _lexists(target):
            previous = _unique_sibling(target, "previous")
            os.replace(target, previous)
            previous.chmod(0o700)
            _fsync_directory(target.parent)
        os.replace(staging, target)
        activated = True
        _fsync_directory(target.parent)
        verification = verify(target)
        _fsync_directory(target.parent)
        return ActivationResult(target=target, previous_target=previous, verification=verification)
    except BaseException:
        rollback_error: BaseException | None = None
        try:
            if activated and _lexists(target):
                failed_tree = _unique_sibling(target, "failed")
                os.replace(target, failed_tree)
                _fsync_directory(target.parent)
            if previous is not None and _lexists(previous):
                os.replace(previous, target)
                _fsync_directory(target.parent)
            if failed_tree is not None:
                if restore_staging_on_failure:
                    if _lexists(staging):
                        raise RuntimeError("could not restore failed deployment staging path")
                    os.replace(failed_tree, staging)
                    _fsync_directory(target.parent)
                    failed_tree = None
                else:
                    remove_tree(failed_tree)
                    _fsync_directory(target.parent)
        except BaseException as exc:  # preserve the original activation error
            rollback_error = exc
        if rollback_error is not None:
            raise RuntimeError(
                "offline deployment activation failed and rollback could not be completed"
            ) from rollback_error
        raise
