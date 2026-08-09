from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.external_validation_exchange as exchange
from scripts.external_validation_source_attestation import (
    attest_public_source,
    copy_verified_public_source,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source(base: Path) -> Path:
    root = base / "source"
    files = {
        "VERSION": b"72.0.50\n",
        "README.md": b"verified source\n",
        "scripts/external_validation_gate.py": b"print('gate')\n",
        "scripts/external_validation_exchange.py": b"print('exchange')\n",
    }
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / "SHA256SUMS.txt").write_text(
        "\n".join(f"{_sha(data)}  {name}" for name, data in sorted(files.items())) + "\n",
        encoding="utf-8",
    )
    return root


def _keys(base: Path) -> tuple[Path, Path]:
    private, public = exchange.generate_keypair(key_id="requester-v109")
    private_path = base / "requester-private.json"
    public_path = base / "requester-public.json"
    private_path.write_text(json.dumps(private), encoding="utf-8")
    public_path.write_text(json.dumps(public), encoding="utf-8")
    private_path.chmod(0o600)
    return private_path, public_path


def _request(base: Path, source: Path, private: Path, public: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    original_identity = exchange._source_identity
    monkeypatch.setattr(exchange, "_source_identity", lambda root=source: original_identity(source if root is exchange.ROOT else root))
    output = base / "request"
    exchange.create_request_bundle(
        output_dir=output,
        private_key_file=private,
        operator_public_key_file=public,
        target_name="v109-lab",
        lifetime_seconds=3600,
        minimum_scanner_files=2,
        soak_iterations=2,
        nonce="n" * 40,
    )
    return output


def test_signed_request_rejects_changed_file_even_when_manifest_file_is_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    private, public = _keys(tmp_path)
    request = _request(tmp_path, source, private, public, monkeypatch)
    assert exchange.verify_request_bundle(request, requester_public_key_file=public, source_root=source)
    (source / "README.md").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="public source verification failed"):
        exchange.verify_request_bundle(request, requester_public_key_file=public, source_root=source)


def test_execution_snapshot_contains_only_manifest_verified_files(tmp_path: Path) -> None:
    source = _source(tmp_path)
    (source / "sitecustomize.py").write_text("raise RuntimeError('unlisted')\n", encoding="utf-8")
    snapshot = tmp_path / "snapshot"
    report = copy_verified_public_source(source, snapshot)
    assert report["passed"] is True
    assert (snapshot / "README.md").is_file()
    assert not (snapshot / "sitecustomize.py").exists()
    assert attest_public_source(snapshot)["identity"] == report["identity"]


def test_execute_request_runs_collector_from_private_verified_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    (source / "unlisted.py").write_text("untrusted\n", encoding="utf-8")
    private, public = _keys(tmp_path)
    request = _request(tmp_path, source, private, public, monkeypatch)
    monkeypatch.setattr(exchange, "ROOT", source)
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        cwd = Path(kwargs["cwd"])
        captured["cwd"] = cwd
        assert cwd != source
        assert (cwd / "README.md").is_file()
        assert not (cwd / "unlisted.py").exists()
        return SimpleNamespace(returncode=1)

    def fake_sign(**kwargs):
        captured["source_root"] = Path(kwargs["source_root"])
        captured["before"] = kwargs["source_attestation_before"]
        captured["after"] = kwargs["source_attestation_after"]
        return {"signed": True}

    monkeypatch.setattr(exchange.subprocess, "run", fake_run)
    monkeypatch.setattr(exchange, "sign_response_bundle", fake_sign)
    statement, exit_code = exchange.execute_request(
        request_dir=request,
        requester_public_key_file=public,
        operator_private_key_file=tmp_path / "unused-operator.json",
        output_dir=tmp_path / "response",
        evidence_output_dir=tmp_path / "evidence",
        runner_label="operator",
        scanner_dir=None,
        chromium="",
        timeout_seconds=300,
    )
    assert exit_code == 1
    assert statement == {"signed": True}
    assert captured["source_root"] == captured["cwd"]
    assert captured["before"]["identity"] == captured["after"]["identity"]


def test_execute_request_rejects_snapshot_change_before_response_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    private, public = _keys(tmp_path)
    request = _request(tmp_path, source, private, public, monkeypatch)
    monkeypatch.setattr(exchange, "ROOT", source)

    def fake_run(command, **kwargs):
        Path(kwargs["cwd"], "README.md").write_text("changed during execution\n", encoding="utf-8")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(exchange.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="public source verification failed"):
        exchange.execute_request(
            request_dir=request,
            requester_public_key_file=public,
            operator_private_key_file=tmp_path / "unused-operator.json",
            output_dir=tmp_path / "response",
            evidence_output_dir=tmp_path / "evidence",
            runner_label="operator",
            scanner_dir=None,
            chromium="",
            timeout_seconds=300,
        )


@pytest.mark.skipif(__import__("os").name != "posix", reason="POSIX symlink boundary")
def test_source_attestation_rejects_manifested_symlink_component(tmp_path: Path) -> None:
    source = tmp_path / "source"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.py").write_text("print('outside')\n", encoding="utf-8")
    source.mkdir()
    (source / "VERSION").write_text("72.0.50\n", encoding="utf-8")
    (source / "linked").symlink_to(outside, target_is_directory=True)
    files = {
        "VERSION": (source / "VERSION").read_bytes(),
        "linked/payload.py": (outside / "payload.py").read_bytes(),
    }
    (source / "SHA256SUMS.txt").write_text(
        "\n".join(f"{_sha(data)}  {name}" for name, data in sorted(files.items())) + "\n",
        encoding="utf-8",
    )
    report = attest_public_source(source)
    assert report["passed"] is False
    assert any("linked" in issue or "escaping" in issue for issue in report["issues"])


def test_execution_snapshot_must_be_new_and_outside_source(tmp_path: Path) -> None:
    source = _source(tmp_path)
    with pytest.raises(ValueError, match="outside the source tree"):
        copy_verified_public_source(source, source / "nested-snapshot")
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="already exists"):
        copy_verified_public_source(source, existing)

@pytest.mark.skipif(__import__("os").name != "posix", reason="POSIX process-group contract")
def test_external_gate_reaps_descendant_after_successful_wrapper_exit(tmp_path: Path) -> None:
    import os
    import signal
    import sys
    import time

    import scripts.external_validation_gate as gate

    pid_file = tmp_path / "descendant.pid"
    child = (
        "import pathlib,subprocess,sys; "
        f"p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); "
        "print('wrapper complete', flush=True)"
    )
    started = time.monotonic()
    result = gate._run_command(
        name="residual-child",
        command=[sys.executable, "-c", child],
        output_dir=tmp_path,
        timeout_seconds=10,
    )
    assert result["exit_code"] == 0
    assert result.get("timed_out") is not True
    assert time.monotonic() - started < 5.0
    assert "wrapper complete" in (tmp_path / "residual-child.log").read_text(encoding="utf-8")
    descendant_pid = int(pid_file.read_text(encoding="utf-8"))
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{descendant_pid}/stat")
            if not stat.exists() or stat.read_text(encoding="utf-8").split()[2] == "Z":
                break
            time.sleep(0.05)
        else:
            pytest.fail("successful wrapper left a live descendant process")
    finally:
        try:
            os.kill(descendant_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
