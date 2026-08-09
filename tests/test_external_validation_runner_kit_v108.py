from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

import scripts.external_validation_exchange as exchange
import scripts.external_validation_runner_kit as kit
from scripts.external_validation_exchange import create_request_bundle, generate_keypair


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_keypair(base: Path, key_id: str) -> tuple[Path, Path]:
    private, public = generate_keypair(key_id=key_id)
    private_path = base / f"{key_id}-private.json"
    public_path = base / f"{key_id}-public.json"
    private_path.write_text(json.dumps(private), encoding="utf-8")
    public_path.write_text(json.dumps(public), encoding="utf-8")
    private_path.chmod(0o600)
    return private_path, public_path


def _minimal_source(base: Path) -> Path:
    root = base / "source"
    (root / "scripts").mkdir(parents=True)
    files = {
        "VERSION": b"72.0.50\n",
        "README.md": b"minimal signed runner source\n",
        "scripts/external_validation_runner_kit.py": b"print('runner')\n",
        "scripts/external_validation_exchange.py": b"print('exchange')\n",
        "scripts/external_validation_gate.py": b"print('gate')\n",
    }
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    lines = [f"{_sha(data)}  {relative}" for relative, data in sorted(files.items())]
    (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


def _request(
    base: Path,
    *,
    source: Path,
    private_key: Path,
    public_key: Path,
    monkeypatch: pytest.MonkeyPatch,
    lifetime_seconds: int = 3600,
) -> Path:
    request = base / "request"
    identity = kit._source_identity(source)
    with monkeypatch.context() as scoped:
        scoped.setattr(exchange, "_source_identity", lambda root=source: identity)
        create_request_bundle(
            output_dir=request,
            private_key_file=private_key,
            operator_public_key_file=public_key,
            target_name="approved-lab",
            lifetime_seconds=lifetime_seconds,
            minimum_scanner_files=20,
            soak_iterations=12,
            now=datetime.now(timezone.utc),
            nonce="n" * 43,
        )
    assert exchange.verify_request_bundle(
        request,
        requester_public_key_file=public_key,
        source_root=source,
    )["target_name"] == "approved-lab"
    return request


def _build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path, Path, Path]:
    source = _minimal_source(tmp_path)
    private, public = _write_keypair(tmp_path, "requester-v108")
    request = _request(
        tmp_path,
        source=source,
        private_key=private,
        public_key=public,
        monkeypatch=monkeypatch,
    )
    archive = tmp_path / "runner-kit.zip"
    result = kit.build_runner_kit(
        output_zip=archive,
        request_dir=request,
        requester_private_key_file=private,
        requester_public_key_file=public,
        source_root=source,
    )
    assert result["verified"] is True
    return archive, source, request, private, public


def _rewrite_zip(source: Path, output: Path, transform) -> None:
    with zipfile.ZipFile(source) as original:
        records = []
        for info in original.infolist():
            data = b"" if info.is_dir() else original.read(info)
            records.append((info.filename, data, info.is_dir(), (info.external_attr >> 16) & 0o777))
    records = transform(records)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data, directory, mode in records:
            info = zipfile.ZipInfo(name, date_time=kit.ZIP_TIMESTAMP)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            type_mode = stat.S_IFDIR if directory else stat.S_IFREG
            info.external_attr = (type_mode | (mode or (0o755 if directory else 0o644))) << 16
            if directory:
                info.external_attr |= 0x10
            archive.writestr(info, data)


def test_runner_kit_is_deterministic_signed_and_contains_no_private_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, source, request, private, public = _build(tmp_path, monkeypatch)
    second = tmp_path / "runner-kit-second.zip"
    kit.build_runner_kit(
        output_zip=second,
        request_dir=request,
        requester_private_key_file=private,
        requester_public_key_file=public,
        source_root=source,
    )
    assert archive.read_bytes() == second.read_bytes()
    report = kit.verify_runner_kit_archive(archive, requester_public_key_file=public)
    assert report["passed"] is True
    with zipfile.ZipFile(archive) as payload:
        all_bytes = b"\n".join(payload.read(info) for info in payload.infolist() if not info.is_dir())
        names = [info.filename for info in payload.infolist()]
    assert b"private_key_base64" not in all_bytes
    assert b"PYTHONDONTWRITEBYTECODE=1" in all_bytes
    assert b"PYTHONDONTWRITEBYTECODE = '1'" in all_bytes
    assert not any("private" in PurePosixPath(name).name.lower() for name in names)


def test_verified_extraction_preserves_exact_inventory_and_launcher_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    result = kit.extract_runner_kit(
        archive,
        requester_public_key_file=public,
        output_dir=tmp_path / "extracted",
    )
    root = Path(result["output"])
    assert result["verification"]["passed"] is True
    assert (root / kit.RUN_SH).is_file()
    if os.name == "posix":
        assert (root / kit.RUN_SH).stat().st_mode & stat.S_IXUSR


def test_payload_tampering_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    tampered = tmp_path / "tampered.zip"

    def transform(records):
        result = []
        for name, data, directory, mode in records:
            if name.endswith("/source/README.md"):
                data += b"tampered\n"
            result.append((name, data, directory, mode))
        return result

    _rewrite_zip(archive, tampered, transform)
    report = kit.verify_runner_kit_archive(tampered, requester_public_key_file=public)
    assert report["passed"] is False
    assert any("payload hash" in issue for issue in report["issues"])


def test_recomputed_payload_manifest_cannot_bypass_signed_statement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    tampered = tmp_path / "recomputed.zip"

    def transform(records):
        root = records[0][0].split("/", 1)[0]
        changed = []
        for name, data, directory, mode in records:
            if name == f"{root}/{kit.RUN_SH}":
                data += b"echo attacker\n"
            changed.append((name, data, directory, mode))
        payload = {
            name[len(root) + 1 :]: data
            for name, data, directory, _ in changed
            if not directory and name not in {
                f"{root}/{kit.KIT_MANIFEST}",
                f"{root}/{kit.KIT_STATEMENT}",
                f"{root}/{kit.KIT_SIGNATURE}",
            }
        }
        new_manifest = "\n".join(f"{_sha(data)}  {name}" for name, data in sorted(payload.items())) + "\n"
        return [
            (name, new_manifest.encode() if name == f"{root}/{kit.KIT_MANIFEST}" else data, directory, mode)
            for name, data, directory, mode in changed
        ]

    _rewrite_zip(archive, tampered, transform)
    report = kit.verify_runner_kit_archive(tampered, requester_public_key_file=public)
    assert report["passed"] is False
    assert any(item["name"] == "kit_bindings" and not item["passed"] for item in report["checks"])


def test_wrong_pinned_requester_key_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, _ = _build(tmp_path, monkeypatch)
    _, wrong_public = _write_keypair(tmp_path, "wrong-requester")
    report = kit.verify_runner_kit_archive(archive, requester_public_key_file=wrong_public)
    assert report["passed"] is False
    assert any(item["name"] == "requester_identity" and not item["passed"] for item in report["checks"])


def test_unsafe_zip_path_and_special_file_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    unsafe = tmp_path / "unsafe.zip"

    def add_unsafe(records):
        return records + [("root/../escape.txt", b"x", False, 0o644)]

    _rewrite_zip(archive, unsafe, add_unsafe)
    assert kit.verify_runner_kit_archive(unsafe, requester_public_key_file=public)["passed"] is False

    special = tmp_path / "special.zip"
    with zipfile.ZipFile(archive) as original, zipfile.ZipFile(special, "w") as output:
        for info in original.infolist():
            output.writestr(info, b"" if info.is_dir() else original.read(info))
        root = original.infolist()[0].filename.split("/", 1)[0]
        link = zipfile.ZipInfo(f"{root}/linked", date_time=kit.ZIP_TIMESTAMP)
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        output.writestr(link, b"target")
    assert kit.verify_runner_kit_archive(special, requester_public_key_file=public)["passed"] is False


def test_archive_root_is_bound_to_request_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    renamed = tmp_path / "renamed-root.zip"

    def rename(records):
        old = records[0][0].split("/", 1)[0]
        return [("Different-Root" + name[len(old):], data, directory, mode) for name, data, directory, mode in records]

    _rewrite_zip(archive, renamed, rename)
    report = kit.verify_runner_kit_archive(renamed, requester_public_key_file=public)
    assert report["passed"] is False
    assert any(item["name"] == "archive_root_binding" and not item["passed"] for item in report["checks"])


def test_expired_kit_fails_execution_verification_but_can_be_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    future = datetime.now(timezone.utc) + timedelta(days=2)
    monkeypatch.setattr(exchange, "_utc_now", lambda: future)
    active = kit.verify_runner_kit_archive(archive, requester_public_key_file=public, require_unexpired=True)
    audit = kit.verify_runner_kit_archive(archive, requester_public_key_file=public, require_unexpired=False)
    assert active["passed"] is False
    assert audit["passed"] is True


def test_output_must_not_exist_or_overlap_protected_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, source, request, private, public = _build(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="already exists"):
        kit.build_runner_kit(
            output_zip=archive,
            request_dir=request,
            requester_private_key_file=private,
            requester_public_key_file=public,
            source_root=source,
        )
    with pytest.raises(ValueError, match="outside source"):
        kit.build_runner_kit(
            output_zip=source / "nested-kit.zip",
            request_dir=request,
            requester_private_key_file=private,
            requester_public_key_file=public,
            source_root=source,
        )


def test_mismatched_private_and_public_requester_keys_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _minimal_source(tmp_path)
    private, public = _write_keypair(tmp_path, "requester-a")
    _, other_public = _write_keypair(tmp_path, "requester-b")
    request = _request(tmp_path, source=source, private_key=private, public_key=public, monkeypatch=monkeypatch)
    with pytest.raises(ValueError, match="do not match"):
        kit.build_runner_kit(
            output_zip=tmp_path / "bad.zip",
            request_dir=request,
            requester_private_key_file=private,
            requester_public_key_file=other_public,
            source_root=source,
        )


@pytest.mark.skipif(__import__("os").name != "posix", reason="POSIX symlink boundary")
def test_source_symlink_component_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    root = tmp_path / "source"
    root.mkdir()
    (root / "VERSION").write_text("72.0.50\n", encoding="utf-8")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    files = {
        "VERSION": (root / "VERSION").read_bytes(),
        "linked/secret.txt": (outside / "secret.txt").read_bytes(),
    }
    (root / "SHA256SUMS.txt").write_text(
        "\n".join(f"{_sha(data)}  {name}" for name, data in sorted(files.items())) + "\n",
        encoding="utf-8",
    )
    result = kit.verify_public_source(root)
    assert result["passed"] is False
    assert any("escaping" in issue for issue in result["issues"])


def test_archive_size_limit_is_enforced_before_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, _, public = _build(tmp_path, monkeypatch)
    monkeypatch.setattr(kit, "MAX_UNCOMPRESSED_BYTES", 128)
    report = kit.verify_runner_kit_archive(archive, requester_public_key_file=public)
    assert report["passed"] is False
    assert any("expands beyond" in issue for issue in report["issues"])


def test_run_directory_verifies_before_invoking_child_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, operator_private, public = _build(tmp_path, monkeypatch)
    extracted = kit.extract_runner_kit(
        archive,
        requester_public_key_file=public,
        output_dir=tmp_path / "extracted",
    )
    root = Path(extracted["output"])
    (root / kit.README_FILE).write_text("tampered", encoding="utf-8")
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kit.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="failed verification"):
        kit.run_extracted_kit(
            kit_root=root,
            requester_public_key_file=public,
            operator_private_key_file=operator_private,
            output_dir=tmp_path / "response",
            evidence_output_dir=tmp_path / "evidence",
            runner_label="operator",
            scanner_dir=None,
            chromium="",
            timeout_seconds=300,
        )
    assert called is False


def test_run_directory_disables_bytecode_for_child_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive, _, _, operator_private, public = _build(tmp_path, monkeypatch)
    extracted = kit.extract_runner_kit(
        archive,
        requester_public_key_file=public,
        output_dir=tmp_path / "extracted",
    )
    root = Path(extracted["output"])
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs.get("env")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kit.subprocess, "run", fake_run)
    report, exit_code = kit.run_extracted_kit(
        kit_root=root,
        requester_public_key_file=public,
        operator_private_key_file=operator_private,
        output_dir=tmp_path / "response",
        evidence_output_dir=tmp_path / "evidence",
        runner_label="operator",
        scanner_dir=None,
        chromium="",
        timeout_seconds=300,
    )
    assert exit_code == 0
    assert report["kit_verification"]["passed"] is True
    assert isinstance(captured["env"], dict)
    assert captured["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
