from __future__ import annotations

"""Offline AST audit for security boundaries that must not depend on PyPI tools."""

import argparse
import ast
import json
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_EXEC = {"app/routers/__init__.py"}
ALLOWED_SOCKET_CONNECT = {
    "app/services/outbound_http.py",
    "app/services/outbound_smtp.py",
}
ALLOWED_YAML_LOAD = {"app/core/scoring.py"}


def _call_name(node: ast.Call) -> str:
    value: ast.AST = node.func
    parts: list[str] = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def audit_source(source: str, *, relative_path: str) -> list[str]:
    try:
        tree = ast.parse(source, filename=relative_path)
    except SyntaxError as exc:
        return [f"{relative_path}:{exc.lineno or 0}: syntax error: {exc.msg}"]

    findings: list[str] = []
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)

        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        line = int(getattr(node, "lineno", 0) or 0)
        kwargs = {item.arg: item.value for item in node.keywords if item.arg}

        if name in {"eval", "builtins.eval"}:
            findings.append(f"{relative_path}:{line}: eval is forbidden")
        if name in {"exec", "builtins.exec"} and relative_path not in ALLOWED_EXEC:
            findings.append(f"{relative_path}:{line}: exec is forbidden")
        if name.endswith("subprocess.run") or name.endswith("subprocess.Popen") or name in {"run", "Popen"}:
            shell = kwargs.get("shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                findings.append(f"{relative_path}:{line}: subprocess shell=True is forbidden")
        if name in {"ssl._create_unverified_context", "_create_unverified_context"}:
            findings.append(f"{relative_path}:{line}: unverified TLS context is forbidden")
        if name in {"tempfile.mktemp", "mktemp"}:
            findings.append(f"{relative_path}:{line}: tempfile.mktemp is forbidden")
        if name in {"requests.Session", "Session"} and "requests" in imported_modules:
            findings.append(f"{relative_path}:{line}: constructing requests.Session bypasses pinned egress")
        if name in {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.request"}:
            findings.append(f"{relative_path}:{line}: direct requests call bypasses pinned egress")
        if name in {"urllib.request.urlopen", "urlopen"} and any(
            module.startswith("urllib") for module in imported_modules
        ):
            findings.append(f"{relative_path}:{line}: direct urlopen bypasses pinned egress")
        if name in {"socket.create_connection", "create_connection"} and "socket" in imported_modules:
            if relative_path not in ALLOWED_SOCKET_CONNECT:
                findings.append(f"{relative_path}:{line}: raw socket connection bypasses egress owner")
        if name in {"yaml.load", "load"} and "yaml" in imported_modules:
            if relative_path not in ALLOWED_YAML_LOAD:
                findings.append(f"{relative_path}:{line}: yaml.load is forbidden outside strict policy loader")

    if any(module == "pickle" or module.startswith("pickle.") for module in imported_modules):
        findings.append(f"{relative_path}:0: pickle imports are forbidden")
    if any(module == "marshal" or module.startswith("marshal.") for module in imported_modules):
        findings.append(f"{relative_path}:0: marshal imports are forbidden")
    if any(module == "requests" or module.startswith("requests.") for module in imported_modules):
        if relative_path.startswith("app/"):
            findings.append(f"{relative_path}:0: requests import bypasses pinned egress owner")
    if any(module == "http.client" or module.startswith("http.client.") for module in imported_modules):
        if relative_path != "app/services/outbound_http.py":
            findings.append(f"{relative_path}:0: http.client import bypasses pinned egress owner")
    return sorted(set(findings))


def audit_paths(paths: Iterable[Path], *, root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for path in sorted(paths):
        if "__pycache__" in path.parts:
            continue
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        findings.extend(audit_source(path.read_text(encoding="utf-8"), relative_path=relative))
    return sorted(set(findings))


def audit_repository(root: Path = ROOT) -> list[str]:
    return audit_paths((root / "app").rglob("*.py"), root=root)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit VulnFlow static security boundaries.")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    findings = audit_repository(ROOT)
    payload = {"format": "vulnflow-static-security-boundary/1", "passed": not findings, "findings": findings}
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if findings:
        for item in findings:
            print(item)
        raise SystemExit(1)
    print("VulnFlow static security boundary audit: PASS")


if __name__ == "__main__":
    main()
