from __future__ import annotations

from scripts.static_security_boundary_audit import audit_repository, audit_source


def test_repository_static_security_boundary_passes() -> None:
    assert audit_repository() == []


def test_direct_requests_and_session_are_rejected() -> None:
    findings = audit_source(
        "import requests\nrequests.get('https://example.test')\nrequests.Session()\n",
        relative_path="app/services/unsafe.py",
    )
    assert any("direct requests call" in item for item in findings)
    assert any("constructing requests.Session" in item for item in findings)
    assert any("requests import" in item for item in findings)


def test_raw_socket_and_unverified_tls_are_rejected() -> None:
    findings = audit_source(
        "import socket, ssl\nsocket.create_connection(('example.test', 443))\nssl._create_unverified_context()\n",
        relative_path="app/services/unsafe.py",
    )
    assert any("raw socket" in item for item in findings)
    assert any("unverified TLS" in item for item in findings)


def test_shell_eval_pickle_and_unsafe_yaml_are_rejected() -> None:
    findings = audit_source(
        "import pickle, subprocess, yaml\nsubprocess.run('id', shell=True)\neval('1+1')\nyaml.load('x')\n",
        relative_path="app/services/unsafe.py",
    )
    assert any("shell=True" in item for item in findings)
    assert any("eval" in item for item in findings)
    assert any("pickle" in item for item in findings)
    assert any("yaml.load" in item for item in findings)
