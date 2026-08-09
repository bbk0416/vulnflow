from __future__ import annotations

"""Exercise pinned SMTP STARTTLS, hostname verification, and private relay policy."""

import argparse
from email.message import EmailMessage
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.outbound_http import OutboundPolicyError  # noqa: E402
from app.services.outbound_smtp import connect_outbound_smtp  # noqa: E402
from scripts.local_tls_certificate import generate_self_signed_certificate  # noqa: E402


def _certificate(directory: Path) -> tuple[Path, Path]:
    return generate_self_signed_certificate(
        directory,
        common_name="smtp.example.test",
        dns_names=("smtp.example.test",),
        certificate_name="smtp.crt",
        private_key_name="smtp.key",
    )


def _readline(stream) -> bytes:
    line = stream.readline(65537)
    if not line or len(line) > 65536:
        raise RuntimeError("SMTP client closed or sent an oversized line")
    return line


def run_rehearsal() -> dict[str, Any]:
    observed: dict[str, Any] = {"commands": [], "message_received": False}
    ready = threading.Event()
    finished = threading.Event()

    with tempfile.TemporaryDirectory(prefix="vulnflow-smtp-") as raw:
        work = Path(raw)
        cert, key = _certificate(work)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)

        def sni_callback(_socket, server_name, _context):
            observed["sni"] = server_name

        server_context.set_servername_callback(sni_callback)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        port = int(listener.getsockname()[1])

        def smtp_server() -> None:
            connection = None
            stream = None
            try:
                ready.set()
                connection, address = listener.accept()
                observed["peer"] = str(address[0])
                connection.settimeout(8)
                stream = connection.makefile("rb")
                connection.sendall(b"220 smtp.example.test ESMTP\r\n")
                while True:
                    line = _readline(stream)
                    command = line.decode("utf-8", errors="replace").rstrip("\r\n")
                    observed["commands"].append(command.split(" ", 1)[0].upper())
                    upper = command.upper()
                    if upper.startswith("EHLO"):
                        connection.sendall(
                            b"250-smtp.example.test\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n"
                        )
                    elif upper == "STARTTLS":
                        connection.sendall(b"220 Ready to start TLS\r\n")
                        stream.close()
                        connection = server_context.wrap_socket(connection, server_side=True)
                        connection.settimeout(8)
                        stream = connection.makefile("rb")
                    elif upper.startswith("AUTH"):
                        connection.sendall(b"235 2.7.0 Authentication successful\r\n")
                    elif upper.startswith("MAIL FROM"):
                        connection.sendall(b"250 2.1.0 Sender accepted\r\n")
                    elif upper.startswith("RCPT TO"):
                        connection.sendall(b"250 2.1.5 Recipient accepted\r\n")
                    elif upper == "DATA":
                        connection.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        data: list[bytes] = []
                        while True:
                            item = _readline(stream)
                            if item == b".\r\n":
                                break
                            data.append(item)
                        observed["message_received"] = bool(data)
                        observed["message_contains_subject"] = b"Subject: SMTP boundary rehearsal" in b"".join(data)
                        connection.sendall(b"250 2.0.0 Queued\r\n")
                    elif upper == "QUIT":
                        connection.sendall(b"221 2.0.0 Bye\r\n")
                        break
                    else:
                        connection.sendall(b"502 5.5.2 Command not supported\r\n")
            except Exception as exc:  # captured in the report, not silently ignored
                observed["server_error"] = f"{type(exc).__name__}: {exc}"
            finally:
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass
                listener.close()
                finished.set()

        thread = threading.Thread(target=smtp_server, daemon=True)
        thread.start()
        ready.wait(timeout=2)
        client_context = ssl.create_default_context(cafile=str(cert))
        real_getaddrinfo = socket.getaddrinfo

        def pinned_dns(host, requested_port, *args, **kwargs):
            if host == "smtp.example.test":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", requested_port))
                ]
            return real_getaddrinfo(host, requested_port, *args, **kwargs)

        socket.getaddrinfo = pinned_dns
        private_blocked = False
        allowlist_blocked = False
        plain_blocked = False
        delivered = False
        try:
            try:
                connect_outbound_smtp(
                    "smtp.example.test", port, security="STARTTLS",
                    ssl_context=client_context,
                )
            except OutboundPolicyError:
                private_blocked = True
            try:
                connect_outbound_smtp(
                    "smtp.example.test", port, security="STARTTLS",
                    allow_private_networks=True,
                    host_allowlist="mail.example.test",
                    ssl_context=client_context,
                )
            except OutboundPolicyError:
                allowlist_blocked = True
            try:
                connect_outbound_smtp(
                    "smtp.example.test", port, security="PLAIN",
                    allow_private_networks=True,
                    host_allowlist="smtp.example.test",
                )
            except OutboundPolicyError:
                plain_blocked = True

            server = connect_outbound_smtp(
                "smtp.example.test", port, security="STARTTLS",
                allow_private_networks=True,
                host_allowlist="smtp.example.test",
                ssl_context=client_context,
            )
            with server:
                server.login("mailer", "secret")
                message = EmailMessage()
                message["Subject"] = "SMTP boundary rehearsal"
                message["From"] = "vulnflow@example.test"
                message["To"] = "security@example.test"
                message.set_content("Pinned SMTP delivery")
                server.send_message(message)
                delivered = True
        finally:
            socket.getaddrinfo = real_getaddrinfo
            finished.wait(timeout=10)
            thread.join(timeout=2)

    commands = list(observed.get("commands") or [])
    checks = {
        "private_network_default_blocked": private_blocked,
        "hostname_allowlist_enforced": allowlist_blocked,
        "plain_smtp_default_blocked": plain_blocked,
        "validated_ip_connected": observed.get("peer") == "127.0.0.1",
        "tls_sni_original_hostname": observed.get("sni") == "smtp.example.test",
        "starttls_required": "STARTTLS" in commands,
        "authentication_completed": "AUTH" in commands,
        "message_delivered": delivered and observed.get("message_received") is True,
        "message_subject_preserved": observed.get("message_contains_subject") is True,
        "server_completed_without_error": "server_error" not in observed,
    }
    return {
        "format": "vulnflow-smtp-egress-rehearsal/1",
        "passed": all(checks.values()),
        "checks": checks,
        "observed": {"commands": commands, "sni": observed.get("sni")},
        "limitations": [
            "The rehearsal uses a temporary local CA and loopback SMTP server.",
            "It does not validate a customer SMTP relay, firewall, or mail delivery reputation.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    report = run_rehearsal()
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    print(payload)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
