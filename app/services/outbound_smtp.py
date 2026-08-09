from __future__ import annotations

"""Pinned outbound SMTP transport with destination and TLS policy guards."""

import smtplib
import socket
import ssl
from typing import Iterable

from app.services.outbound_http import (
    OutboundPolicyError,
    OutboundTransportError,
    resolve_outbound_host,
)


class _PinnedSMTP(smtplib.SMTP):
    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        *,
        timeout: float,
    ) -> None:
        self._pinned_address = address
        super().__init__(hostname, port, timeout=timeout)

    def _get_socket(self, host: str, port: int, timeout: float):  # type: ignore[override]
        if timeout is not None and not timeout:
            raise ValueError("Non-blocking SMTP sockets are not supported")
        return socket.create_connection(
            (self._pinned_address, port), timeout, self.source_address
        )


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        self._pinned_address = address
        super().__init__(hostname, port, timeout=timeout, context=context)

    def _get_socket(self, host: str, port: int, timeout: float):  # type: ignore[override]
        if timeout is not None and not timeout:
            raise ValueError("Non-blocking SMTP sockets are not supported")
        raw_socket = socket.create_connection(
            (self._pinned_address, port), timeout, self.source_address
        )
        try:
            return self.context.wrap_socket(raw_socket, server_hostname=self._host)
        except Exception:
            raw_socket.close()
            raise


def connect_outbound_smtp(
    host: str,
    port: int,
    *,
    security: str,
    timeout_seconds: int | float = 10,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
    allow_plain: bool = False,
    ssl_context: ssl.SSLContext | None = None,
) -> smtplib.SMTP:
    """Connect to a validated SMTP endpoint while pinning the resolved IP.

    TLS certificate verification and SNI use the configured hostname even
    though the socket connects directly to a previously validated address.
    This prevents a second DNS lookup from bypassing the destination policy.
    """

    mode = str(security or "STARTTLS").strip().upper()
    if mode not in {"STARTTLS", "SSL", "PLAIN"}:
        raise OutboundPolicyError("SMTP security must be STARTTLS, SSL, or PLAIN")
    if mode == "PLAIN" and not allow_plain:
        raise OutboundPolicyError("unencrypted SMTP is disabled")

    target = resolve_outbound_host(
        host,
        port,
        allow_private_networks=allow_private_networks,
        host_allowlist=host_allowlist,
    )
    timeout = max(0.1, float(timeout_seconds))
    context = ssl_context or ssl.create_default_context()
    failures: list[str] = []

    for address in target.addresses:
        server: smtplib.SMTP | None = None
        try:
            if mode == "SSL":
                server = _PinnedSMTPSSL(
                    target.hostname,
                    address,
                    target.port,
                    timeout=timeout,
                    context=context,
                )
            else:
                server = _PinnedSMTP(
                    target.hostname,
                    address,
                    target.port,
                    timeout=timeout,
                )
            code, _ = server.ehlo()
            if int(code) >= 400:
                raise smtplib.SMTPHeloError(code, b"EHLO rejected")
            if mode == "STARTTLS":
                server.starttls(context=context)
                code, _ = server.ehlo()
                if int(code) >= 400:
                    raise smtplib.SMTPHeloError(code, b"post-TLS EHLO rejected")
            return server
        except (OSError, ssl.SSLError, smtplib.SMTPException) as exc:
            failures.append(f"{address}: {type(exc).__name__}")
            if server is not None:
                try:
                    server.close()
                except OSError:
                    pass

    raise OutboundTransportError(
        "SMTP connection failed for every validated address"
        + (f" ({'; '.join(failures)})" if failures else "")
    )


__all__ = ["connect_outbound_smtp"]
