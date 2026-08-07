from __future__ import annotations

"""Pinned outbound HTTP transport with private-network and DNS-rebinding guards."""

from dataclasses import dataclass
import base64
import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


class OutboundError(RuntimeError):
    """Base class for outbound request failures safe to expose to delivery logic."""


class OutboundPolicyError(OutboundError):
    """The configured destination violates the outbound network policy."""


class OutboundResolutionError(OutboundError):
    """The destination could not be resolved to a usable address."""


class OutboundTransportError(OutboundError):
    """A validated destination could not be reached or completed."""


class OutboundResponseTooLarge(OutboundError):
    """The remote response exceeded the configured in-memory limit."""


_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
})


@dataclass(frozen=True, slots=True)
class OutboundHostTarget:
    hostname: str
    port: int
    addresses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OutboundTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    path_and_query: str
    host_header: str
    addresses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OutboundResponse:
    status_code: int
    headers: Mapping[str, str]
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content.decode("utf-8"))


def parse_host_allowlist(raw: str | Iterable[str] | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    values = raw.split(",") if isinstance(raw, str) else list(raw)
    output: list[str] = []
    for item in values:
        value = str(item or "").strip().lower().rstrip(".")
        if not value:
            continue
        if value.startswith("*."):
            value = "." + value[2:]
        if value not in output:
            output.append(value)
    return tuple(output)


def _normalize_hostname(hostname: str) -> str:
    value = str(hostname or "").strip().rstrip(".")
    if not value:
        raise OutboundPolicyError("outbound URL hostname is missing")
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise OutboundPolicyError("outbound URL hostname is invalid") from exc


def _host_allowed(hostname: str, allowlist: tuple[str, ...]) -> bool:
    if not allowlist:
        return True
    for rule in allowlist:
        if rule.startswith("."):
            suffix = rule[1:]
            if hostname.endswith(rule) and hostname != suffix:
                return True
        elif hostname == rule:
            return True
    return False


def _address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool) -> bool:
    if address.is_unspecified or address.is_multicast:
        return False
    if allow_private:
        return True
    return bool(address.is_global)


def _literal_address(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _resolve_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        rows = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OutboundResolutionError(f"outbound hostname resolution failed: {hostname}") from exc
    addresses: list[str] = []
    for row in rows:
        raw = str(row[4][0])
        try:
            normalized = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise OutboundResolutionError(f"outbound hostname returned no usable addresses: {hostname}")
    return tuple(addresses)


def resolve_outbound_host(
    hostname: str,
    port: int,
    *,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
) -> OutboundHostTarget:
    normalized = _normalize_hostname(hostname)
    allowlist = parse_host_allowlist(host_allowlist)
    if not _host_allowed(normalized, allowlist):
        raise OutboundPolicyError(f"outbound hostname is not allowlisted: {normalized}")
    if not allow_private_networks and (
        normalized in _BLOCKED_HOSTNAMES or normalized.endswith(".localhost")
    ):
        raise OutboundPolicyError(f"outbound hostname is not public: {normalized}")
    try:
        normalized_port = int(port)
    except (TypeError, ValueError) as exc:
        raise OutboundPolicyError("outbound port is invalid") from exc
    if not 1 <= normalized_port <= 65535:
        raise OutboundPolicyError("outbound port is invalid")

    literal = _literal_address(normalized)
    addresses = (str(literal),) if literal is not None else _resolve_addresses(normalized, normalized_port)
    rejected = [
        address for address in addresses
        if not _address_allowed(ipaddress.ip_address(address), allow_private=allow_private_networks)
    ]
    if rejected:
        raise OutboundPolicyError(
            f"outbound hostname resolves to a blocked network: {normalized} ({', '.join(rejected)})"
        )
    return OutboundHostTarget(normalized, normalized_port, addresses)


def resolve_outbound_target(
    url: str,
    *,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
) -> OutboundTarget:
    raw_url = str(url or "").strip()
    if not raw_url or "\\" in raw_url or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in raw_url):
        raise OutboundPolicyError("outbound URL contains invalid whitespace or control characters")
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise OutboundPolicyError("outbound URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundPolicyError("outbound URL must not contain user information")
    if parsed.fragment:
        raise OutboundPolicyError("outbound URL fragments are not allowed")
    try:
        port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    except ValueError as exc:
        raise OutboundPolicyError("outbound URL port is invalid") from exc
    resolved = resolve_outbound_host(
        parsed.hostname or "",
        port,
        allow_private_networks=allow_private_networks,
        host_allowlist=host_allowlist,
    )
    hostname = resolved.hostname
    addresses = resolved.addresses
    literal = _literal_address(hostname)

    default_port = 443 if parsed.scheme == "https" else 80
    host_value = f"[{hostname}]" if literal is not None and literal.version == 6 else hostname
    host_header = host_value if port == default_port else f"{host_value}:{port}"
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query += f"?{parsed.query}"
    return OutboundTarget(
        url=raw_url,
        scheme=parsed.scheme,
        hostname=hostname,
        port=port,
        path_and_query=path_and_query,
        host_header=host_header,
        addresses=addresses,
    )


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, address: str, port: int, *, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, hostname: str, address: str, port: int, *, timeout: float, context: ssl.SSLContext
    ):
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        raw_sock = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise


def _encode_body(
    *, body: bytes | str | None, json_body: Any | None, headers: dict[str, str]
) -> bytes | None:
    if body is not None and json_body is not None:
        raise ValueError("body and json_body are mutually exclusive")
    if json_body is not None:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if body is None:
        return None
    return body.encode("utf-8") if isinstance(body, str) else bytes(body)


def request_outbound(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | str | None = None,
    json_body: Any | None = None,
    basic_auth: tuple[str, str] | None = None,
    timeout_seconds: int | float = 10,
    max_response_bytes: int = 1024 * 1024,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> OutboundResponse:
    target = resolve_outbound_target(
        url,
        allow_private_networks=allow_private_networks,
        host_allowlist=host_allowlist,
    )
    request_headers = {str(key): str(value) for key, value in dict(headers or {}).items()}
    request_headers["Host"] = target.host_header
    request_headers.setdefault("Connection", "close")
    if basic_auth is not None:
        token = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")).decode("ascii")
        request_headers["Authorization"] = f"Basic {token}"
    encoded = _encode_body(body=body, json_body=json_body, headers=request_headers)
    if encoded is not None:
        request_headers["Content-Length"] = str(len(encoded))

    timeout = max(0.1, float(timeout_seconds))
    maximum = max(1024, int(max_response_bytes))
    failures: list[str] = []
    for address in target.addresses:
        connection: http.client.HTTPConnection
        if target.scheme == "https":
            connection = _PinnedHTTPSConnection(
                target.hostname,
                address,
                target.port,
                timeout=timeout,
                context=ssl_context or ssl.create_default_context(),
            )
        else:
            connection = _PinnedHTTPConnection(
                target.hostname, address, target.port, timeout=timeout
            )
        try:
            connection.request(
                str(method or "GET").strip().upper(),
                target.path_and_query,
                body=encoded,
                headers=request_headers,
            )
            response = connection.getresponse()
            content = response.read(maximum + 1)
            if len(content) > maximum:
                raise OutboundResponseTooLarge(
                    f"outbound response exceeded {maximum} bytes"
                )
            return OutboundResponse(
                int(response.status),
                {str(key).title(): str(value) for key, value in response.getheaders()},
                content,
            )
        except OutboundResponseTooLarge:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            failures.append(f"{address}: {type(exc).__name__}")
        finally:
            connection.close()
    raise OutboundTransportError(
        "outbound request failed for every validated address"
        + (f" ({'; '.join(failures)})" if failures else "")
    )
