"""Deterministic in-memory aliases and residual checks for scanner samples."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?(?:/\w+)?$")


@dataclass
class AliasVault:
    """Create consistent aliases without exporting the source-to-alias mapping."""

    key: bytes
    aliases: dict[tuple[str, str], str] = field(default_factory=dict)
    source_tokens: set[str] = field(default_factory=set)
    counts: dict[str, int] = field(default_factory=dict)

    def _next(self, category: str) -> int:
        self.counts[category] = self.counts.get(category, 0) + 1
        return self.counts[category]

    def _remember(self, category: str, value: str, alias: str) -> str:
        clean = str(value or "").strip()
        if len(clean) >= 4 and clean.casefold() != alias.casefold():
            self.source_tokens.add(clean)
        self.aliases[(category, clean.casefold())] = alias
        return alias

    def alias(self, category: str, value: str) -> str:
        clean = str(value or "").strip()
        if not clean:
            return ""
        cached = self.aliases.get((category, clean.casefold()))
        if cached:
            return cached
        index = self._next(category)
        if category == "ip":
            alias = self._ip_alias(clean, index)
        elif category == "fqdn":
            alias = f"asset-{index:04d}.example.invalid"
        elif category == "host":
            alias = f"host-{index:04d}"
        elif category == "email":
            alias = f"user-{index:04d}@example.invalid"
        elif category == "mac":
            alias = f"02:00:{(index >> 24) & 255:02x}:{(index >> 16) & 255:02x}:{(index >> 8) & 255:02x}:{index & 255:02x}"
        elif category == "uuid":
            digest = bytearray(hmac.new(self.key, clean.encode("utf-8", "ignore"), hashlib.sha256).digest()[:16])
            digest[6] = (digest[6] & 0x0F) | 0x40
            digest[8] = (digest[8] & 0x3F) | 0x80
            alias = str(uuid.UUID(bytes=bytes(digest)))
        elif category == "url":
            alias = self._url_alias(clean, index)
        elif category in {"product", "component", "version", "environment", "owner"}:
            alias = f"sample-{category}-{index:04d}"
        else:
            alias = f"redacted-{category}-{index:04d}"
        return self._remember(category, clean, alias)

    @staticmethod
    def _ip_alias(value: str, index: int) -> str:
        try:
            address = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return f"host-{index:04d}"
        if address.version == 6:
            return f"2001:db8::{index:x}"
        block = ((index - 1) // 254) % 3
        host = ((index - 1) % 254) + 1
        prefix = ("192.0.2", "198.51.100", "203.0.113")[block]
        return f"{prefix}.{host}"

    def _url_alias(self, value: str, index: int) -> str:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return f"https://service-{index:04d}.example.invalid/"
        scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
        path = parsed.path if parsed.path and ".." not in parsed.path else "/"
        return urlunsplit((scheme, f"service-{index:04d}.example.invalid", path, "", ""))


def classify_identity(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "host"
    try:
        ipaddress.ip_address(text.strip("[]"))
        return "ip"
    except ValueError:
        pass
    if _EMAIL_RE.fullmatch(text):
        return "email"
    if _MAC_RE.fullmatch(text):
        return "mac"
    if _UUID_RE.fullmatch(text):
        return "uuid"
    if "." in text and " " not in text and not _NUMERIC_RE.fullmatch(text):
        return "fqdn"
    return "host"


def safe_scalar(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    return bool(
        _CVE_RE.fullmatch(text)
        or _NUMERIC_RE.fullmatch(text)
        or text.casefold() in {"true", "false", "yes", "no", "unknown", "none", "n/a", "low", "medium", "high", "critical", "tcp", "udp", "general"}
        or re.fullmatch(r"\d+(?:/\w+)?", text)
        or re.fullmatch(r"\d+(?:\.\d+){2,}", text)
    )


def residual_tokens(output: bytes, source_tokens: set[str]) -> list[str]:
    text = output.decode("utf-8", "ignore").casefold()
    found = [token for token in source_tokens if token.casefold() in text]
    return sorted(found, key=lambda item: (len(item), item.casefold()))[:50]


__all__ = ["AliasVault", "classify_identity", "residual_tokens", "safe_scalar"]
