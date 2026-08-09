from __future__ import annotations

"""Generate short-lived self-signed TLS material without an external OpenSSL CLI."""

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_certificate(
    directory: Path,
    *,
    common_name: str,
    dns_names: Iterable[str] = (),
    ip_addresses: Iterable[str] = (),
    certificate_name: str = "certificate.pem",
    private_key_name: str = "private-key.pem",
) -> tuple[Path, Path]:
    """Write one short-lived localhost/rehearsal certificate and private key."""

    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / private_key_name
    certificate_path = directory / certificate_name
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    alternative_names: list[x509.GeneralName] = [
        x509.DNSName(str(value)) for value in dict.fromkeys(dns_names) if str(value)
    ]
    alternative_names.extend(
        x509.IPAddress(ipaddress.ip_address(str(value)))
        for value in dict.fromkeys(ip_addresses)
        if str(value)
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(alternative_names), critical=False
        )
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate_path, key_path


__all__ = ["generate_self_signed_certificate"]
