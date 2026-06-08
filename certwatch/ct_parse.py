"""Parse RFC 6962 CT log entries into a normalised cert summary.

A get-entries response item has two base64 fields: ``leaf_input`` (a TLS-
encoded ``MerkleTreeLeaf``) and ``extra_data``. For X509 entries the cert
is in leaf_input; for precert entries the full pre-certificate is the first
ASN.1Cert inside extra_data (RFC 6962 s4.6).
"""
from __future__ import annotations

import base64
import logging
import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedCert:
    entry_type: str  # "x509" or "precert"
    timestamp_ms: int
    domains: tuple[str, ...]
    issuer_o: str | None
    issuer_cn: str | None
    not_before: str
    not_after: str
    serial: str
    fingerprint: str


def parse_entry(leaf_input_b64: str, extra_data_b64: str | None) -> ParsedCert | None:
    """Return a ParsedCert, or None if the entry can't be decoded."""
    try:
        leaf = base64.b64decode(leaf_input_b64)
    except (ValueError, TypeError):
        return None
    extra = base64.b64decode(extra_data_b64) if extra_data_b64 else b""

    if len(leaf) < 12 or leaf[0] != 0 or leaf[1] != 0:
        # Only MerkleTreeLeaf v1 / TimestampedEntry is defined.
        return None

    pos = 2
    timestamp = struct.unpack(">Q", leaf[pos:pos + 8])[0]
    pos += 8
    entry_type = struct.unpack(">H", leaf[pos:pos + 2])[0]
    pos += 2

    if entry_type == 0:  # x509_entry
        cert_len = int.from_bytes(leaf[pos:pos + 3], "big")
        pos += 3
        cert_der = leaf[pos:pos + cert_len]
        type_label = "x509"
    elif entry_type == 1:  # precert_entry — full pre-cert lives in extra_data
        if len(extra) < 3:
            return None
        precert_len = int.from_bytes(extra[0:3], "big")
        cert_der = extra[3:3 + precert_len]
        type_label = "precert"
    else:
        return None

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        logger.debug("failed to parse cert DER: %s", exc)
        return None

    domains = _extract_domains(cert)
    if not domains:
        return None

    return ParsedCert(
        entry_type=type_label,
        timestamp_ms=timestamp,
        domains=domains,
        issuer_o=_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        issuer_cn=_attr(cert.issuer, NameOID.COMMON_NAME),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        serial=format(cert.serial_number, "x"),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )


def _attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _extract_domains(cert: x509.Certificate) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    cn = _attr(cert.subject, NameOID.COMMON_NAME)
    if cn:
        out.append(cn)
        seen.add(cn)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for d in san.get_values_for_type(x509.DNSName):
            if d not in seen:
                out.append(d)
                seen.add(d)
    except x509.ExtensionNotFound:
        pass
    return tuple(out)
