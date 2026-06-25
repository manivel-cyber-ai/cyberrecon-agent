"""Security validation helpers for CyberRecon inputs."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address
import re

ALLOWED_TARGET_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),
)

ALLOWED_SCAN_TYPES = {"syn", "connect", "udp", "version"}

MAX_XML_SIZE = 5_000_000


@dataclass(frozen=True)
class SanitizedScanRequest:
    target_ip: str
    scan_type: str


def sanitize_target_ip(target_ip: str) -> str:
    """Validate a target IP and reject public addresses."""

    if not isinstance(target_ip, str):
        raise ValueError("Target IP must be a string.")

    normalized = target_ip.strip()
    if not normalized:
        raise ValueError("Target IP is required.")

    address = ip_address(normalized)
    if not isinstance(address, IPv4Address):
        raise ValueError("Only IPv4 addresses are supported.")

    if not any(address in network for network in ALLOWED_TARGET_NETWORKS):
        raise ValueError(
            f"Target IP {normalized} is not allowed. Only 10.0.0.0/8, 192.168.0.0/16, and 127.0.0.0/8 are accepted."
        )

    return str(address)


def sanitize_scan_type(scan_type: str) -> str:
    """Validate a scan type before it is mapped to Nmap arguments."""

    if not isinstance(scan_type, str):
        raise ValueError("Scan type must be a string.")

    normalized = scan_type.strip().lower()
    if not normalized:
        raise ValueError("Scan type is required.")

    if normalized not in ALLOWED_SCAN_TYPES:
        allowed_values = ", ".join(sorted(ALLOWED_SCAN_TYPES))
        raise ValueError(f"Unsupported scan_type '{scan_type}'. Allowed values: {allowed_values}.")

    return normalized


def sanitize_xml_data(xml_data: str) -> str:
    """Validate XML input before it is parsed."""

    if not isinstance(xml_data, str):
        raise ValueError("XML data must be a string.")

    normalized = xml_data.strip()
    if not normalized:
        raise ValueError("XML data is required.")

    if len(normalized) > MAX_XML_SIZE:
        raise ValueError("XML data is too large to process safely.")

    if not normalized.startswith("<"):
        raise ValueError("XML data must begin with an XML element.")

    return normalized


def sanitize_scan_request(target_ip: str, scan_type: str) -> SanitizedScanRequest:
    """Sanitize the user-supplied scan parameters in one step."""

    return SanitizedScanRequest(target_ip=sanitize_target_ip(target_ip), scan_type=sanitize_scan_type(scan_type))