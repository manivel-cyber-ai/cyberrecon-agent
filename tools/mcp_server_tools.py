"""Shared helpers for the CyberRecon MCP server."""

from __future__ import annotations

from typing import Any

from tools.nmap_tools import parse_nmap_xml, run_nmap_scan_with_mode
from tools.security import sanitize_scan_type, sanitize_target_ip, sanitize_xml_data

SCAN_TYPE_ARGUMENTS = {
    "syn": "-sS -sV -oX -",
    "connect": "-sT -sV -oX -",
    "udp": "-sU -sV -oX -",
    "version": "-sV -oX -",
}


def validate_private_target(target_ip: str) -> str:
    """Validate that a target IP is in an approved private or loopback range."""

    return sanitize_target_ip(target_ip)


def build_nmap_arguments(scan_type: str) -> str:
    """Translate a user-facing scan type into safe Nmap arguments."""

    normalized_scan_type = sanitize_scan_type(scan_type)
    return SCAN_TYPE_ARGUMENTS[normalized_scan_type]


def summarize_scan_results(xml_data: str) -> dict[str, Any]:
    """Return a compact JSON-ready summary of Nmap XML results."""

    parsed = parse_nmap_xml(sanitize_xml_data(xml_data))
    hosts_summary: list[dict[str, Any]] = []
    open_port_count = 0
    services: set[str] = set()

    for host in parsed.get("hosts", []):
        host_open_ports: list[dict[str, Any]] = []
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue

            service = port.get("service") or {}
            service_name = service.get("name", "unknown")
            services.add(service_name)
            host_open_ports.append(
                {
                    "portid": port.get("portid"),
                    "protocol": port.get("protocol", "unknown"),
                    "service_name": service_name,
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extra_info": service.get("extrainfo", ""),
                }
            )

        open_port_count += len(host_open_ports)
        hosts_summary.append(
            {
                "status": host.get("status", "unknown"),
                "addresses": host.get("addresses", []),
                "open_ports": host_open_ports,
            }
        )

    return {
        "scanner": parsed.get("scanner", "nmap"),
        "args": parsed.get("args", ""),
        "scan_type": parsed.get("scan_type", ""),
        "host_count": len(parsed.get("hosts", [])),
        "open_port_count": open_port_count,
        "services": sorted(services),
        "hosts": hosts_summary,
    }


def execute_scan(target_ip: str, scan_type: str, demo_mode: bool = False) -> str:
    """Run a scan or replay the demo XML fixture."""

    normalized_target = sanitize_target_ip(target_ip)
    normalized_scan_type = sanitize_scan_type(scan_type)
    return run_nmap_scan_with_mode(
        target_ip=normalized_target,
        nmap_args=SCAN_TYPE_ARGUMENTS[normalized_scan_type],
        demo_mode=demo_mode,
    )