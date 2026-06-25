"""Analyzer agent for interpreting Nmap results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AnalyzerAgent:
    name: str = "AnalyzerAgent"

    def run(self, nmap_data: dict[str, Any]) -> dict[str, Any]:
        hosts = nmap_data.get("hosts", [])
        open_ports: list[dict[str, Any]] = []
        risks: list[str] = []

        for host in hosts:
            for port in host.get("ports", []):
                if port.get("state") != "open":
                    continue

                open_ports.append(port)
                service_name = (port.get("service") or {}).get("name", "unknown")
                port_id = port.get("portid")

                if port_id in {21, 23, 80, 8080, 3306, 5432, 6379, 9200, 27017, 445}:
                    risks.append(f"Port {port_id}/{service_name} is exposed and should be reviewed for access control.")

                if service_name in {"ftp", "telnet", "rdp", "smb", "mongodb", "redis"}:
                    risks.append(f"Service {service_name} on port {port_id} may require hardening or network restriction.")

        summary = {
            "host_count": len(hosts),
            "open_port_count": len(open_ports),
            "service_count": len({(port.get("service") or {}).get("name", "unknown") for port in open_ports}),
        }

        recommendations = [
            "Restrict exposure with firewalls or security groups.",
            "Disable or secure unused services.",
            "Patch vulnerable software versions and verify authentication controls.",
        ]

        return {
            "hosts": hosts,
            "open_ports": open_ports,
            "risks": sorted(set(risks)),
            "summary": summary,
            "recommendations": recommendations,
        }