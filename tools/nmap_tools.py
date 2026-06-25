"""Nmap execution and XML parsing helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET


DEMO_XML_PATH = Path(__file__).resolve().parent.parent / "sample_data" / "nmap_demo_192_168_1_1.xml"


@dataclass
class NmapPort:
    portid: int
    protocol: str
    state: str
    service: dict[str, Any] = field(default_factory=dict)


@dataclass
class NmapHost:
    addresses: list[dict[str, str]]
    status: str
    ports: list[NmapPort] = field(default_factory=list)


def run_nmap_scan(target_ip: str, nmap_args: str = "-sV -oX -") -> str:
    return run_nmap_scan_with_mode(target_ip=target_ip, nmap_args=nmap_args, demo_mode=False)


def run_nmap_scan_with_mode(target_ip: str, nmap_args: str = "-sV -oX -", demo_mode: bool = False) -> str:
    if demo_mode:
        demo_xml = DEMO_XML_PATH.read_text(encoding="utf-8")
        if target_ip != "192.168.1.1":
            return demo_xml.replace("192.168.1.1", target_ip)
        return demo_xml

    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap is not installed. Enable demo mode or install dependencies with pip install -r requirements.txt."
        ) from exc

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target_ip, arguments=nmap_args)
    xml_output = scanner.get_nmap_last_output()
    if not xml_output:
        raise RuntimeError("Nmap did not return XML output")
    return xml_output


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []

    for host_element in root.findall("host"):
        status_element = host_element.find("status")
        address_elements = host_element.findall("address")
        port_entries: list[dict[str, Any]] = []

        ports_element = host_element.find("ports")
        if ports_element is not None:
            for port_element in ports_element.findall("port"):
                service_element = port_element.find("service")
                state_element = port_element.find("state")
                port_entries.append(
                    {
                        "portid": int(port_element.get("portid", "0")),
                        "protocol": port_element.get("protocol", "unknown"),
                        "state": state_element.get("state", "unknown") if state_element is not None else "unknown",
                        "service": service_element.attrib if service_element is not None else {},
                    }
                )

        hosts.append(
            {
                "status": status_element.get("state", "unknown") if status_element is not None else "unknown",
                "addresses": [address.attrib for address in address_elements],
                "ports": port_entries,
            }
        )

    scan_info = root.find("scaninfo")
    return {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "scan_type": scan_info.get("type", "") if scan_info is not None else "",
        "hosts": hosts,
    }