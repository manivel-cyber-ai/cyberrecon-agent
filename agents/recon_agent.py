"""Recon agent responsible for executing and parsing Nmap scans."""

from __future__ import annotations

from dataclasses import dataclass

from tools.nmap_tools import parse_nmap_xml, run_nmap_scan


@dataclass
class ReconAgent:
    name: str = "ReconAgent"

    def run(self, target_ip: str, nmap_args: str = "-sV -oX -") -> dict:
        xml_output = run_nmap_scan(target_ip=target_ip, nmap_args=nmap_args)
        return parse_nmap_xml(xml_output)