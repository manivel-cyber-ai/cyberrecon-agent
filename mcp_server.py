"""Local MCP server exposing private-target Nmap tools."""

from __future__ import annotations

import logging
import os

from mcp.server.mcpserver import MCPServer

from tools.audit_log import record_scan_audit
from tools.mcp_server_tools import execute_scan, summarize_scan_results, validate_private_target
from tools.security import sanitize_xml_data

logging.basicConfig(level=logging.INFO)

mcp = MCPServer("CyberRecon MCP Server")


@mcp.tool()
def run_nmap_scan(target_ip: str, scan_type: str) -> str:
    """Execute Nmap against an allowed private target and return XML output."""

    validated_target = validate_private_target(target_ip)
    demo_mode = os.getenv("CYBERRECON_DEMO_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
    record_scan_audit(validated_target, "mcp.run_nmap_scan", scan_type=scan_type, status="requested")
    xml_output = execute_scan(target_ip=validated_target, scan_type=scan_type, demo_mode=demo_mode)
    record_scan_audit(validated_target, "mcp.run_nmap_scan", scan_type=scan_type, status="completed")
    return xml_output


@mcp.tool()
def parse_scan_results(xml_data: str) -> dict:
    """Parse Nmap XML and return a JSON-ready summary."""

    return summarize_scan_results(sanitize_xml_data(xml_data))


def main() -> int:
    """Run the MCP server on localhost:8080."""

    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8080,
        json_response=True,
        stateless_http=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())