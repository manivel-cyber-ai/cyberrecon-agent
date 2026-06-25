"""Markdown report rendering helpers."""

from __future__ import annotations

from typing import Any


def render_markdown_report(target_ip: str, analysis: dict[str, Any]) -> str:
    summary = analysis.get("summary", {})
    open_ports = analysis.get("open_ports", [])
    risks = analysis.get("risks", [])
    recommendations = analysis.get("recommendations", [])

    lines = [
        f"# CyberRecon Security Report for {target_ip}",
        "",
        "## Executive Summary",
        f"- Hosts discovered: {summary.get('host_count', 0)}",
        f"- Open ports discovered: {summary.get('open_port_count', 0)}",
        f"- Services identified: {summary.get('service_count', 0)}",
        "",
        "## Open Ports",
    ]

    if open_ports:
        for port in open_ports:
            service = port.get("service") or {}
            lines.append(
                f"- {port.get('portid')}/{port.get('protocol')} - {service.get('name', 'unknown')} "
                f"({service.get('product', 'no product info')})"
            )
    else:
        lines.append("- No open ports were reported.")

    lines.extend([
        "",
        "## Potential Risks",
    ])

    if risks:
        lines.extend(f"- {risk}" for risk in risks)
    else:
        lines.append("- No obvious service risks were flagged by the analyzer.")

    lines.extend([
        "",
        "## Recommendations",
    ])

    lines.extend(f"- {recommendation}" for recommendation in recommendations)

    return "\n".join(lines) + "\n"