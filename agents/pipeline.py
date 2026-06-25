"""Simple orchestration pipeline for the three CyberRecon agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agents.analyzer_agent import AnalyzerAgent
from agents.recon_agent import ReconAgent
from agents.reporter_agent import ReporterAgent
from tools.audit_log import record_scan_audit
from tools.mcp_server_tools import build_nmap_arguments, execute_scan
from tools.security import sanitize_scan_request


@dataclass
class CyberReconPipeline:
    output_dir: Path = Path("reports")
    recon_agent: ReconAgent = field(default_factory=ReconAgent)
    analyzer_agent: AnalyzerAgent = field(default_factory=AnalyzerAgent)
    reporter_agent: ReporterAgent = field(init=False)

    def __post_init__(self) -> None:
        self.reporter_agent = ReporterAgent(output_dir=self.output_dir)

    def run(self, target_ip: str, scan_type: str = "version", demo_mode: bool = False) -> Path:
        sanitized_request = sanitize_scan_request(target_ip=target_ip, scan_type=scan_type)
        record_scan_audit(sanitized_request.target_ip, "pipeline.run", scan_type=sanitized_request.scan_type, status="requested")

        if demo_mode:
            scan_data = execute_scan(
                target_ip=sanitized_request.target_ip,
                scan_type=sanitized_request.scan_type,
                demo_mode=True,
            )
        else:
            scan_data = self.recon_agent.run(
                target_ip=sanitized_request.target_ip,
                nmap_args=build_nmap_arguments(sanitized_request.scan_type),
            )
        analysis = self.analyzer_agent.run(scan_data)
        record_scan_audit(sanitized_request.target_ip, "pipeline.run", scan_type=sanitized_request.scan_type, status="completed")
        return self.reporter_agent.run(target_ip=sanitized_request.target_ip, analysis=analysis)