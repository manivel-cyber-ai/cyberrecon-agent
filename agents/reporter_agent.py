"""Reporter agent for generating markdown security reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.report_tools import render_markdown_report


@dataclass
class ReporterAgent:
    name: str = "ReporterAgent"
    output_dir: Path = Path("reports")

    def run(self, target_ip: str, analysis: dict[str, Any]) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"cyberrecon_{target_ip}_{timestamp}.md"
        report_path.write_text(render_markdown_report(target_ip, analysis), encoding="utf-8")
        return report_path