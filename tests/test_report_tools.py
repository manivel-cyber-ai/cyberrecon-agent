from __future__ import annotations

import unittest

from tools.report_tools import render_markdown_report


class ReportToolsTest(unittest.TestCase):
    def test_render_markdown_report_contains_sections(self) -> None:
        report = render_markdown_report(
            "192.0.2.10",
            {
                "summary": {"host_count": 1, "open_port_count": 1, "service_count": 1},
                "open_ports": [{"portid": 80, "protocol": "tcp", "service": {"name": "http", "product": "Apache"}}],
                "risks": ["Example risk"],
                "recommendations": ["Example recommendation"],
            },
        )

        self.assertIn("# CyberRecon Security Report for 192.0.2.10", report)
        self.assertIn("## Open Ports", report)
        self.assertIn("Example risk", report)


if __name__ == "__main__":
    unittest.main()