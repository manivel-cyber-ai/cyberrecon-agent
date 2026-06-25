from __future__ import annotations

import unittest

from agents.analyzer_agent import AnalyzerAgent


class AnalyzerAgentTest(unittest.TestCase):
    def test_run_flags_risky_services(self) -> None:
        analyzer = AnalyzerAgent()
        data = {
            "hosts": [
                {
                    "ports": [
                        {"portid": 23, "protocol": "tcp", "state": "open", "service": {"name": "telnet"}},
                        {"portid": 80, "protocol": "tcp", "state": "open", "service": {"name": "http"}},
                    ]
                }
            ]
        }

        analysis = analyzer.run(data)

        self.assertEqual(analysis["summary"]["open_port_count"], 2)
        self.assertTrue(any("telnet" in risk for risk in analysis["risks"]))


if __name__ == "__main__":
    unittest.main()