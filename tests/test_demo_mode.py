from __future__ import annotations

import unittest
from pathlib import Path

from tools.nmap_tools import DEMO_XML_PATH, parse_nmap_xml, run_nmap_scan_with_mode


class DemoModeTest(unittest.TestCase):
    def test_demo_xml_fixture_exists(self) -> None:
        self.assertTrue(DEMO_XML_PATH.exists())

    def test_demo_mode_returns_sample_xml(self) -> None:
        xml_text = run_nmap_scan_with_mode("192.168.1.1", demo_mode=True)
        parsed = parse_nmap_xml(xml_text)

        self.assertEqual(parsed["hosts"][0]["addresses"][0]["addr"], "192.168.1.1")
        self.assertEqual(parsed["hosts"][0]["ports"][0]["portid"], 22)


if __name__ == "__main__":
    unittest.main()