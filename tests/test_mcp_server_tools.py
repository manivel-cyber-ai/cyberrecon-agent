from __future__ import annotations

import unittest

from tools.mcp_server_tools import build_nmap_arguments, summarize_scan_results, validate_private_target


class MCPServerToolsTest(unittest.TestCase):
    def test_validate_private_target_accepts_private_ip(self) -> None:
        self.assertEqual(str(validate_private_target("192.168.1.20")), "192.168.1.20")

    def test_validate_private_target_rejects_public_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "not allowed"):
            validate_private_target("8.8.8.8")

    def test_build_nmap_arguments_maps_scan_types(self) -> None:
        self.assertEqual(build_nmap_arguments("syn"), "-sS -sV -oX -")

    def test_summarize_scan_results_returns_json_ready_summary(self) -> None:
        xml_text = """<?xml version='1.0'?>
<nmaprun scanner='nmap' args='-sS -sV -oX -'>
  <scaninfo type='syn' protocol='tcp' numservices='1' services='80'/>
  <host>
    <status state='up'/>
    <address addr='192.168.1.20' addrtype='ipv4'/>
    <ports>
      <port protocol='tcp' portid='80'>
        <state state='open'/>
        <service name='http' product='Apache httpd' version='2.4'/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

        summary = summarize_scan_results(xml_text)

        self.assertEqual(summary["host_count"], 1)
        self.assertEqual(summary["open_port_count"], 1)
        self.assertEqual(summary["services"], ["http"])
        self.assertEqual(summary["hosts"][0]["open_ports"][0]["portid"], 80)


if __name__ == "__main__":
    unittest.main()