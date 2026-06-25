from __future__ import annotations

import unittest

from tools.nmap_tools import parse_nmap_xml


class NmapToolsTest(unittest.TestCase):
    def test_parse_nmap_xml_extracts_ports(self) -> None:
        xml_text = """<?xml version='1.0'?>
<nmaprun scanner='nmap' args='-sV -oX -'>
  <scaninfo type='syn' protocol='tcp' numservices='1' services='80'/>
  <host>
    <status state='up'/>
    <address addr='192.0.2.10' addrtype='ipv4'/>
    <ports>
      <port protocol='tcp' portid='80'>
        <state state='open'/>
        <service name='http' product='Apache httpd'/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

        parsed = parse_nmap_xml(xml_text)

        self.assertEqual(parsed["scanner"], "nmap")
        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(parsed["hosts"][0]["ports"][0]["portid"], 80)
        self.assertEqual(parsed["hosts"][0]["ports"][0]["service"]["name"], "http")


if __name__ == "__main__":
    unittest.main()