from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.audit_log import record_scan_audit
from tools.security import sanitize_scan_request, sanitize_scan_type, sanitize_target_ip, sanitize_xml_data


class SecurityValidationTest(unittest.TestCase):
    def test_sanitize_target_ip_accepts_private_ip(self) -> None:
        self.assertEqual(sanitize_target_ip(" 10.0.0.5 "), "10.0.0.5")

    def test_sanitize_target_ip_rejects_public_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "not allowed"):
            sanitize_target_ip("8.8.8.8")

    def test_sanitize_scan_type_rejects_unknown_scan(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported scan_type"):
            sanitize_scan_type("--script=evil")

    def test_sanitize_xml_data_rejects_non_xml(self) -> None:
        with self.assertRaisesRegex(ValueError, "must begin with an XML element"):
            sanitize_xml_data("not xml")

    def test_sanitize_scan_request_returns_normalized_values(self) -> None:
        request = sanitize_scan_request("192.168.1.10", "version")
        self.assertEqual(request.target_ip, "192.168.1.10")
        self.assertEqual(request.scan_type, "version")

    def test_record_scan_audit_writes_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = Path(temp_dir) / "audit.log"
            os.environ["CYBERRECON_AUDIT_LOG"] = str(audit_path)
            try:
                written_path = record_scan_audit("192.168.1.10", "unit-test", scan_type="syn", status="requested")
            finally:
                os.environ.pop("CYBERRECON_AUDIT_LOG", None)

            self.assertEqual(written_path, audit_path)
            contents = audit_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(contents), 1)
            record = json.loads(contents[0])
            self.assertEqual(record["target_ip"], "192.168.1.10")
            self.assertEqual(record["user_action"], "unit-test")
            self.assertEqual(record["scan_type"], "syn")


if __name__ == "__main__":
    unittest.main()