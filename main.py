"""Entry point for the CyberRecon AI Agent pipeline."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

from agents.pipeline import CyberReconPipeline
from tools.security import sanitize_scan_request, sanitize_scan_type


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CyberRecon AI Agent pipeline.")
    parser.add_argument("--target", help="Target IP address to scan.")
    parser.add_argument(
        "--scan-type",
        default="version",
        choices=["syn", "connect", "udp", "version"],
        help="Validated scan preset to use.",
    )
    parser.add_argument(
        "--demo-mode",
        action="store_true",
        help="Replay a sample Nmap XML result instead of running a live scan.",
    )
    parser.add_argument("--output-dir", default="reports", help="Directory for markdown reports.")
    return parser


def main() -> int:
    load_dotenv()

    parser = build_parser()
    args = parser.parse_args()

    target_ip = args.target or os.getenv("TARGET_IP")
    if not target_ip:
        parser.error("A target IP must be provided through --target or TARGET_IP in .env")

    sanitized_request = sanitize_scan_request(target_ip=target_ip, scan_type=sanitize_scan_type(args.scan_type))
    demo_mode = args.demo_mode or os.getenv("CYBERRECON_DEMO_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}

    pipeline = CyberReconPipeline(output_dir=Path(args.output_dir))
    report_path = pipeline.run(
        target_ip=sanitized_request.target_ip,
        scan_type=sanitized_request.scan_type,
        demo_mode=demo_mode,
    )
    print(f"Report written to {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())