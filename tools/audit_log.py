"""Audit logging for CyberRecon scan activity."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _get_audit_log_path() -> Path:
    configured_path = os.getenv("CYBERRECON_AUDIT_LOG")
    if configured_path:
        return Path(configured_path)
    return Path("logs") / "security_audit.log"


def record_scan_audit(target_ip: str, user_action: str, *, scan_type: str, status: str = "requested") -> Path:
    """Append a JSON audit record for a scan request."""

    log_path = _get_audit_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_ip": target_ip,
        "user_action": user_action,
        "scan_type": scan_type,
        "status": status,
    }
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, sort_keys=True) + "\n")

    return log_path