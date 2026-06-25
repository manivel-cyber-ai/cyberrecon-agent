# CyberRecon Security Context

## Mandatory Security Rules

- Validate every user-supplied value before it reaches any agent, MCP tool, or file writer.
- Accept target IPs only from `10.0.0.0/8`, `192.168.0.0/16`, and `127.0.0.0/8`.
- Reject public IPv4 and all IPv6 targets with a clear error message.
- Allow only approved scan types that map to safe Nmap argument presets.
- Do not accept free-form Nmap arguments from users or agents.
- Treat XML input as untrusted and reject empty, oversized, or non-XML payloads before parsing.
- Record every scan in the security audit log with timestamp, target IP, user action, scan type, and status.
- Never hardcode API keys, tokens, passwords, private keys, or other credentials in source files.
- Keep secrets only in `.env` or another ignored local secret store.
- Do not print credentials or secret values in logs, reports, or exceptions.
- Prefer explicit, minimal error messages that do not leak sensitive environment details.

## Audit Logging

- Audit logs are written as JSON lines.
- Default path: `logs/security_audit.log`.
- The log path may be overridden with `CYBERRECON_AUDIT_LOG` for local testing.

## Approved Inputs

- Target IP: sanitized private IPv4 only.
- Scan type: `syn`, `connect`, `udp`, or `version`.
- XML data: only validated Nmap XML produced by the tool or a trusted source.