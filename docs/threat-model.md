# Threat model

## Assets to protect
- The machine running the scanner/MCP server.
- The model context of an MCP client.
- Secrets accidentally exposed by a scanned target.
- Third-party targets from unintended active testing.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| SSRF into localhost/private cloud networks | DNS resolution checks, blocked reserved ranges, DNS answer pinning for the actual socket connection, re-validation on every redirect |
| Oversized/unbounded response | Byte caps + timeouts |
| Indirect prompt injection via scanned HTML | Classify + hash suspicious hidden text; never return raw matched text over MCP |
| Secret leakage from `.env`/debug probes | Fingerprint only; body omitted from findings |
| Scanner becomes an exploit framework | Passive by default; small fixed authorized probes; no credential attacks, brute force, ports or exploit payloads |
| Agent misunderstands side effects | MCP tool annotations declare read-only/idempotent/open-world behavior |

## Non-goals
This project is not a pentest suite, crawler, internet-wide scanner, exploit framework, or credential-auditing tool.
