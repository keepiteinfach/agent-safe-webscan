# Security policy

AgentSafe WebScan is a security tool, so false positives and scanner-side vulnerabilities matter.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could expose users or targets. Contact the maintainer privately first and include a minimal reproduction, affected version, and impact.

## Scanner boundaries

- Public HTTP(S) targets only.
- Private, loopback, link-local and reserved network targets are rejected.
- Redirect hops are re-validated before fetching.
- Passive mode is the default.
- Authorized mode uses only a small, fixed set of GET probes; it performs no exploit payloads, authentication attacks, brute force, port scanning, or subdomain brute force.
- Suspicious hidden agent instructions are never returned verbatim through MCP.

Only scan systems you own or are explicitly authorized to test.
