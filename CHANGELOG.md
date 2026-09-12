# Changelog

## 0.1.0 — prototype
- Passive-first web security scan with severity + confidence.
- SSRF-safe fetch boundary and redirect re-validation.
- Header, cookie, CORS, mixed-content, jQuery, SRI, and `security.txt` checks.
- Agent-context checks that quarantine hidden prompt-injection evidence instead of forwarding raw text.
- Unicode obfuscation signal for hidden agent-directed content.
- Optional authorized exposure fingerprints for `.git`, `.env`, `phpinfo`, `server-status`, and WordPress debug logs.
- CLI, JSON, SARIF 2.1.0, and MCP server interfaces.
- Lightweight AI-surface inventory for `llms.txt` and MCP references.
