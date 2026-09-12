# Report contract (schemaVersion 0.1)

Every interface consumes the same deterministic report. MCP returns a sanitized subset.

Core finding fields:
- `id` — stable rule identifier.
- `title` — short human-readable title.
- `severity` — `critical|high|medium|low|info`.
- `confidence` — independent confidence signal such as `high|medium|heuristic`.
- `category` — e.g. `web-security`, `exposure`, `agent-security`.
- `standard` — optional CWE/OWASP mapping.
- `evidence` — bounded evidence; never raw hidden prompt-injection or exposed secret bodies.
- `remediation` — actionable fix guidance.

The `safety` object makes scanner guarantees machine-readable, including SSRF protection and evidence quarantine.
