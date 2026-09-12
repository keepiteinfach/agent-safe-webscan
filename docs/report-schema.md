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

Rule ids are stable across targets. Where one rule can fire several times on
one page — every `cookie-*` rule, for example — the id stays fixed and the
specific subject is named in `title` and `evidence`. SARIF therefore emits one
`rule` per id and one `result` per finding, and the rule carries the highest
severity any of its results reports.

Inventory objects (`securityTxt`, `aiSurface.llmsTxt`) carry three fields:
- `checked` — whether the probe reached the target at all.
- `present` — whether the file was found. Only meaningful when `checked` is true.
- `status` — the HTTP status, or `null` when the probe did not complete.

A network error is reported as `checked: false`, not as `present: false`: an
unreachable target is not evidence of absence.

`coverage` records what the scan actually managed to assess:
- `probesRun` / `probesTotal` — authorized exposure probes that completed.
- `incomplete` — probes that never reached the target, with the reason.
- `responseTruncated` — whether the main response hit the byte cap.

An exposure probe that could not be completed also emits an `info` finding
(`probe-incomplete`). Without it, a transient connection reset during an
authorized scan would leave a clean-looking report for a path that was never
actually checked.
