# Changelog

## Unreleased
- MCP server was unable to start; `serveStdio` returns a handle, not a promise.
- Both MCP tools now publish an `outputSchema`, so `structuredContent` is contractual.
- Report contract: inventory objects (`securityTxt`, `aiSurface.llmsTxt`) gained a
  required `checked` field and `status` is no longer optional. A probe that could
  not reach the target is reported as `checked: false` rather than `present: false`.
- New `coverage` object plus a `probe-incomplete` finding: an exposure check that
  never completed is no longer indistinguishable from a clean result.
- Cookie rules use stable ids (`cookie-missing-secure` and friends) instead of
  embedding the scanned site's cookie name, so SARIF groups them as one rule.
- CLI accepts flags and the URL in any order, and rejects an unknown `--fail-on`
  threshold instead of silently passing the CI gate.
- One timeout budget per `safeFetch` call, covering DNS, every redirect hop and
  every address attempt.
- A 3xx response without `Location` is reported instead of failing the scan.

## 0.1.0 — prototype
- Passive-first web security scan with severity + confidence.
- SSRF-safe fetch boundary and redirect re-validation.
- Header, cookie, CORS, mixed-content, jQuery, SRI, and `security.txt` checks.
- Agent-context checks that quarantine hidden prompt-injection evidence instead of forwarding raw text.
- Unicode obfuscation signal for hidden agent-directed content.
- Optional authorized exposure fingerprints for `.git`, `.env`, `phpinfo`, `server-status`, and WordPress debug logs.
- CLI, JSON, SARIF 2.1.0, and MCP server interfaces.
- Lightweight AI-surface inventory for `llms.txt` and MCP references.
