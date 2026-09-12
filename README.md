# AgentSafe WebScan

[![ci](https://github.com/keepiteinfach/agent-safe-webscan/actions/workflows/ci.yml/badge.svg)](https://github.com/keepiteinfach/agent-safe-webscan/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A522-brightgreen.svg)](package.json)

**Agent-safe, passive-first website security scanning for humans, CI, and coding agents.**

📄 [Project page](https://keepiteinfach.github.io/agent-safe-webscan/)

AgentSafe WebScan turns a public URL into a compact, evidence-based security report and exposes the same deterministic scanner through a CLI, JSON, SARIF 2.1.0, and MCP. It is intentionally narrower than a pentest suite: no exploit chains, no credential attacks, no port scanning, no subdomain brute force.

The project grew out of a larger internal website-audit tool and was rebuilt as a small open-source core with stricter safety boundaries.

## The different part: the scanner is an agent trust boundary

Once a scanner is exposed through MCP, website content can flow into a coding agent. That creates an indirect prompt-injection path that classic website scanners were not designed around.

AgentSafe WebScan therefore adds two agent-native controls:

- **Quarantined evidence:** suspicious hidden instructions are classified and SHA-256 fingerprinted, not returned verbatim to the model. Potential `.env`/debug-log contents are also never emitted.
- **MCP-native structured findings:** agents receive bounded fields (`severity`, `confidence`, `standard`, `evidence`, `remediation`) plus read-only/idempotent/open-world tool annotations instead of an arbitrary page dump.
- **Honest coverage:** the report separates "checked and clean" from "could not check". An agent acting on the result can tell the difference.

It also includes SSRF guards, redirect re-validation and DNS pinning, response-size caps, timeouts, and passive-by-default behavior.

## Current checks

| Area | Examples |
| --- | --- |
| Headers | HSTS, CSP, clickjacking protection, nosniff, Referrer-Policy, version disclosure |
| Cookies | Secure, HttpOnly for session-like cookies, SameSite |
| CORS | Arbitrary Origin reflection and credentialed reflection |
| Frontend | Mixed content, old jQuery, third-party scripts without SRI |
| Agent security | Hidden/comment prompt-injection heuristics, Unicode obfuscation, content withholding |
| Exposure (`--authorized`) | `.git/HEAD`, `.env`, `phpinfo.php`, Apache `server-status`, WordPress `debug.log` |
| Hygiene | `security.txt`, lightweight technology fingerprinting |
| AI surface inventory | `llms.txt` presence and MCP references found in the page |

Findings separate **severity** from **confidence** so a heuristic signal is not presented as a confirmed vulnerability.

## Quick start

Requires Node.js 22+.

```bash
npm install
npm run scan -- https://example.com
```

JSON:

```bash
npm run scan -- https://example.com --format json
```

SARIF for CI/code-scanning pipelines:

```bash
npm run scan -- https://example.com --format sarif > agent-safe-webscan.sarif
```

Authorized exposure checks — only for systems you own or have explicit permission to test:

```bash
npm run scan -- https://your-site.example --authorized
```

Fail CI when a finding meets a threshold:

```bash
npm run scan -- https://your-site.example --fail-on high
```

## MCP

The server uses MCP's current v2 TypeScript server package and `serveStdio`, which is the SDK path for the modern 2026 protocol era while retaining compatible negotiation behavior.

```bash
npm run mcp
```

Tools:

- `scan_site` — scan a URL in `passive` or `authorized` mode.
- `scanner_policy` — inspect scanner boundaries without making a network request.

Example local registration pattern:

```bash
codex mcp add agent-safe-webscan -- node /absolute/path/to/agent-safe-webscan/src/mcp.js
```

An agent can then ask:

```text
Scan https://example.com in passive mode and turn only the structured findings into a prioritized remediation plan.
```

## Example output

```text
AgentSafe WebScan 0.1.0 · passive
https://example.com/ · HTTP 200 · score 72/100 (C)

[MEDIUM] Content Security Policy is missing
  Content-Security-Policy header not present
  Fix: Deploy a restrictive CSP and iterate with report-only mode first.

[LOW] Referrer-Policy is missing
  Referrer-Policy header not present
```

## Safety model

- Public HTTP(S) targets only.
- Private/reserved IP ranges and local hostnames are rejected; validated DNS answers are pinned for the actual request to reduce rebinding risk.
- Every redirect destination is resolved and checked again.
- Responses are bounded by byte limits and timeouts.
- No login attempts, brute force, port scans, subdomain brute force, or exploit payloads.
- Exposure checks are opt-in via `--authorized`.
- `.env`/debug responses are fingerprinted but contents are never included in findings.
- Hidden agent-directed instructions are hashed rather than returned raw over MCP.
- A check that could not be completed is reported as such. An unreachable path is never
  presented to the agent as a clean result — see the `coverage` object and the
  `probe-incomplete` finding.

See [`docs/threat-model.md`](docs/threat-model.md) for the compact threat model.

## Architecture

```text
Public URL
   │
   ▼
Safe fetch boundary ── SSRF guard / redirect validation / byte + time caps
   │
   ▼
Deterministic analyzer ── web findings + agent-context findings
   │
   ├────────► CLI / JSON
   ├────────► SARIF 2.1.0
   └────────► MCP (sanitized structured report only)
```

See [`docs/architecture.md`](docs/architecture.md) for details.

## Development

```bash
npm test
npm run check
```

The analyzer does not require an LLM or remote vulnerability database, keeping local results deterministic and reviewable.

## Contributing

PRs are welcome. New rules should be bounded, low-noise, have stable IDs, return no secrets, and include regression tests. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Open-source application notes

The repository includes [`docs/application.md`](docs/application.md) with an honest maintainer/adoption checklist. Do not claim stars, downloads, or users that the project does not actually have.

## License

MIT
