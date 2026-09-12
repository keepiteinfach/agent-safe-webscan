# Architecture

AgentSafe WebScan has three deliberately small layers:

1. **Safe fetch boundary** — normalizes URLs, rejects local/private targets, re-checks redirect destinations and pins the validated DNS address for each request, caps response sizes and timeouts.
2. **Deterministic analyzer** — produces structured findings with severity, confidence, evidence, standards mapping, and remediation.
3. **Adapters** — CLI, SARIF, and MCP all consume the same report object.

## Agent-context safety

A security scanner exposed over MCP can become an indirect prompt-injection channel if it returns arbitrary page text to the model. AgentSafe WebScan therefore treats all page content as hostile. The hidden-instruction detector returns only classification labels and a short SHA-256 fingerprint, never the matched raw instruction text.

## Scan modes

`passive` performs the homepage fetch, a CORS behavior check, and a `security.txt` check. `authorized` adds a small fixed set of read-only exposure probes such as `/.git/HEAD` and `/.env`, but reports only whether a known fingerprint matched. It never returns secrets from those files.
