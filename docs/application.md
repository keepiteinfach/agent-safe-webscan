# Codex for Open Source application notes

AgentSafe WebScan is designed to be a real maintained open-source project, not a one-off application artifact.

## Why the project can matter

Coding agents increasingly consume web content and MCP tool output. A normal web scanner can accidentally become a second attack surface when untrusted page text is copied into model context. AgentSafe WebScan combines deterministic website hygiene checks with an explicit **agent-context trust boundary**: suspicious hidden instructions and potentially secret exposure bodies are classified/fingerprinted but never forwarded verbatim to the model.

## Maintainer workflow story

Codex/API credits would be used for legitimate OSS maintenance work: triaging reproducible false-positive reports, generating regression fixtures for rule changes, reviewing pull requests, drafting release notes, and maintaining compatibility with MCP protocol changes. The scanner itself does not depend on an LLM and remains deterministic.

## What to measure before applying

Do not invent adoption numbers. Collect real signals:
- GitHub stars/forks/watchers.
- npm downloads if published.
- Unique downstream users or integrations you can substantiate.
- External issues/PRs and response/merge activity.
- Tagged releases and changelog cadence.

A strong application should quote those real numbers and explain the agent-safety niche in plain language.

## Ready-to-adapt form text

### Why does this repository qualify? (448 chars before replacing placeholders)

> AgentSafe WebScan is an open-source, passive-first website security scanner built for the agent era. It detects web misconfigurations while treating scanned content as untrusted: hidden prompt-injection text and exposed-secret bodies are quarantined instead of forwarded through MCP. It provides CLI, SARIF and MCP 2026 output with SSRF/DNS-rebinding safeguards. I am the primary maintainer. Usage: [X stars / Y monthly downloads / Z integrations].

### How will you use API credits? (385 chars)

> I would use API credits for OSS maintenance: triaging reproducible false-positive reports, generating regression fixtures for new rules, reviewing community PRs, maintaining MCP compatibility, and preparing releases/changelogs. The scanner remains deterministic and does not require an LLM at runtime; Codex would support maintainer workflows rather than decide vulnerability findings.

Replace the usage placeholders only with real, verifiable numbers before submitting.
