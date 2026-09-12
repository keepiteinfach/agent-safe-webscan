## What changed

## Rule/evidence impact
- Rule IDs added/changed:
- Expected false-positive impact:
- Evidence returned to MCP clients remains bounded/sanitized: yes / no / n/a

## Checklist
- [ ] Tests cover a positive case and a likely false-positive case.
- [ ] `npm test` passes.
- [ ] `npm run check` passes.
- [ ] No target secrets or raw hidden prompt-injection text are emitted.
- [ ] The change stays within the defensive scan boundaries in `SECURITY.md`.
