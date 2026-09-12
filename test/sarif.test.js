import test from "node:test";
import assert from "node:assert/strict";
import { toSarif } from "../src/sarif.js";

test("emits SARIF 2.1.0", () => {
  const sarif = toSarif({
    scanner: { version: "0.1.0" },
    target: { finalUrl: "https://example.test/" },
    findings: [{
      id: "demo",
      title: "Demo finding",
      severity: "medium",
      confidence: "high",
      category: "web-security",
      standard: "CWE-16",
      evidence: "demo",
      remediation: "fix it"
    }]
  });
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].ruleId, "demo");
});
