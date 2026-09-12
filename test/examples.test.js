import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toSarif } from "../src/sarif.js";
import { reportSchema } from "../src/mcp.js";

const read = (name) => JSON.parse(readFileSync(fileURLToPath(new URL(`../examples/${name}`, import.meta.url)), "utf8"));

// These files are shipped and linked from the README. They drifted twice while
// the report shape changed, so the contract is asserted rather than remembered.
test("examples/sample-report.json still matches the published report schema", () => {
  const parsed = reportSchema.safeParse(read("sample-report.json"));
  assert.ok(parsed.success, `example drifted from reportSchema: ${JSON.stringify(parsed.error?.issues, null, 2)}`);
});

test("examples/sample-report.sarif is exactly what toSarif produces today", () => {
  const expected = `${JSON.stringify(toSarif(read("sample-report.json")), null, 2)}\n`;
  const actual = readFileSync(fileURLToPath(new URL("../examples/sample-report.sarif", import.meta.url)), "utf8");
  assert.equal(actual, expected, "regenerate with: node -e \"...toSarif...\"");
});
