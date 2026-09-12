import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeScan } from "../src/analyze.js";
import { toSarif } from "../src/sarif.js";

function scan(cookies) {
  const headers = new Headers();
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return analyzeScan({ requestedUrl: "https://x/", finalUrl: "https://x/", status: 200, headers, html: "" });
}

test("cookie finding ids are stable and not derived from site-controlled names", () => {
  const report = scan(["PHPSESSID=a; Path=/", "tracking=b; Path=/"]);
  const ids = new Set(report.findings.filter((f) => f.id.startsWith("cookie")).map((f) => f.id));
  assert.deepEqual([...ids].sort(), ["cookie-missing-httponly", "cookie-missing-samesite", "cookie-missing-secure"]);
});

test("the concrete cookie name is still reported in title and evidence", () => {
  const report = scan(["PHPSESSID=a; Path=/"]);
  const httpOnly = report.findings.find((f) => f.id === "cookie-missing-httponly");
  assert.match(httpOnly.title, /PHPSESSID/);
  assert.match(httpOnly.evidence, /PHPSESSID/);
});

test("hostile cookie names cannot leak unsanitised characters into findings", () => {
  const report = scan(['a" onload="x=1; Path=/']);
  for (const finding of report.findings.filter((f) => f.id.startsWith("cookie"))) {
    assert.doesNotMatch(finding.title, /["<>]/, `unsanitised name in ${finding.id}: ${finding.title}`);
  }
});

test("SARIF collapses repeated cookie issues into one rule per id", () => {
  const report = scan(["sess=a; Path=/", "other=b; Path=/", "third=c; Path=/"]);
  const sarif = toSarif(report);
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.equal(new Set(ruleIds).size, ruleIds.length, "rules must be unique");
  // Three cookies each lack SameSite, so there must be more results than rules.
  const sameSiteResults = sarif.runs[0].results.filter((r) => r.ruleId === "cookie-missing-samesite");
  assert.equal(sameSiteResults.length, 3);
  assert.equal(ruleIds.filter((id) => id === "cookie-missing-samesite").length, 1);
});

test("secure flag is only required on https targets", () => {
  const headers = new Headers();
  headers.append("set-cookie", "sess=a; Path=/");
  const http = analyzeScan({ requestedUrl: "http://x/", finalUrl: "http://x/", status: 200, headers, html: "" });
  assert.equal(http.findings.some((f) => f.id === "cookie-missing-secure"), false);
});
