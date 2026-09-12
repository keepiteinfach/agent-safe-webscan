import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeUrl, nextRedirectTarget } from "../src/fetcher.js";

const base = new URL("https://example.com/start");

test("normalizeUrl defaults to https and strips credentials and fragments", () => {
  assert.equal(normalizeUrl("example.com").toString(), "https://example.com/");
  assert.equal(normalizeUrl("https://user:pw@example.com/a#frag").toString(), "https://example.com/a");
});

test("normalizeUrl rejects non-HTTP schemes", () => {
  assert.throws(() => normalizeUrl("file:///etc/passwd"), /Only http/);
  assert.throws(() => normalizeUrl(""), /URL is required/);
});

test("followable redirects resolve relative and absolute targets", () => {
  for (const status of [301, 302, 303, 307, 308]) {
    assert.equal(nextRedirectTarget(status, "/next", base).toString(), "https://example.com/next");
  }
  assert.equal(nextRedirectTarget(302, "https://other.example/x", base).toString(), "https://other.example/x");
});

test("a 3xx without Location is terminal, not an error", () => {
  // The 0.1.0 prototype turned this into a thrown "Redirect handling failed"
  // and lost the whole scan.
  assert.equal(nextRedirectTarget(301, null, base), null);
  assert.equal(nextRedirectTarget(302, "", base), null);
});

test("non-redirect statuses are terminal even when Location is present", () => {
  assert.equal(nextRedirectTarget(200, "/next", base), null);
  assert.equal(nextRedirectTarget(304, "/next", base), null);
  assert.equal(nextRedirectTarget(201, "/created", base), null);
});

test("redirects to non-HTTP schemes are refused", () => {
  assert.throws(() => nextRedirectTarget(302, "file:///etc/passwd", base), /Refusing redirect/);
  assert.throws(() => nextRedirectTarget(302, "gopher://example.com/", base), /Refusing redirect/);
});
