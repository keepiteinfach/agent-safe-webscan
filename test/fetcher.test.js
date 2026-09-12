import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeUrl, nextRedirectTarget, safeFetch } from "../src/fetcher.js";
import { resolvePublicHostname } from "../src/ip.js";

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

// The SSRF guard refuses loopback by design, so this budget check cannot use a
// local server and needs a real multi-address, redirecting host. It must not
// pass for the wrong reason on a runner without egress, so the rejection is
// asserted to be a timeout and the test skips when DNS is unavailable.
const networkProbe = await resolvePublicHostname("github.com").then(() => null, (error) => error.message);

test("the timeout budget covers the whole call, not each hop or address", { skip: networkProbe ? `no network: ${networkProbe}` : false }, async () => {
  const budgetMs = 120;
  const started = Date.now();
  await assert.rejects(
    () => safeFetch("http://github.com", { timeoutMs: budgetMs }),
    (error) => {
      // Anything else (DNS failure, connection refused) would make this test
      // green without exercising the deadline at all.
      assert.match(error.message, /abort|Timed out/i, `expected a timeout, got: ${error.message}`);
      return true;
    }
  );
  const elapsed = Date.now() - started;
  // The point is a small multiple of the budget, not 6 hops x 3 addresses.
  assert.ok(elapsed < budgetMs * 6, `took ${elapsed}ms on a ${budgetMs}ms budget`);
});

test("DNS resolution is bounded by the deadline", async () => {
  const aborted = AbortSignal.abort();
  await assert.rejects(() => resolvePublicHostname("example.com", { signal: aborted }), /Timed out/);
});

test("the SSRF guard still rejects private targets and local names", async () => {
  for (const host of ["localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254", "foo.internal", "[::1]"]) {
    await assert.rejects(() => resolvePublicHostname(host.replace(/[[\]]/g, "")), /Refusing/, `${host} must be refused`);
  }
});
