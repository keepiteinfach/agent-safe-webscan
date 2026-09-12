import http from "node:http";
import https from "node:https";
import { resolvePublicHostname } from "./ip.js";

const DEFAULT_UA = "AgentSafe-WebScan/0.1 (+https://github.com/keepiteinfach/agent-safe-webscan)";

export function normalizeUrl(input) {
  const raw = String(input ?? "").trim();
  if (!raw) throw new Error("URL is required");
  const value = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only http:// and https:// URLs are supported");
  url.username = "";
  url.password = "";
  url.hash = "";
  return url;
}

function toHeaders(nodeHeaders) {
  const out = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (Array.isArray(value)) for (const item of value) out.append(name, item);
    else if (value !== undefined) out.append(name, String(value));
  }
  return out;
}

function requestOnePinned(url, selected, options) {
  const transport = url.protocol === "https:" ? https : http;
  const method = options.method ?? "GET";
  const maxBytes = options.maxBytes ?? 512_000;
  const signal = options.signal;

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    const req = transport.request(url, {
      method,
      signal,
      headers: {
        "user-agent": DEFAULT_UA,
        accept: "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.1",
        "accept-encoding": "identity",
        ...options.headers
      },
      // Pin the already-validated DNS answer. This closes the usual DNS-rebinding
      // time-of-check/time-of-use gap in SSRF filters while preserving Host/SNI.
      lookup: (_hostname, lookupOptions, callback) => {
        if (lookupOptions?.all) callback(null, [{ address: selected.address, family: selected.family }]);
        else callback(null, selected.address, selected.family);
      }
    }, (res) => {
      const headers = toHeaders(res.headers);
      const status = res.statusCode ?? 0;
      if (method === "HEAD") {
        res.resume();
        finish(resolve, { status, headers, text: "", bytes: 0, truncated: false, family: selected.family });
        return;
      }

      const chunks = [];
      let total = 0;
      let truncated = false;
      res.on("data", (chunk) => {
        if (settled) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = maxBytes - total;
        if (remaining <= 0) {
          truncated = true;
          res.destroy();
          return;
        }
        if (buf.length > remaining) {
          chunks.push(buf.subarray(0, remaining));
          total += remaining;
          truncated = true;
          res.destroy();
          return;
        }
        chunks.push(buf);
        total += buf.length;
      });
      const resolveBody = () => finish(resolve, {
        status,
        headers,
        family: selected.family,
        text: Buffer.concat(chunks, total).toString("utf8"),
        bytes: total,
        truncated
      });
      res.on("end", resolveBody);
      res.on("close", () => {
        if (truncated) resolveBody();
      });
      res.on("error", (error) => {
        if (truncated) resolveBody();
        else finish(reject, error);
      });
    });

    req.on("error", (error) => finish(reject, error));
    req.end();
  });
}

const MAX_ADDRESS_ATTEMPTS = 3;

// Combines the scan deadline with any signal the caller passed in, so an
// externally cancelled request is not silently ignored.
function combineSignals(deadline, external) {
  if (!external) return deadline;
  return typeof AbortSignal.any === "function" ? AbortSignal.any([deadline, external]) : deadline;
}

// Every address in `resolved` has already passed the public-IP check. Trying
// them in order keeps multi-homed hosts reachable when the first record is
// unhealthy, without ever widening what the SSRF guard allowed.
//
// All attempts share one deadline and are capped in number, so a host with
// many blackholed records cannot multiply the caller's timeout budget.
async function requestPinned(url, resolved, options) {
  const signal = combineSignals(options.deadline, options.signal);
  const candidates = resolved.slice(0, MAX_ADDRESS_ATTEMPTS);
  let lastError = null;

  for (const selected of candidates) {
    if (signal.aborted) break;
    try {
      return await requestOnePinned(url, selected, { ...options, signal });
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error(`No usable address for ${url.hostname}`);
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Decides whether a response is a followable redirect and where it points.
 * Exported so the redirect rules can be tested without network access.
 *
 * Returns `null` when the response is terminal — including a 3xx that carries
 * no Location header, which cannot be followed and is therefore reported like
 * any other response rather than failing the scan.
 */
export function nextRedirectTarget(status, location, current) {
  if (!REDIRECT_STATUSES.has(status) || !location) return null;
  const target = new URL(location, current);
  if (!["http:", "https:"].includes(target.protocol)) {
    throw new Error(`Refusing redirect to ${target.protocol}`);
  }
  return target;
}

export async function safeFetch(input, options = {}) {
  let current = normalizeUrl(input);
  const method = options.method ?? "GET";
  const maxRedirects = options.maxRedirects ?? 5;
  const started = Date.now();

  // One deadline for the whole call. Creating it per hop let a redirect chain
  // multiply the caller's budget by the number of hops.
  const deadline = AbortSignal.timeout(options.timeoutMs ?? 8_000);

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const resolved = await resolvePublicHostname(current.hostname, { signal: deadline });
    const response = await requestPinned(current, resolved, { ...options, method, deadline });

    const target = nextRedirectTarget(response.status, response.headers.get("location"), current);
    if (target) {
      if (hop === maxRedirects) throw new Error(`Too many redirects (>${maxRedirects})`);
      current = target;
      continue;
    }

    return {
      requestedUrl: normalizeUrl(input).toString(),
      url: current.toString(),
      status: response.status,
      headers: response.headers,
      text: response.text,
      bytes: response.bytes,
      truncated: response.truncated,
      durationMs: Date.now() - started,
      network: { dnsPinned: true, resolvedAddressFamily: response.family ?? null }
    };
  }
  throw new Error(`Too many redirects (>${maxRedirects})`);
}
