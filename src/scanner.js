import { safeFetch, normalizeUrl } from "./fetcher.js";
import { analyzeScan } from "./analyze.js";

const PROBE_ORIGIN = "https://agentsafe.invalid";

const AUTHORIZED_PROBES = [
  {
    id: "exposed-git-head",
    path: "/.git/HEAD",
    title: "Exposed Git metadata",
    severity: "critical",
    standard: "CWE-538",
    fingerprint: (text) => /^ref:\s+refs\//m.test(text),
    fingerprintName: "git-head-ref",
    remediation: "Block access to .git at the web server/CDN layer and remove repository metadata from the document root."
  },
  {
    id: "exposed-env",
    path: "/.env",
    title: "Potentially exposed environment file",
    severity: "critical",
    standard: "CWE-200",
    fingerprint: (text) => /^(?:[A-Z][A-Z0-9_]{2,})\s*=.+$/m.test(text) && !/<html[\s>]/i.test(text),
    fingerprintName: "dotenv-key-value",
    remediation: "Remove .env files from the public document root and deny dotfile access. Rotate any exposed credentials."
  },
  {
    id: "exposed-phpinfo",
    path: "/phpinfo.php",
    title: "Public phpinfo() page",
    severity: "high",
    standard: "CWE-200",
    fingerprint: (text) => /<title>phpinfo\(\)<\/title>|PHP Version/i.test(text),
    fingerprintName: "phpinfo",
    remediation: "Remove phpinfo() pages from production."
  },
  {
    id: "exposed-server-status",
    path: "/server-status",
    title: "Public Apache server-status",
    severity: "high",
    standard: "CWE-200",
    fingerprint: (text) => /Apache Server Status for|Server Version:/i.test(text),
    fingerprintName: "apache-status",
    remediation: "Restrict mod_status to trusted administrative networks or disable it in production."
  },
  {
    id: "exposed-wp-debug-log",
    path: "/wp-content/debug.log",
    title: "Public WordPress debug log",
    severity: "high",
    standard: "CWE-532",
    fingerprint: (text) => /PHP (?:Warning|Notice|Fatal error|Deprecated)|WordPress database error/i.test(text),
    fingerprintName: "wordpress-debug-log",
    remediation: "Disable public debug logging in production and deny web access to debug.log."
  }
];

// Auxiliary probes must never fail the whole scan, but a network error is not
// the same as a 404: reporting an unreachable /.well-known/security.txt as
// "absent" states something the scan did not establish.
async function safeAuxFetch(url, options) {
  try {
    return await safeFetch(url, options);
  } catch (error) {
    return { failed: true, error: error instanceof Error ? error.message : String(error) };
  }
}

function inventory(res, test) {
  if (!res || res.failed) return { present: false, checked: false, status: null };
  return { present: isPresent(res, test), checked: true, status: res.status };
}

async function runAuthorizedProbes(baseUrl) {
  const base = new URL(baseUrl);
  const out = [];
  for (const probe of AUTHORIZED_PROBES) {
    const url = new URL(probe.path, base.origin).toString();
    const res = await safeAuxFetch(url, { maxBytes: 64_000, timeoutMs: 6_000 });
    const reachable = res && !res.failed;
    const text = reachable ? res.text : "";
    out.push({
      id: probe.id,
      path: probe.path,
      title: probe.title,
      severity: probe.severity,
      standard: probe.standard,
      remediation: probe.remediation,
      status: reachable ? res.status : null,
      matched: Boolean(reachable && res.status >= 200 && res.status < 300 && probe.fingerprint(text)),
      fingerprint: probe.fingerprintName
    });
  }
  return out;
}

function isPresent(res, test = () => true) {
  return Boolean(res && !res.failed && res.status >= 200 && res.status < 300 && test(res.text));
}

export async function scanSite(input, options = {}) {
  const mode = options.mode === "authorized" ? "authorized" : "passive";
  const requested = normalizeUrl(input);
  const main = await safeFetch(requested, { maxBytes: 768_000, timeoutMs: 10_000 });
  const final = new URL(main.url);

  const [cors, securityTxt, llmsTxt] = await Promise.all([
    safeAuxFetch(final, { maxBytes: 8_000, timeoutMs: 6_000, headers: { Origin: PROBE_ORIGIN } }),
    safeAuxFetch(new URL("/.well-known/security.txt", final.origin), { maxBytes: 32_000, timeoutMs: 6_000 }),
    safeAuxFetch(new URL("/llms.txt", final.origin), { maxBytes: 32_000, timeoutMs: 6_000 })
  ]);

  const probes = mode === "authorized" ? await runAuthorizedProbes(final) : [];
  const securityTxtInfo = inventory(securityTxt, (text) => /\bContact\s*:/i.test(text));
  const llmsTxtInfo = inventory(llmsTxt, (text) => text.trim().length > 0 && !/<html[\s>]/i.test(text));
  const mcpHints = [...main.text.matchAll(/(?:href|src)=["']([^"']*(?:\/mcp\b|modelcontextprotocol)[^"']*)["']/gi)]
    .slice(0, 5)
    .map((m) => {
      try { return new URL(m[1], final).pathname; } catch { return "mcp-reference"; }
    });

  const report = analyzeScan({
    requestedUrl: main.requestedUrl,
    finalUrl: main.url,
    status: main.status,
    headers: main.headers,
    html: main.text,
    aux: {
      mode,
      cors,
      probeOrigin: PROBE_ORIGIN,
      securityTxt: securityTxtInfo,
      aiSurface: {
        llmsTxt: llmsTxtInfo,
        mcpReferences: [...new Set(mcpHints)]
      }
    },
    probes
  });

  return {
    ...report,
    timing: { durationMs: main.durationMs },
    response: { bytesInspected: main.bytes, truncated: main.truncated },
    note: mode === "authorized"
      ? "Authorized mode uses a small, fixed set of GET probes. Run it only against systems you own or are authorized to test."
      : "Passive mode is the default. It avoids exploit payloads, authentication attacks, brute force, port scans, and subdomain enumeration."
  };
}

export function mcpSafeReport(report) {
  return {
    schemaVersion: report.schemaVersion,
    scanner: report.scanner,
    target: report.target,
    summary: report.summary,
    technologies: report.technologies,
    securityTxt: report.securityTxt,
    aiSurface: report.aiSurface,
    safety: report.safety,
    findings: report.findings.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      standard: f.standard,
      evidence: f.evidence,
      remediation: f.remediation
    }))
  };
}
