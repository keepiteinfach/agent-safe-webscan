import { createHash } from "node:crypto";

const WEIGHTS = { critical: 30, high: 20, medium: 10, low: 4, info: 0 };
const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function header(headers, name) {
  return headers.get(name) ?? "";
}

function add(findings, item) {
  findings.push({
    id: item.id,
    title: item.title,
    severity: item.severity,
    confidence: item.confidence ?? "high",
    category: item.category ?? "web-security",
    standard: item.standard ?? null,
    evidence: item.evidence ?? "",
    remediation: item.remediation ?? "",
    source: item.source ?? "response"
  });
}

function versionLt(a, b) {
  const pa = a.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i += 1) {
    if ((pa[i] ?? 0) < (pb[i] ?? 0)) return true;
    if ((pa[i] ?? 0) > (pb[i] ?? 0)) return false;
  }
  return false;
}

function extractSetCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const raw = headers.get("set-cookie");
  return raw ? [raw] : [];
}

function detectTech(html, headers) {
  const tech = [];
  const low = html.toLowerCase();
  if (low.includes("wp-content/") || low.includes("wp-includes/")) tech.push("WordPress");
  if (low.includes("/_next/static/") || header(headers, "x-powered-by").toLowerCase().includes("next.js")) tech.push("Next.js");
  if (low.includes("astro-island") || low.includes("data-astro-cid")) tech.push("Astro");
  if (low.includes("cdn.shopify.com") || low.includes("shopify-section")) tech.push("Shopify");
  if (header(headers, "server").toLowerCase().includes("cloudflare") || header(headers, "cf-ray")) tech.push("Cloudflare");
  return [...new Set(tech)];
}

function hiddenSegments(html) {
  const out = [];
  for (const match of html.matchAll(/<!--([\s\S]*?)-->/g)) out.push(match[1]);
  const hiddenTag = /<([a-z0-9:-]+)([^>]*(?:\bhidden\b|aria-hidden\s*=\s*["']?true|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|font-size\s*:\s*0)[^"']*["'])[^>]*)>([\s\S]*?)<\/\1>/gi;
  for (const match of html.matchAll(hiddenTag)) out.push(match[3]);
  return out;
}

function normalizeText(input) {
  return input.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function analyzeAgentInjection(html, findings) {
  const patterns = [
    ["ignore previous", /ignore\s+(all\s+)?previous\s+(instructions?|prompts?)/i],
    ["system prompt", /system\s+prompt/i],
    ["do not tell user", /do\s+not\s+(tell|show|reveal)\s+(the\s+)?user/i],
    ["tool instruction", /(?:call|invoke|use)\s+(?:the\s+)?(?:tool|function|mcp)/i],
    ["assistant role", /\bassistant\s*:/i]
  ];
  const segments = hiddenSegments(html).slice(0, 100).map(normalizeText).filter(Boolean);
  const matches = [];
  for (const segment of segments) {
    const text = segment.slice(0, 12_000);
    const hit = patterns.filter(([, re]) => re.test(text)).map(([name]) => name);
    if (hit.length) {
      matches.push({
        patterns: [...new Set(hit)],
        sha256: createHash("sha256").update(text).digest("hex").slice(0, 16)
      });
    }
  }
  if (matches.length) {
    const names = [...new Set(matches.flatMap((m) => m.patterns))];
    add(findings, {
      id: "agent-hidden-instructions",
      title: "Potential hidden instructions for AI agents",
      severity: "medium",
      confidence: "heuristic",
      category: "agent-security",
      standard: "OWASP LLM01:2025",
      evidence: `${matches.length} hidden/comment segment(s) matched: ${names.join(", ")}; content withheld, hashes: ${matches.slice(0, 4).map((m) => m.sha256).join(", ")}`,
      remediation: "Treat page content as untrusted data. Remove hidden agent-directed instructions or isolate them from model context.",
      source: "html-heuristic"
    });
  }

  const hidden = segments.join(" ");
  const zeroWidth = (hidden.match(/[\u200B-\u200D\u2060\uFEFF]/g) ?? []).length;
  const bidi = (hidden.match(/[\u202A-\u202E\u2066-\u2069]/g) ?? []).length;
  if (zeroWidth + bidi >= 3) {
    add(findings, {
      id: "agent-obfuscated-hidden-text",
      title: "Hidden text uses Unicode obfuscation controls",
      severity: "low",
      confidence: "heuristic",
      category: "agent-security",
      standard: "OWASP LLM01:2025",
      evidence: `Hidden content contains ${zeroWidth} zero-width and ${bidi} bidi control characters; raw text withheld`,
      remediation: "Review hidden content for legitimate localization/accessibility use and remove obfuscation around agent-directed instructions.",
      source: "html-heuristic"
    });
  }
}

function analyzeHeaders(finalUrl, headers, findings) {
  const isHttps = new URL(finalUrl).protocol === "https:";
  const csp = header(headers, "content-security-policy");
  const xfo = header(headers, "x-frame-options");
  if (isHttps && !header(headers, "strict-transport-security")) {
    add(findings, { id: "missing-hsts", title: "HSTS is missing", severity: "medium", standard: "CWE-319", evidence: "Strict-Transport-Security header not present", remediation: "Enable HSTS after confirming all subdomains are HTTPS-ready." });
  }
  if (!csp) {
    add(findings, { id: "missing-csp", title: "Content Security Policy is missing", severity: "medium", standard: "CWE-1021", evidence: "Content-Security-Policy header not present", remediation: "Deploy a restrictive CSP and iterate with report-only mode first." });
  } else if (/unsafe-eval/i.test(csp) && /unsafe-inline/i.test(csp)) {
    add(findings, { id: "weak-csp", title: "CSP allows both unsafe-inline and unsafe-eval", severity: "medium", standard: "CWE-79", evidence: "CSP contains unsafe-inline + unsafe-eval", remediation: "Replace broad script allowances with nonces/hashes and remove unsafe-eval where possible." });
  }
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    add(findings, { id: "clickjacking-protection", title: "No clickjacking protection detected", severity: "medium", standard: "CWE-1021", evidence: "Neither X-Frame-Options nor CSP frame-ancestors is present", remediation: "Set CSP frame-ancestors (preferred) or X-Frame-Options." });
  }
  if (!header(headers, "x-content-type-options")) {
    add(findings, { id: "missing-nosniff", title: "X-Content-Type-Options is missing", severity: "low", standard: "CWE-16", evidence: "X-Content-Type-Options header not present", remediation: "Set X-Content-Type-Options: nosniff." });
  }
  if (!header(headers, "referrer-policy")) {
    add(findings, { id: "missing-referrer-policy", title: "Referrer-Policy is missing", severity: "low", standard: "CWE-200", evidence: "Referrer-Policy header not present", remediation: "Set a policy such as strict-origin-when-cross-origin." });
  }
  const server = header(headers, "server");
  const powered = header(headers, "x-powered-by");
  if (powered || /\d+\.\d+/.test(server)) {
    add(findings, { id: "version-disclosure", title: "Technology/version disclosure in response headers", severity: "low", confidence: "medium", standard: "CWE-200", evidence: `Server/X-Powered-By reveals implementation details`, remediation: "Remove unnecessary version/product headers where practical." });
  }
}

// Cookie names come from the scanned site. Embedding them verbatim in a
// finding id produces unstable, sometimes malformed SARIF ruleIds, which
// breaks rule grouping in code-scanning UIs. Ids stay fixed; the concrete
// name lives in the title and evidence instead.
function cookieLabel(name) {
  // Unicode-aware: a plain \w strips non-ASCII letters and would display
  // "suesssession" as "ssession", i.e. a name that is not on the server.
  // Quotes, angle brackets, control characters and ANSI escapes stay out.
  const safe = name.replace(/[^\p{L}\p{N}_.-]/gu, "").slice(0, 64);
  return safe || "unnamed";
}

function analyzeCookies(finalUrl, headers, findings) {
  const isHttps = new URL(finalUrl).protocol === "https:";
  for (const cookie of extractSetCookies(headers).slice(0, 40)) {
    const rawName = cookie.split("=", 1)[0].trim();
    const name = cookieLabel(rawName);
    const lower = cookie.toLowerCase();
    // Classify on the raw name: the display label is truncated, and a session
    // keyword sitting past the cut would otherwise downgrade the finding.
    const sensitive = /(session|sess|auth|token|jwt|sid)/i.test(rawName);
    if (isHttps && !/;\s*secure\b/i.test(cookie)) {
      add(findings, { id: "cookie-missing-secure", title: `Cookie '${name}' is missing Secure`, severity: sensitive ? "medium" : "low", standard: "CWE-614", evidence: `Cookie '${name}' does not set the Secure attribute`, remediation: "Set Secure for cookies transmitted over HTTPS.", source: "set-cookie" });
    }
    if (sensitive && !/;\s*httponly\b/i.test(cookie)) {
      add(findings, { id: "cookie-missing-httponly", title: `Sensitive-looking cookie '${name}' is missing HttpOnly`, severity: "medium", standard: "CWE-1004", evidence: `Cookie '${name}' looks session/auth related and does not set HttpOnly`, remediation: "Set HttpOnly unless client-side JavaScript truly needs access.", source: "set-cookie" });
    }
    if (!/;\s*samesite\s*=/.test(lower)) {
      add(findings, { id: "cookie-missing-samesite", title: `Cookie '${name}' has no SameSite attribute`, severity: "low", standard: "CWE-352", evidence: `Cookie '${name}' does not set a SameSite attribute`, remediation: "Set SameSite=Lax or Strict unless cross-site behavior is required.", source: "set-cookie" });
    }
  }
}

function analyzeHtml(finalUrl, html, findings) {
  const url = new URL(finalUrl);
  if (url.protocol === "http:" && /<input[^>]+type\s*=\s*["']?password/i.test(html)) {
    add(findings, { id: "password-over-http", title: "Password field served over HTTP", severity: "high", standard: "CWE-319", evidence: "Page contains a password input and is not HTTPS", remediation: "Serve the entire authentication flow over HTTPS and redirect HTTP to HTTPS." });
  }
  if (url.protocol === "https:" && /<(?:script|iframe|link|img|source)[^>]+(?:src|href)\s*=\s*["']http:\/\//i.test(html)) {
    add(findings, { id: "mixed-content", title: "Potential active/passive mixed content", severity: "medium", standard: "CWE-319", evidence: "HTTPS page references at least one http:// asset", remediation: "Serve all assets over HTTPS or use relative HTTPS-safe URLs." });
  }

  const jquery = [...html.matchAll(/(?:src|href)=["'][^"']*jquery(?:-|\.)(\d+\.\d+(?:\.\d+)?)[^"']*["']/gi)].map((m) => m[1]);
  const old = jquery.find((v) => versionLt(v, "3.5.0"));
  if (old) {
    add(findings, { id: "jquery-old", title: `Outdated jQuery ${old} detected`, severity: "medium", standard: "CWE-79", evidence: `jQuery ${old} is older than 3.5.0`, remediation: "Upgrade jQuery and test dependent plugins. Versions before 3.5.0 are affected by known XSS issues including CVE-2020-11022/11023.", source: "html-fingerprint" });
  }

  let externalWithoutSri = 0;
  for (const m of html.matchAll(/<script\b([^>]*)\bsrc=["']([^"']+)["']([^>]*)>/gi)) {
    const attrs = `${m[1]} ${m[3]}`;
    try {
      const src = new URL(m[2], url);
      if (src.origin !== url.origin && !/\bintegrity\s*=/.test(attrs)) externalWithoutSri += 1;
    } catch { /* ignore malformed URL */ }
  }
  if (externalWithoutSri > 0) {
    add(findings, { id: "third-party-script-no-sri", title: "Third-party scripts without Subresource Integrity", severity: "info", confidence: "medium", standard: "CWE-829", evidence: `${externalWithoutSri} cross-origin script(s) lack an integrity attribute`, remediation: "Where assets are version-pinned and static, consider SRI or self-hosting. Dynamic scripts may not be compatible with SRI." });
  }

  analyzeAgentInjection(html, findings);
}

function analyzeCors(aux, findings) {
  if (!aux?.cors || aux.cors.failed) return;
  const acao = header(aux.cors.headers, "access-control-allow-origin");
  const acc = header(aux.cors.headers, "access-control-allow-credentials").toLowerCase() === "true";
  const probeOrigin = aux.probeOrigin;
  if (acao === probeOrigin && acc) {
    add(findings, { id: "cors-origin-reflection-credentials", title: "CORS reflects arbitrary origin with credentials", severity: "high", confidence: "high", standard: "CWE-942", evidence: `Access-Control-Allow-Origin reflected the scanner origin and credentials are enabled`, remediation: "Use an explicit origin allowlist and never reflect arbitrary Origin values when credentials are allowed.", source: "cors-probe" });
  } else if (acao === probeOrigin) {
    add(findings, { id: "cors-origin-reflection", title: "CORS reflects arbitrary origin", severity: "medium", confidence: "medium", standard: "CWE-942", evidence: "Access-Control-Allow-Origin reflected the supplied untrusted origin", remediation: "Use an explicit origin allowlist and return ACAO only for trusted origins.", source: "cors-probe" });
  } else if (acao === "*" && acc) {
    add(findings, { id: "cors-wildcard-credentials", title: "CORS wildcard combined with credentials flag", severity: "low", confidence: "high", standard: "CWE-942", evidence: "ACAO is * while Access-Control-Allow-Credentials is true", remediation: "Remove the credentials flag or use an explicit allowlist. Browsers reject credentialed wildcard requests, but the configuration is misleading." });
  }
}

function analyzeProbe(probe, findings) {
  if (probe && probe.checked === false) {
    add(findings, {
      id: "probe-incomplete",
      title: `Exposure check for ${probe.path} could not be completed`,
      severity: "info",
      confidence: "high",
      category: "coverage",
      standard: null,
      evidence: `${probe.path} was not reachable (${probe.error ?? "unknown error"}); this path was not assessed`,
      remediation: "Re-run the scan. An unreachable path is not evidence that the file is absent.",
      source: "authorized-probe"
    });
    return;
  }
  if (!probe?.matched) return;
  add(findings, {
    id: probe.id,
    title: probe.title,
    severity: probe.severity,
    confidence: "high",
    category: "exposure",
    standard: probe.standard,
    evidence: `${probe.path} returned ${probe.status}; fingerprint matched (${probe.fingerprint})`,
    remediation: probe.remediation,
    source: "authorized-probe"
  });
}

export function calculateScore(findings) {
  const penalty = findings.reduce((sum, f) => sum + (WEIGHTS[f.severity] ?? 0), 0);
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  return { score, grade };
}

export function analyzeScan({ requestedUrl, finalUrl, status, headers, html, aux = {}, probes = [] }) {
  const findings = [];
  analyzeHeaders(finalUrl, headers, findings);
  analyzeCookies(finalUrl, headers, findings);
  analyzeHtml(finalUrl, html, findings);
  analyzeCors(aux, findings);
  for (const probe of probes) analyzeProbe(probe, findings);
  findings.sort((a, b) => (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0) || a.id.localeCompare(b.id));
  const { score, grade } = calculateScore(findings);
  return {
    schemaVersion: "0.1",
    scanner: { name: "AgentSafe WebScan", version: "0.1.0", mode: aux.mode ?? "passive" },
    target: { requestedUrl, finalUrl, status },
    summary: {
      score,
      grade,
      counts: Object.fromEntries(["critical", "high", "medium", "low", "info"].map((s) => [s, findings.filter((f) => f.severity === s).length]))
    },
    technologies: detectTech(html, headers),
    securityTxt: aux.securityTxt ?? { present: false, checked: false, status: null },
    aiSurface: aux.aiSurface ?? { llmsTxt: { present: false, checked: false, status: null }, mcpReferences: [] },
    safety: {
      rawUntrustedInstructionsReturned: false,
      untrustedEvidenceQuarantined: true,
      ssrfGuard: true,
      dnsPinned: true,
      activeExploitation: false,
      authenticatedTesting: false
    },
    findings
  };
}
