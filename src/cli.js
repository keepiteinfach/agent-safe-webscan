#!/usr/bin/env node
import { scanSite } from "./scanner.js";
import { toSarif } from "./sarif.js";

function help() {
  console.log(`AgentSafe WebScan 0.1 — agent-safe web security scanner

Usage:
  agentwebscan <url> [--format text|json|sarif] [--authorized] [--fail-on high|medium|low]

Examples:
  agentwebscan https://example.com
  agentwebscan https://example.com --format json
  agentwebscan https://your-site.example --authorized --format sarif > report.sarif

Safety:
  Passive mode is the default. --authorized enables a small fixed set of exposure probes
  and should only be used on systems you own or are explicitly authorized to test.`);
}

function parse(argv) {
  const args = [...argv];
  if (!args.length || args.includes("--help") || args.includes("-h")) return { help: true };
  const url = args.shift();
  let format = "text";
  let mode = "passive";
  let failOn = null;
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--authorized") mode = "authorized";
    else if (args[i] === "--format") format = args[++i] ?? "text";
    else if (args[i] === "--fail-on") failOn = args[++i] ?? null;
    else throw new Error(`Unknown argument: ${args[i]}`);
  }
  if (!new Set(["text", "json", "sarif"]).has(format)) throw new Error(`Unsupported format: ${format}`);
  return { url, format, mode, failOn };
}

const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function textReport(report) {
  const lines = [];
  lines.push(`AgentSafe WebScan ${report.scanner.version} · ${report.scanner.mode}`);
  lines.push(`${report.target.finalUrl} · HTTP ${report.target.status} · score ${report.summary.score}/100 (${report.summary.grade})`);
  if (report.technologies.length) lines.push(`Tech: ${report.technologies.join(", ")}`);
  lines.push("");
  if (!report.findings.length) lines.push("No findings.");
  for (const f of report.findings) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  ${f.evidence}`);
    if (f.standard) lines.push(`  ${f.standard}`);
    if (f.remediation) lines.push(`  Fix: ${f.remediation}`);
  }
  lines.push("");
  lines.push(report.note);
  return lines.join("\n");
}

try {
  const opts = parse(process.argv.slice(2));
  if (opts.help) {
    help();
    process.exit(0);
  }
  const report = await scanSite(opts.url, { mode: opts.mode });
  if (opts.format === "json") console.log(JSON.stringify(report, null, 2));
  else if (opts.format === "sarif") console.log(JSON.stringify(toSarif(report), null, 2));
  else console.log(textReport(report));

  if (opts.failOn && rank[opts.failOn] !== undefined) {
    if (report.findings.some((f) => rank[f.severity] >= rank[opts.failOn])) process.exitCode = 2;
  }
} catch (error) {
  console.error(`AgentSafe WebScan error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
