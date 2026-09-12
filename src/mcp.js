import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { pathToFileURL, fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import * as z from "zod/v4";
import { scanSite, mcpSafeReport } from "./scanner.js";

const severityEnum = z.enum(["critical", "high", "medium", "low", "info"]);

const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: severityEnum,
  confidence: z.string(),
  category: z.string(),
  standard: z.string().nullable(),
  evidence: z.string(),
  remediation: z.string()
});

export const reportSchema = z.object({
  schemaVersion: z.string(),
  scanner: z.object({ name: z.string(), version: z.string(), mode: z.enum(["passive", "authorized"]) }),
  target: z.object({ requestedUrl: z.string(), finalUrl: z.string(), status: z.number() }),
  summary: z.object({
    score: z.number(),
    grade: z.string(),
    counts: z.record(severityEnum, z.number())
  }),
  technologies: z.array(z.string()),
  securityTxt: z.object({ present: z.boolean(), status: z.number().nullable().optional() }),
  aiSurface: z.object({
    llmsTxt: z.object({ present: z.boolean(), status: z.number().nullable().optional() }),
    mcpReferences: z.array(z.string())
  }),
  safety: z.object({
    rawUntrustedInstructionsReturned: z.boolean(),
    untrustedEvidenceQuarantined: z.boolean(),
    ssrfGuard: z.boolean(),
    dnsPinned: z.boolean(),
    activeExploitation: z.boolean(),
    authenticatedTesting: z.boolean()
  }),
  findings: z.array(findingSchema)
});

export const policySchema = z.object({
  defaultMode: z.string(),
  activeExploitation: z.boolean(),
  bruteForce: z.boolean(),
  credentialAttacks: z.boolean(),
  portScanning: z.boolean(),
  subdomainBruteforce: z.boolean(),
  ssrfProtection: z.string(),
  promptInjectionProtection: z.string(),
  evidenceBoundary: z.string()
});

export function buildServer() {
  const server = new McpServer({
    name: "agent-safe-webscan",
    title: "AgentSafe WebScan",
    version: "0.1.0",
    websiteUrl: "https://github.com/keepiteinfach/agent-safe-webscan"
  });

  server.registerTool(
    "scan_site",
    {
      title: "Scan public website",
      description: "Run a bounded website security scan. Passive mode is the default; authorized mode adds a fixed set of read-only exposure probes and must only be used with permission.",
      annotations: {
        title: "Scan public website",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      },
      inputSchema: z.object({
        url: z.url().describe("Public HTTP(S) URL to scan"),
        mode: z.enum(["passive", "authorized"]).default("passive")
      }),
      outputSchema: reportSchema
    },
    async ({ url, mode }) => {
      const report = mcpSafeReport(await scanSite(url, { mode }));
      return {
        content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
        structuredContent: report
      };
    }
  );

  server.registerTool(
    "scanner_policy",
    {
      title: "Inspect scanner safety policy",
      description: "Return AgentSafe WebScan's safety boundaries and agent-context protections without making any network request.",
      annotations: {
        title: "Inspect scanner safety policy",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: z.object({}),
      outputSchema: policySchema
    },
    async () => {
      const policy = {
        defaultMode: "passive",
        activeExploitation: false,
        bruteForce: false,
        credentialAttacks: false,
        portScanning: false,
        subdomainBruteforce: false,
        ssrfProtection: "Public HTTP(S) targets only; private/reserved IPs and local hostnames are rejected before every redirect hop.",
        promptInjectionProtection: "Suspicious hidden page instructions are classified and hashed; raw matched instruction text is never returned to the MCP client.",
        evidenceBoundary: "Potential secrets from exposure probes are fingerprinted in memory and omitted from findings."
      };
      return {
        content: [{ type: "text", text: JSON.stringify(policy, null, 2) }],
        structuredContent: policy
      };
    }
  );

  return server;
}

// `serveStdio` returns a handle synchronously; it is not a promise.
// Out-of-band transport errors arrive through `onerror`.
//
// Both sides must be normalised before comparing. `import.meta.url` is
// percent-encoded and symlink-resolved; `process.argv[1]` is a raw path. A
// naive string comparison silently skips the start — exit 0, no output, no
// error — for npx/npm bin symlinks, any symlinked directory in the path,
// paths containing spaces, and every path on Windows.
function isDirectInvocation() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return false;
  }
}

if (isDirectInvocation()) {
  serveStdio(() => buildServer(), {
    onerror: (error) => {
      console.error(`agent-safe-webscan MCP error: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
}
