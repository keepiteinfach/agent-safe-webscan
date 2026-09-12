import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { scanSite, mcpSafeReport } from "./scanner.js";

function buildServer() {
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
        url: z.string().url().describe("Public HTTP(S) URL to scan"),
        mode: z.enum(["passive", "authorized"]).default("passive")
      })
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
      inputSchema: z.object({})
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

serveStdio(() => buildServer()).catch((error) => {
  console.error(error);
  process.exit(1);
});
