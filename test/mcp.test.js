import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("../src/mcp.js", import.meta.url));

// Drives the real stdio entry point. The 0.1.0 prototype shipped an MCP server
// that threw on startup because nothing ever executed this path in CI.
function talk(messages, { timeoutMs = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`MCP server timed out.\nstdout: ${stdout}\nstderr: ${stderr}`));
    }, timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code) => {
      clearTimeout(timer);
      const frames = stdout.split("\n").filter(Boolean).map((line) => JSON.parse(line));
      resolve({ code, frames, stderr });
    });

    for (const message of messages) child.stdin.write(`${JSON.stringify(message)}\n`);
    child.stdin.end();
  });
}

const OPENING = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" }
];

test("MCP server completes the stdio handshake", async () => {
  const { frames, stderr } = await talk(OPENING);
  const init = frames.find((f) => f.id === 1);
  assert.ok(init, `no initialize response; stderr: ${stderr}`);
  assert.equal(init.result.serverInfo.name, "agent-safe-webscan");
});

test("MCP server advertises both tools with safety annotations and schemas", async () => {
  const { frames } = await talk([...OPENING, { jsonrpc: "2.0", id: 2, method: "tools/list" }]);
  const tools = frames.find((f) => f.id === 2).result.tools;
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["scan_site", "scanner_policy"]);

  for (const tool of tools) {
    assert.equal(tool.annotations.readOnlyHint, true, `${tool.name} must be read-only`);
    assert.equal(tool.annotations.destructiveHint, false, `${tool.name} must be non-destructive`);
    // structuredContent is only contractual when an outputSchema is published.
    assert.ok(tool.outputSchema, `${tool.name} must publish an outputSchema`);
  }

  const scan = tools.find((t) => t.name === "scan_site");
  assert.equal(scan.inputSchema.properties.mode.default, "passive", "passive must stay the default mode");
});

test("scanner_policy answers without any network request", async () => {
  const { frames } = await talk([...OPENING, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "scanner_policy", arguments: {} } }]);
  const call = frames.find((f) => f.id === 3);
  assert.ok(call.result, `expected a result, got ${JSON.stringify(call)}`);
  assert.equal(call.result.isError, undefined);
  assert.equal(call.result.structuredContent.defaultMode, "passive");
  assert.equal(call.result.structuredContent.activeExploitation, false);
});
