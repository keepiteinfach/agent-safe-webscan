// Portable replacement for a shell glob: `for f in src/*.js` is sh syntax and
// fails on Windows, where npm runs scripts through cmd.
import { readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
let failed = 0;

function* jsFiles(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // an optional directory that does not exist is not a failure
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* jsFiles(full);
    else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) yield full;
  }
}

let checked = 0;
for (const dir of ["src", "test", "scripts"]) {
  for (const file of jsFiles(join(root, dir))) {
    checked += 1;
    try {
      execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
    } catch (error) {
      failed += 1;
      process.stderr.write(`${relative(root, file)}\n${error.stderr?.toString() ?? error.message}\n`);
    }
  }
}

if (failed) {
  process.stderr.write(`${failed} file(s) failed the syntax check\n`);
  process.exit(1);
}
console.log(`syntax check passed (${checked} files)`);
