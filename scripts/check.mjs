// Portable replacement for a shell glob: `for f in src/*.js` is sh syntax and
// fails on Windows, where npm runs scripts through cmd.
import { readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
let failed = 0;

for (const dir of ["src", "test", "scripts"]) {
  for (const name of readdirSync(join(root, dir))) {
    if (!name.endsWith(".js") && !name.endsWith(".mjs")) continue;
    const file = join(root, dir, name);
    try {
      execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
    } catch (error) {
      failed += 1;
      process.stderr.write(`${dir}/${name}\n${error.stderr?.toString() ?? error.message}\n`);
    }
  }
}

if (failed) {
  process.stderr.write(`${failed} file(s) failed the syntax check\n`);
  process.exit(1);
}
console.log("syntax check passed");
