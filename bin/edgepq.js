#!/usr/bin/env node
// From the published package the compiled JavaScript under dist/ runs on any
// supported Node. From a checkout the TypeScript sources run directly, so an
// edit is live without a build: Node strips types natively from 22.18, and an
// older Node would fail on the first import with ERR_UNKNOWN_FILE_EXTENSION,
// which says nothing useful, so the version is checked before anything is
// imported.
import { existsSync } from 'node:fs';

const [major, minor] = process.versions.node.split('.').map(Number);
const atLeast = (maj, min) => major > maj || (major === maj && minor >= min);
const source = new URL('../src/cli/main.ts', import.meta.url);
const built = new URL('../dist/cli/main.js', import.meta.url);

if (!atLeast(20, 10)) {
  process.stderr.write(`edgepq needs Node 20.10 or later (verify needs 22.20); this is Node ${process.versions.node}\n`);
  process.exit(2);
}
const entry = existsSync(source) && atLeast(22, 18) ? source : existsSync(built) ? built : undefined;
if (!entry) {
  process.stderr.write(`edgepq: Node ${process.versions.node} cannot run the TypeScript sources and there is no build under dist/; run \`npm run build\` or use Node 22.18 or later\n`);
  process.exit(2);
}

/* `edgepq rules | head` closes the pipe early; that is not an error. */
process.stdout.on('error', (e) => { if (e.code === 'EPIPE') process.exit(0); throw e; });

const { main } = await import(entry);
const code = await main(process.argv.slice(2), {
  out: (s) => process.stdout.write(s + '\n'),
  err: (s) => process.stderr.write(s + '\n'),
});
process.exitCode = code;
