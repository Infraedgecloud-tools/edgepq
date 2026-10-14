#!/usr/bin/env node
// The sources are TypeScript, which Node strips natively from 22.18. An
// older Node would fail on the first import with ERR_UNKNOWN_FILE_EXTENSION,
// which says nothing useful, so the version is checked before anything is
// imported.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 18)) {
  process.stderr.write(`edgepq needs Node 22.18 or later (verify needs 22.20); this is Node ${process.versions.node}\n`);
  process.exit(2);
}

/* `edgepq rules | head` closes the pipe early; that is not an error. */
process.stdout.on('error', (e) => { if (e.code === 'EPIPE') process.exit(0); throw e; });

const { main } = await import('../src/cli/main.ts');
const code = await main(process.argv.slice(2), {
  out: (s) => process.stdout.write(s + '\n'),
  err: (s) => process.stderr.write(s + '\n'),
});
process.exitCode = code;
