#!/usr/bin/env node
// Runs the TypeScript sources directly: Node 22.18+ strips types natively.
import { main } from '../src/cli/main.ts';

const code = await main(process.argv.slice(2), {
  out: (s) => process.stdout.write(s + '\n'),
  err: (s) => process.stderr.write(s + '\n'),
});
process.exitCode = code;
