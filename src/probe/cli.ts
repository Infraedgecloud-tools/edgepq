/* Manual runner only: node --experimental-strip-types src/probe/cli.ts <host[:port]>
   The real `edgepq` subcommand is a later PR. */
import { probe } from './index.ts';

const arg = process.argv[2];
if (!arg) {
  console.error('usage: node --experimental-strip-types src/probe/cli.ts <host[:port]>');
  process.exit(2);
}
const i = arg.lastIndexOf(':');
const target = i > 0 ? { host: arg.slice(0, i), port: Number(arg.slice(i + 1)) } : { host: arg };
console.log(JSON.stringify(await probe(target), null, 2));
