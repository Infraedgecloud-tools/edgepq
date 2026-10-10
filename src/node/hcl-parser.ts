/* Node wiring for the HCL parser: HashiCorp's parser compiled to WebAssembly,
   loaded by the package itself from its gzipped bundle. */
import { createRequire } from 'node:module';
import type { HclParser } from '../adapters/hcl.ts';

const require = createRequire(import.meta.url);

export const parseHcl: HclParser = async (filename, contents) => {
  const { parse } = require('@cdktf/hcl2json') as { parse: (f: string, c: string) => Promise<unknown> };
  return parse(filename, contents);
};
