/* ============================================================================
   Build the browser bundle: the engine, the rules and the renderers as one
   IIFE for a page to load, with no network after the parser has loaded.
   Deterministic: the same sources and the same esbuild give the same bytes,
   which the tests and the website that embeds it rely on.

     node --experimental-strip-types scripts/build-web.ts [outDir]   (default dist/web)

   Writes:
     <outDir>/edgepq.js            the engine, rules, renderers and the Go runtime shim
     <outDir>/hcl2json-<ver>.wasm  HashiCorp's HCL parser (MPL-2.0), gunzipped from the package
   ========================================================================= */

import { build } from 'esbuild';
import { readdir, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { validateRules } from '../src/engine/rules.ts';

const root = fileURLToPath(new URL('..', import.meta.url));
const outDir = resolve(process.argv[2] ?? join(root, 'dist', 'web'));
const require = createRequire(import.meta.url);
const hcl2jsonDir = join(require.resolve('@cdktf/hcl2json/package.json'), '..');
const hcl2jsonVersion = (JSON.parse(await readFile(join(hcl2jsonDir, 'package.json'), 'utf8')) as { version: string }).version;
const version = (JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as { version: string }).version;

const rulesDir = join(root, 'rules');
const rules = [];
for (const name of (await readdir(rulesDir)).filter((n) => n.endsWith('.yaml')).sort()) rules.push(parse(await readFile(join(rulesDir, name), 'utf8')));
validateRules(rules);
const policyData = {
  elb: JSON.parse(await readFile(join(rulesDir, 'data/elb-security-policies.json'), 'utf8')),
  apigw: JSON.parse(await readFile(join(rulesDir, 'data/apigw-security-policies.json'), 'utf8')),
};

const virtual: { [name: string]: string } = {
  'edgepq:rules': `export default ${JSON.stringify(rules)};`,
  'edgepq:policy-data': `export default ${JSON.stringify(policyData)};`,
  'edgepq:version': `export default ${JSON.stringify(version)};`,
  /* The wasm carries the parser version in its name: a site that caches its
     assets as immutable can then ship a new parser as a new file. */
  'edgepq:wasm-url': `export default ${JSON.stringify(`/js/hcl2json-${hcl2jsonVersion}.wasm`)};`,
};

await mkdir(outDir, { recursive: true });
const result = await build({
  entryPoints: [join(root, 'src/web/index.ts')],
  bundle: true,
  format: 'iife',
  globalName: 'EdgePQ',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  legalComments: 'none',
  sourcemap: false,
  write: false,
  banner: {
    js: [
      `/* EdgePQ Check ${version} — runs entirely in this browser; nothing is uploaded.`,
      ` * Engine and rules: https://github.com/infraedgecloud-tools/edgepq (Apache-2.0)`,
      ` * HCL parser: @cdktf/hcl2json ${hcl2jsonVersion} (HashiCorp, MPL-2.0, https://github.com/hashicorp/terraform-cdk/tree/main/packages/@cdktf/hcl2json),`,
      ` *   loaded from hcl2json-${hcl2jsonVersion}.wasm beside this file; its Go runtime shim wasm_exec.js (BSD-3-Clause, Go Authors) is bundled below. */`,
    ].join('\n'),
  },
  plugins: [{
    name: 'edgepq-virtual',
    setup(b) {
      b.onResolve({ filter: /^edgepq:/ }, (args) => ({ path: args.path, namespace: 'edgepq-virtual' }));
      b.onLoad({ filter: /.*/, namespace: 'edgepq-virtual' }, (args) => ({ contents: virtual[args.path] ?? '', loader: 'js' }));
    },
  }],
});
const js = result.outputFiles[0]!.text;
await writeFile(join(outDir, 'edgepq.js'), js);
const wasm = gunzipSync(await readFile(join(hcl2jsonDir, 'main.wasm.gz')));
const wasmName = `hcl2json-${hcl2jsonVersion}.wasm`;
for (const stale of (await readdir(outDir)).filter((n) => /^hcl2json-.*\.wasm$/.test(n) && n !== wasmName)) await rm(join(outDir, stale));
await writeFile(join(outDir, wasmName), wasm);
console.log(`edgepq.js ${(js.length / 1024).toFixed(0)} kB, ${wasmName} ${(wasm.length / 1024 / 1024).toFixed(1)} MB → ${outDir}`);
