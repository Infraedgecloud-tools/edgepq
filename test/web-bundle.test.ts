/* ============================================================================
   The browser bundle is the engine: a build is reproducible byte for byte,
   and it gives the same findings as the Node pipeline on the same input.
   Runs the IIFE under Node with a fetch shim for the wasm, so no browser is
   needed for parity; the website that embeds the bundle tests the page.
   ========================================================================= */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { runInThisContext } from 'node:vm';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRulesFromDir } from '../src/node/load-rules.ts';
import { parseHcl } from '../src/node/hcl-parser.ts';
import { scanHclFiles } from '../src/adapters/hcl.ts';
import { evaluateAll } from '../src/engine/evaluate.ts';

const root = fileURLToPath(new URL('..', import.meta.url));

async function buildInto(dir: string): Promise<void> {
  execFileSync(process.execPath, ['--experimental-strip-types', join(root, 'scripts/build-web.ts'), dir], { stdio: 'pipe' });
}

test('two builds give the same bytes', async () => {
  const a = await mkdtemp(join(tmpdir(), 'edgepq-web-'));
  const b = await mkdtemp(join(tmpdir(), 'edgepq-web-'));
  await buildInto(a);
  await buildInto(b);
  assert.equal(await readFile(join(a, 'edgepq.js'), 'utf8'), await readFile(join(b, 'edgepq.js'), 'utf8'));
  const wasm = (await readdir(a)).find((n) => n.endsWith('.wasm'))!;
  assert.deepEqual(await readFile(join(a, wasm)), await readFile(join(b, wasm)));
  assert.match(await readFile(join(a, 'edgepq.js'), 'utf8'), /^\/\* EdgePQ Check \d+\.\d+\.\d+ /);
});

test('the bundle evaluates the fixtures exactly as the Node pipeline does', async () => {
  const siteJs = await mkdtemp(join(tmpdir(), 'edgepq-web-'));
  await buildInto(siteJs);
  const wasmName = (await readdir(siteJs)).find((n) => /^hcl2json-.*\.wasm$/.test(n))!;
  const wasmBytes = await readFile(join(siteJs, wasmName));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request) => {
    if (String(url).endsWith(wasmName)) return new Response(wasmBytes, { headers: { 'content-type': 'application/wasm' } });
    throw new Error(`unexpected fetch ${String(url)}`);
  }) as typeof fetch;
  try {
    /* A classic script: its top-level `var EdgePQ` becomes a global, as in a browser. */
    runInThisContext(await readFile(join(siteJs, 'edgepq.js'), 'utf8'), { filename: 'edgepq.js' });
    const EdgePQ = (globalThis as { EdgePQ?: { ready: (u?: string) => Promise<void>; check: (t: string, n?: string) => Promise<{ report: { findings: unknown[]; resources: unknown[] } }>; info: { wasmUrl: string } } }).EdgePQ!;
    assert.equal(EdgePQ.info.wasmUrl, `/js/${wasmName}`);
    await EdgePQ.ready();
    const rules = await loadRulesFromDir(join(root, 'rules'));
    const fixtures = join(root, 'test/fixtures/rules');
    let compared = 0;
    for (const id of (await readdir(fixtures)).sort()) {
      for (const file of ['fail.tf', 'pass.tf']) {
        const text = await readFile(join(fixtures, id, file), 'utf8');
        const web = await EdgePQ.check(text, file);
        const scan = await scanHclFiles([{ name: file, contents: text }], parseHcl);
        const node = evaluateAll(rules, scan.resources);
        const strip = (f: unknown) => { const { id: _id, ...rest } = f as { id: string }; return rest; };
        assert.deepEqual(web.report.findings.map(strip), node.map(strip), `${id}/${file}`);
        assert.deepEqual(web.report.resources, scan.resources, `${id}/${file} resources`);
        compared += 1;
      }
    }
    assert.ok(compared >= 20);
  } finally {
    globalThis.fetch = realFetch;
  }
});
