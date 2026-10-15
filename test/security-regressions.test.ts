/* Synthetic private review canaries only; no real credentials or identifiers. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resourcesFromTerraformJson } from '../src/adapters/plan.ts';
import { loadRules } from '../src/node/report.ts';
import { evaluateAll } from '../src/engine/evaluate.ts';
import { buildPatchesWithSkips, combinePatches } from '../src/patch/index.ts';
import { scanHclFiles } from '../src/adapters/hcl.ts';
import { parseHcl } from '../src/node/hcl-parser.ts';
import { renderMarkdown } from '../src/render/markdown.ts';
import { reportForTerraform } from '../src/node/report.ts';

async function runCli(args: string[], io: { out: (s: string) => void; err: (s: string) => void }): Promise<number | null> {
  const bin = process.env.EDGEPQ_BIN ?? fileURLToPath(new URL('../bin/edgepq.js', import.meta.url));
  return new Promise((resolve) => {
    const child = spawn(process.env.EDGEPQ_NODE ?? process.execPath, [bin, ...args], { cwd: tmpdir() });
    child.stdout.on('data', (d) => io.out(String(d)));
    child.stderr.on('data', (d) => io.err(String(d)));
    child.once('close', resolve);
  });
}

const canary = 'EDGE_SYNTHETIC_CANARY_482716';

test('sensitive plan/state masks remove values before assessment and every output', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-private-'));
  const plan = { format_version: '1.2', resource_changes: [{ address: 'aws_lb_listener.x', type: 'aws_lb_listener', mode: 'managed', change: { actions: ['create'], after: { protocol: 'HTTPS', ssl_policy: canary, arbitrary: { nested: canary }, list: [{ hidden: canary }] }, after_unknown: {}, after_sensitive: { ssl_policy: true, arbitrary: true, list: [{ hidden: true }] } } }] };
  const resources = resourcesFromTerraformJson(plan).resources;
  assert.ok(!JSON.stringify(resources).includes(canary));
  assert.ok(evaluateAll(await loadRules(), resources).some((f) => f.rule.id === 'ELB-KX-001' && f.status === 'unknown'));
  const file = join(dir, 'plan.json');
  await writeFile(file, JSON.stringify(plan));
  const out = join(dir, 'out');
  let stdout = '', stderr = '';
  assert.equal(await runCli(['scan', file, '--out', out], { out: (s) => { stdout += s; }, err: (s) => { stderr += s; } }), 0);
  assert.ok(!(stdout + stderr).includes(canary));
  for (const name of await readdir(out)) assert.ok(!(await readFile(join(out, name), 'utf8')).includes(canary), name);
  const malformedMask = structuredClone(plan);
  malformedMask.resource_changes[0]!.change.after_sensitive = { ssl_policy: { child: true } } as never;
  assert.throws(() => resourcesFromTerraformJson(malformedMask), /shape/);
  const state = { format_version: '1.0', values: { root_module: { resources: [{ address: 'aws_lb_listener.x', type: 'aws_lb_listener', mode: 'managed', values: { protocol: 'HTTPS', ssl_policy: canary }, sensitive_values: true }] } } };
  assert.ok(!JSON.stringify(resourcesFromTerraformJson(state)).includes(canary));
});

test('generated individual and combined patches omit adjacent source; mixed changed lines are refused', async () => {
  const rule = (await loadRules()).find((r) => r.id === 'ELB-KX-001')!;
  const contents = `resource "aws_lb_listener" "x" {\n protocol = "HTTPS"\n ssl_policy = "ELBSecurityPolicy-2016-08"\n password = "${canary}"\n}\n`;
  const scan = await scanHclFiles([{ name: 'x.tf', contents }], parseHcl);
  const findings = evaluateAll([rule], scan.resources);
  const built = buildPatchesWithSkips(findings, [{ name: 'x.tf', contents }]);
  assert.equal(built.patches.length, 1);
  assert.ok(!built.patches[0]!.diff.includes(canary));
  assert.ok(!combinePatches(built.patches, { safety: 'all' }).diff.includes(canary));
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-private-patch-'));
  await writeFile(join(dir, 'x.tf'), contents);
  const out = join(dir, 'out');
  assert.equal(await runCli(['scan', dir, '--out', out], { out: () => {}, err: () => {} }), 0);
  for (const name of await readdir(join(out, 'patches'))) assert.ok(!(await readFile(join(out, 'patches', name), 'utf8')).includes(canary), name);
  const withComment = contents.replace('ssl_policy = "ELBSecurityPolicy-2016-08"', `ssl_policy = "ELBSecurityPolicy-2016-08" # ${canary}`);
  const blocked = buildPatchesWithSkips(findings, [{ name: 'x.tf', contents: withComment }]);
  assert.equal(blocked.patches.length, 0);
  assert.match(blocked.skipped[0]!.reason, /unrelated/);
});

test('malformed JSON and HCL errors do not echo source excerpts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-private-error-'));
  const bad = join(dir, 'plan.json');
  await writeFile(bad, `{"${canary}" invalid`);
  let output = '';
  const io = { out: (s: string) => { output += s; }, err: (s: string) => { output += s; } };
  assert.equal(await runCli(['scan', bad, '--out', join(dir, 'json-out')], io), 2);
  assert.ok(!output.includes(canary));
  const source = join(dir, 'source');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(source);
  await writeFile(join(source, 'broken.tf'), `resource "aws_lb_listener" "x" {\n value = "${canary}"\n`);
  output = '';
  assert.equal(await runCli(['scan', source, '--out', join(dir, 'hcl-out')], io), 2);
  assert.ok(!output.includes(canary));
  for (const name of await readdir(join(dir, 'hcl-out'))) assert.ok(!(await readFile(join(dir, 'hcl-out', name), 'utf8')).includes(canary));
});

test('terminal controls and Markdown resource injection are inert', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-private-display-'));
  const source = join(dir, 'plan.json');
  await writeFile(source, JSON.stringify({ format_version: '1.2', resource_changes: [{ address: 'aws_lb_listener.\u001b[31m<img src=x>\n# heading', type: 'aws_lb_listener', mode: 'managed', change: { actions: ['create'], after: { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-2016-08' } } }] }));
  const { report } = await reportForTerraform(source, await loadRules());
  const markdown = renderMarkdown(report);
  assert.ok(!markdown.includes('<img'));
  assert.ok(!markdown.includes('\n# heading'));
  let output = '';
  await runCli(['scan', source, '--out', join(dir, 'out')], { out: (s) => { output += s; }, err: (s) => { output += s; } });
  assert.ok(!output.includes('\u001b'));
  assert.ok(!output.includes('\n# heading'));
});


test('sensitive HCL defaults and supplied sensitive inputs stay unknown', async () => {
  const files = [{ name: 'x.tf', contents: `variable "policy" {\n sensitive = true\n default = "${canary}"\n}\nresource "aws_lb_listener" "x" {\n protocol = "HTTPS"\n ssl_policy = var.policy\n}\n` }];
  for (const inputs of [{}, { policy: canary }]) {
    const scan = await scanHclFiles(files, parseHcl, { inputs });
    const findings = evaluateAll(await loadRules(), scan.resources);
    assert.ok(!JSON.stringify(findings).includes(canary));
    assert.ok(findings.some((f) => f.rule.id === 'ELB-KX-001' && f.status === 'unknown'));
  }
});
