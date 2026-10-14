/* End to end: the real binary, on the fixtures, through a child process. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = fileURLToPath(new URL('..', import.meta.url));
const bin = join(root, 'bin/edgepq.js');

function run(args: string[], cwd = root): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], { cwd });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('scan a Terraform directory: all five outputs plus patches, exit 0, exit 1 with --fail-on', async () => {
  const out = await mkdtemp(join(tmpdir(), 'edgepq-'));
  const r = await run(['scan', 'test/fixtures/rules/ELB-KX-001', '--out', out]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /failed 3\s+not configurable 0\s+could not check 4\s+already enabled 3/);
  assert.match(r.stdout, /high\s+ELB-KX-001\s+aws_lb_listener\.defaulted\n\s+ssl_policy: ELBSecurityPolicy-2016-08 \(default\) → ELBSecurityPolicy-TLS13-1-0-PQ-2025-09/);
  assert.match(r.stdout, /patches: 3 written, never applied/);
  const names = (await readdir(out)).sort();
  assert.deepEqual(names, ['edgepq-cbom.cdx.json', 'edgepq-findings.json', 'edgepq-findings.sarif', 'edgepq-report.html', 'edgepq-report.md', 'patches']);
  /* SARIF paths are relative to the working directory and point at the resource block. */
  const sarif = JSON.parse(await readFile(join(out, 'edgepq-findings.sarif'), 'utf8')) as { runs: { results: { ruleId: string; locations: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }[]; properties: { address: string } }[] }[] };
  const defaulted = sarif.runs[0]!.results.find((r) => r.properties.address === 'aws_lb_listener.defaulted')!;
  assert.equal(defaulted.locations[0]!.physicalLocation.artifactLocation.uri, 'test/fixtures/rules/ELB-KX-001/fail.tf');
  const fixture = await readFile(join(root, 'test/fixtures/rules/ELB-KX-001/fail.tf'), 'utf8');
  const expectedLine = fixture.slice(0, fixture.indexOf('resource "aws_lb_listener" "defaulted"')).split('\n').length;
  assert.equal(defaulted.locations[0]!.physicalLocation.region?.startLine, expectedLine);
  const patches = (await readdir(join(out, 'patches'))).sort();
  assert.ok(patches.includes('edgepq-auto.patch') && patches.includes('edgepq-all.patch'), patches.join(','));

  const findings = JSON.parse(await readFile(join(out, 'edgepq-findings.json'), 'utf8')) as { input: { kind: string } };
  const schema = JSON.parse(await readFile(join(root, 'schema/findings.schema.json'), 'utf8'));
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats.default(ajv);
  assert.ok(ajv.validate(schema, findings), JSON.stringify(ajv.errors?.slice(0, 3)));
  assert.equal(findings.input.kind, 'hcl');

  const html = await readFile(join(out, 'edgepq-report.html'), 'utf8');
  assert.doesNotMatch(html, /quantum[- ]safe|compliant/i);

  const failing = await run(['scan', 'test/fixtures/rules/ELB-KX-001', '--out', out, '--fail-on', 'high']);
  assert.equal(failing.code, 1);
  const lowBar = await run(['scan', 'test/fixtures/rules/ELB-KX-001', '--out', out, '--fail-on', 'critical']);
  assert.equal(lowBar.code, 0);
});

test('scan a plan JSON: outputs but no patches', async () => {
  const out = await mkdtemp(join(tmpdir(), 'edgepq-'));
  const r = await run(['scan', 'test/fixtures/terraform/plan-create.json', '--out', out]);
  assert.equal(r.code, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /patches:/);
  await assert.rejects(stat(join(out, 'patches')));
  const findings = JSON.parse(await readFile(join(out, 'edgepq-findings.json'), 'utf8')) as { input: { kind: string }; findings: { rule: { id: string }; status: string }[] };
  assert.equal(findings.input.kind, 'plan');
  assert.ok(findings.findings.some((f: { rule: { id: string }; status: string }) => f.rule.id === 'ELB-KX-001' && f.status === 'fail'));
});

test('usage errors exit 2 and say why', async () => {
  assert.equal((await run([])).code, 2);
  const bad = await run(['scan']);
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /scan needs a Terraform directory/);
  const sev = await run(['scan', 'test/fixtures/rules/ELB-KX-001', '--fail-on', 'severe', '--out', await mkdtemp(join(tmpdir(), 'edgepq-'))]);
  assert.equal(sev.code, 2);
  const notJson = await run(['scan', 'package.json', '--out', await mkdtemp(join(tmpdir(), 'edgepq-'))]);
  assert.equal(notJson.code, 2);
  assert.match(notJson.stderr, /neither a Terraform plan nor a state/);
  /* Node's own parseArgs text is not shown; the option is named. */
  const unknown = await run(['scan', 'test/fixtures/rules/ELB-KX-001', '--outdir', 'x']);
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /^edgepq: unknown option --outdir/m);
  assert.doesNotMatch(unknown.stderr, /positional argument/);
  const missing = await run(['scan', 'test/fixtures/rules/ELB-KX-001', '--out']);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /^edgepq: --out needs a value/m);
  const extra = await run(['aws', 'something']);
  assert.equal(extra.code, 2);
  assert.match(extra.stderr, /^edgepq: unexpected argument something/m);
});

test('a file that does not parse makes the scan exit 2 and name the file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-broken-'));
  await writeFile(join(dir, 'good.tf'), 'resource "aws_kms_key" "k" {}\n');
  await writeFile(join(dir, 'bad.tf'), 'resource "a" "b" {\n');
  const r = await run(['scan', dir, '--out', join(dir, 'out')]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /bad\.tf did not parse/);
  assert.ok((await readdir(join(dir, 'out'))).includes('edgepq-findings.json'), 'outputs are still written');
});

test('rules lists every rule with its sources', async () => {
  const r = await run(['rules']);
  assert.equal(r.code, 0);
  const dirs = (await readdir(join(root, 'rules'))).filter((n) => n.endsWith('.yaml')).map((n) => n.replace('.yaml', ''));
  for (const id of dirs) assert.match(r.stdout, new RegExp(`^${id}\\s`, 'm'));
  assert.match(r.stdout, /\(verified \d{4}-\d{2}-\d{2}\)/);
});

test('an empty directory is an error, not a clean scan', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-empty-'));
  const r = await run(['scan', dir, '--out', join(dir, 'out')]);
  assert.equal(r.code, 2, r.stdout);
  assert.match(r.stderr, /no Terraform resources found/);
});

test('verify against nothing listening is inconclusive and exits 2, not a crash', async () => {
  const r = await run(['verify', '127.0.0.1:1', '--json', '--timeout', '1000']);
  assert.equal(r.code, 2, r.stderr);
  const result = JSON.parse(r.stdout) as { verdict: string; reachable: boolean; target: { host: string; port: number } };
  assert.equal(result.verdict, 'inconclusive');
  assert.equal(result.reachable, false);
  assert.deepEqual(result.target, { host: '127.0.0.1', port: 1, servername: '127.0.0.1' });
});
