import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, symlink, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { reportForTerraform, loadRules } from '../node/report.ts';
import { writeOutputs } from './write.ts';

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'edgepq-writes-'));
  const target = join(dir, 'source');
  await mkdir(target);
  const out = join(dir, 'out');
  const file = join(target, 'main.tf');
  const contents = 'resource "aws_lb_listener" "test" {\n  protocol = "HTTPS"\n  ssl_policy = "ELBSecurityPolicy-2016-08"\n}\n';
  await writeFile(file, contents);
  const rules = await loadRules();
  const scan = async () => {
    const { report, input } = await reportForTerraform(target, rules);
    return writeOutputs(report, out, { target, input });
  };
  return { dir, out, file, contents, scan };
}

test('fail-to-pass rescan removes stale patches and all reports describe the latest run', async () => {
  const f = await fixture();
  assert.equal((await f.scan()).patches, 1);
  await writeFile(f.file, f.contents.replace('ELBSecurityPolicy-2016-08', 'ELBSecurityPolicy-TLS13-1-0-PQ-2025-09'));
  assert.equal((await f.scan()).patches, 0);
  assert.ok(!(await readdir(f.out)).includes('patches'));
  const report = JSON.parse(await readFile(join(f.out, 'edgepq-findings.json'), 'utf8'));
  assert.ok(!report.findings.some((x: { status: string }) => x.status === 'fail'));
  assert.doesNotMatch(await readFile(join(f.out, 'edgepq-report.md'), 'utf8'), /ELBSecurityPolicy-2016-08/);
});

test('fewer findings replace owned per-fix patches', async () => {
  const f = await fixture();
  await writeFile(f.file, f.contents + f.contents.replace('"test"', '"second"'));
  assert.equal((await f.scan()).patches, 2);
  await writeFile(f.file, f.contents);
  assert.equal((await f.scan()).patches, 1);
  assert.ok(!(await readdir(join(f.out, 'patches'))).some((name) => name.includes('second')));
});

test('unowned files, output collisions and symlinks are refused without modifying user data', async () => {
  const f = await fixture();
  await mkdir(f.out);
  await writeFile(join(f.out, 'edgepq-findings.json'), 'user data');
  await assert.rejects(f.scan(), /not owned/);
  assert.equal(await readFile(join(f.out, 'edgepq-findings.json'), 'utf8'), 'user data');
  const other = await fixture();
  await symlink(other.dir, other.out);
  await assert.rejects(other.scan(), /real directory/);
});

test('user additions to an owned directory are preserved and block replacement', async () => {
  const f = await fixture();
  await f.scan();
  const before = await readFile(join(f.out, 'edgepq-findings.json'), 'utf8');
  await writeFile(join(f.out, 'my-notes'), 'keep');
  await assert.rejects(f.scan(), /unowned/);
  assert.equal(await readFile(join(f.out, 'my-notes'), 'utf8'), 'keep');
  assert.equal(await readFile(join(f.out, 'edgepq-findings.json'), 'utf8'), before);
});

test('interrupted run lock blocks another writer without exposing mixed reports', async () => {
  const f = await fixture();
  await f.scan();
  const before = await readFile(join(f.out, 'edgepq-findings.json'), 'utf8');
  await writeFile(f.out + '.edgepq-lock', 'interrupted run');
  await assert.rejects(f.scan(), /EEXIST/);
  assert.equal(await readFile(join(f.out, 'edgepq-findings.json'), 'utf8'), before);
});

test('invalid parent path fails before changing previous reports', async () => {
  const f = await fixture();
  await f.scan();
  const before = await readFile(join(f.out, 'edgepq-findings.json'), 'utf8');
  await writeFile(join(f.dir, 'not-a-directory'), 'keep');
  const { report, input } = await reportForTerraform(join(f.dir, 'source'), await loadRules());
  await assert.rejects(writeOutputs(report, join(f.dir, 'not-a-directory', 'out'), { target: join(f.dir, 'source'), input }));
  assert.equal(await readFile(join(f.out, 'edgepq-findings.json'), 'utf8'), before);
});
