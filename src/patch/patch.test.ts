/* Round trip: every rule fixture that fails is patched, the diff is checked
   with git, applied in a scratch directory, and the file re-scanned. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRulesFromDir } from '../node/load-rules.ts';
import { parseHcl } from '../node/hcl-parser.ts';
import { scanHclFiles } from '../adapters/hcl.ts';
import { evaluateAll } from '../engine/evaluate.ts';
import { buildPatches, buildPatchesWithSkips, combinePatches } from './index.ts';

const root = fileURLToPath(new URL('../..', import.meta.url));
const rules = await loadRulesFromDir(join(root, 'rules'));
const haveGit = spawnSync('git', ['--version']).status === 0;

const scan = async (rule: (typeof rules)[number], name: string, contents: string) =>
  evaluateAll([rule], (await scanHclFiles([{ name, contents }], parseHcl)).resources);

function gitApply(dir: string, patch: string, check: boolean) {
  writeFileSync(join(dir, 'x.patch'), patch);
  return spawnSync('git', ['apply', ...(check ? ['--check'] : []), 'x.patch'], { cwd: dir, encoding: 'utf8' });
}

for (const rule of rules) {
  test(`${rule.id}: patches fix the fail fixture, or none for guidance`, { skip: !haveGit && 'git is not installed' }, async () => {
    const contents = readFileSync(join(root, 'test/fixtures/rules', rule.id, 'fail.tf'), 'utf8');
    const findings = await scan(rule, 'fail.tf', contents);
    const patches = buildPatches(findings, [{ name: 'fail.tf', contents }]);
    if (rule.fix?.kind !== 'set-attribute') {
      assert.equal(patches.length, 0);
      return;
    }
    /* A fix that `unless` turned into guidance writes no patch. */
    const patchable = findings.filter((f) => f.fix?.kind === 'set-attribute');
    assert.equal(patches.length, patchable.length, 'one patch per failing resource with a set-attribute fix');
    const dir = mkdtempSync(join(tmpdir(), 'edgepq-patch-'));
    try {
      writeFileSync(join(dir, 'fail.tf'), contents);
      for (const p of patches) {
        assert.match(p.diff, /^# .*\n(# .*\n)*--- a\/fail\.tf\n\+\+\+ b\/fail\.tf\n@@ /);
        assert.ok(p.diff.includes('# EdgePQ does not apply patches. Review, then apply with: git apply <file>'));
        const check = gitApply(dir, p.diff, true);
        assert.equal(check.status, 0, check.stderr);
      }
      const combined = combinePatches(patches, { safety: 'all' });
      assert.equal(combined.skipped.length, 0);
      const applied = gitApply(dir, combined.diff, false);
      assert.equal(applied.status, 0, applied.stderr);
      const patched = readFileSync(join(dir, 'fail.tf'), 'utf8');
      const after = await scan(rule, 'fail.tf', patched);
      /* Everything a patch touched now passes; a resource whose fix was guidance still fails. */
      const guided = new Set(findings.filter((f) => f.fix?.kind !== 'set-attribute').map((f) => f.resource.address));
      assert.deepEqual(after.map((f) => f.status), after.map((f) => (guided.has(f.resource.address) ? 'fail' : 'pass')), patched);
      assert.equal(after.length, findings.length);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('combinePatches: auto filter, and a second patch on the same attribute is reported', async () => {
  const rule = rules.find((r) => r.id === 'APIGW-KX-003')!;
  const contents = readFileSync(join(root, 'test/fixtures/rules/APIGW-KX-003/fail.tf'), 'utf8');
  const patches = buildPatches(await scan(rule, 'fail.tf', contents), [{ name: 'fail.tf', contents }]);
  assert.ok(patches.length > 0 && patches.every((p) => p.safety === 'review'));
  assert.equal(combinePatches(patches, { safety: 'auto' }).diff, '');
  const dup = combinePatches([patches[0]!, patches[0]!], { safety: 'all' });
  assert.equal(dup.included.length, 1);
  assert.equal(dup.skipped.length, 1);
  assert.match(dup.skipped[0]!.reason, /already changed/);
});

test('findings that are not literal, not HCL or not failing produce no patch, and refusals are reported', async () => {
  const rule = rules.find((r) => r.id === 'ELB-KX-001')!;
  const contents = 'resource "aws_lb_listener" "a" {\n  protocol   = "HTTPS"\n  ssl_policy = var.p\n}\nresource "aws_lb_listener" "b" {\n  protocol   = "HTTPS"\n  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"\n}\nresource "aws_lb_listener" "b" {\n  protocol = "HTTPS"\n}\n';
  const findings = await scan(rule, 'x.tf', contents);
  const { patches, skipped } = buildPatchesWithSkips(findings, [{ name: 'x.tf', contents }]);
  assert.equal(findings.find((f) => f.resource.address.endsWith('.a'))!.status, 'unknown');
  assert.equal(patches.length, 0, 'unknown is never patched');
  assert.ok(skipped.length >= 1, 'a duplicated resource is refused and reported');
  assert.deepEqual(buildPatches(findings.map((f) => ({ ...f, resource: { ...f.resource, origin: { kind: 'plan' as const } } })), []), []);
});
