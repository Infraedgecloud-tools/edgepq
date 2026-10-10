/* ============================================================================
   Every shipped rule has a failing and a passing fixture, and they evaluate
   as named. This is the contract the README makes: no rule without evidence
   that it fires, and evidence that it stays quiet.

   test/fixtures/rules/<RULE-ID>/fail.tf   every applicable resource -> fail
   test/fixtures/rules/<RULE-ID>/pass.tf   every applicable resource -> pass
   test/fixtures/rules/<RULE-ID>/unknown.tf (optional) -> unknown

   Two markers relax the pass side, and the file must say which:
   `edgepq-fixture: no-passing-configuration-exists`  the service offers
       nothing to set, so no resource of that type can pass today;
   `edgepq-fixture: passing-means-not-applicable`     the rule only exists to
       name a configuration that cannot be fixed, and the way out of it is a
       configuration the rule no longer applies to.
   With either marker the harness requires only that pass.tf produces no
   failure.
   ========================================================================= */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRulesFromDir } from '../src/node/load-rules.ts';
import { parseHcl } from '../src/node/hcl-parser.ts';
import { scanHclFiles } from '../src/adapters/hcl.ts';
import { evaluateAll } from '../src/engine/evaluate.ts';
import type { Rule, Status } from '../src/engine/types.ts';

const root = fileURLToPath(new URL('..', import.meta.url));
const rulesDir = join(root, 'rules');
const fixturesDir = join(root, 'test/fixtures/rules');
const MARKERS = ['edgepq-fixture: no-passing-configuration-exists', 'edgepq-fixture: passing-means-not-applicable'];

async function statusesFor(rule: Rule, file: string): Promise<{ statuses: Status[]; marker: boolean; notes: number }> {
  const contents = await readFile(file, 'utf8');
  const scan = await scanHclFiles([{ name: file, contents }], parseHcl);
  const findings = evaluateAll([rule], scan.resources);
  return { statuses: findings.map((f) => f.status), marker: MARKERS.some((m) => contents.includes(m)), notes: scan.notes.length };
}

const rules = await loadRulesFromDir(rulesDir);

test('every rule has a fixture directory and every fixture directory has a rule', async () => {
  const dirs = (await readdir(fixturesDir)).sort();
  assert.deepEqual(dirs, rules.map((r) => r.id));
});

for (const rule of rules) {
  test(`${rule.id}: fail.tf fails and pass.tf passes`, async () => {
    const dir = join(fixturesDir, rule.id);
    const fail = await statusesFor(rule, join(dir, 'fail.tf'));
    assert.equal(fail.notes, 0, 'fixture must parse cleanly');
    assert.ok(fail.statuses.length > 0, 'fail.tf has no resource the rule applies to');
    assert.deepEqual([...new Set(fail.statuses)], ['fail'], `fail.tf statuses: ${fail.statuses.join(', ')}`);

    const pass = await statusesFor(rule, join(dir, 'pass.tf'));
    assert.equal(pass.notes, 0, 'fixture must parse cleanly');
    if (pass.marker) {
      assert.ok(!pass.statuses.includes('fail') && !pass.statuses.includes('unknown'), `marked pass.tf must be free of failures: ${pass.statuses.join(', ')}`);
    } else {
      assert.ok(pass.statuses.length > 0, 'pass.tf has no resource the rule applies to');
      assert.deepEqual([...new Set(pass.statuses)], ['pass'], `pass.tf statuses: ${pass.statuses.join(', ')}`);
    }

    const unknownFile = join(dir, 'unknown.tf');
    if (await stat(unknownFile).then(() => true, () => false)) {
      const unknown = await statusesFor(rule, unknownFile);
      assert.ok(unknown.statuses.length > 0);
      assert.deepEqual([...new Set(unknown.statuses)], ['unknown']);
    }
  });
}

test('ELB-KX-001 policy_map matches the generated policy data', async () => {
  const data = JSON.parse(await readFile(join(rulesDir, 'data/elb-security-policies.json'), 'utf8')) as {
    pq_superset: { [k: string]: { value: string; safety: string; note: string } };
    policies: { [k: string]: { post_quantum: boolean } };
  };
  const rule = rules.find((r) => r.id === 'ELB-KX-001')!;
  assert.deepEqual(rule.tables?.policy_map, data.pq_superset);
  /* And every classical policy AWS documents has a mapping. */
  const classical = Object.entries(data.policies).filter(([, p]) => !p.post_quantum).map(([n]) => n).sort();
  assert.deepEqual(Object.keys(data.pq_superset).sort(), classical);
  for (const [, m] of Object.entries(data.pq_superset)) assert.ok(data.policies[m.value]?.post_quantum, m.value);
});

test('API Gateway policy_map targets exist in the policy data and are post-quantum', async () => {
  const data = JSON.parse(await readFile(join(rulesDir, 'data/apigw-security-policies.json'), 'utf8')) as {
    policies: { [k: string]: { post_quantum: boolean; endpoint_types: string[] } };
  };
  for (const rule of rules.filter((r) => r.id.startsWith('APIGW-') && r.tables)) {
    for (const [from, entry] of Object.entries(rule.tables!.policy_map!)) {
      const to = typeof entry === 'string' ? entry : entry.value;
      assert.ok(data.policies[from], `${rule.id}: unknown source policy ${from}`);
      assert.ok(data.policies[to]?.post_quantum, `${rule.id}: ${to} is not a PQ policy`);
    }
  }
});
