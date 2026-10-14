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
    assert.deepEqual([...new Set(fail.statuses)], [rule.fail_as ?? 'fail'], `fail.tf statuses: ${fail.statuses.join(', ')}`);

    const pass = await statusesFor(rule, join(dir, 'pass.tf'));
    assert.equal(pass.notes, 0, 'fixture must parse cleanly');
    if (pass.marker) {
      assert.ok(!pass.statuses.includes('fail') && !pass.statuses.includes('not_configurable') && !pass.statuses.includes('unknown'), `marked pass.tf must be free of failures: ${pass.statuses.join(', ')}`);
    } else {
      assert.ok(pass.statuses.length > 0, 'pass.tf has no resource the rule applies to');
      assert.deepEqual([...new Set(pass.statuses)], [rule.pass_as ?? 'pass'], `pass.tf statuses: ${pass.statuses.join(', ')}`);
    }

    const unknownFile = join(dir, 'unknown.tf');
    if (await stat(unknownFile).then(() => true, () => false)) {
      const unknown = await statusesFor(rule, unknownFile);
      assert.ok(unknown.statuses.length > 0);
      assert.deepEqual([...new Set(unknown.statuses)], ['unknown']);
    }
  });
}

test('APIGW-KX-001: mutual TLS turns the fix into guidance', async () => {
  const rule = rules.find((r) => r.id === 'APIGW-KX-001')!;
  const contents = await readFile(join(fixturesDir, 'APIGW-KX-001/fail.tf'), 'utf8');
  const scan = await scanHclFiles([{ name: 'fail.tf', contents }], parseHcl);
  const findings = evaluateAll([rule], scan.resources);
  const mtls = findings.find((f) => f.resource.address === 'aws_api_gateway_domain_name.mtls_legacy')!;
  assert.equal(mtls.status, 'fail');
  assert.equal(mtls.fix?.kind, 'guidance');
  assert.ok(findings.some((f) => f.resource.address === 'aws_api_gateway_domain_name.regional_legacy' && f.fix?.kind === 'set-attribute'));
});

test('ELB-KX-001 policy_map matches the generated policy data', async () => {
  const data = JSON.parse(await readFile(join(rulesDir, 'data/elb-security-policies.json'), 'utf8')) as {
    pq_superset: { [k: string]: { value: string; safety: string; note: string } };
    policies: { [k: string]: { post_quantum: boolean } };
  };
  const rule = rules.find((r) => r.id === 'ELB-KX-001')!;
  assert.deepEqual(rule.tables?.policy_map, data.pq_superset);
  /* The known-policy and PQ-policy lists in the predicates are the data file's too. */
  const all = Object.keys(data.policies).sort();
  const pq = all.filter((n) => data.policies[n]!.post_quantum);
  const inList = (pred: unknown): string[] => (pred as { in: string[] }).in;
  const policyNot = (rule.unknown_when as { any: { not: { attr: string } }[] }).any.find((p) => p.not.attr === 'ssl_policy')!.not;
  assert.deepEqual([...inList(policyNot)].sort(), all);
  assert.deepEqual([...inList(rule.pass_when)].sort(), pq);
  /* And every classical policy AWS documents has a mapping. */
  const classical = Object.entries(data.policies).filter(([, p]) => !p.post_quantum).map(([n]) => n).sort();
  assert.deepEqual(Object.keys(data.pq_superset).sort(), classical);
  for (const [, m] of Object.entries(data.pq_superset)) assert.ok(data.policies[m.value]?.post_quantum, m.value);
});

test('API Gateway rules list the policies the data file lists, and nothing else', async () => {
  const data = JSON.parse(await readFile(join(rulesDir, 'data/apigw-security-policies.json'), 'utf8')) as {
    policies: { [k: string]: { post_quantum: boolean; endpoint_types: string[]; accepted_by_api?: boolean } };
    defaults: { rest_api: { [t: string]: string }; domain_name: { [t: string]: string } };
  };
  const accepted = Object.entries(data.policies).filter(([, p]) => p.accepted_by_api !== false);
  const forTypes = (types: string[]) => accepted.filter(([, p]) => p.endpoint_types.some((t) => types.includes(t)));
  const inList = (pred: unknown): string[] => [...(pred as { in: string[] }).in].sort();
  const knownList = (rule: Rule) => inList((rule.unknown_when as { any: { not?: { attr: string } }[] }).any.find((p) => p.not?.attr === 'security_policy')!.not);
  /* Regional and private domains and REST APIs: the known list is every policy the API
     accepts for those endpoint types; the pass list is the post-quantum ones among them. */
  for (const [id, types, defaults] of [['APIGW-KX-001', ['REGIONAL', 'PRIVATE'], data.defaults.domain_name], ['APIGW-KX-003', ['REGIONAL'], data.defaults.rest_api], ['APIGW-KX-004', ['PRIVATE'], data.defaults.rest_api]] as const) {
    const rule = rules.find((r) => r.id === id)!;
    const known = forTypes([...types]).map(([n]) => n).sort();
    assert.deepEqual(knownList(rule), known, `${id}: known policies`);
    assert.deepEqual(inList(rule.pass_when), forTypes([...types]).filter(([, p]) => p.post_quantum).map(([n]) => n).sort(), `${id}: PQ policies`);
    for (const t of types) assert.equal(rule.defaults?.security_policy, defaults[t], `${id}: default for ${t}`);
    /* Every classical policy for the endpoint type has a mapping; every mapping lands on a PQ policy. */
    const classical = forTypes([...types]).filter(([, p]) => !p.post_quantum).map(([n]) => n).sort();
    assert.deepEqual(Object.keys(rule.tables!.policy_map!).sort(), classical, `${id}: policy_map covers every classical policy`);
    for (const [from, entry] of Object.entries(rule.tables!.policy_map!)) {
      const to = typeof entry === 'string' ? entry : entry.value;
      assert.ok(data.policies[to]?.post_quantum && data.policies[to]?.accepted_by_api !== false, `${id}: ${from} maps to ${to}, which is not a PQ policy the API accepts`);
    }
  }
  for (const rule of rules.filter((r) => r.id.startsWith('APIGW-') && r.tables)) {
    for (const [from, entry] of Object.entries(rule.tables!.policy_map!)) {
      const to = typeof entry === 'string' ? entry : entry.value;
      assert.ok(data.policies[from], `${rule.id}: unknown source policy ${from}`);
      assert.ok(data.policies[to]?.post_quantum, `${rule.id}: ${to} is not a PQ policy`);
    }
  }
});
