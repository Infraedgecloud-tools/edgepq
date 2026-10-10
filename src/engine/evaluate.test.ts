import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAll, evaluatePair } from './evaluate.ts';
import { validateRule } from './rules.ts';
import type { Resource, Rule } from './types.ts';

const rule: Rule = validateRule({
  id: 'ELB-KX-001',
  title: 'Listener offers no hybrid key exchange',
  resource_types: ['aws_lb_listener'],
  category: 'key-exchange',
  severity: 'high',
  applies_when: { attr: 'protocol', in: ['HTTPS', 'TLS'] },
  pass_when: { attr: 'ssl_policy', matches: '-PQ-' },
  defaults: { ssl_policy: 'ELBSecurityPolicy-2016-08' },
  fix: { kind: 'set-attribute', attr: 'ssl_policy', value_from: 'policies', safety: 'review' },
  tables: { policies: {
    'ELBSecurityPolicy-2016-08': 'ELBSecurityPolicy-TLS13-1-0-PQ-2025-09',
    'ELBSecurityPolicy-TLS13-1-2-2021-06': { value: 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09', safety: 'auto', note: 'superset' },
  } },
  message: { fail: '{address} uses {ssl_policy}', pass: '{address} ok', unknown: '{address} unknown' },
  sources: [{ url: 'https://docs.aws.amazon.com/x', verified: '2026-10-10' }],
});

const listener = (attrs: Resource['attrs'], unknown: string[] = []): Resource =>
  ({ type: 'aws_lb_listener', address: 'aws_lb_listener.a', attrs, unknown, origin: { kind: 'hcl', file: 'main.tf' } });

test('fail with the default applied and a mapped fix', () => {
  const f = evaluatePair(rule, listener({ protocol: 'HTTPS' }));
  assert.ok(f);
  assert.equal(f.status, 'fail');
  assert.equal(f.message, 'aws_lb_listener.a uses ELBSecurityPolicy-2016-08');
  assert.deepEqual(f.observed.ssl_policy, { value: 'ELBSecurityPolicy-2016-08', defaulted: true });
  assert.deepEqual(f.fix, { kind: 'set-attribute', attr: 'ssl_policy', value: 'ELBSecurityPolicy-TLS13-1-0-PQ-2025-09', safety: 'review' });
});

test('a table entry carries its own safety and note', () => {
  const f = evaluatePair(rule, listener({ protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06' }));
  assert.deepEqual(f?.fix, { kind: 'set-attribute', attr: 'ssl_policy', value: 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09', safety: 'auto', note: 'superset' });
});

test('also_set travels with the resolved fix', () => {
  const r: Rule = { ...rule, fix: { kind: 'set-attribute', attr: 'ssl_policy', value: 'X-PQ-1', safety: 'review', also_set: { endpoint_access_mode: 'BASIC' } } };
  const f = evaluatePair(r, listener({ protocol: 'HTTPS' }));
  assert.deepEqual(f?.fix, { kind: 'set-attribute', attr: 'ssl_policy', value: 'X-PQ-1', safety: 'review', also_set: { endpoint_access_mode: 'BASIC' } });
});

test('messages can name any literal attribute, and the AWS origin supplies account and region', () => {
  const r: Rule = { ...rule, message: { fail: '{address} {port} {account}/{region} {missing}', pass: 'p', unknown: 'u' } };
  const f = evaluatePair(r, { ...listener({ protocol: 'HTTPS', port: 443 }), origin: { kind: 'aws', account: '111', region: 'eu-west-2' } });
  assert.equal(f?.message, 'aws_lb_listener.a 443 111/eu-west-2 {missing}');
});

test('no mapping means guidance, not an invented target', () => {
  const f = evaluatePair(rule, listener({ protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-FS-2018-06' }));
  assert.equal(f?.fix?.kind, 'guidance');
});

test('pass, unknown and not applicable', () => {
  assert.equal(evaluatePair(rule, listener({ protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09' }))?.status, 'pass');
  assert.equal(evaluatePair(rule, listener({ protocol: 'HTTPS', ssl_policy: '${var.p}' }))?.status, 'unknown');
  assert.equal(evaluatePair(rule, listener({ protocol: 'HTTPS' }, ['ssl_policy']))?.status, 'unknown');
  assert.equal(evaluatePair(rule, listener({ protocol: 'HTTP' })), undefined);
  assert.equal(evaluatePair(rule, listener({ protocol: '${var.proto}' }))?.status, 'unknown');
  assert.equal(evaluatePair(rule, { ...listener({}), type: 'aws_s3_bucket' }), undefined);
});

test('ranking puts fails first, then key exchange before signatures', () => {
  const sig: Rule = { ...rule, id: 'KMS-SIG-001', category: 'signature', severity: 'critical', resource_types: ['aws_kms_key'], applies_when: undefined as never, pass_when: { attr: 'x', present: true } };
  delete (sig as { applies_when?: unknown }).applies_when;
  const findings = evaluateAll([sig, rule], [
    { type: 'aws_kms_key', address: 'aws_kms_key.k', attrs: {}, unknown: [], origin: { kind: 'plan' } },
    listener({ protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09' }),
    listener({ protocol: 'HTTPS' }),
  ]);
  assert.deepEqual(findings.map((f) => [f.rule.id, f.status]), [
    ['ELB-KX-001', 'fail'], ['KMS-SIG-001', 'fail'], ['ELB-KX-001', 'pass'],
  ]);
});
