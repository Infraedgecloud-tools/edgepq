import test from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint, fnv1a64 } from './fingerprint.ts';
import { evaluatePair } from './evaluate.ts';
import { validateRule } from './rules.ts';

/* Published FNV-1a 64-bit vectors. */
test('fnv1a64 matches the reference values', () => {
  assert.equal(fnv1a64(''), 'cbf29ce484222325');
  assert.equal(fnv1a64('a'), 'af63dc4c8601ec8c');
  assert.equal(fnv1a64('foobar'), '85944171f73967e8');
});

test('the fingerprint follows the resource across files; the id does not', () => {
  const rule = validateRule({
    id: 'KMS-KX-001', version: 1, title: 't', resource_types: ['aws_kms_key'], category: 'key-exchange', severity: 'low',
    pass_when: { attr: 'customer_master_key_spec', eq: 'SYMMETRIC_DEFAULT' },
    message: { fail: 'f', pass: 'p', unknown: 'u' }, sources: [{ url: 'https://x', verified: '2026-01-01' }],
  });
  const key = (file: string) => ({ type: 'aws_kms_key', address: 'aws_kms_key.main', attrs: { customer_master_key_spec: 'RSA_2048' }, unknown: [], origin: { kind: 'hcl' as const, file } });
  const a = evaluatePair(rule, key('kms.tf'))!;
  const b = evaluatePair(rule, key('keys/main.tf'))!;
  assert.notEqual(a.id, b.id);
  assert.equal(a.fingerprint, b.fingerprint);
  assert.equal(a.fingerprint, fingerprint('KMS-KX-001', 'aws_kms_key', 'aws_kms_key.main'));
  assert.match(a.fingerprint, /^[0-9a-f]{16}$/);
  /* A different rule or a different resource is a different fingerprint. */
  assert.notEqual(a.fingerprint, fingerprint('KMS-SIG-001', 'aws_kms_key', 'aws_kms_key.main'));
  assert.notEqual(a.fingerprint, fingerprint('KMS-KX-001', 'aws_kms_key', 'module.x.aws_kms_key.main'));
  assert.equal(a.rule.version, 1);
});
