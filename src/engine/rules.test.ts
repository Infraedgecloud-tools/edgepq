import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRule, validateRules, RuleError } from './rules.ts';

const good = {
  id: 'KMS-SIG-001', title: 't', resource_types: ['aws_kms_key'], category: 'signature', severity: 'low',
  pass_when: { attr: 'customer_master_key_spec', in: ['ML_DSA_44'] },
  message: { fail: 'f', pass: 'p', unknown: 'u' },
  sources: [{ url: 'https://docs.aws.amazon.com/kms', verified: '2026-10-10', quote: 'q' }],
};

test('a complete rule validates', () => {
  assert.equal(validateRule(good).id, 'KMS-SIG-001');
});

const bad: [string, unknown, RegExp][] = [
  ['no sources', { ...good, sources: [] }, /no rule ships without a source/],
  ['undated source', { ...good, sources: [{ url: 'https://x' }] }, /verified must be a YYYY-MM-DD/],
  ['http source', { ...good, sources: [{ url: 'http://x', verified: '2026-10-10' }] }, /https URL/],
  ['bad id', { ...good, id: 'kms1' }, /AREA-KIND-001/],
  ['bad category', { ...good, category: 'misc' }, /category must be one of/],
  ['two ops in a leaf', { ...good, pass_when: { attr: 'a', eq: 1, in: [1] } }, /exactly one of/],
  ['bad regexp', { ...good, pass_when: { attr: 'a', matches: '(' } }, /not a valid regular expression/],
  ['unknown field', { ...good, extra: 1 }, /unknown field 'extra'/],
  ['fix without table', { ...good, fix: { kind: 'set-attribute', attr: 'a', value_from: 'nope', safety: 'auto' } }, /does not define/],
  ['missing message', { ...good, message: { fail: 'f', pass: 'p' } }, /message.unknown is required/],
];
for (const [name, raw, re] of bad) {
  test(`rejects ${name}`, () => { assert.throws(() => validateRule(raw), re); });
}

test('duplicate ids are rejected and output is sorted', () => {
  assert.throws(() => validateRules([good, good]), RuleError);
  const out = validateRules([{ ...good, id: 'ZZZ-SIG-001' }, good]);
  assert.deepEqual(out.map((r) => r.id), ['KMS-SIG-001', 'ZZZ-SIG-001']);
});
