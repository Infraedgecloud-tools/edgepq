import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, lookup } from './predicate.ts';
import type { Resource } from './types.ts';

const res = (attrs: Resource['attrs'], unknown: string[] = []): Resource =>
  ({ type: 'aws_lb_listener', address: 'aws_lb_listener.x', attrs, unknown, origin: { kind: 'plan' } });

test('literal, absent and expression values', () => {
  const r = res({ protocol: 'HTTPS', ssl_policy: '${var.policy}', port: 443 });
  assert.deepEqual(lookup(r, 'protocol'), { value: 'HTTPS', unknown: false });
  assert.deepEqual(lookup(r, 'missing'), { value: undefined, unknown: false });
  assert.deepEqual(lookup(r, 'ssl_policy'), { value: undefined, unknown: true });
  assert.equal(evaluate({ attr: 'port', eq: 443 }, r), true);
  assert.equal(evaluate({ attr: 'ssl_policy', matches: '-PQ-' }, r), 'unknown');
  assert.equal(evaluate({ attr: 'missing', absent: true }, r), true);
  assert.equal(evaluate({ attr: 'ssl_policy', absent: true }, r), 'unknown');
});

test('single blocks unwrap, multiple blocks need an index', () => {
  const r = res({
    viewer_certificate: [{ minimum_protocol_version: 'TLSv1.2_2021' }],
    default_action: [{ type: 'forward' }, { type: 'redirect' }],
  });
  assert.equal(lookup(r, 'viewer_certificate.minimum_protocol_version').value, 'TLSv1.2_2021');
  assert.equal(lookup(r, 'default_action.type').unknown, true);
  assert.equal(lookup(r, 'default_action[1].type').value, 'redirect');
  assert.deepEqual(lookup(r, 'default_action[*].type').value, ['forward', 'redirect']);
  assert.equal(evaluate({ attr: 'default_action[*].type', eq: 'redirect' }, r), true);
  assert.equal(evaluate({ attr: 'default_action[*].type', eq: 'fixed-response' }, r), false);
});

test('unknown paths from the adapter propagate to children', () => {
  const r = res({ viewer_certificate: [{ minimum_protocol_version: 'TLSv1' }] }, ['viewer_certificate']);
  assert.equal(lookup(r, 'viewer_certificate.minimum_protocol_version').unknown, true);
});

test('three-valued combinators', () => {
  const r = res({ a: '1', b: '${x}' });
  const t = { attr: 'a', eq: '1' };
  const f = { attr: 'a', eq: '2' };
  const u = { attr: 'b', eq: '1' };
  assert.equal(evaluate({ all: [t, u] }, r), 'unknown');
  assert.equal(evaluate({ all: [f, u] }, r), false);
  assert.equal(evaluate({ any: [t, u] }, r), true);
  assert.equal(evaluate({ any: [f, u] }, r), 'unknown');
  assert.equal(evaluate({ not: u }, r), 'unknown');
  assert.equal(evaluate({ not: f }, r), true);
  assert.equal(evaluate({ attr: 'a', in: ['0', '1'] }, r), true);
});
