import test from 'node:test';
import assert from 'node:assert/strict';
import { applyFix, quote, type SetAttributeFix } from './apply.ts';

const fix = (attr: string, value: string, also_set?: { [k: string]: string }): SetAttributeFix =>
  ({ kind: 'set-attribute', attr, value, safety: 'review', ...(also_set ? { also_set } : {}) });

test('quote escapes quotes, backslashes and interpolation', () => {
  assert.equal(quote('a"b\\c${d}%{e}'), '"a\\"b\\\\c$${d}%%{e}"');
});

test('a literal is replaced in place and the rest of the file is untouched', () => {
  const t = 'resource "x" "y" {\n  ssl_policy        = "old" # keep\n  other             = 1\n}\n';
  const r = applyFix(t, 'x', 'y', fix('ssl_policy', 'new'));
  assert.equal(r.changed, true);
  assert.equal(r.text, 'resource "x" "y" {\n  ssl_policy        = "new" # keep\n  other             = 1\n}\n');
});

test('an absent attribute is inserted with a single space or the neighbours alignment', () => {
  const plain = applyFix('resource "x" "y" {\n  a = 1\n  b {\n  }\n}\n', 'x', 'y', fix('new_attr', 'v'));
  assert.equal(plain.text, 'resource "x" "y" {\n  a = 1\n  new_attr = "v"\n  b {\n  }\n}\n');
  const aligned = applyFix('resource "x" "y" {\n  name   = "n"\n  region = "r"\n}\n', 'x', 'y', fix('mode', 'v'));
  assert.equal(aligned.text, 'resource "x" "y" {\n  name   = "n"\n  region = "r"\n  mode   = "v"\n}\n');
});

test('a nested path edits only that block', () => {
  const t = 'resource "x" "y" {\n  a {\n    min = "1"\n  }\n  b {\n    min = "1"\n  }\n}\n';
  assert.equal(applyFix(t, 'x', 'y', fix('a.min', '2')).text, t.replace('min = "1"', 'min = "2"'));
  const absent = applyFix('resource "x" "y" {\n  vc {\n    arn = "a"\n  }\n}\n', 'x', 'y', fix('vc.min', '2'));
  assert.equal(absent.text, 'resource "x" "y" {\n  vc {\n    arn = "a"\n    min = "2"\n  }\n}\n');
});

test('also_set adds a missing attribute and leaves an existing STRICT alone', () => {
  const lacking = 'resource "aws_api_gateway_domain_name" "a" {\n  domain_name     = "d"\n  security_policy = "TLS_1_2"\n}\n';
  const r = applyFix(lacking, 'aws_api_gateway_domain_name', 'a', fix('security_policy', 'SecurityPolicy_X', { endpoint_access_mode: 'BASIC' }));
  assert.equal(r.text, 'resource "aws_api_gateway_domain_name" "a" {\n  domain_name     = "d"\n  security_policy = "SecurityPolicy_X"\n  endpoint_access_mode = "BASIC"\n}\n');
  assert.deepEqual(r.added, { endpoint_access_mode: 'BASIC' });

  const strict = 'resource "aws_api_gateway_domain_name" "b" {\n  security_policy      = "TLS_1_2"\n  endpoint_access_mode = "STRICT"\n}\n';
  const s = applyFix(strict, 'aws_api_gateway_domain_name', 'b', fix('security_policy', 'SecurityPolicy_X', { endpoint_access_mode: 'BASIC' }));
  assert.equal(s.text, strict.replace('TLS_1_2', 'SecurityPolicy_X'));
  assert.equal(s.added, undefined);
});

test('expressions, heredocs and duplicates are refused with a reason and the text unchanged', () => {
  for (const body of ['ssl_policy = var.p', 'ssl_policy = "${var.p}"', 'ssl_policy = <<EOT\nx\nEOT', 'ssl_policy = lookup(m,\n "k")']) {
    const t = `resource "x" "y" {\n  ${body}\n}\n`;
    const r = applyFix(t, 'x', 'y', fix('ssl_policy', 'new'));
    assert.equal(r.changed, false, body);
    assert.equal(r.text, t);
    assert.ok(r.reason);
  }
  const dup = 'resource "x" "y" {\n  a = "1"\n}\nresource "x" "y" {\n  a = "2"\n}\n';
  assert.equal(applyFix(dup, 'x', 'y', fix('a', '3')).changed, false);
  assert.equal(applyFix(dup, 'x', 'nope', fix('a', '3')).changed, false);
});

test('an unambiguous failure in also_set leaves the whole file unchanged', () => {
  const t = 'resource "x" "y" {\n  a = "1"\n  m = "1"\n  m = "2"\n}\n';
  const r = applyFix(t, 'x', 'y', fix('a', '2', { m: 'x' }));
  assert.equal(r.changed, false);
  assert.equal(r.text, t);
});

test('setting the value already there is not a change', () => {
  assert.equal(applyFix('resource "x" "y" {\n  a = "1"\n}\n', 'x', 'y', fix('a', '1')).changed, false);
});
