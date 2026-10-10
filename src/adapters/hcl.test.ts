import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resourcesFromHclJson, scanHclFiles } from './hcl.ts';
import { parseHcl } from '../node/hcl-parser.ts';
import { lookup } from '../engine/predicate.ts';

const fixture = fileURLToPath(new URL('../../test/fixtures/terraform/basic/main.tf', import.meta.url));

test('the basic fixture through the real parser', async () => {
  const scan = await scanHclFiles([{ name: 'main.tf', contents: await readFile(fixture, 'utf8') }], parseHcl);
  const byAddress = Object.fromEntries(scan.resources.map((r) => [r.address, r]));
  assert.deepEqual(Object.keys(byAddress).sort(), [
    'aws_cloudfront_distribution.site', 'aws_lb_listener.classical', 'aws_lb_listener.from_variable', 'aws_lb_listener.plain',
  ]);
  const classical = byAddress['aws_lb_listener.classical']!;
  assert.equal(lookup(classical, 'ssl_policy').value, 'ELBSecurityPolicy-2016-08');
  assert.equal(lookup(classical, 'default_action.type').value, 'forward');
  assert.equal(lookup(classical, 'load_balancer_arn').unknown, true);
  assert.equal(lookup(byAddress['aws_lb_listener.from_variable']!, 'ssl_policy').unknown, true);

  const cf = byAddress['aws_cloudfront_distribution.site']!;
  assert.equal(lookup(cf, 'viewer_certificate.minimum_protocol_version').value, 'TLSv1.2_2021');
  assert.equal(lookup(cf, 'default_cache_behavior.viewer_protocol_policy').value, 'redirect-to-https');
  assert.equal(lookup(cf, 'ordered_cache_behavior[*].viewer_protocol_policy').unknown, true, 'dynamic blocks are unknown');
  assert.equal('dynamic' in cf.attrs, false);

  assert.deepEqual(scan.notes, [
    { kind: 'dynamic-block', address: 'aws_cloudfront_distribution.site', file: 'main.tf', block: 'ordered_cache_behavior' },
    { kind: 'module-call', address: 'module.alb', file: 'main.tf', source: 'terraform-aws-modules/alb/aws' },
  ]);
});

test('a file that does not parse is a note, not a crash', async () => {
  const scan = await scanHclFiles([{ name: 'bad.tf', contents: 'resource "a" "b" {' }], parseHcl);
  assert.equal(scan.resources.length, 0);
  assert.equal(scan.notes[0]?.kind, 'parse-error');
});

test('meta-arguments are dropped from attributes', () => {
  const scan = resourcesFromHclJson({ resource: { aws_kms_key: { k: [{ count: 2, key_usage: 'SIGN_VERIFY', lifecycle: [{ prevent_destroy: true }] }] } } }, 'x.tf');
  assert.deepEqual(scan.resources[0]?.attrs, { key_usage: 'SIGN_VERIFY' });
});
