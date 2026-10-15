import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resourcesFromTerraformJson } from './plan.ts';
import { lookup } from '../engine/predicate.ts';

const fixture = fileURLToPath(new URL('../../test/fixtures/terraform/plan-create.json', import.meta.url));

test('a real plan: after values, after_unknown paths, deletes skipped', async () => {
  const scan = resourcesFromTerraformJson(JSON.parse(await readFile(fixture, 'utf8')));
  assert.equal(scan.kind, 'plan');
  const byAddress = Object.fromEntries(scan.resources.map((r) => [r.address, r]));
  const classical = byAddress['aws_lb_listener.classical']!;
  assert.equal(classical.type, 'aws_lb_listener');
  assert.equal(lookup(classical, 'ssl_policy').value, 'ELBSecurityPolicy-2016-08');
  assert.equal(lookup(classical, 'default_action.type').value, 'forward');
  /* The ARN of a not-yet-created load balancer is unknown in the plan. */
  assert.equal(lookup(classical, 'load_balancer_arn').unknown, true);
  assert.equal(lookup(classical, 'default_action.target_group_arn').unknown, true);
  /* A variable is resolved by terraform plan, so it is a literal here. */
  assert.equal(lookup(byAddress['aws_lb_listener.pq']!, 'ssl_policy').value, 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09');
  /* Absent attributes stay absent (null in the plan is "not set"). */
  assert.equal(lookup(byAddress['aws_kms_key.symmetric']!, 'customer_master_key_spec').value, 'SYMMETRIC_DEFAULT');
  assert.equal(lookup(byAddress['aws_api_gateway_domain_name.api']!, 'security_policy').value, 'TLS_1_2');
});

test('deletes are skipped and reported', () => {
  const scan = resourcesFromTerraformJson({ format_version: '1.2', resource_changes: [
    { address: 'aws_lb_listener.gone', type: 'aws_lb_listener', mode: 'managed', change: { actions: ['delete'], before: { protocol: 'HTTPS' }, after: null } },
    { address: 'data.aws_caller_identity.me', type: 'aws_caller_identity', mode: 'data', change: { actions: ['read'] } },
  ] });
  assert.equal(scan.resources.length, 0);
  assert.deepEqual(scan.skipped, [{ address: 'aws_lb_listener.gone', reason: 'planned for deletion' }]);
});

test('a state document walks child modules', () => {
  const scan = resourcesFromTerraformJson({ format_version: '1.0', values: { root_module: {
    resources: [{ address: 'aws_kms_key.a', type: 'aws_kms_key', mode: 'managed', values: { key_usage: 'SIGN_VERIFY' } }],
    child_modules: [{ address: 'module.m', resources: [{ address: 'module.m.aws_lb_listener.l', type: 'aws_lb_listener', mode: 'managed', values: { protocol: 'TLS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-3-PQ-2025-09' } }] }],
  } } });
  assert.equal(scan.kind, 'state');
  assert.deepEqual(scan.resources.map((r) => r.address), ['aws_kms_key.a', 'module.m.aws_lb_listener.l']);
});

test('something else is unrecognised', () => {
  assert.equal(resourcesFromTerraformJson({ hello: 1 }).kind, 'unrecognised');
});


test('incomplete, errored, future major and malformed documents fail explicitly', () => {
  for (const doc of [
    { format_version: '2.0', resource_changes: [] },
    { format_version: '1.2', complete: false, resource_changes: [] },
    { format_version: '1.2', errored: true, resource_changes: [] },
    { format_version: '1.2', resource_changes: {} },
    { format_version: '1.2', resource_changes: [{ address: 'aws_kms_key.k', type: 'aws_kms_key', mode: 'managed', change: { actions: ['future-action'], after: {} } }] },
    { format_version: '1.2', resource_changes: [{ address: 'aws_kms_key.k', type: 'aws_kms_key', mode: 'managed', change: { actions: ['update'] } }] },
    { format_version: '1.0', values: { root_module: { resources: [{}] } } },
  ]) assert.throws(() => resourcesFromTerraformJson(doc));
  const noOp = resourcesFromTerraformJson({ format_version: '1.99', applyable: false, complete: true, resource_changes: [] });
  assert.equal(noOp.kind, 'plan');
  assert.equal(noOp.resources.length, 0);
});

test('whole-resource unknown values cannot take configured defaults', () => {
  const result = resourcesFromTerraformJson({ format_version: '1.2', resource_changes: [{ address: 'aws_lb_listener.x', type: 'aws_lb_listener', mode: 'managed', change: { actions: ['create'], after: {}, after_unknown: true } }] });
  assert.equal(lookup(result.resources[0]!, 'ssl_policy').unknown, true);
});


test('invalid actions, mask values and unsupported providers cannot pass', () => {
  const resource = { address: 'aws_lb_listener.x', type: 'aws_lb_listener', mode: 'managed', change: { actions: ['create'], after: { protocol: 'HTTPS' } } };
  assert.throws(() => resourcesFromTerraformJson({ resource_changes: [resource] }), /format_version/);
  for (const actions of [['create', 'update'], ['delete', 'delete'], [['create']], ['delete,create']]) assert.throws(() => resourcesFromTerraformJson({ format_version: '1.2', resource_changes: [{ ...resource, change: { ...resource.change, actions } }] }), /actions/);
  assert.throws(() => resourcesFromTerraformJson({ format_version: '1.2', resource_changes: [{ ...resource, provider_name: 'not.aws/provider' }] }), /provider/);
  for (const mask of ['true', { child: true }]) assert.throws(() => resourcesFromTerraformJson({ format_version: '1.2', resource_changes: [{ ...resource, change: { ...resource.change, after_unknown: { ssl_policy: mask } } }] }), /mask/);
  assert.throws(() => resourcesFromTerraformJson({ format_version: '1.0', values: { root_module: { resources: [{ ...resource, provider_name: 'wrong/provider', values: {} }] } } }), /provider/);
});
