import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { readTerraform } from './read-terraform.ts';
import { lookup } from '../engine/predicate.ts';

const fixture = fileURLToPath(new URL('../../test/fixtures/terraform/modules', import.meta.url));

test('a directory is read as Terraform does: root, called modules with their inputs, uncalled directories as roots', async () => {
  const input = await readTerraform(fixture);
  assert.equal(input.kind, 'hcl');
  if (input.kind !== 'hcl') return;
  const byAddress = Object.fromEntries(input.scan.resources.map((r) => [r.address, r]));
  assert.deepEqual(Object.keys(byAddress).sort(), [
    'aws_lb_listener.conditional',
    'module.edge.aws_lb_listener.https',
    'module.edge_default.aws_lb_listener.https',
    'standalone:aws_lb_listener.https',
  ]);

  /* The call passed var.root_policy, itself resolved from the root default. */
  assert.equal(lookup(byAddress['module.edge.aws_lb_listener.https']!, 'ssl_policy').value, 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09');
  /* No input: the module's own default, and a note that it is an assumption. */
  assert.equal(lookup(byAddress['module.edge_default.aws_lb_listener.https']!, 'ssl_policy').value, 'ELBSecurityPolicy-2016-08');
  assert.ok(input.scan.notes.some((n) => n.kind === 'default-used' && n.address === 'module.edge_default.aws_lb_listener.https' && n.variable === 'ssl_policy' && n.attr === 'ssl_policy'));
  /* A literal local resolves; the count expression is noted, not silent. */
  assert.equal(lookup(byAddress['aws_lb_listener.conditional']!, 'ssl_policy').value, 'ELBSecurityPolicy-2016-08');
  assert.ok(input.scan.notes.some((n) => n.kind === 'count-expression' && n.address === 'aws_lb_listener.conditional' && n.meta === 'count'));
  /* The module directory is read under its call, and not again as a root. */
  const edgeNotes = input.scan.notes.filter((n) => n.kind === 'module-call');
  assert.equal(edgeNotes.length, 2);
  assert.ok(edgeNotes.every((n) => n.kind === 'module-call' && n.scanned === true));
  assert.equal(input.scan.resources.filter((r) => r.origin.kind === 'hcl' && r.origin.file === 'edge/main.tf').length, 2);
  /* Every file is listed once per time it was read. */
  assert.deepEqual(input.files.sort(), ['edge/main.tf', 'edge/main.tf', 'main.tf', 'standalone/main.tf']);
});
