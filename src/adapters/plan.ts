/* ============================================================================
   `terraform show -json` → Resource[].

   Two documents share the command: a plan (has `resource_changes`) and a
   state (has `values.root_module` and no changes). Both are handled. For a
   plan the resource's *after* state is what gets checked, and every leaf
   marked true in `after_unknown` becomes an unknown path. Resources being
   deleted are skipped: there is nothing to make post-quantum about a thing
   that will not exist.
   ========================================================================= */

import type { AttrValue, Resource } from '../engine/types.ts';

type Json = { [k: string]: unknown };
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

export type PlanScan = { resources: Resource[]; kind: 'plan' | 'state' | 'unrecognised'; skipped: { address: string; reason: string }[] };

export function resourcesFromTerraformJson(doc: unknown): PlanScan {
  if (!isObj(doc)) return { resources: [], kind: 'unrecognised', skipped: [] };
  if (('resource_changes' in doc || 'values' in doc) && typeof doc.format_version !== 'string') throw new Error('Terraform JSON requires format_version');
  if (typeof doc.format_version === 'string' && !/^1\.\d+$/.test(doc.format_version)) throw new Error('unsupported Terraform JSON format_version (expected major 1)');
  if (('complete' in doc && typeof doc.complete !== 'boolean') || ('errored' in doc && typeof doc.errored !== 'boolean')) throw new Error('malformed Terraform plan status');
  if (doc.errored === true || doc.complete === false) throw new Error('Terraform plan is errored or incomplete; full assessment is unavailable');
  if ('resource_changes' in doc && !Array.isArray(doc.resource_changes)) throw new Error('malformed resource_changes');
  if (Array.isArray(doc.resource_changes)) return fromPlan(doc.resource_changes);
  if (isObj(doc.values) && isObj(doc.values.root_module)) return fromState(doc.values.root_module);
  return { resources: [], kind: 'unrecognised', skipped: [] };
}

function fromPlan(changes: unknown[]): PlanScan {
  const out: PlanScan = { resources: [], kind: 'plan', skipped: [] };
  for (const rc of changes) {
    if (!isObj(rc) || typeof rc.address !== 'string' || typeof rc.type !== 'string' || !['managed', 'data'].includes(rc.mode as string)) throw new Error('malformed Terraform resource change');
    if (rc.mode !== 'managed') continue;
    if (!isObj(rc.change)) throw new Error('malformed Terraform change');
    const change = rc.change;
    const actions = Array.isArray(change.actions) ? change.actions : [];
    const supported = [['no-op'], ['create'], ['read'], ['update'], ['delete'], ['forget'], ['delete', 'create'], ['create', 'delete']].some((known) => known.length === actions.length && known.every((value, i) => value === actions[i]));
    if (!supported) throw new Error('unsupported or malformed Terraform change actions');
    if (actions.length === 1 && (actions[0] === 'delete' || actions[0] === 'forget')) {
      out.skipped.push({ address: rc.address, reason: 'planned for deletion' });
      continue;
    }
    if (!isObj(change.after) && change.after_unknown !== true) throw new Error('malformed Terraform after values');
    if (rc.type.startsWith('aws_') && rc.provider_name !== undefined && (typeof rc.provider_name !== 'string' || !['registry.terraform.io/hashicorp/aws', 'registry.opentofu.org/hashicorp/aws'].includes(rc.provider_name))) throw new Error('unsupported provider for AWS resource assessment');
    validateMask(change.after_unknown, change.after);
    const after = isObj(change.after) ? change.after : {};
    const unknown = change.after_unknown === true ? ['*'] : unknownPaths(change.after_unknown, '');
    out.resources.push({ type: rc.type, address: rc.address, attrs: withoutNulls(after) as Resource['attrs'], unknown, origin: { kind: 'plan' } });
  }
  return out;
}

function fromState(root: Json): PlanScan {
  const out: PlanScan = { resources: [], kind: 'state', skipped: [] };
  const walk = (mod: Json, depth = 0) => {
    if (depth > 64) throw new Error('Terraform state module depth exceeds 64');
    if ('resources' in mod && !Array.isArray(mod.resources) || 'child_modules' in mod && !Array.isArray(mod.child_modules)) throw new Error('malformed Terraform state module');
    for (const r of Array.isArray(mod.resources) ? mod.resources : []) {
      if (!isObj(r) || typeof r.address !== 'string' || typeof r.type !== 'string' || !['managed', 'data'].includes(r.mode as string)) throw new Error('malformed Terraform state resource');
      if (r.mode !== 'managed') continue;
      if (!isObj(r.values)) throw new Error('malformed Terraform state values');
      if (r.type.startsWith('aws_') && r.provider_name !== undefined && (typeof r.provider_name !== 'string' || !['registry.terraform.io/hashicorp/aws', 'registry.opentofu.org/hashicorp/aws'].includes(r.provider_name))) throw new Error('unsupported provider for AWS resource assessment');
      const values = isObj(r.values) ? r.values : {};
      out.resources.push({ type: r.type, address: r.address, attrs: withoutNulls(values) as { [k: string]: AttrValue }, unknown: [], origin: { kind: 'plan' } });
    }
    for (const child of Array.isArray(mod.child_modules) ? mod.child_modules : []) { if (!isObj(child)) throw new Error('malformed Terraform child module'); walk(child, depth + 1); }
  };
  walk(root);
  return out;
}

/* In `terraform show -json`, null is how an optional attribute that was not
   set is written. The rules' defaults apply to an absent attribute, so nulls
   are dropped rather than carried as values. */
function withoutNulls(node: Json, depth = 0): Json {
  if (depth > 64) throw new Error('Terraform value depth exceeds 64');
  const out: Json = {};
  for (const [k, v] of Object.entries(node)) {
    if (v === null) continue;
    out[k] = Array.isArray(v) ? v.map((x) => (isObj(x) ? withoutNulls(x, depth + 1) : x)) : isObj(v) ? withoutNulls(v, depth + 1) : v;
  }
  return out;
}

/* after_unknown mirrors the attribute tree with `true` at every unknown leaf.
   A list of blocks appears as an array of objects; an index becomes `[n]`.
   A list that is wholly unknown appears as `true` at the list's own path. */
function unknownPaths(node: unknown, prefix: string, depth = 0): string[] {
  if (depth > 64) throw new Error('Terraform unknown mask depth exceeds 64');
  if (node === true) return prefix ? [prefix] : [];
  if (Array.isArray(node)) {
    return node.flatMap((item, i) => unknownPaths(item, `${prefix}[${i}]`, depth + 1));
  }
  if (isObj(node)) {
    return Object.entries(node).flatMap(([k, v]) => unknownPaths(v, prefix ? `${prefix}.${k}` : k, depth + 1));
  }
  return [];
}



function validateMask(mask: unknown, value: unknown, depth = 0): void {
  if (depth > 64) throw new Error('Terraform mask depth exceeds 64');
  if (mask === undefined || typeof mask === 'boolean') return;
  if (Array.isArray(mask)) {
    if (!Array.isArray(value) && mask.length) throw new Error('Terraform mask does not match value shape');
    for (const [i, child] of mask.entries()) validateMask(child, Array.isArray(value) ? value[i] : undefined, depth + 1);
    return;
  }
  if (isObj(mask)) {
    if (!isObj(value) && Object.keys(mask).length) throw new Error('Terraform mask does not match value shape');
    for (const [key, child] of Object.entries(mask)) validateMask(child, isObj(value) ? value[key] : undefined, depth + 1);
    return;
  }
  throw new Error('malformed Terraform unknown/sensitive mask');
}
