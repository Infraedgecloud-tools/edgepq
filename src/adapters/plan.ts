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
  if (Array.isArray(doc.resource_changes)) return fromPlan(doc.resource_changes);
  if (isObj(doc.values) && isObj(doc.values.root_module)) return fromState(doc.values.root_module);
  return { resources: [], kind: 'unrecognised', skipped: [] };
}

function fromPlan(changes: unknown[]): PlanScan {
  const out: PlanScan = { resources: [], kind: 'plan', skipped: [] };
  for (const rc of changes) {
    if (!isObj(rc) || typeof rc.address !== 'string' || typeof rc.type !== 'string') continue;
    if (rc.mode !== 'managed') continue;
    const change = isObj(rc.change) ? rc.change : {};
    const actions = Array.isArray(change.actions) ? change.actions : [];
    if (actions.length === 1 && actions[0] === 'delete') {
      out.skipped.push({ address: rc.address, reason: 'planned for deletion' });
      continue;
    }
    const after = isObj(change.after) ? change.after : {};
    const unknown = change.after_unknown === true ? ['*'] : unknownPaths(change.after_unknown, '');
    out.resources.push({ type: rc.type, address: rc.address, attrs: withoutNulls(after) as Resource['attrs'], unknown, origin: { kind: 'plan' } });
  }
  return out;
}

function fromState(root: Json): PlanScan {
  const out: PlanScan = { resources: [], kind: 'state', skipped: [] };
  const walk = (mod: Json) => {
    for (const r of Array.isArray(mod.resources) ? mod.resources : []) {
      if (!isObj(r) || typeof r.address !== 'string' || typeof r.type !== 'string' || r.mode !== 'managed') continue;
      const values = isObj(r.values) ? r.values : {};
      out.resources.push({ type: r.type, address: r.address, attrs: withoutNulls(values) as { [k: string]: AttrValue }, unknown: [], origin: { kind: 'plan' } });
    }
    for (const child of Array.isArray(mod.child_modules) ? mod.child_modules : []) if (isObj(child)) walk(child);
  };
  walk(root);
  return out;
}

/* In `terraform show -json`, null is how an optional attribute that was not
   set is written. The rules' defaults apply to an absent attribute, so nulls
   are dropped rather than carried as values. */
function withoutNulls(node: Json): Json {
  const out: Json = {};
  for (const [k, v] of Object.entries(node)) {
    if (v === null) continue;
    out[k] = Array.isArray(v) ? v.map((x) => (isObj(x) ? withoutNulls(x) : x)) : isObj(v) ? withoutNulls(v) : v;
  }
  return out;
}

/* after_unknown mirrors the attribute tree with `true` at every unknown leaf.
   A list of blocks appears as an array of objects; an index becomes `[n]`.
   A list that is wholly unknown appears as `true` at the list's own path. */
function unknownPaths(node: unknown, prefix: string): string[] {
  if (node === true) return prefix ? [prefix] : [];
  if (Array.isArray(node)) {
    return node.flatMap((item, i) => unknownPaths(item, `${prefix}[${i}]`));
  }
  if (isObj(node)) {
    return Object.entries(node).flatMap(([k, v]) => unknownPaths(v, prefix ? `${prefix}.${k}` : k));
  }
  return [];
}
