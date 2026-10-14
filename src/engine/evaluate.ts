/* ============================================================================
   rules × resources → findings.

   One finding per (rule, resource) where the rule applies, including passes:
   a report that lists what is already enabled is half the point. Resources
   the rule does not apply to produce nothing; `not_applicable` exists in the
   type for callers that want to ask about a single pair.
   ========================================================================= */

import { attributesRead, evaluate as evalPredicate, isExpression, lookup } from './predicate.ts';
import { CATEGORY_ORDER, SEVERITY_ORDER } from './types.ts';
import type { AttrValue, Finding, ResolvedFix, Resource, Rule, Status } from './types.ts';

function withDefaults(rule: Rule, resource: Resource): { resource: Resource; defaulted: Set<string> } {
  const defaulted = new Set<string>();
  if (!rule.defaults) return { resource, defaulted };
  let attrs = resource.attrs;
  for (const [attr, value] of Object.entries(rule.defaults)) {
    const { value: current, unknown } = lookup(resource, attr);
    if (current !== undefined || unknown) continue;
    const next = setDefault(attrs, attr.split('.'), value);
    if (next) {
      attrs = next;
      defaulted.add(attr);
    }
  }
  return { resource: { ...resource, attrs }, defaulted };
}

/* Returns a copy of `attrs` with the default in place, or undefined when the
   path's parent block does not exist: a default for an attribute inside a
   block the configuration never opened would invent the block too. */
function setDefault(attrs: Resource['attrs'], segments: string[], value: AttrValue): Resource['attrs'] | undefined {
  const [head, ...rest] = segments;
  if (head === undefined) return undefined;
  if (rest.length === 0) return { ...attrs, [head]: value };
  const child = attrs[head];
  if (Array.isArray(child) && child.length === 1 && typeof child[0] === 'object' && child[0] !== null && !Array.isArray(child[0])) {
    const inner = setDefault(child[0] as Resource['attrs'], rest, value);
    return inner ? { ...attrs, [head]: [inner] } : undefined;
  }
  if (typeof child === 'object' && child !== null && !Array.isArray(child)) {
    const inner = setDefault(child as Resource['attrs'], rest, value);
    return inner ? { ...attrs, [head]: inner } : undefined;
  }
  return undefined;
}

function fill(template: string, values: { [k: string]: string }): string {
  return template.replace(/\{([a-zA-Z0-9_.[\]*]+)\}/g, (m, key: string) => (key in values ? (values[key] as string) : m));
}

function resolveFix(rule: Rule, observed: Finding['observed'], resource: Resource): ResolvedFix | undefined {
  const fix = rule.fix;
  if (!fix) return undefined;
  if (fix.kind === 'guidance') return fix;
  if (fix.unless && evalPredicate(fix.unless, resource) !== false) return { kind: 'guidance', safety: 'none', note: fix.unless_note as string };
  if ('value' in fix) {
    const out: ResolvedFix = { kind: 'set-attribute', attr: fix.attr, value: fix.value, safety: fix.safety };
    if (fix.note) out.note = fix.note;
    if (fix.also_set) out.also_set = fix.also_set;
    return out;
  }
  const table = rule.tables?.[fix.value_from];
  const current = observed[fix.attr]?.value;
  const mapped = table && typeof current === 'string' ? table[current] : undefined;
  if (mapped === undefined) {
    /* No documented mapping from the observed value: say so rather than invent one. */
    return { kind: 'guidance', safety: 'none', note: `No documented mapping from ${fix.attr} = ${String(current)}; choose a target by hand.${fix.note ? ' ' + fix.note : ''}` };
  }
  const entry = typeof mapped === 'string' ? { value: mapped, safety: fix.safety, note: fix.note } : mapped;
  const out: ResolvedFix = { kind: 'set-attribute', attr: fix.attr, value: entry.value, safety: entry.safety };
  const note = [entry.note, typeof mapped === 'string' ? undefined : fix.note].filter(Boolean).join(' ');
  if (note) out.note = note;
  if (fix.also_set) out.also_set = fix.also_set;
  return out;
}

export function evaluatePair(rule: Rule, original: Resource): Finding | undefined {
  if (!rule.resource_types.includes(original.type)) return undefined;
  const { resource, defaulted } = withDefaults(rule, original);

  if (rule.applies_when) {
    const applies = evalPredicate(rule.applies_when, resource);
    if (applies === false) return undefined;
    /* Unknown applicability is reported as unknown: the resource might be in
       scope, and silence would read as a pass. */
    if (applies === 'unknown') return build(rule, original, resource, defaulted, 'unknown');
  }
  if (rule.unknown_when && evalPredicate(rule.unknown_when, resource) !== false) return build(rule, original, resource, defaulted, 'unknown');
  const passes = evalPredicate(rule.pass_when, resource);
  const status: Status = passes === 'unknown' ? 'unknown' : passes ? rule.pass_as ?? 'pass' : rule.fail_as ?? 'fail';
  return build(rule, original, resource, defaulted, status);
}

function build(rule: Rule, original: Resource, resource: Resource, defaulted: Set<string>, status: Status): Finding {
  const observed: Finding['observed'] = {};
  const read = new Set<string>([...(rule.applies_when ? attributesRead(rule.applies_when) : []), ...(rule.unknown_when ? attributesRead(rule.unknown_when) : []), ...attributesRead(rule.pass_when)]);
  if (rule.fix && rule.fix.kind === 'set-attribute') {
    read.add(rule.fix.attr);
    if (rule.fix.unless) for (const a of attributesRead(rule.fix.unless)) read.add(a);
  }
  /* A message may name any literal attribute, not only the ones the
     predicates read; the AWS origin also supplies account and region. */
  const templateValues: { [k: string]: string } = { address: original.address, type: original.type };
  if (original.origin.kind === 'aws') { templateValues.account = original.origin.account; templateValues.region = original.origin.region; }
  for (const [k, v] of Object.entries(resource.attrs)) {
    if (v === null || v === undefined) continue;
    if (typeof v !== 'object' || Array.isArray(v)) templateValues[k] = Array.isArray(v) && resource.origin.kind === 'hcl' && v.some(isExpression) ? '(not known offline)' : show(v);
  }
  for (const attr of read) {
    const { value, unknown } = lookup(resource, attr);
    const entry: Finding['observed'][string] = { value };
    if (defaulted.has(attr)) entry.defaulted = true;
    if (unknown) entry.unknown = true;
    observed[attr] = entry;
    templateValues[attr] = unknown ? '(not known offline)' : value === undefined ? '(absent)' : show(value);
  }
  /* HCL input may define the same address in two files (Terraform would
     refuse the configuration, but the scan still reports both). */
  const where = original.origin.kind === 'hcl' ? `${original.origin.file}:` : '';
  /* When the reason is an attribute that could not be read, say which one,
     rather than a per-rule sentence written around a different attribute. */
  const unresolved = Object.entries(observed).filter(([, o]) => o.unknown).map(([a]) => a);
  const message = status === 'unknown' && unresolved.length
    ? `${original.address}: ${unresolved.join(' and ')} ${unresolved.length === 1 ? 'is' : 'are'} not a literal value here (an expression, a dynamic block, or a value a plan cannot show before apply), so the rule could not be checked offline. The state or the account can show it.`
    : fill(rule.message[status === 'not_applicable' || status === 'on_by_default' ? 'pass' : status === 'not_configurable' ? 'fail' : status], templateValues);
  const finding: Finding = {
    id: `${rule.id}:${where}${original.address}`,
    rule: { id: rule.id, title: rule.title, category: rule.category, severity: rule.severity },
    status,
    resource: { type: original.type, address: original.address, origin: original.origin, ...(original.ignore_changes ? { ignore_changes: original.ignore_changes } : {}) },
    observed,
    message,
    sources: rule.sources,
  };
  if (status === 'fail' || status === 'not_configurable') {
    const fix = resolveFix(rule, observed, resource);
    if (fix) finding.fix = fix;
  }
  return finding;
}

function show(value: AttrValue): string {
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

export function rank(findings: Finding[]): Finding[] {
  const statusOrder: Status[] = ['fail', 'not_configurable', 'unknown', 'pass', 'on_by_default', 'not_applicable'];
  return [...findings].sort((a, b) =>
    statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status)
    || CATEGORY_ORDER.indexOf(a.rule.category) - CATEGORY_ORDER.indexOf(b.rule.category)
    || SEVERITY_ORDER.indexOf(a.rule.severity) - SEVERITY_ORDER.indexOf(b.rule.severity)
    || a.rule.id.localeCompare(b.rule.id)
    || a.resource.address.localeCompare(b.resource.address));
}

export function evaluateAll(rules: Rule[], resources: Resource[]): Finding[] {
  const out: Finding[] = [];
  const seen = new Map<string, number>();
  for (const resource of resources) {
    for (const rule of rules) {
      const f = evaluatePair(rule, resource);
      if (!f) continue;
      /* The same address twice in one file (Terraform would refuse it) still
         gets two distinct ids. */
      const n = (seen.get(f.id) ?? 0) + 1;
      seen.set(f.id, n);
      if (n > 1) f.id = `${f.id}#${n}`;
      out.push(f);
    }
  }
  return rank(out);
}
