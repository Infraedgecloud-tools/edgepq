/* ============================================================================
   rules × resources → findings.

   One finding per (rule, resource) where the rule applies, including passes:
   a report that lists what is already enabled is half the point. Resources
   the rule does not apply to produce nothing; `not_applicable` exists in the
   type for callers that want to ask about a single pair.
   ========================================================================= */

import { attributesRead, evaluate as evalPredicate, lookup } from './predicate.ts';
import { CATEGORY_ORDER, SEVERITY_ORDER } from './types.ts';
import type { AttrValue, Finding, ResolvedFix, Resource, Rule, Status } from './types.ts';

function withDefaults(rule: Rule, resource: Resource): { resource: Resource; defaulted: Set<string> } {
  const defaulted = new Set<string>();
  if (!rule.defaults) return { resource, defaulted };
  const attrs = { ...resource.attrs };
  for (const [attr, value] of Object.entries(rule.defaults)) {
    if (attr.includes('.')) continue; /* defaults are top-level by design; nested defaults would hide more than they explain */
    const { value: current, unknown } = lookup(resource, attr);
    if (current === undefined && !unknown) {
      attrs[attr] = value;
      defaulted.add(attr);
    }
  }
  return { resource: { ...resource, attrs }, defaulted };
}

function fill(template: string, values: { [k: string]: string }): string {
  return template.replace(/\{([a-zA-Z0-9_.[\]*]+)\}/g, (m, key: string) => (key in values ? (values[key] as string) : m));
}

function resolveFix(rule: Rule, observed: Finding['observed']): ResolvedFix | undefined {
  const fix = rule.fix;
  if (!fix) return undefined;
  if (fix.kind === 'guidance') return fix;
  if ('value' in fix) {
    const out: ResolvedFix = { kind: 'set-attribute', attr: fix.attr, value: fix.value, safety: fix.safety };
    if (fix.note) out.note = fix.note;
    return out;
  }
  const table = rule.tables?.[fix.value_from];
  const current = observed[fix.attr]?.value;
  const mapped = table && typeof current === 'string' ? table[current] : undefined;
  if (mapped === undefined) {
    /* No documented mapping from the observed value: say so rather than invent one. */
    return { kind: 'guidance', safety: 'none', note: `No documented mapping from ${fix.attr} = ${String(current)}; choose a target by hand.${fix.note ? ' ' + fix.note : ''}` };
  }
  const out: ResolvedFix = { kind: 'set-attribute', attr: fix.attr, value: mapped, safety: fix.safety };
  if (fix.note) out.note = fix.note;
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
  const passes = evalPredicate(rule.pass_when, resource);
  const status: Status = passes === 'unknown' ? 'unknown' : passes ? 'pass' : 'fail';
  return build(rule, original, resource, defaulted, status);
}

function build(rule: Rule, original: Resource, resource: Resource, defaulted: Set<string>, status: Status): Finding {
  const observed: Finding['observed'] = {};
  const read = new Set<string>([...(rule.applies_when ? attributesRead(rule.applies_when) : []), ...attributesRead(rule.pass_when)]);
  if (rule.fix && rule.fix.kind === 'set-attribute') read.add(rule.fix.attr);
  const templateValues: { [k: string]: string } = { address: original.address, type: original.type };
  for (const attr of read) {
    const { value, unknown } = lookup(resource, attr);
    const entry: Finding['observed'][string] = { value };
    if (defaulted.has(attr)) entry.defaulted = true;
    if (unknown) entry.unknown = true;
    observed[attr] = entry;
    templateValues[attr] = unknown ? '(not known offline)' : value === undefined ? '(absent)' : show(value);
  }
  const finding: Finding = {
    id: `${rule.id}:${original.address}`,
    rule: { id: rule.id, title: rule.title, category: rule.category, severity: rule.severity },
    status,
    resource: { type: original.type, address: original.address, origin: original.origin },
    observed,
    message: fill(rule.message[status === 'not_applicable' ? 'pass' : status], templateValues),
    sources: rule.sources,
  };
  if (status === 'fail') {
    const fix = resolveFix(rule, observed);
    if (fix) finding.fix = fix;
  }
  return finding;
}

function show(value: AttrValue): string {
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

export function rank(findings: Finding[]): Finding[] {
  const statusOrder: Status[] = ['fail', 'unknown', 'pass', 'not_applicable'];
  return [...findings].sort((a, b) =>
    statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status)
    || CATEGORY_ORDER.indexOf(a.rule.category) - CATEGORY_ORDER.indexOf(b.rule.category)
    || SEVERITY_ORDER.indexOf(a.rule.severity) - SEVERITY_ORDER.indexOf(b.rule.severity)
    || a.rule.id.localeCompare(b.rule.id)
    || a.resource.address.localeCompare(b.resource.address));
}

export function evaluateAll(rules: Rule[], resources: Resource[]): Finding[] {
  const out: Finding[] = [];
  for (const resource of resources) {
    for (const rule of rules) {
      const f = evaluatePair(rule, resource);
      if (f) out.push(f);
    }
  }
  return rank(out);
}
