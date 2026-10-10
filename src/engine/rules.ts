/* ============================================================================
   Rule validation.

   Rules are authored as YAML and arrive here already parsed. The checks are
   the schema: a rule that gets through `validateRule` has every field the
   evaluator and the renderers rely on, and every source carries a date.
   Errors name the rule and the field so a bad rule fails CI with a message
   a person can act on.
   ========================================================================= */

import { CATEGORY_ORDER, SEVERITY_ORDER } from './types.ts';
import type { AttrValue, Fix, Predicate, Rule, Source, TableEntry } from './types.ts';

export class RuleError extends Error {
  readonly ruleId: string;
  constructor(ruleId: string, message: string) {
    super(`rule ${ruleId}: ${message}`);
    this.ruleId = ruleId;
  }
}

const ID_RE = /^[A-Z]+-[A-Z]+-\d{3}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isRecord(v: unknown): v is { [k: string]: unknown } {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isAttrValue(v: unknown): v is AttrValue {
  if (v === null) return true;
  if (['string', 'number', 'boolean'].includes(typeof v)) return true;
  if (Array.isArray(v)) return v.every(isAttrValue);
  if (isRecord(v)) return Object.values(v).every(isAttrValue);
  return false;
}

function validatePredicate(id: string, p: unknown, where: string): Predicate {
  if (!isRecord(p)) throw new RuleError(id, `${where} must be a mapping`);
  const keys = Object.keys(p);
  if ('all' in p || 'any' in p) {
    const k = 'all' in p ? 'all' : 'any';
    if (keys.length !== 1) throw new RuleError(id, `${where}: '${k}' takes no sibling keys`);
    const list = p[k];
    if (!Array.isArray(list) || list.length === 0) throw new RuleError(id, `${where}.${k} must be a non-empty list`);
    const items = list.map((item, i) => validatePredicate(id, item, `${where}.${k}[${i}]`));
    return k === 'all' ? { all: items } : { any: items };
  }
  if ('not' in p) {
    if (keys.length !== 1) throw new RuleError(id, `${where}: 'not' takes no sibling keys`);
    return { not: validatePredicate(id, p.not, `${where}.not`) };
  }
  if (typeof p.attr !== 'string' || !p.attr) throw new RuleError(id, `${where}.attr must be a non-empty string`);
  const attr = p.attr;
  const ops = keys.filter((k) => k !== 'attr');
  if (ops.length !== 1) throw new RuleError(id, `${where} must have exactly one of eq, in, matches, present, absent`);
  const op = ops[0] as string;
  const v = p[op];
  switch (op) {
    case 'eq':
      if (!isAttrValue(v) || v === null || typeof v === 'object') throw new RuleError(id, `${where}.eq must be a scalar`);
      return { attr, eq: v };
    case 'in':
      if (!Array.isArray(v) || v.length === 0 || !v.every((x) => typeof x !== 'object')) {
        throw new RuleError(id, `${where}.in must be a non-empty list of scalars`);
      }
      return { attr, in: v as AttrValue[] };
    case 'matches':
      if (typeof v !== 'string') throw new RuleError(id, `${where}.matches must be a string`);
      try { new RegExp(v); } catch { throw new RuleError(id, `${where}.matches is not a valid regular expression`); }
      return { attr, matches: v };
    case 'present':
      if (v !== true) throw new RuleError(id, `${where}.present must be true`);
      return { attr, present: true };
    case 'absent':
      if (v !== true) throw new RuleError(id, `${where}.absent must be true`);
      return { attr, absent: true };
    default:
      throw new RuleError(id, `${where}: unknown test '${op}'`);
  }
}

function validateSources(id: string, v: unknown): Source[] {
  if (!Array.isArray(v) || v.length === 0) throw new RuleError(id, 'sources must be a non-empty list; no rule ships without a source');
  return v.map((s, i) => {
    if (!isRecord(s)) throw new RuleError(id, `sources[${i}] must be a mapping`);
    if (typeof s.url !== 'string' || !/^https:\/\//.test(s.url)) throw new RuleError(id, `sources[${i}].url must be an https URL`);
    if (typeof s.verified !== 'string' || !DATE_RE.test(s.verified)) throw new RuleError(id, `sources[${i}].verified must be a YYYY-MM-DD date`);
    if (s.quote !== undefined && typeof s.quote !== 'string') throw new RuleError(id, `sources[${i}].quote must be a string`);
    if (s.paraphrase !== undefined && s.paraphrase !== true) throw new RuleError(id, `sources[${i}].paraphrase must be true when present`);
    const out: Source = { url: s.url, verified: s.verified };
    if (typeof s.quote === 'string') out.quote = s.quote;
    if (s.paraphrase === true) out.paraphrase = true;
    return out;
  });
}

function validateFix(id: string, v: unknown, tables: Rule['tables']): Fix {
  if (!isRecord(v)) throw new RuleError(id, 'fix must be a mapping');
  const safety = v.safety;
  if (v.kind === 'guidance') {
    if (typeof v.note !== 'string' || !v.note) throw new RuleError(id, 'fix.note is required for guidance');
    if (safety !== 'none') throw new RuleError(id, 'fix.safety must be none for guidance');
    return { kind: 'guidance', note: v.note, safety: 'none' };
  }
  if (v.kind !== 'set-attribute') throw new RuleError(id, "fix.kind must be 'set-attribute' or 'guidance'");
  if (safety !== 'auto' && safety !== 'review' && safety !== 'none') throw new RuleError(id, 'fix.safety must be auto, review or none');
  if (typeof v.attr !== 'string' || !v.attr) throw new RuleError(id, 'fix.attr is required');
  const note = typeof v.note === 'string' ? { note: v.note } : {};
  let unless: { unless?: Predicate; unless_note?: string } = {};
  if (v.unless !== undefined) {
    if (typeof v.unless_note !== 'string' || !v.unless_note) throw new RuleError(id, 'fix.unless needs fix.unless_note');
    unless = { unless: validatePredicate(id, v.unless, 'fix.unless'), unless_note: v.unless_note };
  }
  let alsoSet: { also_set?: { [attr: string]: string } } = {};
  if (v.also_set !== undefined) {
    if (!isRecord(v.also_set) || !Object.values(v.also_set).every((x) => typeof x === 'string')) throw new RuleError(id, 'fix.also_set must map attributes to strings');
    alsoSet = { also_set: v.also_set as { [attr: string]: string } };
  }
  if (typeof v.value === 'string') return { kind: 'set-attribute', attr: v.attr, value: v.value, safety, ...note, ...alsoSet, ...unless };
  if (typeof v.value_from === 'string') {
    if (!tables || !(v.value_from in tables)) throw new RuleError(id, `fix.value_from refers to table '${v.value_from}' which the rule does not define`);
    return { kind: 'set-attribute', attr: v.attr, value_from: v.value_from, safety, ...note, ...alsoSet, ...unless };
  }
  throw new RuleError(id, 'fix needs value or value_from');
}

export function validateRule(raw: unknown): Rule {
  if (!isRecord(raw)) throw new RuleError('?', 'a rule must be a mapping');
  const id = typeof raw.id === 'string' ? raw.id : '?';
  if (!ID_RE.test(id)) throw new RuleError(id, 'id must look like AREA-KIND-001');
  if (typeof raw.title !== 'string' || !raw.title) throw new RuleError(id, 'title is required');
  if (!Array.isArray(raw.resource_types) || raw.resource_types.length === 0 || !raw.resource_types.every((t) => typeof t === 'string')) {
    throw new RuleError(id, 'resource_types must be a non-empty list of strings');
  }
  if (!CATEGORY_ORDER.includes(raw.category as never)) throw new RuleError(id, `category must be one of ${CATEGORY_ORDER.join(', ')}`);
  if (!SEVERITY_ORDER.includes(raw.severity as never)) throw new RuleError(id, `severity must be one of ${SEVERITY_ORDER.join(', ')}`);
  if (!isRecord(raw.message)) throw new RuleError(id, 'message must be a mapping');
  for (const k of ['fail', 'pass', 'unknown'] as const) {
    if (typeof raw.message[k] !== 'string' || !raw.message[k]) throw new RuleError(id, `message.${k} is required`);
  }
  const allowed = new Set(['id', 'title', 'resource_types', 'category', 'severity', 'applies_when', 'unknown_when', 'pass_when', 'fail_as', 'defaults', 'fix', 'message', 'sources', 'tables']);
  for (const k of Object.keys(raw)) if (!allowed.has(k)) throw new RuleError(id, `unknown field '${k}'`);

  let tables: Rule['tables'];
  if (raw.tables !== undefined) {
    if (!isRecord(raw.tables)) throw new RuleError(id, 'tables must be a mapping');
    tables = {};
    for (const [name, table] of Object.entries(raw.tables)) {
      if (!isRecord(table)) throw new RuleError(id, `tables.${name} must be a mapping`);
      const entries: { [k: string]: TableEntry } = {};
      for (const [from, entry] of Object.entries(table)) {
        if (typeof entry === 'string') { entries[from] = entry; continue; }
        if (!isRecord(entry) || typeof entry.value !== 'string' || !['auto', 'review', 'none'].includes(entry.safety as string)
          || (entry.note !== undefined && typeof entry.note !== 'string')) {
          throw new RuleError(id, `tables.${name}.${from} must be a string or { value, safety, note? }`);
        }
        const e: TableEntry = { value: entry.value, safety: entry.safety as Fix['safety'] };
        if (typeof entry.note === 'string') e.note = entry.note;
        entries[from] = e;
      }
      tables[name] = entries;
    }
  }
  let defaults: Rule['defaults'];
  if (raw.defaults !== undefined) {
    if (!isRecord(raw.defaults) || !Object.values(raw.defaults).every(isAttrValue)) throw new RuleError(id, 'defaults must map attributes to literal values');
    defaults = raw.defaults as Rule['defaults'];
  }

  const rule: Rule = {
    id,
    title: raw.title,
    resource_types: raw.resource_types as string[],
    category: raw.category as Rule['category'],
    severity: raw.severity as Rule['severity'],
    pass_when: validatePredicate(id, raw.pass_when, 'pass_when'),
    message: { fail: raw.message.fail as string, pass: raw.message.pass as string, unknown: raw.message.unknown as string },
    sources: validateSources(id, raw.sources),
  };
  if (raw.applies_when !== undefined) rule.applies_when = validatePredicate(id, raw.applies_when, 'applies_when');
  if (raw.unknown_when !== undefined) rule.unknown_when = validatePredicate(id, raw.unknown_when, 'unknown_when');
  if (raw.fail_as !== undefined) {
    if (raw.fail_as !== 'not_configurable') throw new RuleError(id, "fail_as must be 'not_configurable' when present");
    rule.fail_as = 'not_configurable';
  }
  if (defaults) rule.defaults = defaults;
  if (tables) rule.tables = tables;
  if (raw.fix !== undefined) rule.fix = validateFix(id, raw.fix, tables);
  return rule;
}

export function validateRules(raws: unknown[]): Rule[] {
  const rules = raws.map(validateRule);
  const seen = new Set<string>();
  for (const r of rules) {
    if (seen.has(r.id)) throw new RuleError(r.id, 'duplicate id');
    seen.add(r.id);
  }
  return rules.sort((a, b) => a.id.localeCompare(b.id));
}
