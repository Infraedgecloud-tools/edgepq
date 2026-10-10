/* ============================================================================
   Predicate evaluation over a Resource's attributes.

   Three-valued on purpose: true, false, or unknown. Unknown wins over both,
   because a rule that cannot see a value must not claim a finding either way.

   Paths are dotted. A segment that lands on an array of blocks is unwrapped
   when the array has exactly one element (the common `viewer_certificate {}`
   shape). `[n]` indexes, `[*]` means "any element". Two or more blocks with
   no index is treated as unknown rather than guessed.
   ========================================================================= */

import type { AttrValue, LeafTest, Predicate, Resource } from './types.ts';

export type Tri = true | false | 'unknown';

/* hcl2json encodes any non-literal expression as "${...}". A template string
   with interpolation inside also carries "${". Either way the value is not
   something the engine can check offline. */
export function isExpression(value: AttrValue | undefined): boolean {
  return typeof value === 'string' && value.includes('${');
}

/* `partial`: a `[*]` list where some elements were known and others not.
   A leaf test over it is true only if a known element satisfies it;
   otherwise it is unknown, never false. */
export type Lookup = { value: AttrValue | undefined; unknown: boolean; partial?: true; /* unknown because the attribute is set to an expression */ exists?: true };

export function lookup(resource: Resource, path: string): Lookup {
  /* A plan can mark a whole resource unknown (after_unknown: true). */
  if (resource.unknown.includes('*')) return { value: undefined, unknown: true };
  /* "${...}" means an expression only in HCL; a plan, a state or the API can
     hold any string. */
  return walk(resource.attrs, path.split('.'), '', resource.unknown, '', resource.origin.kind === 'hcl');
}

function markedUnknown(unknown: string[], ...forms: string[]): boolean {
  return forms.some((f) => f !== '' && unknown.some((u) => u === f || f.startsWith(u + '.') || f.startsWith(u + '[')));
}

/* Walks one segment at a time, carrying two spellings of where it is: the
   path as the rule wrote it, and the canonical one with every block index
   made explicit (`default_action[0].type`). Adapters mark unknowns in the
   canonical form; rules read in the short form; both must match. */
function walk(node: AttrValue | undefined, segments: string[], canonical: string, unknown: string[], written = '', hcl = false): Lookup {
  const expr = (v: AttrValue | undefined) => hcl && isExpression(v);
  if (segments.length === 0) return { value: node, unknown: false };
  const raw = segments[0] as string;
  const rest = segments.slice(1);
  const m = /^([^[]+)(?:\[(\d+|\*)\])?$/.exec(raw);
  if (!m) return { value: undefined, unknown: true };
  const key = m[1] as string;
  const index = m[2];
  if (node === undefined || node === null || typeof node !== 'object' || Array.isArray(node)) return { value: undefined, unknown: false };

  const keyCanonical = canonical ? `${canonical}.${key}` : key;
  const keyWritten = written ? `${written}.${key}` : key;
  if (markedUnknown(unknown, keyCanonical, keyWritten)) return { value: undefined, unknown: true };
  let current: AttrValue | undefined = (node as { [k: string]: AttrValue })[key];
  if (expr(current)) return rest.length === 0 ? { value: undefined, unknown: true, exists: true } : { value: undefined, unknown: true };

  if (!Array.isArray(current)) {
    if (index !== undefined) return { value: undefined, unknown: false };
    return walk(current, rest, keyCanonical, unknown, keyWritten, hcl);
  }
  if (index === '*') {
    const values: AttrValue[] = [];
    let anyUnknown = false;
    current.forEach((element, i) => {
      const r = expr(element) ? { value: undefined, unknown: true } : walk(element, rest, `${keyCanonical}[${i}]`, unknown, `${keyWritten}[${i}]`, hcl);
      if (r.unknown) anyUnknown = true;
      else if (r.value !== undefined) values.push(r.value);
    });
    if (markedUnknown(unknown, keyCanonical)) anyUnknown = true;
    if (anyUnknown && values.length > 0) return { value: values, unknown: false, partial: true };
    return { value: values.length ? values : undefined, unknown: anyUnknown };
  }
  let i: number;
  if (index !== undefined) i = Number(index);
  else if (current.length === 1) i = 0;
  else if (current.length === 0) return { value: undefined, unknown: false };
  else return { value: undefined, unknown: true };
  const element = current[i];
  const elementCanonical = `${keyCanonical}[${i}]`;
  const elementWritten = index !== undefined ? `${keyWritten}[${i}]` : keyWritten;
  if (markedUnknown(unknown, elementCanonical, index !== undefined ? elementWritten : '')) return { value: undefined, unknown: true };
  if (expr(element)) return { value: undefined, unknown: true };
  return walk(element, rest, elementCanonical, unknown, elementWritten, hcl);
}

function asStrings(value: AttrValue | undefined): string[] {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.flatMap(asStrings);
  if (typeof value === 'object') return [];
  return [String(value)];
}

function leaf(test: LeafTest, resource: Resource): Tri {
  const { value, unknown, partial, exists } = lookup(resource, test.attr);
  /* An attribute set to an expression is present whatever it evaluates to. */
  if (unknown && exists) { if ('present' in test) return true; if ('absent' in test) return false; }
  if (unknown) return 'unknown';
  if ('present' in test) return value !== undefined;
  if ('absent' in test) return partial ? 'unknown' : value === undefined;
  const candidates = asStrings(value);
  let hit: boolean;
  if ('eq' in test) hit = candidates.some((c) => c === String(test.eq));
  else if ('in' in test) hit = candidates.some((c) => test.in.map(String).includes(c));
  else if ('matches' in test) { const re = new RegExp(test.matches); hit = candidates.some((c) => re.test(c)); }
  else return 'unknown';
  /* An element that could not be read might have matched. */
  return hit ? true : partial ? 'unknown' : false;
}

export function evaluate(predicate: Predicate, resource: Resource): Tri {
  if ('all' in predicate) {
    let sawUnknown = false;
    for (const p of predicate.all) {
      const r = evaluate(p, resource);
      if (r === false) return false;
      if (r === 'unknown') sawUnknown = true;
    }
    return sawUnknown ? 'unknown' : true;
  }
  if ('any' in predicate) {
    let sawUnknown = false;
    for (const p of predicate.any) {
      const r = evaluate(p, resource);
      if (r === true) return true;
      if (r === 'unknown') sawUnknown = true;
    }
    return sawUnknown ? 'unknown' : false;
  }
  if ('not' in predicate) {
    const r = evaluate(predicate.not, resource);
    return r === 'unknown' ? 'unknown' : !r;
  }
  return leaf(predicate, resource);
}

/* Every attribute path a predicate reads, so a finding can report what was
   observed. */
export function attributesRead(predicate: Predicate): string[] {
  if ('all' in predicate) return predicate.all.flatMap(attributesRead);
  if ('any' in predicate) return predicate.any.flatMap(attributesRead);
  if ('not' in predicate) return attributesRead(predicate.not);
  return [predicate.attr];
}
