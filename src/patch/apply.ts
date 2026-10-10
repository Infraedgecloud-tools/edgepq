/* A set-attribute fix applied to Terraform source text. Literal values are
   replaced in place, absent ones are inserted; anything else is refused,
   because the engine already reports it as unknown and a patch never guesses. */
import type { ResolvedFix } from '../engine/types.ts';
import { locateAttribute, locateResource } from './locate.ts';

export type SetAttributeFix = Extract<ResolvedFix, { kind: 'set-attribute' }>;
export type ApplyResult = { text: string; changed: boolean; reason?: string; added?: { [attr: string]: string } };

export function quote(value: string): string {
  return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\$\{/g, () => '$${').replace(/%\{/g, () => '%%{') + '"';
}

export function applyFix(text: string, type: string, name: string, fix: SetAttributeFix): ApplyResult {
  const refuse = (reason: string): ApplyResult => ({ text, changed: false, reason });
  const sets: [string, string][] = [[fix.attr, fix.value], ...Object.entries(fix.also_set ?? {})];
  const added: { [attr: string]: string } = {};
  let cur = text;
  let changed = false;
  for (const [i, [path, value]] of sets.entries()) {
    const res = locateResource(cur, type, name);
    if (!res) return refuse(`resource ${type}.${name} not found`);
    const loc = locateAttribute(cur, { ...res.body, duplicate: res.duplicate }, path);
    if (loc.kind === 'ambiguous') return refuse(`${path}: ${loc.reason}`);
    if (loc.kind === 'present-not-literal') {
      if (i === 0) return refuse(`${path} is set to an expression, not a literal`);
      continue; /* an also_set attribute that is already set stays as it is */
    }
    if (loc.kind === 'literal-string') {
      if (i > 0) continue;
      const { start, end } = loc.valueRange;
      if (cur.slice(start, end) === quote(value)) continue;
      cur = cur.slice(0, start) + quote(value) + cur.slice(end);
    } else {
      const attr = path.split('.').pop() as string;
      const pad = loc.align === undefined ? 1 : Math.max(1, loc.align - loc.indent.length - attr.length);
      cur = cur.slice(0, loc.insertAt) + `${loc.indent}${attr}${' '.repeat(pad)}= ${quote(value)}\n` + cur.slice(loc.insertAt);
      if (i > 0) added[path] = value;
    }
    changed = true;
  }
  if (!changed) return refuse('already set to the target value');
  return Object.keys(added).length ? { text: cur, changed, added } : { text: cur, changed };
}
