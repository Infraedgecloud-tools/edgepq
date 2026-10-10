/* A set-attribute fix applied to Terraform source text. Literal values are
   replaced in place, absent ones are inserted; anything else is refused,
   because the engine already reports it as unknown and a patch never guesses.

   A fix is first planned as edits against the unchanged text (offsets into
   the original), then applied. Planning against the original is what lets
   many fixes to one file be combined in a single pass. */
import type { ResolvedFix } from '../engine/types.ts';
import { locateAttribute, locateResource } from './locate.ts';

export type SetAttributeFix = Extract<ResolvedFix, { kind: 'set-attribute' }>;
export type Edit = { start: number; end: number; text: string };
export type Plan = { edits: Edit[]; reason?: string; added?: { [attr: string]: string }; keys: string[] };
export type ApplyResult = { text: string; changed: boolean; reason?: string; added?: { [attr: string]: string } };

export function quote(value: string): string {
  return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\$\{/g, () => '$${').replace(/%\{/g, () => '%%{') + '"';
}

/* Offsets are into `text` as given; nothing here changes it. `keys` names the
   attributes the plan touches (`type.name#attr`) so two plans on one file can
   be checked for a clash before they are merged. */
export function planFix(text: string, type: string, name: string, fix: SetAttributeFix): Plan {
  const refuse = (reason: string): Plan => ({ edits: [], reason, keys: [] });
  const sets: [string, string][] = [[fix.attr, fix.value], ...Object.entries(fix.also_set ?? {})];
  const res = locateResource(text, type, name);
  if (!res) return refuse(`resource ${type}.${name} not found`);
  const edits: Edit[] = [];
  const added: { [attr: string]: string } = {};
  const keys: string[] = [];
  for (const [i, [path, value]] of sets.entries()) {
    const loc = locateAttribute(text, { ...res.body, duplicate: res.duplicate }, path);
    if (loc.kind === 'ambiguous') return refuse(`${path}: ${loc.reason}`);
    if (loc.kind === 'present-not-literal') {
      if (i === 0) return refuse(`${path} is set to an expression, not a literal`);
      continue; /* an also_set attribute that is already set stays as it is */
    }
    if (loc.kind === 'literal-string') {
      if (i > 0) continue;
      const { start, end } = loc.valueRange;
      if (text.slice(start, end) === quote(value)) continue;
      edits.push({ start, end, text: quote(value) });
    } else {
      const attr = path.split('.').pop() as string;
      const pad = loc.align === undefined ? 1 : Math.max(1, loc.align - loc.indent.length - attr.length);
      const eol = text.includes('\r\n') ? '\r\n' : '\n';
      edits.push({ start: loc.insertAt, end: loc.insertAt, text: `${loc.indent}${attr}${' '.repeat(pad)}= ${quote(value)}${eol}` });
      if (i > 0) added[path] = value;
    }
    keys.push(`${type}.${name}#${path}`);
  }
  if (edits.length === 0) return refuse('already set to the target value');
  return Object.keys(added).length ? { edits, added, keys } : { edits, keys };
}

/* Apply edits planned against `text`, from the end backwards so earlier
   offsets stay valid. Two insertions at one point keep their planning order. */
export function applyEdits(text: string, edits: Edit[]): string {
  const ordered = edits.map((e, i) => ({ e, i })).sort((x, y) => y.e.start - x.e.start || y.i - x.i);
  let out = text;
  for (const { e } of ordered) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

export function applyFix(text: string, type: string, name: string, fix: SetAttributeFix): ApplyResult {
  const plan = planFix(text, type, name, fix);
  if (plan.edits.length === 0) return { text, changed: false, ...(plan.reason ? { reason: plan.reason } : {}) };
  return { text: applyEdits(text, plan.edits), changed: true, ...(plan.added ? { added: plan.added } : {}) };
}
