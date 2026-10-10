/* ============================================================================
   Findings → patches. A patch is a unified diff for one resource, written for
   a person to read and `git apply`. Nothing here touches the filesystem and
   nothing applies a patch.
   ========================================================================= */
import type { Finding } from '../engine/types.ts';
import { applyFix, type SetAttributeFix } from './apply.ts';
import { unifiedDiff } from './diff.ts';

export type Patch = {
  ruleId: string;
  address: string;
  file: string;
  safety: 'auto' | 'review';
  note?: string;
  /* Header comment (lines starting `# `) followed by the unified diff. */
  diff: string;
  /* Attributes added only because the target value needs them. */
  also_set?: { [attr: string]: string };
  /* What combinePatches needs to replay the change on a file other patches already touched. */
  edit: { type: string; name: string; fix: SetAttributeFix; source: string };
};
export type Skipped = { ruleId: string; address: string; file?: string; reason: string };

const APPLY_WITH = 'EdgePQ does not apply patches. Review, then apply with: git apply <file>';

function header(p: { ruleId: string; title: string; address: string; safety: string; note?: string }): string {
  const lines = [`# ${p.ruleId}: ${p.title}`, `# Resource: ${p.address}`, `# Safety: ${p.safety}`];
  if (p.note) lines.push(`# Note: ${p.note.replace(/\s*\n\s*/g, ' ')}`);
  return lines.join('\n') + `\n# ${APPLY_WITH}\n`;
}

export function buildPatchesWithSkips(findings: Finding[], files: { name: string; contents: string }[]): { patches: Patch[]; skipped: Skipped[] } {
  const patches: Patch[] = [];
  const skipped: Skipped[] = [];
  for (const f of findings) {
    const fix = f.fix;
    if (f.status !== 'fail' || fix?.kind !== 'set-attribute' || fix.safety === 'none' || f.resource.origin.kind !== 'hcl') continue;
    const file = f.resource.origin.file;
    const source = files.find((x) => x.name === file)?.contents;
    const skip = (reason: string) => skipped.push({ ruleId: f.rule.id, address: f.resource.address, file, reason });
    if (source === undefined) { skip('source file was not supplied'); continue; }
    const dot = f.resource.address.indexOf('.');
    const type = f.resource.address.slice(0, dot), name = f.resource.address.slice(dot + 1);
    const res = applyFix(source, type, name, fix);
    if (!res.changed) { skip(res.reason ?? 'no change'); continue; }
    const patch: Patch = {
      ruleId: f.rule.id, address: f.resource.address, file, safety: fix.safety,
      diff: header({ ruleId: f.rule.id, title: f.rule.title, address: f.resource.address, safety: fix.safety, ...(fix.note ? { note: fix.note } : {}) }) + unifiedDiff(source, res.text, file, file),
      edit: { type, name, fix, source },
    };
    if (fix.note) patch.note = fix.note;
    if (res.added) patch.also_set = res.added;
    patches.push(patch);
  }
  return { patches, skipped };
}

export function buildPatches(findings: Finding[], files: { name: string; contents: string }[]): Patch[] {
  return buildPatchesWithSkips(findings, files).patches;
}

/* One diff per file, patches replayed in order on the evolving text. A patch
   that touches an attribute an earlier one already set is reported, not merged. */
export function combinePatches(patches: Patch[], opts: { safety: 'auto' | 'all' }): { diff: string; included: Patch[]; skipped: Skipped[] } {
  const chosen = patches.filter((p) => opts.safety === 'all' || p.safety === 'auto');
  const byFile = new Map<string, Patch[]>();
  for (const p of chosen) byFile.set(p.file, [...(byFile.get(p.file) ?? []), p]);
  const included: Patch[] = [];
  const skipped: Skipped[] = [];
  let body = '';
  for (const [file, list] of byFile) {
    const source = (list[0] as Patch).edit.source;
    let text = source;
    const touched = new Set<string>();
    for (const p of list) {
      const { type, name, fix } = p.edit;
      const keys = [fix.attr, ...Object.keys(fix.also_set ?? {})].map((a) => `${type}.${name}#${a}`);
      const clash = keys.find((k) => touched.has(k));
      const res = clash ? undefined : applyFix(text, type, name, fix);
      if (!res?.changed) {
        skipped.push({ ruleId: p.ruleId, address: p.address, file, reason: clash ? `${clash.split('#')[1]} was already changed by another patch` : (res?.reason ?? 'no change') });
        continue;
      }
      keys.forEach((k) => touched.add(k));
      text = res.text;
      included.push(p);
    }
    body += unifiedDiff(source, text, file, file);
  }
  const lines = included.map((p) => `# - ${p.ruleId} ${p.address} (${p.safety})`);
  const head = included.length ? `# EdgePQ combined patch: ${included.length} change${included.length === 1 ? '' : 's'}\n${lines.join('\n')}\n# ${APPLY_WITH}\n` : '';
  return { diff: head + body, included, skipped };
}
