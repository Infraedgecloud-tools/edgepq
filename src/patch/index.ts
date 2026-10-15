/* ============================================================================
   Findings → patches. A patch is a unified diff for one resource, written for
   a person to read and `git apply`. Nothing here touches the filesystem and
   nothing applies a patch.
   ========================================================================= */
import type { Finding } from '../engine/types.ts';
import { applyEdits, planFix, type Edit, type SetAttributeFix } from './apply.ts';

const span = (edits: Edit[]): { start: number; end: number } => ({ start: Math.min(...edits.map((e) => e.start)), end: Math.max(...edits.map((e) => e.end)) });
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

const APPLY_WITH = 'EdgePQ does not apply patches. Review, then apply with: git apply --unidiff-zero <file>, then run terraform fmt (an inserted line may re-align its neighbours)';

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
    if (!/^[A-Za-z0-9_./-]+$/.test(file) || file.startsWith('/') || file.split('/').includes('..') || /[\x00-\x1f\x7f]/.test(f.resource.address)) { skip('resource or file identity cannot be represented safely in a patch'); continue; }
    if (source === undefined) { skip('source file was not supplied'); continue; }
    /* The address may carry a module or directory prefix; the block in the
       file is still type "name". */
    const type = f.resource.type;
    const name = f.resource.address.slice(f.resource.address.lastIndexOf(`${type}.`) + type.length + 1);
    if (file.endsWith('.json')) { skip('JSON Terraform files are not patched; change the value by hand'); continue; }
    const plan = planFix(source, type, name, fix);
    if (plan.edits.length === 0) { skip(plan.reason ?? 'no change'); continue; }
    /* Two reasons a fix the rule calls automatic still needs a person:
       an attribute under lifecycle.ignore_changes (the patch applies, Terraform
       ignores it on the live resource, and the next scan reports it enabled),
       and a file inside a called module, which every caller of that module
       shares, so the change lands on all of them at once. */
    const ignored = (f.resource.ignore_changes ?? []).some((a) => a === 'all' || a === fix.attr);
    const inModule = /^module\./.test(f.resource.address);
    const safety = ignored || inModule ? 'review' : fix.safety;
    const reasons = [
      ignored ? `${fix.attr} is listed in lifecycle.ignore_changes, so this change will not reach the existing resource until that entry is removed.` : undefined,
      inModule ? `${file} belongs to the module called as ${f.resource.address.replace(/\.[^.]+\.[^.]+$/, '')}; every caller of that module takes this change. If callers need different values, make ${fix.attr} a variable of the module instead.` : undefined,
      fix.note,
    ].filter(Boolean);
    const note = reasons.length ? reasons.join(' ') : undefined;
    const diff = unifiedDiff(source, applyEdits(source, plan.edits), file, file, 0, span(plan.edits));
    if (!assignmentOnly(diff, fix)) { skip('changed lines include comments or unrelated source text; edit the attribute manually'); continue; }
    const patch: Patch = {
      ruleId: f.rule.id, address: f.resource.address, file, safety,
      diff: header({ ruleId: f.rule.id, title: f.rule.title, address: f.resource.address, safety, ...(note ? { note } : {}) }) + diff,
      edit: { type, name, fix, source },
    };
    if (note) patch.note = note;
    if (plan.added) patch.also_set = plan.added;
    patches.push(patch);
  }
  return { patches, skipped };
}

export function buildPatches(findings: Finding[], files: { name: string; contents: string }[]): Patch[] {
  return buildPatchesWithSkips(findings, files).patches;
}

/* One diff per file. Every patch is planned against the original text, the
   plans are checked for clashes (two rules changing one attribute), then all
   edits are applied in a single pass and diffed once. */
export function combinePatches(patches: Patch[], opts: { safety: 'auto' | 'all' }): { diff: string; included: Patch[]; skipped: Skipped[] } {
  const chosen = patches.filter((p) => opts.safety === 'all' || p.safety === 'auto');
  const byFile = new Map<string, Patch[]>();
  for (const p of chosen) byFile.set(p.file, [...(byFile.get(p.file) ?? []), p]);
  const included: Patch[] = [];
  const skipped: Skipped[] = [];
  let body = '';
  for (const [file, list] of byFile) {
    const source = (list[0] as Patch).edit.source;
    const touched = new Set<string>();
    const edits: Edit[] = [];
    for (const p of list) {
      const { type, name, fix } = p.edit;
      const plan = planFix(source, type, name, fix);
      const clash = plan.keys.find((k) => touched.has(k));
      if (clash || plan.edits.length === 0) {
        skipped.push({ ruleId: p.ruleId, address: p.address, file, reason: clash ? `${clash.split('#')[1]} was already changed by another patch` : (plan.reason ?? 'no change') });
        continue;
      }
      plan.keys.forEach((k) => touched.add(k));
      edits.push(...plan.edits);
      included.push(p);
    }
    if (edits.length) body += unifiedDiff(source, applyEdits(source, edits), file, file, 0, span(edits));
  }
  const lines = included.map((p) => `# - ${p.ruleId} ${p.address} (${p.safety})`);
  const head = included.length ? `# EdgePQ combined patch: ${included.length} change${included.length === 1 ? '' : 's'}\n${lines.join('\n')}\n# ${APPLY_WITH}\n` : '';
  return { diff: head + body, included, skipped };
}


/* Zero-context diffs avoid copying neighbouring configuration into reports.
   A changed line itself must contain only the intended literal assignment. */
function assignmentOnly(diff: string, fix: SetAttributeFix): boolean {
  const allowed = new Set([fix.attr, ...Object.keys(fix.also_set ?? {})].map((path) => path.split('.').pop()));
  return diff.split('\n').filter((line) => /^[+-]/.test(line) && !/^(---|\+\+\+)/.test(line)).every((line) => {
    const match = /^\s*([A-Za-z_]\w*)\s*=\s*"(?:[^"\\]|\\.)*"\s*$/.exec(line.slice(1));
    return match !== null && allowed.has(match[1]);
  });
}
