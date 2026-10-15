import { buildDoc } from './document.ts';
import type { ScanReport } from './types.ts';

const inline = (s: string): string => s.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/[\\`*[\]{}|#!]/g, (c) => `\\${c}`);
const cell = inline;

export function renderMarkdown(report: ScanReport): string {
  const d = buildDoc(report);
  const out: string[] = [`# ${d.title}`, '', d.scope, '', '## What this report does and does not say', '', d.intro.join(' '), ''];
  const notCovered = d.coverage.find((c) => c.label === 'Not covered')!;
  out.push(...notCovered.items.map((i) => `- ${inline(i)}`), '');
  for (const g of d.groups) {
    out.push(`## Findings: ${g.label} (${g.findings.length})`, '');
    for (const f of g.findings) {
      out.push(`### ${inline(f.heading)}`, '', `Severity: ${f.severity}. Category: ${f.category}.`, '', inline(f.message), '');
      if (f.observed.length) {
        out.push('| Attribute | Value |', '| --- | --- |', ...f.observed.map((o) => `| ${cell(o.attr)} | ${cell(o.value)}${o.defaulted ? ' (defaulted)' : ''} |`), '');
      }
      if (f.fix.code.length || f.fix.text.length) {
        out.push('Fix:', '');
        if (f.fix.code.length) out.push('```hcl', ...f.fix.code, '```', '');
        out.push(...f.fix.text.flatMap((t) => [inline(t), '']));
      }
      if (f.sources.length) out.push('Sources:', '', ...f.sources.map((s) => `- ${s.url} (verified ${s.verified})`), '');
    }
  }
  out.push('## Coverage', '');
  for (const c of d.coverage) if (c.items.length) out.push(`**${c.label}**`, '', ...c.items.map((i) => `- ${inline(i)}`), '');
  out.push('## Rules run', '', '| Rule | Version | Title | Category | Severity | Sources |', '| --- | --- | --- | --- | --- | --- |',
    ...d.rules.map((r) => `| ${r.id} | ${r.version} | ${cell(r.title)} | ${r.category} | ${r.severity} | ${r.sources} |`), '');
  return out.join('\n');
}
