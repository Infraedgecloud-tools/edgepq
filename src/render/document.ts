/* A neutral document model. Markdown and HTML are two serialisations of this,
   so the two reports cannot drift apart. Quote text from sources is never
   included: URLs and verification dates only. */
import type { Finding, Status } from '../engine/types.ts';
import { NOT_COVERED } from './not-covered.ts';
import type { ScanInput, ScanReport } from './types.ts';

export type FindingView = {
  id: string; heading: string; severity: string; category: string; message: string;
  observed: { attr: string; value: string; defaulted: boolean }[];
  fix: { code: string[]; text: string[] };
  sources: { url: string; verified: string }[];
};
export type Doc = {
  title: string; scope: string; intro: string[];
  groups: { label: string; status: Status; findings: FindingView[] }[];
  coverage: { label: string; items: string[] }[];
  rules: { id: string; title: string; category: string; severity: string; sources: number }[];
};

export const GROUPS: { status: Status; label: string }[] = [
  { status: 'fail', label: 'Failed' }, { status: 'unknown', label: 'Could not check' }, { status: 'pass', label: 'Already enabled' },
];
const show = (v: unknown): string => (v === undefined ? '(absent)' : typeof v === 'string' ? v : JSON.stringify(v));

function fixLines(f: Finding): FindingView['fix'] {
  const fix = f.fix;
  if (!fix) return { code: [], text: [] };
  if (fix.kind === 'guidance') return { code: [], text: [fix.note] };
  const code = [`${fix.attr} = ${JSON.stringify(fix.value)}`, ...Object.entries(fix.also_set ?? {}).map(([k, v]) => `${k} = ${JSON.stringify(v)}`)];
  return { code, text: [`Safety: ${fix.safety}.${fix.note ? ' ' + fix.note : ''}`] };
}

function inputItems(input: ScanInput): { label: string; items: string[] }[] {
  if (input.kind === 'hcl') {
    return [
      { label: 'Files scanned', items: input.files },
      { label: 'Notes', items: input.notes.map((n) => n.kind === 'module-call' ? `${n.address} (${n.file}) is a module call${n.source ? ` of ${n.source}` : ''}; its resources were not scanned.`
        : n.kind === 'dynamic-block' ? `${n.address} (${n.file}) generates "${n.block}" blocks at plan time; they were not read.`
        : `${n.file} could not be parsed: ${n.message}`) },
    ];
  }
  if (input.kind === 'aws') {
    return [
      { label: 'Accounts', items: input.accounts }, { label: 'Regions', items: input.regions },
      { label: 'Not checked', items: input.not_checked.map((n) => `${n.account} ${n.region} ${n.service}: ${n.reason}`) },
    ];
  }
  return [{ label: 'File scanned', items: [input.file] }, { label: 'Skipped', items: input.skipped.map((s) => `${s.address}: ${s.reason}`) }];
}

/* Two quotes from one page are two sources in the rule and one line here. */
function dedupe(sources: { url: string; verified: string }[]): { url: string; verified: string }[] {
  const seen = new Set<string>();
  return sources.filter((s) => (seen.has(s.url) ? false : (seen.add(s.url), true)));
}

export function buildDoc(report: ScanReport): Doc {
  const kind = { hcl: 'Terraform source files', plan: 'a Terraform plan', state: 'Terraform state', aws: 'a live AWS account scan' }[report.input.kind];
  const counts = GROUPS.map((g) => report.findings.filter((f) => f.status === g.status).length);
  return {
    title: 'EdgePQ post-quantum readiness report',
    scope: `Scope: ${kind}, ${report.resources.length} resources, ${report.rules.length} rules, generated ${report.generated_at}. ${GROUPS.map((g, i) => `${counts[i]} ${g.label.toLowerCase()}`).join(', ')}.`,
    intro: [
      'This report lists what is enabled, what is not enabled, and what could not be checked.',
      'It does not look at the items listed under "Not covered", and nothing here describes how a particular client behaves.',
      'A line saying a setting is already enabled describes that one setting and is not a certification of anything.',
    ],
    groups: GROUPS.map((g) => ({
      label: g.label, status: g.status,
      findings: report.findings.filter((f) => f.status === g.status).map((f) => ({
        id: f.id, heading: `${f.rule.id} · ${f.resource.address}`, severity: f.rule.severity, category: f.rule.category, message: f.message,
        observed: Object.entries(f.observed).map(([attr, o]) => ({ attr, value: o.unknown ? '(not known offline)' : show(o.value), defaulted: o.defaulted === true })),
        fix: fixLines(f), sources: dedupe(f.sources.map((s) => ({ url: s.url, verified: s.verified }))),
      })),
    })),
    coverage: [{ label: 'Input', items: [report.input.kind] }, ...inputItems(report.input), { label: 'Not covered', items: [...NOT_COVERED] }],
    rules: report.rules.map((r) => ({ id: r.id, title: r.title, category: r.category, severity: r.severity, sources: r.sources.length })),
  };
}
