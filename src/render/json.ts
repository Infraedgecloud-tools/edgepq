import type { Category, Severity, Status } from '../engine/types.ts';
import { CATEGORY_ORDER, SEVERITY_ORDER } from '../engine/types.ts';
import { NOT_COVERED } from './not-covered.ts';
import type { ScanReport } from './types.ts';

const tally = <K extends string>(keys: readonly K[], items: K[]): Record<K, number> =>
  Object.fromEntries(keys.map((k) => [k, items.filter((i) => i === k).length])) as Record<K, number>;

export function renderJson(report: ScanReport): string {
  const fails = report.findings.filter((f) => f.status === 'fail');
  const i = report.input;
  const doc = {
    schema_version: '1',
    tool: report.tool,
    generated_at: report.generated_at,
    input: i,
    summary: {
      by_status: tally<Status>(['fail', 'not_configurable', 'unknown', 'pass', 'on_by_default', 'not_applicable'], report.findings.map((f) => f.status)),
      /* Failing findings only, so a report full of passes does not look busy. */
      by_category: tally<Category>(CATEGORY_ORDER, fails.map((f) => f.rule.category)),
      by_severity: tally<Severity>(SEVERITY_ORDER, fails.map((f) => f.rule.severity)),
      resources_scanned: report.resources.length,
      rules_run: report.rules.length,
    },
    findings: report.findings,
    coverage: {
      notes: i.kind === 'hcl' ? i.notes : [],
      skipped: i.kind === 'plan' || i.kind === 'state' ? i.skipped : [],
      not_checked: i.kind === 'aws' ? i.not_checked : [],
      not_covered: NOT_COVERED,
    },
  };
  return JSON.stringify(doc, null, 2) + '\n';
}
