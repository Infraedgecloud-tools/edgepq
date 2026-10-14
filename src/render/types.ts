/* The one input every renderer takes. Browser-safe: no Node imports under src/render. */
import type { Category, Finding, Resource, Severity, Source } from '../engine/types.ts';
import type { CoverageNote } from '../adapters/hcl.ts';

export type ScanInput =
  | { kind: 'hcl'; files: string[]; notes: CoverageNote[]; patches_skipped?: { ruleId: string; address: string; reason: string }[] }
  | { kind: 'plan' | 'state'; file: string; skipped: { address: string; reason: string }[] }
  | { kind: 'aws'; accounts: string[]; regions: string[]; not_checked: { account: string; region: string; service: string; reason: string }[] };

export type ScanReport = {
  tool: { name: 'edgepq'; version: string };
  generated_at: string;
  input: ScanInput;
  /* Every rule that ran, even if it produced nothing. */
  rules: { id: string; version: number; title: string; category: Category; severity: Severity; sources: Source[] }[];
  findings: Finding[];
  resources: Resource[];
  /* The parsed rules/data/*.json files. Passed in so renderers never read files. */
  policy_data: { elb: unknown; apigw: unknown };
};
