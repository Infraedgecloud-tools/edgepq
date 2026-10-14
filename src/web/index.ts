/* ============================================================================
   EdgePQ Check — the browser entry. Everything the CLI's `scan` does on a
   directory, on a pasted string, in the page. No network after the parser
   has loaded, no upload, no telemetry: there is nothing in here that could.

   The rules and the policy tables are compiled in at build time by
   scripts/build-web.ts (virtual modules), so the page and the CLI evaluate
   the same files.
   ========================================================================= */

import rulesJson from 'edgepq:rules';
import policyData from 'edgepq:policy-data';
import version from 'edgepq:version';
import defaultWasmUrl from 'edgepq:wasm-url';
import { resourcesFromHclJson, scanHclFiles } from '../adapters/hcl.ts';
import { resourcesFromTerraformJson } from '../adapters/plan.ts';
import { evaluateAll } from '../engine/evaluate.ts';
import { validateRules } from '../engine/rules.ts';
import type { Resource, Rule } from '../engine/types.ts';
import { buildDoc, type Doc } from '../render/document.ts';
import { renderCbomJson } from '../render/cbom.ts';
import { renderJson } from '../render/json.ts';
import { renderMarkdown } from '../render/markdown.ts';
import { NOT_COVERED } from '../render/not-covered.ts';
import type { ScanInput, ScanReport } from '../render/types.ts';
import { browserHclParser, loadHclParser } from './hcl-browser.ts';

export type CheckResult = {
  kind: 'hcl' | 'plan' | 'state';
  report: ScanReport;
  doc: Doc;
  json: string;
  markdown: string;
  cbom: string;
  summary: { fail: number; not_configurable: number; unknown: number; pass: number; on_by_default: number; resources: number; rules: number };
};

const rules: Rule[] = validateRules(rulesJson as unknown[]);
let wasmUrl: string = defaultWasmUrl;

function report(input: ScanInput, resources: Resource[]): ScanReport {
  return {
    tool: { name: 'edgepq', version: version as string },
    generated_at: new Date().toISOString(),
    input,
    rules: rules.map((r) => ({ id: r.id, version: r.version, title: r.title, category: r.category, severity: r.severity, sources: r.sources })),
    findings: evaluateAll(rules, resources),
    resources,
    policy_data: policyData as ScanReport['policy_data'],
  };
}

function finish(kind: CheckResult['kind'], rep: ScanReport): CheckResult {
  const count = (s: string) => rep.findings.filter((f) => f.status === s).length;
  return {
    kind, report: rep, doc: buildDoc(rep), json: renderJson(rep), markdown: renderMarkdown(rep), cbom: renderCbomJson(rep),
    summary: { fail: count('fail'), not_configurable: count('not_configurable'), unknown: count('unknown'), pass: count('pass'), on_by_default: count('on_by_default'), resources: rep.resources.length, rules: rules.length },
  };
}

/* JSON in: a plan or state from `terraform show -json`. Anything else: HCL. */
export async function check(text: string, filename = 'main.tf'): Promise<CheckResult> {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    let doc: unknown;
    try { doc = JSON.parse(trimmed); } catch (e) { throw new Error(`this looks like JSON but does not parse: ${(e as Error).message}`); }
    const scan = resourcesFromTerraformJson(doc);
    if (scan.kind === 'unrecognised') throw new Error('this JSON is neither a Terraform plan nor a state (terraform show -json output expected)');
    return finish(scan.kind, report({ kind: scan.kind, file: filename, skipped: scan.skipped }, scan.resources));
  }
  const scan = await scanHclFiles([{ name: filename, contents: text }], browserHclParser(wasmUrl));
  if (scan.resources.length === 0 && scan.notes.some((n) => n.kind === 'parse-error')) {
    const err = scan.notes.find((n) => n.kind === 'parse-error') as { message: string };
    throw new Error(`Terraform did not parse: ${err.message}`);
  }
  return finish('hcl', report({ kind: 'hcl', files: [filename], notes: scan.notes }, scan.resources));
}

/* Start the parser download now, so the page works offline from then on. */
export function ready(url?: string): Promise<void> {
  if (url) wasmUrl = url;
  return loadHclParser(wasmUrl).then(() => undefined);
}

export const info = { version: version as string, wasmUrl: defaultWasmUrl as string, rules: rules.map((r) => ({ id: r.id, title: r.title, severity: r.severity, category: r.category })), notCovered: NOT_COVERED };
export { resourcesFromHclJson };
