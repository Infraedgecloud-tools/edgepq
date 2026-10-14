/* Assemble a ScanReport from either input. Node-only glue; the renderers
   never see the filesystem. */
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateAll } from '../engine/evaluate.ts';
import type { Resource, Rule } from '../engine/types.ts';
import type { ScanInput, ScanReport } from '../render/types.ts';
import { loadRulesFromDir } from './load-rules.ts';
import { readPolicyData, readToolVersion } from './read-policy-data.ts';
import { readTerraform, type TerraformInput } from './read-terraform.ts';
import { scanAws } from '../aws/scan.ts';
import type { AwsScan, AwsScanOptions } from '../aws/types.ts';

export const packageRoot = fileURLToPath(new URL('../../', import.meta.url));
export const rulesDir = join(packageRoot, 'rules');

export async function loadRules(): Promise<Rule[]> {
  return loadRulesFromDir(rulesDir);
}

async function assemble(rules: Rule[], input: ScanInput, resources: Resource[]): Promise<ScanReport> {
  return {
    tool: { name: 'edgepq', version: await readToolVersion(join(packageRoot, 'package.json')) },
    generated_at: new Date().toISOString(),
    input,
    rules: rules.map((r) => ({ id: r.id, version: r.version, title: r.title, category: r.category, severity: r.severity, sources: r.sources })),
    findings: evaluateAll(rules, resources),
    resources,
    policy_data: await readPolicyData(rulesDir),
  };
}

export async function reportForTerraform(target: string, rules: Rule[]): Promise<{ report: ScanReport; input: TerraformInput }> {
  const input = await readTerraform(target);
  if (input.kind === 'hcl') {
    return { report: await assemble(rules, { kind: 'hcl', files: input.files, notes: input.scan.notes }, input.scan.resources), input };
  }
  if (input.scan.kind === 'unrecognised') {
    throw new Error(`${input.file} is neither a Terraform plan nor a state (\`terraform show -json\` output expected)`);
  }
  return { report: await assemble(rules, { kind: input.scan.kind, file: input.file, skipped: input.scan.skipped }, input.scan.resources), input };
}

export async function reportForAws(opts: AwsScanOptions, rules: Rule[]): Promise<{ report: ScanReport; scan: AwsScan }> {
  const scan = await scanAws(opts);
  const input: ScanInput = { kind: 'aws', accounts: scan.accounts, regions: scan.regions, not_checked: scan.not_checked };
  return { report: await assemble(rules, input, scan.resources), scan };
}
