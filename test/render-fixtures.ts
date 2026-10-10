/* A ScanReport built from the real fixtures, the real parser and every rule. */
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanHclFiles } from '../src/adapters/hcl.ts';
import { evaluateAll } from '../src/engine/evaluate.ts';
import type { Resource } from '../src/engine/types.ts';
import { loadRulesFromDir } from '../src/node/load-rules.ts';
import { parseHcl } from '../src/node/hcl-parser.ts';
import { readPolicyData, readToolVersion } from '../src/node/read-policy-data.ts';
import type { ScanReport } from '../src/render/types.ts';

export const root = fileURLToPath(new URL('..', import.meta.url));

export async function buildReport(extra: Resource[] = [], withInventory = false): Promise<ScanReport> {
  const rules = await loadRulesFromDir(join(root, 'rules'));
  const dir = join(root, 'test/fixtures/rules');
  const names: string[] = [];
  for (const rule of (await readdir(dir)).sort()) for (const f of (await readdir(join(dir, rule))).sort()) names.push(join(rule, f));
  if (withInventory) names.push('../terraform/inventory/main.tf');
  const files = await Promise.all(names.map(async (name) => ({ name, contents: await readFile(join(dir, name), 'utf8') })));
  const scan = await scanHclFiles(files, parseHcl);
  const resources = [...scan.resources, ...extra];
  return {
    tool: { name: 'edgepq', version: await readToolVersion(join(root, 'package.json')) },
    generated_at: '2026-10-10T12:00:00.000Z',
    input: { kind: 'hcl', files: files.map((f) => f.name), notes: scan.notes },
    rules: rules.map((r) => ({ id: r.id, title: r.title, category: r.category, severity: r.severity, sources: r.sources })),
    findings: evaluateAll(rules, resources),
    resources,
    policy_data: await readPolicyData(join(root, 'rules')),
  };
}

export const hostile = (address: string): Resource => ({
  type: 'aws_lb_listener', address, unknown: [], origin: { kind: 'hcl', file: '<b>x.tf' },
  attrs: { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-2016-08' },
});
