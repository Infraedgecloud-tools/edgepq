/* ============================================================================
   edgepq — the command line.

     edgepq scan <dir | plan.json | state.json> [--out DIR] [--fail-on SEV]
     edgepq aws [--accounts a,b] [--org] [--regions r,s] [--role-name N]
                [--external-id X] [--cloudtrail-sample N] [--out DIR] [--fail-on SEV]
     edgepq verify <host[:port]> [--servername NAME] [--json]
     edgepq rules

   Exit codes: 0 done; 1 findings at or above --fail-on; 2 usage or input
   error. Nothing here applies a change anywhere.
   ========================================================================= */

import { parseArgs } from 'node:util';
import { join } from 'node:path';
import { SEVERITY_ORDER, type Severity } from '../engine/types.ts';
import type { ScanReport } from '../render/types.ts';
import { loadRules, reportForAws, reportForTerraform } from '../node/report.ts';
import { writeOutputs, type Written } from './write.ts';
import { probe } from '../probe/index.ts';

export type Io = { out: (s: string) => void; err: (s: string) => void };

const USAGE = `usage:
  edgepq scan <dir | plan.json | state.json> [--out DIR] [--fail-on SEV]
  edgepq aws [--accounts a,b] [--org] [--regions r,s] [--role-name N] [--external-id X]
             [--cloudtrail-sample N] [--out DIR] [--fail-on SEV]
  edgepq verify <host[:port]> [--servername NAME] [--json]
  edgepq rules

  --out DIR        where to write the outputs (default: ./edgepq-out)
  --fail-on SEV    exit 1 when a failed finding is at or above SEV
                   (critical, high, medium, low, info)`;

class UsageError extends Error {}

function severityAtOrAbove(report: ScanReport, threshold: Severity): number {
  const limit = SEVERITY_ORDER.indexOf(threshold);
  return report.findings.filter((f) => f.status === 'fail' && SEVERITY_ORDER.indexOf(f.rule.severity) <= limit).length;
}

function summary(report: ScanReport, written: Written, outDir: string): string {
  const count = (status: string) => report.findings.filter((f) => f.status === status).length;
  const lines = [
    `edgepq ${report.tool.version}: ${report.resources.length} resource(s), ${report.rules.length} rule(s)`,
    `  failed ${count('fail')}   could not check ${count('unknown')}   already enabled ${count('pass')}`,
  ];
  if (report.input.kind === 'hcl' && report.input.notes.length) lines.push(`  not inspected: ${report.input.notes.length} item(s) (module calls, dynamic blocks or parse errors; see the report)`);
  if (report.input.kind === 'aws' && report.input.not_checked.length) lines.push(`  not checked: ${report.input.not_checked.length} account/region/service combination(s); see the report`);
  if (written.patches) lines.push(`  patches: ${written.patches} written, never applied`);
  if (written.patchesSkipped.length) lines.push(`  patches not written: ${written.patchesSkipped.length} (value is not a literal or the block is ambiguous)`);
  lines.push(`  outputs: ${outDir}/ (${written.files.filter((f) => !f.includes('/')).join(', ')}${written.patches ? ', patches/' : ''})`);
  return lines.join('\n');
}

function parseThreshold(v: string | undefined): Severity | undefined {
  if (v === undefined) return undefined;
  if (!SEVERITY_ORDER.includes(v as Severity)) throw new UsageError(`--fail-on must be one of ${SEVERITY_ORDER.join(', ')}`);
  return v as Severity;
}

export async function main(argv: string[], io: Io): Promise<number> {
  try {
    const [command, ...rest] = argv;
    switch (command) {
      case 'scan': return await scan(rest, io);
      case 'aws': return await aws(rest, io);
      case 'verify': return await verify(rest, io);
      case 'rules': return await rules(io);
      case '--help': case '-h': case 'help': case undefined:
        io.out(USAGE);
        return command === undefined ? 2 : 0;
      case '--version': case '-v':
        io.out((await loadRulesAndVersion()).version);
        return 0;
      default:
        throw new UsageError(`unknown command '${command}'`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      io.err(`edgepq: ${e.message}\n${USAGE}`);
      return 2;
    }
    io.err(`edgepq: ${(e as Error).message}`);
    return 2;
  }
}

async function loadRulesAndVersion() {
  const { readToolVersion } = await import('../node/read-policy-data.ts');
  const { packageRoot } = await import('../node/report.ts');
  return { version: await readToolVersion(join(packageRoot, 'package.json')) };
}

async function scan(args: string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { out: { type: 'string' }, 'fail-on': { type: 'string' } } });
  const target = positionals[0];
  if (!target) throw new UsageError('scan needs a Terraform directory or a terraform show -json file');
  const threshold = parseThreshold(values['fail-on']);
  const outDir = values.out ?? 'edgepq-out';
  const { report, input } = await reportForTerraform(target, await loadRules());
  const written = await writeOutputs(report, outDir, { target, input });
  io.out(summary(report, written, outDir));
  return threshold && severityAtOrAbove(report, threshold) > 0 ? 1 : 0;
}

async function aws(args: string[], io: Io): Promise<number> {
  const { values } = parseArgs({ args, options: {
    accounts: { type: 'string' }, org: { type: 'boolean' }, regions: { type: 'string' }, 'role-name': { type: 'string' },
    'external-id': { type: 'string' }, 'cloudtrail-sample': { type: 'string' }, out: { type: 'string' }, 'fail-on': { type: 'string' }, quiet: { type: 'boolean' },
  } });
  const threshold = parseThreshold(values['fail-on']);
  const outDir = values.out ?? 'edgepq-out';
  const sample = values['cloudtrail-sample'] === undefined ? undefined : Number(values['cloudtrail-sample']);
  if (sample !== undefined && (!Number.isInteger(sample) || sample < 0)) throw new UsageError('--cloudtrail-sample must be a whole number');
  const { report } = await reportForAws({
    ...(values.accounts ? { accounts: values.accounts.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
    ...(values.org ? { organization: true } : {}),
    ...(values.regions ? { regions: values.regions.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
    ...(values['role-name'] ? { roleName: values['role-name'] } : {}),
    ...(values['external-id'] ? { externalId: values['external-id'] } : {}),
    ...(sample !== undefined ? { cloudTrailSample: sample } : {}),
    log: values.quiet ? () => {} : (line) => io.err(`  ${line}`),
  }, await loadRules());
  const written = await writeOutputs(report, outDir);
  io.out(summary(report, written, outDir));
  return threshold && severityAtOrAbove(report, threshold) > 0 ? 1 : 0;
}

async function verify(args: string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { servername: { type: 'string' }, json: { type: 'boolean' }, timeout: { type: 'string' } } });
  const target = positionals[0];
  if (!target) throw new UsageError('verify needs a host or host:port');
  const m = /^(\[?[^\]]+\]?|[^:]+)(?::(\d+))?$/.exec(target);
  if (!m) throw new UsageError(`cannot read '${target}' as host[:port]`);
  const host = (m[1] as string).replace(/^\[|\]$/g, '');
  const port = m[2] ? Number(m[2]) : 443;
  const result = await probe({ host, port, ...(values.servername ? { servername: values.servername } : {}) }, { timeoutMs: values.timeout ? Number(values.timeout) : 5000 });
  if (values.json) { io.out(JSON.stringify(result, null, 2)); return 0; }
  const b = result.browser_offer;
  const lines = [
    `${result.target.servername}:${result.target.port} probed ${result.probed_at}`,
    `  verdict: ${result.verdict.replace(/_/g, ' ')}`,
    `  browser-like offer: ${b.outcome}${b.tls_version ? ` TLS ${b.tls_version}` : ''}${b.group ? ` group ${b.group.name}` : ''}${b.cipher_suite ? ` ${b.cipher_suite.name}` : ''}${b.alert ? ` alert ${b.alert.name}` : ''}${b.error ? ` (${b.error})` : ''}`,
    `  hybrid-only offer: ${result.hybrid_only_offer.outcome}${result.hybrid_only_offer.group ? ` group ${result.hybrid_only_offer.group.name}` : ''}${result.hybrid_only_offer.alert ? ` alert ${result.hybrid_only_offer.alert.name}` : ''}`,
    ...result.handshakes.map((h) => `  handshake ${h.group}: ${h.not_testable ? 'not testable on this Node' : h.completed ? `completed (${h.protocol ?? ''} ${h.cipher ?? ''})`.trim() : `failed${h.error ? ` (${h.error})` : ''}`}`),
    ...result.evidence_notes.map((n) => `  note: ${n}`),
  ];
  io.out(lines.join('\n'));
  return 0;
}

async function rules(io: Io): Promise<number> {
  const all = await loadRules();
  for (const r of all) {
    io.out(`${r.id}  ${r.severity.padEnd(8)} ${r.category.padEnd(12)} ${r.title}`);
    for (const s of r.sources) io.out(`    ${s.url} (verified ${s.verified})`);
  }
  return 0;
}
