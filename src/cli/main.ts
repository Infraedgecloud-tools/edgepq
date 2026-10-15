/* ============================================================================
   edgepq — the command line.

     edgepq scan <dir | plan.json | state.json> [--out DIR] [--fail-on SEV]
     edgepq aws [--accounts a,b] [--org] [--regions r,s] [--role-name N]
                [--external-id X] [--cloudtrail-sample N] [--coverage strict|advisory] [--out DIR] [--fail-on SEV]
     edgepq verify <host[:port]> [--servername NAME] [--json]
     edgepq rules

   Exit codes: 0 done; 1 findings at or above --fail-on; 2 usage or input
   error. Nothing here applies a change anywhere.
   ========================================================================= */

import { parseArgs, type ParseArgsConfig } from 'node:util';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { SEVERITY_ORDER, type Severity } from '../engine/types.ts';
import type { ScanReport } from '../render/types.ts';
import { loadRules, reportForAws, reportForTerraform } from '../node/report.ts';
import { writeOutputs, type Written } from './write.ts';
import { probe } from '../probe/index.ts';

const display = (s: string): string => s.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');

export type Io = { out: (s: string) => void; err: (s: string) => void };

const USAGE = `usage:
  edgepq scan <dir | plan.json | state.json> [--out DIR] [--fail-on SEV]
  edgepq aws [--accounts a,b] [--org] [--regions r,s] [--role-name N] [--external-id X]
             [--cloudtrail-sample N] [--coverage strict|advisory] [--out DIR] [--fail-on SEV]
  edgepq verify <host[:port]> [--servername NAME] [--json] [--timeout MS]
  edgepq rules

  --out DIR        where to write the outputs (default: ./edgepq-out)
  --fail-on SEV    exit 1 when a failed finding is at or above SEV
                   (critical, high, medium, low, info)

AWS coverage defaults to strict: partial or failed collection exits 2.
--coverage advisory permits partial collection; zero usable collection still exits 2.
A fully enumerated empty AWS scope is complete. Commercial aws partition only.
Explicit --accounts and --regions lists must contain at least one nonempty value.

Exit codes: scan and aws exit 0, 1 when --fail-on is reached, 2 on bad input or
collection failure. scan also exits 2 for zero resources; complete empty AWS
enumeration exits 0. verify exits 0 when the endpoint selects or
completes a real hybrid key exchange, 1 when it is classical or TLS 1.2 only, 2 when the
answer is inconclusive or the host could not be reached.`;

class UsageError extends Error {}

/* Node's parseArgs messages are written for the person who wrote the options
   table, not the one typing the command ("To specify a positional argument
   starting with a '-', place it at the end of the command after '--'"). The
   option that went wrong is enough. */
function options<const T extends ParseArgsConfig>(config: T): ReturnType<typeof parseArgs<T>> {
  try {
    return parseArgs(config);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    const name = /'([^' ]+)[^']*'/.exec(err.message)?.[1];
    switch (err.code) {
      case 'ERR_PARSE_ARGS_UNKNOWN_OPTION': throw new UsageError(`unknown option ${name ?? ''}`.trim());
      case 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE':
        throw new UsageError(name ? (/does not take an argument/.test(err.message) ? `${name} takes no value` : `${name} needs a value`) : err.message);
      case 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL': throw new UsageError(`unexpected argument ${name ?? ''}`.trim());
      default: throw e;
    }
  }
}

function severityAtOrAbove(report: ScanReport, threshold: Severity): number {
  const limit = SEVERITY_ORDER.indexOf(threshold);
  return report.findings.filter((f) => f.status === 'fail' && SEVERITY_ORDER.indexOf(f.rule.severity) <= limit).length;
}

/* One line per failed finding, worst first, so the terminal says what failed
   before the report is opened. The fix is shown when it is a value to set. */
function failedLines(report: ScanReport, limit = 12): string[] {
  const failed = report.findings
    .filter((f) => f.status === 'fail')
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.rule.severity) - SEVERITY_ORDER.indexOf(b.rule.severity) || a.resource.address.localeCompare(b.resource.address));
  const lines = failed.slice(0, limit).flatMap((f) => {
    const head = `  ${f.rule.severity.padEnd(8)} ${f.rule.id.padEnd(13)} ${display(f.resource.address)}`;
    if (f.fix?.kind !== 'set-attribute') return [head, `           ${f.fix ? 'fix: see the report' : 'no fix is offered; see the report'}`];
    const observed = f.observed[f.fix.attr];
    const current = observed?.value === undefined ? 'unset' : `${display(String(observed.value))}${observed.defaulted ? ' (default)' : ''}`;
    return [head, `           ${f.fix.attr}: ${current} → ${display(f.fix.value)}`];
  });
  if (failed.length > limit) lines.push(`  ... and ${failed.length - limit} more; see the report`);
  return lines;
}

function summary(report: ScanReport, written: Written, outDir: string): string {
  const count = (status: string) => report.findings.filter((f) => f.status === status).length;
  const lines = [
    `edgepq ${report.tool.version}: ${report.resources.length} resource(s), ${report.rules.length} rule(s)`,
    `  failed ${count('fail')}   not configurable ${count('not_configurable')}   could not check ${count('unknown')}   already enabled ${count('pass')}   on by default ${count('on_by_default')}`,
    ...failedLines(report),
  ];
  if (report.input.kind === 'hcl') {
    const notes = report.input.notes;
    const gaps = notes.filter((n) => (n.kind === 'module-call' && !n.scanned) || n.kind === 'dynamic-block' || n.kind === 'parse-error' || n.kind === 'count-expression').length;
    const assumed = notes.filter((n) => n.kind === 'default-used').length;
    if (gaps) lines.push(`  not inspected: ${gaps} item(s) (remote modules, dynamic blocks, count expressions or parse errors; see the report)`);
    if (assumed) lines.push(`  assumed: ${assumed} value(s) taken from variable defaults; see the report`);
  }
  if (report.input.kind === 'aws') lines.push(`  collection: ${report.input.status ?? 'unknown'} (${report.input.coverage?.filter((c) => c.status === 'complete').length ?? 0} completed account/region/service scope(s))`);
  if (report.input.kind === 'aws' && report.input.not_checked.length) lines.push(`  not checked: ${report.input.not_checked.length} account/region/service combination(s); see the report`);
  if (written.patches) lines.push(`  patches: ${written.patches} written, never applied${written.perFixFilesOmitted ? ' (combined patches only: more than 200 fixes)' : ''}`);
  for (const s of written.patchesSkipped) lines.push(`  patch not written: ${display(s.ruleId)} ${display(s.address)}: ${display(s.reason)}`);
  lines.push(`  outputs: ${display(outDir)}/ (${written.files.filter((f) => !f.includes('/')).join(', ')}${written.patches ? ', patches/' : ''})`);
  return lines.join('\n');
}

function parseThreshold(v: string | undefined): Severity | undefined {
  if (v === undefined) return undefined;
  if (!SEVERITY_ORDER.includes(v as Severity)) throw new UsageError(`--fail-on must be one of ${SEVERITY_ORDER.join(', ')}`);
  return v as Severity;
}

export async function main(argv: string[], io: Io): Promise<number> {
  const terminal = io;
  const clean = (s: string) => s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, '');
  io = { out: (s) => terminal.out(clean(s)), err: (s) => terminal.err(clean(s)) };
  try {
    const [command, ...rest] = argv;
    if (command !== undefined && ['rules', '--help', '-h', 'help', '--version', '-v'].includes(command) && rest.length) throw new UsageError(`${command} takes no arguments`);
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
      io.err(`edgepq: ${display(e.message)}\n${USAGE}`);
      return 2;
    }
    io.err(`edgepq: ${display((e as Error).message)}`);
    return 2;
  }
}

async function loadRulesAndVersion() {
  const { readToolVersion } = await import('../node/read-policy-data.ts');
  const { packageRoot } = await import('../node/report.ts');
  return { version: await readToolVersion(join(packageRoot, 'package.json')) };
}

async function scan(args: string[], io: Io): Promise<number> {
  const { values, positionals } = options({ args, allowPositionals: true, options: { out: { type: 'string' }, 'fail-on': { type: 'string' } } });
  const target = positionals[0];
  if (!target) throw new UsageError('scan needs a Terraform directory or a terraform show -json file');
  if (positionals.length !== 1) throw new UsageError('scan needs exactly one Terraform directory or JSON file');
  const threshold = parseThreshold(values['fail-on']);
  const outDir = values.out ?? 'edgepq-out';
  await stat(target).catch(() => { throw new UsageError(`${target}: no such file or directory`); });
  const { report, input } = await reportForTerraform(target, await loadRules());
  const written = await writeOutputs(report, outDir, { target, input });
  io.out(summary(report, written, outDir));
  /* Nothing to check is not a clean result. A gate pointed at the wrong
     directory, or at a plan with no resources, must not pass quietly. */
  if (report.resources.length === 0) {
    io.err(`edgepq: no Terraform resources found in ${target}; is this the right ${input.kind === 'hcl' ? 'directory' : 'file'}?`);
    return 2;
  }
  /* A file the tool could not read is an input error, not a clean scan: the
     outputs are still written, but the exit code says the tree was not covered. */
  const unreadable = report.input.kind === 'hcl' ? report.input.notes.filter((n) => n.kind === 'parse-error') : [];
  if (unreadable.length) {
    for (const n of unreadable) if (n.kind === 'parse-error') io.err(`edgepq: ${display(n.file)} did not parse: ${display(n.message)}`);
    return 2;
  }
  return threshold && severityAtOrAbove(report, threshold) > 0 ? 1 : 0;
}

function explicitScope(value: string | undefined, flag: string): string[] | undefined {
  if (value === undefined) return undefined;
  const scope = value.split(',').map((part) => part.trim()).filter(Boolean);
  if (!scope.length) throw new UsageError(`${flag} requires at least one nonempty value`);
  return scope;
}

async function aws(args: string[], io: Io): Promise<number> {
  const { values } = options({ args, options: {
    accounts: { type: 'string' }, org: { type: 'boolean' }, regions: { type: 'string' }, 'role-name': { type: 'string' },
    'external-id': { type: 'string' }, 'cloudtrail-sample': { type: 'string' }, out: { type: 'string' }, 'fail-on': { type: 'string' }, quiet: { type: 'boolean' }, coverage: { type: 'string' }, timeout: { type: 'string' },
  } });
  const threshold = parseThreshold(values['fail-on']);
  const outDir = values.out ?? 'edgepq-out';
  const accounts = explicitScope(values.accounts, '--accounts');
  const regions = explicitScope(values.regions, '--regions');
  const timeoutMs = values.timeout === undefined ? 120000 : Number(values.timeout);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000) throw new UsageError('--timeout must be between 1 and 3600000 milliseconds');
  const coverage = values.coverage ?? 'strict';
  if (coverage !== 'strict' && coverage !== 'advisory') throw new UsageError('--coverage must be strict or advisory');
  const sample = values['cloudtrail-sample'] === undefined ? undefined : Number(values['cloudtrail-sample']);
  if (sample !== undefined && (!Number.isInteger(sample) || sample < 0 || sample > 10000)) throw new UsageError('--cloudtrail-sample must be a whole number from 0 to 10000');
  const { report } = await reportForAws({
    timeoutMs,
    ...(accounts !== undefined ? { accounts } : {}),
    ...(values.org ? { organization: true } : {}),
    ...(regions !== undefined ? { regions } : {}),
    ...(values['role-name'] ? { roleName: values['role-name'] } : {}),
    ...(values['external-id'] ? { externalId: values['external-id'] } : {}),
    ...(sample !== undefined ? { cloudTrailSample: sample } : {}),
    log: values.quiet ? () => {} : (line) => io.err(`  ${line}`),
  }, await loadRules());
  const written = await writeOutputs(report, outDir);
  io.out(summary(report, written, outDir));
  if (report.input.kind === 'aws' && (report.input.status === 'failed' || report.input.status !== 'complete' && coverage === 'strict')) {
    io.err(`edgepq: AWS collection ${report.input.status ?? 'unknown'}; see coverage and not_checked in the report`);
    return 2;
  }
  if (report.input.kind === 'aws' && report.input.status === 'partial') io.err('edgepq: advisory continuation with partial AWS coverage');
  return threshold && severityAtOrAbove(report, threshold) > 0 ? 1 : 0;
}

async function verify(args: string[], io: Io): Promise<number> {
  const { values, positionals } = options({ args, allowPositionals: true, options: { servername: { type: 'string' }, json: { type: 'boolean' }, timeout: { type: 'string' } } });
  const target = positionals[0];
  if (!target) throw new UsageError('verify needs a host or host:port');
  if (positionals.length !== 1) throw new UsageError('verify needs exactly one host or host:port');
  const { host, port } = parseHostPort(target);
  const timeoutMs = values.timeout === undefined ? 5000 : Number(values.timeout);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) throw new UsageError('--timeout must be a whole number of milliseconds');
  const result = await probe({ host, port, ...(values.servername ? { servername: values.servername } : {}) }, { timeoutMs });
  /* The verdict is the exit code, so verify can gate a pipeline: 0 for a
     hybrid group selected or supported, 1 for classical or TLS 1.2 only, 2
     when the answer is inconclusive or the host was not reached. */
  const code = result.verdict === 'hybrid_selected' || result.verdict === 'hybrid_supported_not_preferred' || result.verdict === 'hybrid_supported_preference_unknown' ? 0
    : result.verdict === 'classical_only' || result.verdict === 'tls_1_2_only' ? 1 : 2;
  if (values.json) { io.out(JSON.stringify(result, null, 2)); return code; }
  const b = result.browser_offer;
  const lines = [
    `${result.target.servername}:${result.target.port} probed ${result.probed_at}`,
    `  verdict: ${result.verdict.replace(/_/g, ' ')}`,
    `  browser-like offer: ${b.outcome}${b.tls_version ? ` TLS ${b.tls_version}` : ''}${b.group ? ` group ${b.group.name}` : ''}${b.cipher_suite ? ` ${b.cipher_suite.name}` : ''}${b.alert ? ` alert ${b.alert.name}` : ''}${b.error ? ` (${b.error})` : ''}`,
    `  hybrid-only offer: ${result.hybrid_only_offer.outcome}${result.hybrid_only_offer.group ? ` group ${result.hybrid_only_offer.group.name}` : ''}${result.hybrid_only_offer.alert ? ` alert ${result.hybrid_only_offer.alert.name}` : ''}`,
    ...result.handshakes.map((h) => `  handshake ${h.group}: ${h.not_testable ? 'not testable on this Node' : h.completed ? `completed (${h.protocol ?? ''} ${h.cipher ?? ''})`.trim() : `failed${h.error ? ` (${h.error})` : ''}`}`),
    ...result.evidence_notes.map((n) => `  note: ${n}`),
  ];
  io.out(lines.map(display).join('\n'));
  return code;
}

/* host, host:port, [v6], [v6]:port. A bare IPv6 literal without brackets
   cannot carry a port, which is how the last colon is disambiguated. */
export function parseHostPort(target: string): { host: string; port: number } {
  const result = parseHostPortUnchecked(target);
  if (!Number.isInteger(result.port) || result.port < 1 || result.port > 65535) throw new UsageError('port must be between 1 and 65535');
  return result;
}

function parseHostPortUnchecked(target: string): { host: string; port: number } {
  const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(target);
  if (bracketed) return { host: bracketed[1] as string, port: bracketed[2] ? Number(bracketed[2]) : 443 };
  const plain = /^([^:]+)(?::(\d{1,5}))?$/.exec(target);
  if (plain) return { host: plain[1] as string, port: plain[2] ? Number(plain[2]) : 443 };
  if (/^[0-9a-fA-F:]+$/.test(target)) return { host: target, port: 443 };
  throw new UsageError(`cannot read '${target}' as host[:port]`);
}

async function rules(io: Io): Promise<number> {
  const all = await loadRules();
  for (const r of all) {
    io.out(`${r.id}  v${String(r.version).padEnd(3)} ${r.severity.padEnd(8)} ${r.category.padEnd(12)} ${r.title}`);
    for (const s of r.sources) io.out(`    ${s.url} (verified ${s.verified})`);
  }
  return 0;
}
