import { COLLECTORS } from './collectors/index.ts';
import { assumedRole, callerIdentity, enabledRegions, organizationAccounts } from './clients.ts';
import type { AwsScan, AwsScanOptions, Collector, CollectorContext, NotChecked } from './types.ts';
import type { Resource } from '../engine/types.ts';

/* Orchestration: accounts × regions × collectors, global collectors once per
   account. A collector that throws becomes a not_checked entry with the
   error's message; the scan continues. Nothing here writes to AWS. */
export async function scanAws(opts: AwsScanOptions = {}, deps = { callerIdentity, enabledRegions, organizationAccounts, assumedRole, collectors: COLLECTORS as Collector[] }): Promise<AwsScan> {
  const log = opts.log ?? (() => {});
  const timeoutMs = opts.timeoutMs ?? 120000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000) throw new Error('AWS timeout must be between 1 and 3600000 milliseconds');
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(new Error('AWS total run budget exceeded')), timeoutMs);
  const signal = opts.signal ? AbortSignal.any([opts.signal, deadline.signal]) : deadline.signal;
  try {
  signal.throwIfAborted();
  const caller = await deps.callerIdentity(signal);
  let accounts = opts.accounts?.length ? [...opts.accounts] : [caller.account];
  if (opts.organization) accounts = await deps.organizationAccounts(signal);
  accounts = [...new Set(accounts)].sort();

  if (!accounts.length || accounts.length > 100 || accounts.some((a) => !/^\d{12}$/.test(a))) throw new Error('AWS scope requires 1 to 100 valid 12-digit accounts');
  if (opts.regions && (!opts.regions.length || opts.regions.length > 100 || opts.regions.some((r) => !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(r)))) throw new Error('AWS scope requires 1 to 100 valid regions');
  if (opts.cloudTrailSample !== undefined && (!Number.isInteger(opts.cloudTrailSample) || opts.cloudTrailSample < 0 || opts.cloudTrailSample > 10000)) throw new Error('CloudTrail sample must be between 0 and 10000');
  let scopes = 0;
  const resources: Resource[] = [];
  const not_checked: NotChecked[] = [];
  const notes: string[] = [];
  const regions = new Set<string>();
  const coverage: AwsScan['coverage'] = [];
  if (!caller.arn.startsWith('arn:aws:')) throw new Error('AWS scanner supports the commercial aws partition only');

  for (const account of accounts) {
    if (signal.aborted) { not_checked.push({ account, region: '*', service: '*', reason: 'AWS scan cancelled or total run budget exceeded' }); continue; }
    const credentials = account === caller.account ? undefined : opts.roleName ? deps.assumedRole(account, opts.roleName, opts.externalId, signal) : undefined;
    if (account !== caller.account && !opts.roleName) {
      not_checked.push({ account, region: '*', service: '*', reason: 'no role name given to assume into this account' });
      continue;
    }
    let accountRegions = [...new Set(opts.regions ?? [])].sort();
    if (accountRegions.length === 0) {
      try {
        accountRegions = await deps.enabledRegions(credentials, signal);
        accountRegions = [...new Set(accountRegions)].sort();
      } catch (e) {
        not_checked.push({ account, region: '*', service: 'ec2:DescribeRegions', reason: message(e) });
        continue;
      }
    }
    if (accountRegions.length > 100 || accountRegions.some((r) => !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(r))) throw new Error('discovered AWS regions exceed supported scope');
    if (!accountRegions.length) {
      not_checked.push({ account, region: '*', service: 'ec2:DescribeRegions', reason: 'no enabled regions returned; scope was not observed' });
      continue;
    }
    if (accountRegions.some((r) => /^(cn-|us-gov-|us-iso)/.test(r))) throw new Error('AWS scanner supports the commercial aws partition only');
    for (const region of accountRegions) regions.add(region);
    const run = async (c: Collector, region: string) => {
      if (++scopes > 5000) throw new Error('AWS collection scope count exceeds 5000');
      if (signal.aborted) {
        not_checked.push({ account, region, service: c.service, reason: 'AWS scan cancelled or total run budget exceeded' });
        return;
      }
      const ctx: CollectorContext = { scope: { account, region }, credentials, cloudTrailSample: opts.cloudTrailSample ?? 200, signal };
      log(`${account} ${region} ${c.service}`);
      try {
        const out = await c.run(ctx);
        if (resources.length + out.resources.length > 100000) throw new Error('AWS resource count exceeds 100000');
        coverage.push({ account, region, service: c.service, status: out.excluded ? 'excluded' : 'complete', resources: out.resources.length });
        resources.push(...out.resources);
        notes.push(...(out.notes ?? []));
      } catch (e) {
        coverage.push({ account, region, service: c.service, status: 'failed', resources: 0 });
        not_checked.push({ account, region, service: c.service, reason: message(e) });
      }
    };
    for (const c of deps.collectors.filter((c) => c.global)) await run(c, 'us-east-1');
    for (const region of accountRegions) {
      for (const c of deps.collectors.filter((c) => !c.global)) await run(c, region);
    }
  }
  const completed = coverage.filter((c) => c.status === 'complete').length;
  const status = completed === 0 ? 'failed' : not_checked.length ? 'partial' : 'complete';
  return { caller, accounts, regions: [...regions].sort(), resources, not_checked, notes, coverage, status };
  } finally { clearTimeout(timer); }
}

function message(e: unknown): string {
  if (e && typeof e === 'object' && 'name' in e && 'message' in e) return `${String((e as { name: unknown }).name)}: ${String((e as { message: unknown }).message)}`;
  return String(e);
}
