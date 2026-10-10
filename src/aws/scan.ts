import { COLLECTORS } from './collectors/index.ts';
import { assumedRole, callerIdentity, enabledRegions, organizationAccounts } from './clients.ts';
import type { AwsScan, AwsScanOptions, Collector, CollectorContext, NotChecked } from './types.ts';
import type { Resource } from '../engine/types.ts';

/* Orchestration: accounts × regions × collectors, global collectors once per
   account. A collector that throws becomes a not_checked entry with the
   error's message; the scan continues. Nothing here writes to AWS. */
export async function scanAws(opts: AwsScanOptions = {}, deps = { callerIdentity, enabledRegions, organizationAccounts, assumedRole, collectors: COLLECTORS as Collector[] }): Promise<AwsScan> {
  const log = opts.log ?? (() => {});
  const caller = await deps.callerIdentity();
  let accounts = opts.accounts?.length ? [...opts.accounts] : [caller.account];
  if (opts.organization) accounts = await deps.organizationAccounts();
  accounts = [...new Set(accounts)].sort();

  const resources: Resource[] = [];
  const not_checked: NotChecked[] = [];
  const notes: string[] = [];
  let regions: string[] = opts.regions ?? [];

  for (const account of accounts) {
    const credentials = account === caller.account ? undefined : opts.roleName ? deps.assumedRole(account, opts.roleName, opts.externalId) : undefined;
    if (account !== caller.account && !opts.roleName) {
      not_checked.push({ account, region: '*', service: '*', reason: 'no role name given to assume into this account' });
      continue;
    }
    let accountRegions = regions;
    if (accountRegions.length === 0) {
      try {
        accountRegions = await deps.enabledRegions(credentials);
        if (!opts.regions) regions = accountRegions;
      } catch (e) {
        not_checked.push({ account, region: '*', service: 'ec2:DescribeRegions', reason: message(e) });
        continue;
      }
    }
    const run = async (c: Collector, region: string) => {
      const ctx: CollectorContext = { scope: { account, region }, credentials, cloudTrailSample: opts.cloudTrailSample ?? 200 };
      log(`${account} ${region} ${c.service}`);
      try {
        const out = await c.run(ctx);
        resources.push(...out.resources);
        notes.push(...(out.notes ?? []));
      } catch (e) {
        not_checked.push({ account, region, service: c.service, reason: message(e) });
      }
    };
    for (const c of deps.collectors.filter((c) => c.global)) await run(c, 'us-east-1');
    for (const region of accountRegions) {
      for (const c of deps.collectors.filter((c) => !c.global)) await run(c, region);
    }
  }
  return { caller, accounts, regions, resources, not_checked, notes };
}

function message(e: unknown): string {
  if (e && typeof e === 'object' && 'name' in e && 'message' in e) return `${String((e as { name: unknown }).name)}: ${String((e as { message: unknown }).message)}`;
  return String(e);
}
