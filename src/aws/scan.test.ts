import test from 'node:test';
import assert from 'node:assert/strict';
import { scanAws } from './scan.ts';
import type { Collector } from './types.ts';

const seen: string[] = [];
const ok: Collector = { service: 'ok', run: async (ctx) => { seen.push(`${ctx.scope.account}/${ctx.scope.region}/ok`); return { resources: [{ type: 'x', address: `${ctx.scope.account}:${ctx.scope.region}`, attrs: {}, unknown: [], origin: { kind: 'aws', account: ctx.scope.account, region: ctx.scope.region } }], notes: ['n'] }; } };
const glob: Collector = { service: 'glob', global: true, run: async (ctx) => { seen.push(`${ctx.scope.account}/${ctx.scope.region}/glob`); return { resources: [] }; } };
const boom: Collector = { service: 'boom', run: async () => { const e = new Error('not authorized'); e.name = 'AccessDeniedException'; throw e; } };

type Deps = Parameters<typeof scanAws>[1];
const deps = (regions: string[] = ['eu-west-2', 'us-east-1']): NonNullable<Deps> => ({
  callerIdentity: async () => ({ account: '111111111111', arn: 'arn:aws:iam::111111111111:user/me' }),
  enabledRegions: async () => regions,
  organizationAccounts: async () => ['111111111111', '222222222222'],
  assumedRole: (account: string, _role: string, _ext: string | undefined) => (async () => ({ accessKeyId: account, secretAccessKey: 's' })),
  collectors: [ok, glob, boom],
});

test('own account, every enabled region, failures recorded per service', async () => {
  seen.length = 0;
  const scan = await scanAws({}, deps());
  assert.deepEqual(scan.accounts, ['111111111111']);
  assert.deepEqual(scan.regions, ['eu-west-2', 'us-east-1']);
  assert.deepEqual(seen, ['111111111111/us-east-1/glob', '111111111111/eu-west-2/ok', '111111111111/us-east-1/ok']);
  assert.deepEqual(scan.not_checked, [
    { account: '111111111111', region: 'eu-west-2', service: 'boom', reason: 'AccessDeniedException: not authorized' },
    { account: '111111111111', region: 'us-east-1', service: 'boom', reason: 'AccessDeniedException: not authorized' },
  ]);
  assert.equal(scan.resources.length, 2);
  assert.deepEqual(scan.notes, ['n', 'n']);
});

test('another account needs a role name, and gets it', async () => {
  const without = await scanAws({ accounts: ['222222222222'], regions: ['eu-west-2'] }, deps());
  assert.deepEqual(without.not_checked, [{ account: '222222222222', region: '*', service: '*', reason: 'no role name given to assume into this account' }]);
  assert.equal(without.resources.length, 0);
  const d = deps();
  let assumed = '';
  d.assumedRole = (account: string, role: string) => { assumed = `${account}:${role}`; return async () => ({ accessKeyId: 'a', secretAccessKey: 's' }); };
  const withRole = await scanAws({ accounts: ['222222222222'], regions: ['eu-west-2'], roleName: 'edgepq-readonly' }, d);
  assert.equal(assumed, '222222222222:edgepq-readonly');
  assert.equal(withRole.resources.length, 1);
});

test('organization mode lists accounts, explicit regions are not discovered', async () => {
  const d = deps();
  d.enabledRegions = async () => { throw new Error('must not be called'); };
  const scan = await scanAws({ organization: true, regions: ['eu-west-1'], roleName: 'r' }, d);
  assert.deepEqual(scan.accounts, ['111111111111', '222222222222']);
  assert.deepEqual(scan.resources.map((r) => r.address), ['111111111111:eu-west-1', '222222222222:eu-west-1']);
});

test('a region discovery failure is recorded, not fatal', async () => {
  const d = deps();
  d.enabledRegions = async () => { throw new Error('ec2 denied'); };
  const scan = await scanAws({}, d);
  assert.deepEqual(scan.not_checked, [{ account: '111111111111', region: '*', service: 'ec2:DescribeRegions', reason: 'Error: ec2 denied' }]);
});
