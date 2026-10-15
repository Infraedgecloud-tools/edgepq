import { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { EC2Client, DescribeRegionsCommand } from '@aws-sdk/client-ec2';
import { OrganizationsClient, paginateListAccounts } from '@aws-sdk/client-organizations';
import { AWS_LIMITS, checkedPages } from './bounds.ts';
import type { CredentialProvider } from './types.ts';

export async function callerIdentity(signal?: AbortSignal): Promise<{ account: string; arn: string }> {
  const out = await new STSClient(AWS_LIMITS).send(new GetCallerIdentityCommand({}), signal ? { abortSignal: signal } : {});
  if (!out.Account || !out.Arn) throw new Error('sts:GetCallerIdentity returned no account');
  return { account: out.Account, arn: out.Arn };
}

export async function enabledRegions(credentials: CredentialProvider | undefined, signal?: AbortSignal): Promise<string[]> {
  const out = await new EC2Client({ ...AWS_LIMITS, region: 'us-east-1', ...(credentials ? { credentials } : {}) }).send(new DescribeRegionsCommand({ AllRegions: false }), signal ? { abortSignal: signal } : {});
  return (out.Regions ?? []).map((r) => r.RegionName).filter((r): r is string => !!r).sort();
}

export async function organizationAccounts(signal?: AbortSignal): Promise<string[]> {
  const ids: string[] = [];
  for await (const page of checkedPages(paginateListAccounts({ client: new OrganizationsClient(AWS_LIMITS), stopOnSameToken: true }, {}, signal ? { abortSignal: signal } : {}), signal)) {
    for (const a of page.Accounts ?? []) if ((a.State ?? a.Status) === 'ACTIVE' && a.Id) { ids.push(a.Id); if (ids.length > 100) throw new Error('account count exceeds 100; select an explicit bounded account scope'); }
  }
  return ids.sort();
}

export function assumedRole(account: string, roleName: string, externalId: string | undefined, signal?: AbortSignal): CredentialProvider {
  const client = new STSClient(AWS_LIMITS);
  let cached: { accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: Date } | undefined;
  return async () => {
    signal?.throwIfAborted();
    if (cached && cached.expiration.getTime() - Date.now() > 60000) return cached;
    const out = await client.send(new AssumeRoleCommand({ RoleArn: `arn:aws:iam::${account}:role/${roleName}`, RoleSessionName: 'edgepq-scan', DurationSeconds: 3600, ...(externalId ? { ExternalId: externalId } : {}) }), signal ? { abortSignal: signal } : {});
    const c = out.Credentials;
    if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken || !c.Expiration) throw new Error('AssumeRole returned incomplete credentials');
    cached = { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, expiration: c.Expiration };
    return cached;
  };
}
