import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { EC2Client, DescribeRegionsCommand } from '@aws-sdk/client-ec2';
import { OrganizationsClient, paginateListAccounts } from '@aws-sdk/client-organizations';
import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';
import type { CredentialProvider } from './types.ts';

export async function callerIdentity(): Promise<{ account: string; arn: string }> {
  const out = await new STSClient({}).send(new GetCallerIdentityCommand({}));
  if (!out.Account || !out.Arn) throw new Error('sts:GetCallerIdentity returned no account');
  return { account: out.Account, arn: out.Arn };
}

export async function enabledRegions(credentials: CredentialProvider | undefined): Promise<string[]> {
  const out = await new EC2Client({ region: 'us-east-1', ...(credentials ? { credentials } : {}) }).send(new DescribeRegionsCommand({ AllRegions: false }));
  return (out.Regions ?? []).map((r) => r.RegionName).filter((r): r is string => !!r).sort();
}

export async function organizationAccounts(): Promise<string[]> {
  const ids: string[] = [];
  for await (const page of paginateListAccounts({ client: new OrganizationsClient({}) }, {})) {
    for (const a of page.Accounts ?? []) if (a.Status === 'ACTIVE' && a.Id) ids.push(a.Id);
  }
  return ids.sort();
}

export function assumedRole(account: string, roleName: string, externalId: string | undefined): CredentialProvider {
  return fromTemporaryCredentials({
    params: {
      RoleArn: `arn:aws:iam::${account}:role/${roleName}`,
      RoleSessionName: 'edgepq-scan',
      DurationSeconds: 3600,
      ...(externalId ? { ExternalId: externalId } : {}),
    },
  });
}
