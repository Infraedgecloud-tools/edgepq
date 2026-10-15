/* ============================================================================
   The AWS scanner. Read-only, one collector per service, every failure
   recorded as "not checked" for that account/region/service rather than
   skipped in silence. Node-only: nothing under src/aws is bundled for the
   browser.
   ========================================================================= */

import type { STSClient } from '@aws-sdk/client-sts';
import type { Resource } from '../engine/types.ts';

/* The credential provider type every client accepts, taken from one of them
   rather than from a package of its own. */
export type CredentialProvider = NonNullable<NonNullable<ConstructorParameters<typeof STSClient>[0]>['credentials']>;

export type Scope = { account: string; region: string };

export type NotChecked = { account: string; region: string; service: string; reason: string };

export type Collected = { resources: Resource[]; notes?: string[]; excluded?: true };

/* A collector sees one account in one region, through credentials for that
   account. Global services (CloudFront) run once per account in us-east-1. */
export type Collector = {
  service: string;
  global?: true;
  run: (ctx: CollectorContext) => Promise<Collected>;
};

export type CollectorContext = {
  scope: Scope;
  credentials: CredentialProvider | undefined;   /* undefined = default provider chain */
  cloudTrailSample: number;
  signal?: AbortSignal;
};

export type AwsScanOptions = {
  accounts?: string[];            /* account ids; default: the caller's own */
  organization?: boolean;         /* list every active account in the organization */
  regions?: string[];             /* default: every region the account has enabled */
  roleName?: string;              /* assumed as arn:aws:iam::<account>:role/<roleName> in every account but the caller's own */
  externalId?: string;
  cloudTrailSample?: number;      /* events per service per region, default 200; 0 disables */
  timeoutMs?: number;             /* total run budget, default 120000, maximum 3600000 */
  signal?: AbortSignal;
  log?: (line: string) => void;
};

export type AwsScan = {
  caller: { account: string; arn: string };
  accounts: string[];
  regions: string[];
  /** Successfully enumerated empty scopes count as complete collection. */
  status: 'complete' | 'partial' | 'failed';
  coverage: { account: string; region: string; service: string; status: 'complete' | 'failed' | 'excluded'; resources: number }[];
  resources: Resource[];
  not_checked: NotChecked[];
  notes: string[];
};
