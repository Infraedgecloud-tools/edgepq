import { AWS_LIMITS } from '../bounds.ts';
import type { AttrValue, Resource } from '../../engine/types.ts';
import type { CollectorContext } from '../types.ts';

/* A field the API left out is absent, as it would be in Terraform; the rules
   apply their documented defaults to absent attributes, never to nulls. */
export function resource(ctx: CollectorContext, type: string, arn: string, attrs: { [k: string]: AttrValue }): Resource {
  const present: { [k: string]: AttrValue } = {};
  for (const [k, v] of Object.entries(attrs)) if (v !== null) present[k] = v;
  return { type, address: arn, attrs: present, unknown: [], origin: { kind: 'aws', account: ctx.scope.account, region: ctx.scope.region, arn } };
}

export function clientConfig(ctx: CollectorContext, region = ctx.scope.region) {
  return { ...AWS_LIMITS, region, ...(ctx.credentials ? { credentials: ctx.credentials } : {}) };
}
