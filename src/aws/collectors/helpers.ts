import type { AttrValue, Resource } from '../../engine/types.ts';
import type { CollectorContext } from '../types.ts';

export function resource(ctx: CollectorContext, type: string, arn: string, attrs: { [k: string]: AttrValue }): Resource {
  return { type, address: arn, attrs, unknown: [], origin: { kind: 'aws', account: ctx.scope.account, region: ctx.scope.region, arn } };
}

export function clientConfig(ctx: CollectorContext, region = ctx.scope.region) {
  return { region, ...(ctx.credentials ? { credentials: ctx.credentials } : {}) };
}
