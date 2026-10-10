import { CloudTrailClient, paginateLookupEvents } from '@aws-sdk/client-cloudtrail';
import type { Collector, CollectorContext } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

/* Client readiness, from evidence rather than inventory: the last N API calls
   to the services whose endpoints already offer ML-KEM, and what key
   exchange each client actually negotiated. CloudTrail's 90-day event
   history is read with LookupEvents, which needs no trail and costs nothing.
   Events made by an AWS service on the caller's behalf carry no tlsDetails
   and are left out of the sample.

   The result is one synthetic resource per service, which CLIENT-KX-001
   evaluates. */
export const SAMPLED_SERVICES = ['kms.amazonaws.com', 'secretsmanager.amazonaws.com'];

type Sample = { events_sampled: number; classical_count: number; hybrid_count: number; user_agents_classical: string[]; no_tls_details: number };

export function summarise(events: string[]): Sample {
  const s: Sample = { events_sampled: 0, classical_count: 0, hybrid_count: 0, user_agents_classical: [], no_tls_details: 0 };
  const agents = new Map<string, number>();
  for (const raw of events) {
    let e: { tlsDetails?: { keyExchange?: string; tlsVersion?: string }; userAgent?: string };
    try { e = JSON.parse(raw); } catch { continue; }
    const kx = e.tlsDetails?.keyExchange;
    if (!kx) { s.no_tls_details += 1; continue; }
    s.events_sampled += 1;
    if (/MLKEM/i.test(kx)) { s.hybrid_count += 1; continue; }
    s.classical_count += 1;
    const ua = (e.userAgent ?? 'unknown user agent').slice(0, 120);
    agents.set(ua, (agents.get(ua) ?? 0) + 1);
  }
  s.user_agents_classical = [...agents.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ua, n]) => `${ua} (${n})`);
  return s;
}

export const cloudtrail: Collector = {
  service: 'cloudtrail',
  async run(ctx: CollectorContext) {
    if (ctx.cloudTrailSample <= 0) return { resources: [], notes: ['cloudtrail: client sample disabled'] };
    const client = new CloudTrailClient(clientConfig(ctx));
    const resources = [];
    for (const service of SAMPLED_SERVICES) {
      const raws: string[] = [];
      for await (const page of paginateLookupEvents({ client }, { LookupAttributes: [{ AttributeKey: 'EventSource', AttributeValue: service }], MaxResults: 50 })) {
        for (const ev of page.Events ?? []) if (ev.CloudTrailEvent) raws.push(ev.CloudTrailEvent);
        if (raws.length >= ctx.cloudTrailSample) break;
      }
      const sample = summarise(raws.slice(0, ctx.cloudTrailSample));
      resources.push(resource(ctx, 'edgepq_cloudtrail_tls_sample', `edgepq:${ctx.scope.account}:${ctx.scope.region}:${service}`, {
        account: ctx.scope.account,
        region: ctx.scope.region,
        service,
        ...sample,
      }));
    }
    return { resources };
  },
};
